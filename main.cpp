/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   main.cpp
 * Author: vt
 *
 * Created on May 22, 2020, 10:01 AM
 */

#include <cstdlib>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <ibmtss/tss.h> // Official tss; consists of create, delete, execute
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tsstransmit.h>	/* for simulator power up */
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <cstring>
#include "objecttemplates.h"
#include "json.hpp"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>

using namespace std;
using json = nlohmann::json;    // for convenience

typedef struct {string description; int pcr; unsigned char *digest; unsigned int digestLen;} boot_log_t;
boot_log_t boot_log[10];    // create a string array as boot record
int boot_log_i = 0;

int DigestMessage(const char *message, size_t messageLen, unsigned char **digest, unsigned int *digestLen);
int MeasureElement(string description, string data, int pcr);
void ErrorCodePlotter(TPM_RC rc);

/*
 * 
 */
int main(int argc, char** argv) {
    
 /***************************************************************
 *  Measured boot
 ***************************************************************/   
    TPM_RC rc = 0;
    TSS_CONTEXT *tssContext = NULL;
    
    // Powerup
    rc = TSS_Create(&tssContext);
    rc |= TSS_TransmitPlatform(tssContext, TPM_SIGNAL_POWER_OFF, "TPM2_PowerOffPlatform");   // Message only for printf
    rc |= TSS_TransmitPlatform(tssContext, TPM_SIGNAL_POWER_ON, "TPM2_PowerOnPlatform");
    rc |= TSS_TransmitPlatform(tssContext, TPM_SIGNAL_NV_ON, "TPM2_NvOnPlatform");
    if(TPM_RC_SUCCESS != rc){
        ErrorCodePlotter(rc);
        return -1;
    }
    rc = TSS_Delete(tssContext);
    if(TPM_RC_SUCCESS != rc){
        ErrorCodePlotter(rc);
        return -1;
    }
    
    // Startup    
    rc = TSS_Create(&tssContext);   // Needed, but why?
    Startup_In inStart;
    inStart.startupType = TPM_SU_CLEAR;
    rc = TSS_Execute(tssContext,
                     NULL, 
                     (COMMAND_PARAMETERS *)&inStart,
                     NULL,
                     TPM_CC_Startup,
                     TPM_RH_NULL, NULL, 0);
    if(TPM_RC_SUCCESS != rc){
        ErrorCodePlotter(rc);
        return -1;
    }
    
    rc = TSS_Delete(tssContext);
    if(TPM_RC_SUCCESS != rc){
        ErrorCodePlotter(rc);
        return -1;
    }

    // Init PCRs with 0?
    
    // CRTM measures the firmware and passes control to it.
    if(0 != MeasureElement("Firmware ver 1234", "Firmware blob", 0))
        return -1; 
    

    // Firmware measures the boot loader and passes control to it.
    if(0 != MeasureElement("Boot loader /EFI/boot.efi", "Boot loader blob", 1))
        return -1; 

    // Boot loader measures the OS kernel and passes control to it.
    if(0 != MeasureElement("Kernel file /boot/vmlinuz-linux", "Kernel blob", 1))
        return -1;
    
/***************************************************************
 *  Establish a TCP connection with the Client
 ***************************************************************/
    
    // Create a socket
    int sockListen = socket(AF_INET, SOCK_STREAM, 0);
    if (sockListen == -1)
    {
        cerr << "Can't create a socket! Quitting" << endl;
        return -1;
    }
 
    // Bind the ip address and port to a socket
    sockaddr_in hint;
    hint.sin_family = AF_INET;
    hint.sin_port = htons(7777);
    inet_pton(AF_INET, "0.0.0.0", &hint.sin_addr);  // any ip address
 
    if (bind(sockListen, (sockaddr*)&hint, sizeof(hint)) == -1)  //connect socket to port
    {
        cerr << "Can't bind to IP/port" << endl;
        return -1;
    }
 
    // Make the socket for listening in
    if( listen(sockListen, SOMAXCONN) == -1)
    {
        cerr << "Can't listen" << endl;
        return -1;
    }
 
    // Wait for a connection
    sockaddr_in client;
    socklen_t clientSize = sizeof(client);
    
    printf("Wait for connection...\n");
    int clientSocket = accept(sockListen, (sockaddr*)&client, &clientSize);
    
    printf("Connection established\n");
    char host[NI_MAXHOST];      // Client's remote name
    char service[NI_MAXSERV];   // Service (i.e. port) the client is connect on
    memset(host, 0, NI_MAXHOST);
    memset(service, 0, NI_MAXSERV);
 
    if (getnameinfo((sockaddr*)&client, sizeof(client), host, NI_MAXHOST, service, NI_MAXSERV, 0) == 0)
    {
        cout << host << " connected on port " << service << endl;
    }
    else
    {
        inet_ntop(AF_INET, &client.sin_addr, host, NI_MAXHOST);
        cout << host << " connected on port " << ntohs(client.sin_port) << endl;
    }
 
    // Close listening socket
    close(sockListen);
 
    char recvBuf[4096];
    memset(recvBuf, 0, 4096);
    int recvBufLen = 0;
    
    // Wait for client to send data 
    recvBufLen = recv(clientSocket, &recvBuf[recvBufLen], 4096, 0);
    if (recvBufLen == -1)
    {
        cerr << "Error in recv(). Quitting" << endl;
        close(clientSocket);
        return -1;
    }
    cout << "Request received " << endl;
        
    cout << "Received message: "<< string(recvBuf, 0, recvBufLen) << endl;  // Print received message
    
    
/***************************************************************
 *  Process received command from client
 ***************************************************************/
    json jRequest;
    long nonce;
    try {
         jRequest = json::parse(recvBuf);  // When it tries to parse nonsense, it gives SIGABRT 

        if (jRequest["Request"] != 1)  // Request = 1: full vehicle status measurement 
        {
            cerr << "Invalid request received" << endl;
            return -1;
        }

        nonce = jRequest["Nonce"];
        cout << "Nonce: " << nonce << endl;
    } catch(...){
        cerr << "Error while parsing JSON!"<< endl;
        return -1;
    }
    
 /***************************************************************
 *  Send commands to ECUs
 ***************************************************************/   
    // Create a nonce for every ECU and send them
    int numberEcu = 3;
    int nonceEcu[numberEcu];
    for(int i=0; i<numberEcu; i++)
    {
        // GetRandom
        GetRandom_In inRandom;
        GetRandom_Out outRandom;
        inRandom.bytesRequested = 4;    // Not sure how long it should be. 4 bytes fit in an Int
        rc = TSS_Create(&tssContext);
        if(TPM_RC_SUCCESS != rc){
            ErrorCodePlotter(rc);
            return -1;
        }

        rc = TSS_Execute(tssContext,
                        (RESPONSE_PARAMETERS *)&outRandom, 
                        (COMMAND_PARAMETERS *)&inRandom,
                        NULL,
                        TPM_CC_GetRandom,
                        TPM_RH_NULL, NULL, 0);  // TPM_RH_NULL, NULL, 0 terminates a list of 3-tuples with additional handlers
        if(TPM_RC_SUCCESS != rc){
            ErrorCodePlotter(rc);
            return -1;
        }

        memcpy(&nonceEcu[i], outRandom.randomBytes.t.buffer, outRandom.randomBytes.t.size);

        rc = TSS_Delete(tssContext);
        if(TPM_RC_SUCCESS != rc){
            ErrorCodePlotter(rc);
            return -1;
        }
    }
    
    // ECUs:
    for(int i=0; i<numberEcu; i++)
    {
        
    }
    
/***************************************************************
 *  Send answer back to client
 ***************************************************************/    
    json jAnswer;
    
    jAnswer["PCR"]["PCR1"] = 0xABC; // Dummy long
    jAnswer["PCR"]["PCR2"] = 0xABC; // Dummy long
    jAnswer["PCR"]["Nonce"] = 0xABC; // Dummy long
    jAnswer["PCR"]["Signature"] = 0xABC; // Dummy long
    
    jAnswer["EventLog"] = "Dummy string";
    
    string sendString = jAnswer.dump();
    // char sendBuf[4096];
    
    send(clientSocket, sendString.c_str(), sendString.length(), 0);  // +1?
    cout << "answer sent: " << sendString << endl;
    cout << "answer sent length: " << sendString.length() << endl;
    // Close the socket
    close(clientSocket);
    
    return 0;
}


int MeasureElement(string description, string data, int pcr) {
    // Add digest to event log.
    unsigned char *digest;
    unsigned int digestLen;
    DigestMessage(data.c_str(), data.length(), &digest, &digestLen);
    if(32 != digestLen)
        return -1;
    boot_log[boot_log_i] = (boot_log_t){.description = description,
                                        .pcr = pcr,
                                        .digest = digest,
                                        .digestLen = digestLen};
    boot_log_i++;
    
    // Extend PCR with digest.
    TPM_RC rc = 0;
    TSS_CONTEXT *tssContext = NULL;
    PCR_Extend_In inExtend;
    inExtend.digests.count = 1;
    inExtend.digests.digests[0].hashAlg = TPM_ALG_SHA256;
    memset((uint8_t *)&inExtend.digests.digests[0].digest, 0, sizeof(TPMU_HA)); // sizeof(TPMU_HA)=128
    memcpy((uint8_t *)&inExtend.digests.digests[0].digest, "Hallo", strlen("Hallo")); //digest, digestLen);
    inExtend.pcrHandle = pcr;
    
    //TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    rc = TSS_Create(&tssContext);
    if(TPM_RC_SUCCESS != rc){
        ErrorCodePlotter(rc);
        return -1;
    }
    rc = TSS_Execute(tssContext,
                    NULL, 
                    (COMMAND_PARAMETERS *)&inExtend,
                    NULL,
                    TPM_CC_PCR_Extend,
                    TPM_RS_PW, NULL, 0,
                    TPM_RH_NULL, NULL, 0);
    if(TPM_RC_SUCCESS != rc){
        ErrorCodePlotter(rc);
        return -1;
    }
    
    rc = TSS_Delete(tssContext);        // Always delete the context after it is no longer needed
    if(TPM_RC_SUCCESS != rc){
        ErrorCodePlotter(rc);
        return -1;
    }
    
    return 0;
}

int DigestMessage(const char *message, size_t messageLen, unsigned char **digest, unsigned int *digestLen){
    /* Alternative way (found only later):
        messageDigest.hashAlg = TPM_ALG_SHA256;
        // hash algorithm mapped to size
        sizeInBytes = TSS_GetDigestSize(messageDigest.hashAlg);
        rc = TSS_Hash_Generate(&messageDigest,
                               strlen(messageString), messageString,
                               0, NULL);    
     */
    
    
    // Create a Message Digest context and allocate space for digest
    EVP_MD_CTX *mdctx;
    if((mdctx = EVP_MD_CTX_new()) == NULL)
        return -1;
    if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
        return -1;
    
    // Initialise the context by identifying the algorithm to be used (built-in algorithms are defined in evp.h)
    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
        return -1;
    
    // Provide the message whose digest needs to be calculated. Messages can be divided into sections and provided over a number of calls to the library if necessary
    if(1 != EVP_DigestUpdate(mdctx, message, messageLen))
        return -1;
    
    // Caclulate the digest
    if(1 != EVP_DigestFinal_ex(mdctx, *digest, digestLen))
        return -1;
    
    // Clean up the context if no longer required
    EVP_MD_CTX_free(mdctx);
    
    return 0;
}

void ErrorCodePlotter(TPM_RC rc){
    const char *msg, *submsg, *num;
    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
    printf("rc: %08x: %s%s%s\n", rc, msg, submsg, num);
}

// Create a restricted RSA signing key.
//// Assume this key is trusted by the remote verifier.
//    //var aik = app.CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_RSA,/*restricted=*/1, /*decrypt=*/0, /*sign=*/1);
//    CreatePrimary_In inPrimary;
//    CreatePrimary_Out outPrimary;
//    TPMI_DH_OBJECT signHandle = 0;
//    
//    inPrimary.primaryHandle = TPM_RH_OWNER;  //TPM_RH_NULL, TPM_RH_PLATFORM, TPM_RH_OWNER, TPM_RH_ENDORSEMENT
//    inPrimary.inSensitive.sensitive.userAuth.t.size = 0;    // No key Password
//    inPrimary.inSensitive.sensitive.data.t.size = 0;
//    TPMA_OBJECT addObjectAttributes;
//    TPMA_OBJECT deleteObjectAttributes;
//    addObjectAttributes.val = 0;
//    addObjectAttributes.val |= TPMA_OBJECT_RESTRICTED;
//    addObjectAttributes.val |= TPMA_OBJECT_SIGN;
//    deleteObjectAttributes.val = 0;
//    rc = asymPublicTemplate(&inPrimary.inPublic.publicArea,
//				    addObjectAttributes,
//                                    deleteObjectAttributes,
//				    TYPE_ST,                    // keyType
//                                    TPM_ALG_RSA,                // algPublic
//                                    TPM_ECC_NONE,               // curveID
//                                    TPM_ALG_SHA256,             // nalg
//                                    TPM_ALG_SHA256,             // halg
//                                    NULL);                      // policyFilename
//    if(TPM_RC_SUCCESS != rc){
//        ErrorCodePlotter(rc);
//        return -1;
//    }
//    inPrimary.inPublic.publicArea.unique.rsa.t.size = 0;
//    inPrimary.outsideInfo.t.size = 0;
//    inPrimary.creationPCR.count = 0;
//    
//    rc = TSS_Create(&tssContext);
//    if(TPM_RC_SUCCESS != rc){
//        ErrorCodePlotter(rc);
//        return -1;
//    }
//    
//    rc = TSS_Execute(tssContext,
//                    (RESPONSE_PARAMETERS *)&outPrimary, 
//                    (COMMAND_PARAMETERS *)&inPrimary,
//                    NULL,
//                    TPM_CC_CreatePrimary,
//                    TPM_RS_PW, NULL, 0,     // parentPasswordPtr
//                    TPM_RH_NULL, NULL, 0);
//    if(TPM_RC_SUCCESS != rc){
//        ErrorCodePlotter(rc);
//        return -1;
//    }
//    
//    signHandle = outPrimary.objectHandle;
//    
//    rc = TSS_Delete(tssContext);
//    if(TPM_RC_SUCCESS != rc){
//        ErrorCodePlotter(rc);
//        return -1;
//    }

/*
// Sign PCR quote with random nonce.
    // Quote
    // Unlike TPM2_PCR_Read() it gives a digest of the selected PCRs
    // Does not take the challenge as input yet
    Quote_In inQuote;
    Quote_Out outQuote;
    
    inQuote.PCRselect.pcrSelections[0].sizeofSelect = 3;
    inQuote.PCRselect.pcrSelections[0].pcrSelect[0] = 0;
    inQuote.PCRselect.pcrSelections[0].pcrSelect[1] = 0;
    inQuote.PCRselect.pcrSelections[0].pcrSelect[2] = 0;
    // accumulate PCR select bits: inQuote.PCRselect.pcrSelections[0].pcrSelect[pcrHandle / 8] |= 1 << (pcrHandle % 8);
    inQuote.PCRselect.pcrSelections[0].pcrSelect[0] |= (1<<0) | (1<<1);
    inQuote.PCRselect.count = 2;
    inQuote.PCRselect.pcrSelections[0].hash = TPM_ALG_SHA256;
    inQuote.signHandle = signHandle;
    inQuote.inScheme.scheme = TPM_ALG_RSASSA;
    inQuote.inScheme.details.rsassa.hashAlg = TPM_ALG_SHA256;
    memcpy(inQuote.qualifyingData.t.buffer, &challenge, sizeof(challenge));
    inQuote.qualifyingData.t.size = sizeof(challenge);
    
    
    rc = TSS_Create(&tssContext);
    if(TPM_RC_SUCCESS != rc){
        ErrorCodePlotter(rc);
        return -1;
    }
    
    rc = TSS_Execute(tssContext,
                    (RESPONSE_PARAMETERS *)&outQuote,
                    (COMMAND_PARAMETERS *)&inQuote,
                    NULL,
                    TPM_CC_Quote,
                    TPM_RS_PW, NULL, 0,
                    TPM_RH_NULL, NULL, 0);
    if(TPM_RC_SUCCESS != rc){
        printf("hier?\n");
        ErrorCodePlotter(rc);
        return -1;
    }
    
    rc = TSS_Delete(tssContext);
    if(TPM_RC_SUCCESS != rc){
        ErrorCodePlotter(rc);
        return -1;
    }
    */
    
// Unload key.
// Build forge RSA public key.
// Build forge signature blob.
// Compute message digest.
// Remote attester verifies signature.
// Unmarshal the serialized TPMS_ATTEST buffer.
// Extract the nonce from the tpm2b_attest buffer.
  // It should match the random challenge that we sent. This proves the attested data is fresh.
// Playback digests from boot_log.
// app.Quote selects PCR0, PCR1, PCR2 and PCR3. Therefore, the expected quote
  // is the digest of <PCR0, PCR1, PCR2, PCR3>.  
// Extract selected PCRs digest from the tpm2b_attest buffer.
  // It should match the expected digest computed above.
// Boot log's integrity is verified. Its contents can be used for host integrity evaluation.