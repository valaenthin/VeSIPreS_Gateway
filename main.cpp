/* 
 * VeSIPreS Vehicle Simulator
 * 
 * 
 * File:   main.cpp
 * Author: Valaenthin Tratter (valaenthin.tratter@tum.de)
 *
 * Created on May 22, 2020, 10:01 AM
 */

#include <cstdlib>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <ibmtss/tss.h> // Official tss; contains 'create', 'delete', 'execute'
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
#include <fstream>

using namespace std;
using json = nlohmann::json;    // for convenience

// Boot log
typedef struct {string description; int pcr; unsigned char *digest; unsigned int digestLen;} bootLog_t;
bootLog_t bootLog[10];    // create a string array as boot record
int bootLogIndex = 0;

int DigestMessage(const char *message, size_t messageLen, unsigned char **digest, unsigned int *digestLen);
int MeasureElement(string description, string data, int pcr);
void ErrorCodePlotter(TPM_RC rc);

/*
 * Main function containing measured boot, connection establishment and reporting
 */
int main(int argc, char** argv) {
    cout << "****************************************************************" << endl;
    cout << "*                                                              *" << endl;
    cout << "*                VeSIPreS Vehicle Simulator                    *" << endl;
    cout << "*                                                              *" << endl;
    cout << "*      Vehicle Gateway and ECU emulator for VeSIPreS PoC       *" << endl;
    cout << "*                                                              *" << endl;
    cout << "****************************************************************" << endl<< endl;
    
    cout << "Boot sequence started..." << endl;
    
 /***************************************************************
 *  Measured boot
 ***************************************************************/   
    TPM_RC rc = 0;
    TSS_CONTEXT *tssContext = NULL;
    
    // Powerup
    rc = TSS_Create(&tssContext);
    rc |= TSS_TransmitPlatform(tssContext, TPM_SIGNAL_POWER_OFF, "TPM2_PowerOffPlatform");   // Last parameter only for console printout
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
    rc = TSS_Create(&tssContext);   // New context needed for startup
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

    // Init PCRs not needed since TPM automatically initializes at power on
    
    // CRTM measures the firmware and passes control to it.
    if(0 != MeasureElement("Firmware ver 1234", "Firmware blob", 0))
        return -1; 
    

    // Firmware measures the boot loader and passes control to it.
    if(0 != MeasureElement("Boot loader /EFI/boot.efi", "Boot loader blob", 1))
        return -1; 

    // Boot loader measures the OS kernel and passes control to it.
    if(0 != MeasureElement("Kernel file /boot/vmlinuz-linux", "Kernel blob", 1))
        return -1;

    cout << "Measured boot complete" << endl;
/***************************************************************
 *  Create a (restricted) RSA signing key
 ***************************************************************/
// This key is trusted by the remote verifier. Certificate is created at production time of the vehicle by the OEM.
    CreatePrimary_In inPrimary;
    CreatePrimary_Out outPrimary;
    TPMI_DH_OBJECT signHandle = 0;
    
    inPrimary.primaryHandle = TPM_RH_OWNER;  //TPM_RH_NULL, TPM_RH_PLATFORM, TPM_RH_OWNER, TPM_RH_ENDORSEMENT
    inPrimary.inSensitive.sensitive.userAuth.t.size = 0;    // No key Password
    inPrimary.inSensitive.sensitive.data.t.size = 0;
    TPMA_OBJECT addObjectAttributes;
    TPMA_OBJECT deleteObjectAttributes;
    addObjectAttributes.val = 0;
    addObjectAttributes.val |= TPMA_OBJECT_RESTRICTED;
    addObjectAttributes.val |= TPMA_OBJECT_SIGN;
    deleteObjectAttributes.val = 0;
    rc = asymPublicTemplate(&inPrimary.inPublic.publicArea,
				    addObjectAttributes,
                                    deleteObjectAttributes,
				    TYPE_ST,                    // keyType
                                    TPM_ALG_RSA,                // algPublic
                                    TPM_ECC_NONE,               // curveID
                                    TPM_ALG_SHA256,             // nalg
                                    TPM_ALG_SHA256,             // halg
                                    NULL);                      // policyFilename
    if(TPM_RC_SUCCESS != rc){
        ErrorCodePlotter(rc);
        return -1;
    }
    inPrimary.inPublic.publicArea.unique.rsa.t.size = 0;
    inPrimary.outsideInfo.t.size = 0;
    inPrimary.creationPCR.count = 0;
    
    rc = TSS_Create(&tssContext);
    if(TPM_RC_SUCCESS != rc){
        ErrorCodePlotter(rc);
        return -1;
    }
    
    rc = TSS_Execute(tssContext,
                    (RESPONSE_PARAMETERS *)&outPrimary, 
                    (COMMAND_PARAMETERS *)&inPrimary,
                    NULL,
                    TPM_CC_CreatePrimary,
                    TPM_RS_PW, NULL, 0,     // parentPasswordPtr
                    TPM_RH_NULL, NULL, 0);
    if(TPM_RC_SUCCESS != rc){
        ErrorCodePlotter(rc);
        return -1;
    }
    
    signHandle = outPrimary.objectHandle;
    
    rc = TSS_Delete(tssContext);
    if(TPM_RC_SUCCESS != rc){
        ErrorCodePlotter(rc);
        return -1;
    }
    cout << "RSA signing key created" << endl;
    
    while(true) // main loop
    {
        
/***************************************************************
 *  Establish a TCP connection with the Client
 ***************************************************************/
    // Create a socket
    int sockListen = socket(AF_INET, SOCK_STREAM, 0);
    if (sockListen == -1)
    {
        cerr << "Error: Can't create a socket! Quitting" << endl;
        return -1;
    }
    int enable = 1;
    if (setsockopt(sockListen, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
        {
        cerr << "Error: setsockopt(SO_REUSEADDR) failed" << endl;
        return -1;
    }
 
    // Bind IP address and port to a socket
    sockaddr_in hint;
    hint.sin_family = AF_INET;
    hint.sin_port = htons(7777);
    inet_pton(AF_INET, "0.0.0.0", &hint.sin_addr);  // any ip address accepted
 
    if (bind(sockListen, (sockaddr*)&hint, sizeof(hint)) == -1)  //connect socket to port
    {
        cerr << "Error: Can't bind to IP/port" << endl;
        return -1;
    }
 
    // Make the socket for listening in
    if( listen(sockListen, SOMAXCONN) == -1)
    {
        cerr << "Error: Can't listen" << endl;
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
 
    // initialize receiving buffer
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
    
    cout << "Request received: "<< string(recvBuf, 0, recvBufLen) << endl;  // Print received message
    
    
/***************************************************************
 *  Process received command from client
 ***************************************************************/
    json jRequest;
    long nonceG;
    try {
         jRequest = json::parse(recvBuf);  // When it tries to parse nonsense, it gives SIGABRT 

        if (jRequest["Request"] != 1)  // Request = 1: full vehicle status measurement 
        {
            cerr << "Error: Invalid request received" << endl;
            return -1;
        }

        nonceG = jRequest["NonceG"];
    } catch(...){
        cerr << "Error: Parsing JSON"<< endl;
        return -1;
    }

/***************************************************************
 *  Quote PCR from measured boot
 ***************************************************************/ 
    int pcrQuote = 0;
    // Sign PCR quote with random nonce.
    // Quote
    // Unlike TPM2_PCR_Read() it gives a digest of the selected PCRs
    // Does not take the challenge as input yet
    /*Quote_In inQuote;
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
    memcpy(inQuote.qualifyingData.t.buffer, &nonceG, sizeof(nonceG));
    inQuote.qualifyingData.t.size = sizeof(nonceG);
    
    
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
        ErrorCodePlotter(rc);
        return -1;
    }
    
    rc = TSS_Delete(tssContext);
    if(TPM_RC_SUCCESS != rc){
        ErrorCodePlotter(rc);
        return -1;
    }
   */ 
/***************************************************************
 *  Send commands to ECUs
 ***************************************************************/   
    // Create a nonce for every ECU and send them
    const int EcuCount = 3;
    int EcuNonce[EcuCount]; // Not needed for implemented security stage (SL)
    string EcuDigest[EcuCount];
    const string EcuAddress[EcuCount] = {"/home/vt/Desktop/Ecu0SoftwareStack.bin",
        "/home/vt/Desktop/Ecu1SoftwareStack.bin",
        "/home/vt/Desktop/Ecu2SoftwareStack.bin"};
    
    cout << "Create Nonce for ECUs..." << endl;
    for(int i=0; i<EcuCount; i++)
    {
        // GetRandom
        GetRandom_In inRandom;
        GetRandom_Out outRandom;
        inRandom.bytesRequested = sizeof(int);
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
                        TPM_RH_NULL, NULL, 0);  // [TPM_RH_NULL, NULL, 0] terminates a list of 3-tuples with additional handlers
        if(TPM_RC_SUCCESS != rc){
            ErrorCodePlotter(rc);
            return -1;
        }

        memcpy(&EcuNonce[i], outRandom.randomBytes.t.buffer, outRandom.randomBytes.t.size);

        rc = TSS_Delete(tssContext);
        if(TPM_RC_SUCCESS != rc){
            ErrorCodePlotter(rc);
            return -1;
        }
    }
    cout << "Measure ECUs" << endl;
    // ECUs:
    for(int i=0; i < EcuCount; i++)
    {
        //      read file    
        streampos softwareStackSize;
        char * softwareStack;
        ifstream file (EcuAddress[i], ios::in|ios::binary|ios::ate);

        if (file.is_open())
        {
          softwareStackSize = file.tellg();
          softwareStack = new char [softwareStackSize];
          file.seekg (0, ios::beg);
          file.read (softwareStack, softwareStackSize);
          file.close();

          cout << "File read for ECU" << i<<  endl;
        }
        else cerr << "Error: Unable to open file for ECU" << i<<  endl;


        // calculate digest    
        unsigned char digest[20];
        SHA1(reinterpret_cast<const unsigned char *>(softwareStack), softwareStackSize, digest);
        delete[] softwareStack;

        char digest_string[40];
        for (int j = 0; j < 20; j++) {
            snprintf(&digest_string[2*j], 20, "%02x", digest[j]);
        }

        EcuDigest[i] = digest_string;
        cout << "Digest for ECU" << i << ": "<< EcuDigest[i]<< endl;
        
    }
    
/***************************************************************
 *  Send answer back to client
 ***************************************************************/    
    // create answer JSON
    json jAnswer;
    jAnswer["Pcr"] = pcrQuote;
    for(int i = 0; i < bootLogIndex; i++)
    {
        jAnswer["BootLog"][i]["description"] = bootLog[i].description;
        jAnswer["BootLog"][i]["digest"] = *bootLog[i].digest;   //VT
        jAnswer["BootLog"][i]["digestLen"] = bootLog[i].digestLen;
        jAnswer["BootLog"][i]["pcr"] = bootLog[i].pcr;
    }
    for(int i = 0; i < EcuCount; i++)
    {
        jAnswer["EcuReport"][i]["digest"] = EcuDigest[i];
    }
    
    string sendString = jAnswer.dump();
    // char sendBuf[4096];
    
    send(clientSocket, sendString.c_str(), sendString.length(), 0);  // +1?
    // cout << "answer sent: " << sendString << endl;
    // cout << "answer sent length: " << sendString.length() << endl;
    
    cout << "Answer sent" << endl;
    cout << "Transmission complete!" << endl << endl;
    // Close the socket
    close(clientSocket);
    
    } //main loop
    return 0;
}


int MeasureElement(string description, string data, int pcr) {
    // Add digest to event log.
    unsigned char *digest;
    unsigned int digestLen;
    DigestMessage(data.c_str(), data.length(), &digest, &digestLen);
    if(32 != digestLen)
        return -1;
    bootLog[bootLogIndex] = (bootLog_t){.description = description,
                                        .pcr = pcr,
                                        .digest = digest,
                                        .digestLen = digestLen};
    bootLogIndex++;
    
    // Extend PCR with digest.
    TPM_RC rc = 0;
    TSS_CONTEXT *tssContext = NULL;
    PCR_Extend_In inExtend;
    inExtend.digests.count = 1;
    inExtend.digests.digests[0].hashAlg = TPM_ALG_SHA256;
    memset((uint8_t *)&inExtend.digests.digests[0].digest, 0, sizeof(TPMU_HA)); // sizeof(TPMU_HA)=128
    memcpy((uint8_t *)&inExtend.digests.digests[0].digest, digest, digestLen);
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
    // Create a Message Digest context and allocate space for digest
    EVP_MD_CTX *mdctx;
    if((mdctx = EVP_MD_CTX_new()) == NULL)
        return -1;
    if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
        return -1;
    
    // Initialize the context by identifying the algorithm to be used (built-in algorithms are defined in evp.h)
    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
        return -1;
    
    // Provide the message whose digest needs to be calculated. Messages can be divided into sections and provided over a number of calls to the library if necessary
    if(1 != EVP_DigestUpdate(mdctx, message, messageLen))
        return -1;
    
    // Calculate the digest
    if(1 != EVP_DigestFinal_ex(mdctx, *digest, digestLen))
        return -1;
    
    // Clean up the context if no longer required
    EVP_MD_CTX_free(mdctx);
    
    return 0;
    
    /* Alternative approach:
        messageDigest.hashAlg = TPM_ALG_SHA256;
        // hash algorithm mapped to size
        sizeInBytes = TSS_GetDigestSize(messageDigest.hashAlg);
        rc = TSS_Hash_Generate(&messageDigest,
                               strlen(messageString), messageString,
                               0, NULL);    
     */
}

// Eror code plotter for TSS error codes
void ErrorCodePlotter(TPM_RC rc){
    const char *msg, *submsg, *num;
    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
    printf("rc: %08x: %s%s%s\n", rc, msg, submsg, num);
}