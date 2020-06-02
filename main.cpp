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

using namespace std;

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
    
    TPM_RC rc = 0;
    TSS_CONTEXT *tssContext = NULL;
    
    
// Simulate measured boot.
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
    
// CRTM measures the firmware and passes control to it.
    if(0 != MeasureElement("Firmware ver 1234", "Firmware blob", 0))
        return -1; 
    

// Firmware measures the boot loader and passes control to it.
    if(0 != MeasureElement("Boot loader /EFI/boot.efi", "Boot loader blob", 1))
        return -1; 

// Boot loader measures the OS kernel and passes control to it.
    if(0 != MeasureElement("Kernel file /boot/vmlinuz-linux", "Kernel blob", 1))
        return -1; 
    
// Create a restricted RSA signing key.
// Assume this key is trusted by the remote verifier.
    //var aik = app.CreatePrimary(TPM2_RH_OWNER, TPM2_ALG_RSA,/*restricted=*/1, /*decrypt=*/0, /*sign=*/1);
    CreatePrimary_In inPrimary;
    CreatePrimary_Out outPrimary;
    
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
    
    rc = TSS_Delete(tssContext);
    if(TPM_RC_SUCCESS != rc){
        ErrorCodePlotter(rc);
        return -1;
    }

    
// Remote attester generates a random nonce.
// The challenge is sent to the host.
//    unsigned int challenge = 0;
//    // GetRandom
//    GetRandom_In inRandom;
//    GetRandom_Out outRandom;
//    inRandom.bytesRequested = 8;
//    rc = TSS_Execute(tssContext,
//                    (RESPONSE_PARAMETERS *)&outRandom, 
//                    (COMMAND_PARAMETERS *)&inRandom,
//                    NULL,
//                    TPM_CC_GetRandom,
//                    TPM_RH_NULL, NULL, 0);  // TPM_RH_NULL, NULL, 0 terminates a list of 3-tuples with additional handlers
//    memcpy(&challenge, outRandom.randomBytes.t.buffer, outRandom.randomBytes.t.size);

    
// Sign PCR quote with random nonce.
    
    
    
    
// Unload key.    
    
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