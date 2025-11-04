/*
 * Mock SDF library for testing parameter passing
 * This helps verify that the JNI layer is passing parameters correctly
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef void* HANDLE;
typedef unsigned long ULONG;
typedef unsigned char BYTE;
typedef long LONG;

#define SDR_OK 0
#define SDR_INARGERR 0x0100001D

/* Core functions (mandatory) */
LONG SDF_OpenDevice(HANDLE *phDevice) {
    printf("[MOCK] SDF_OpenDevice called\n");
    *phDevice = (HANDLE)0x1234;
    return SDR_OK;
}

LONG SDF_CloseDevice(HANDLE hDevice) {
    printf("[MOCK] SDF_CloseDevice called\n");
    return SDR_OK;
}

LONG SDF_OpenSession(HANDLE hDevice, HANDLE *phSession) {
    printf("[MOCK] SDF_OpenSession called\n");
    *phSession = (HANDLE)0x5678;
    return SDR_OK;
}

LONG SDF_CloseSession(HANDLE hSession) {
    printf("[MOCK] SDF_CloseSession called\n");
    return SDR_OK;
}

/* SM4 Key Generation */
LONG SDF_GenerateKeyWithIPK_ECC(HANDLE hSessionHandle, ULONG uiIPKIndex, ULONG uiKeyBits,
                                 BYTE *pucKey, ULONG *puiKeyLength, HANDLE *phKeyHandle) {
    printf("[MOCK] SDF_GenerateKeyWithIPK_ECC(session=%p, index=%lu, bits=%lu)\n",
           hSessionHandle, uiIPKIndex, uiKeyBits);

    *phKeyHandle = (HANDLE)0x9ABC;
    *puiKeyLength = 32;
    memset(pucKey, 0xAA, 32);
    return SDR_OK;
}

/* SM4 Single-block operations */
LONG SDF_Encrypt(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                 BYTE *pucIV, BYTE *pucData, ULONG uiDataLength,
                 BYTE *pucEncData, ULONG *puiEncDataLength) {
    printf("[MOCK] SDF_Encrypt(session=%p, key=%p, alg=0x%08lX, iv=%p, data_len=%lu)\n",
           hSessionHandle, hKeyHandle, uiAlgID, (void*)pucIV, uiDataLength);

    /* Check parameters */
    if (hSessionHandle == NULL || hKeyHandle == NULL) {
        printf("[MOCK] ERROR: Invalid handle\n");
        return SDR_INARGERR;
    }

    /* For SM4, block size is 16 bytes */
    ULONG blocks = (uiDataLength + 15) / 16;
    *puiEncDataLength = blocks * 16;

    /* Mock encryption: just copy and pad */
    memcpy(pucEncData, pucData, uiDataLength);
    if (*puiEncDataLength > uiDataLength) {
        memset(pucEncData + uiDataLength, 0x10, *puiEncDataLength - uiDataLength);
    }

    printf("[MOCK] Encrypted %lu bytes -> %lu bytes\n", uiDataLength, *puiEncDataLength);
    return SDR_OK;
}

LONG SDF_Decrypt(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                 BYTE *pucIV, BYTE *pucEncData, ULONG uiEncDataLength,
                 BYTE *pucData, ULONG *puiDataLength) {
    printf("[MOCK] SDF_Decrypt(session=%p, key=%p, alg=0x%08lX, iv=%p, enc_len=%lu)\n",
           hSessionHandle, hKeyHandle, uiAlgID, (void*)pucIV, uiEncDataLength);

    /* Check parameters */
    if (hSessionHandle == NULL || hKeyHandle == NULL) {
        printf("[MOCK] ERROR: Invalid handle\n");
        return SDR_INARGERR;
    }

    /* Mock decryption: just copy */
    *puiDataLength = uiEncDataLength;
    memcpy(pucData, pucEncData, uiEncDataLength);

    /* Remove padding if present */
    if (*puiDataLength >= 16) {
        BYTE last_byte = pucData[*puiDataLength - 1];
        if (last_byte == 0x10) {
            *puiDataLength -= 16;
        } else if (last_byte > 0 && last_byte <= 16) {
            *puiDataLength -= last_byte;
        }
    }

    printf("[MOCK] Decrypted %lu bytes -> %lu bytes\n", uiEncDataLength, *puiDataLength);
    return SDR_OK;
}

LONG SDF_CalculateMAC(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                      BYTE *pucIV, BYTE *pucData, ULONG uiDataLength,
                      BYTE *pucMac, ULONG *puiMacLength) {
    printf("[MOCK] SDF_CalculateMAC(session=%p, key=%p, alg=0x%08lX, iv=%p, data_len=%lu)\n",
           hSessionHandle, hKeyHandle, uiAlgID, (void*)pucIV, uiDataLength);

    /* Check parameters */
    if (hSessionHandle == NULL || hKeyHandle == NULL) {
        printf("[MOCK] ERROR: Invalid handle\n");
        return SDR_INARGERR;
    }

    /* Mock MAC: fixed 16 bytes */
    *puiMacLength = 16;
    memset(pucMac, 0xBB, 16);

    printf("[MOCK] Calculated MAC: %lu bytes\n", *puiMacLength);
    return SDR_OK;
}

/* Multi-block Init operations with 5 parameters */
LONG SDF_EncryptInit(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                     BYTE *pucIV, ULONG uiIVLength) {
    printf("[MOCK] SDF_EncryptInit(session=%p, key=%p, alg=0x%08lX, iv=%p, iv_len=%lu)\n",
           hSessionHandle, hKeyHandle, uiAlgID, (void*)pucIV, uiIVLength);
    return SDR_OK;
}

LONG SDF_DecryptInit(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                     BYTE *pucIV, ULONG uiIVLength) {
    printf("[MOCK] SDF_DecryptInit(session=%p, key=%p, alg=0x%08lX, iv=%p, iv_len=%lu)\n",
           hSessionHandle, hKeyHandle, uiAlgID, (void*)pucIV, uiIVLength);
    return SDR_OK;
}

LONG SDF_CalculateMACInit(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                          BYTE *pucIV, ULONG uiIVLength) {
    printf("[MOCK] SDF_CalculateMACInit(session=%p, key=%p, alg=0x%08lX, iv=%p, iv_len=%lu)\n",
           hSessionHandle, hKeyHandle, uiAlgID, (void*)pucIV, uiIVLength);
    return SDR_OK;
}

/* Support functions */
LONG SDF_DestroyKey(HANDLE hSessionHandle, HANDLE hKeyHandle) {
    printf("[MOCK] SDF_DestroyKey(session=%p, key=%p)\n", hSessionHandle, hKeyHandle);
    return SDR_OK;
}

LONG SDF_GenerateRandom(HANDLE hSessionHandle, ULONG uiLength, BYTE *pucRandom) {
    printf("[MOCK] SDF_GenerateRandom(session=%p, length=%lu)\n", hSessionHandle, uiLength);
    for (ULONG i = 0; i < uiLength; i++) {
        pucRandom[i] = (BYTE)(rand() & 0xFF);
    }
    return SDR_OK;
}

/* Multi-block Update/Final operations */
LONG SDF_EncryptUpdate(HANDLE hSessionHandle, BYTE *pucData, ULONG uiDataLength,
                       BYTE *pucEncData, ULONG *puiEncDataLength) {
    printf("[MOCK] SDF_EncryptUpdate\n");
    *puiEncDataLength = uiDataLength;
    memcpy(pucEncData, pucData, uiDataLength);
    return SDR_OK;
}

LONG SDF_EncryptFinal(HANDLE hSessionHandle, BYTE *pucEncData, ULONG *puiEncDataLength) {
    printf("[MOCK] SDF_EncryptFinal\n");
    *puiEncDataLength = 0;
    return SDR_OK;
}

LONG SDF_DecryptUpdate(HANDLE hSessionHandle, BYTE *pucEncData, ULONG uiEncDataLength,
                       BYTE *pucData, ULONG *puiDataLength) {
    printf("[MOCK] SDF_DecryptUpdate\n");
    *puiDataLength = uiEncDataLength;
    memcpy(pucData, pucEncData, uiEncDataLength);
    return SDR_OK;
}

LONG SDF_DecryptFinal(HANDLE hSessionHandle, BYTE *pucData, ULONG *puiDataLength) {
    printf("[MOCK] SDF_DecryptFinal\n");
    *puiDataLength = 0;
    return SDR_OK;
}

LONG SDF_CalculateMACUpdate(HANDLE hSessionHandle, BYTE *pucData, ULONG uiDataLength) {
    printf("[MOCK] SDF_CalculateMACUpdate\n");
    return SDR_OK;
}

LONG SDF_CalculateMACFinal(HANDLE hSessionHandle, BYTE *pucMac, ULONG *puiMacLength) {
    printf("[MOCK] SDF_CalculateMACFinal\n");
    *puiMacLength = 16;
    memset(pucMac, 0xCC, 16);
    return SDR_OK;
}
