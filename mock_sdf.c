/**
 * Mock SDF library for testing parameter fixes
 * Returns SDR_NOTSUPPORT for most functions to simulate partial implementation
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define SDR_OK           0x00000000
#define SDR_BASE         0x01000000
#define SDR_NOTSUPPORT   (SDR_BASE + 0x00000002)
#define SDR_INARGERR     (SDR_BASE + 0x0000001D)

typedef void* HANDLE;
typedef unsigned char BYTE;
typedef unsigned long ULONG;
typedef long LONG;

// Core functions (mandatory)
LONG SDF_OpenDevice(HANDLE *phDeviceHandle) {
    if (phDeviceHandle == NULL) return SDR_INARGERR;
    *phDeviceHandle = (HANDLE)1;
    return SDR_OK;
}

LONG SDF_CloseDevice(HANDLE hDeviceHandle) {
    return SDR_OK;
}

LONG SDF_OpenSession(HANDLE hDeviceHandle, HANDLE *phSessionHandle) {
    if (phSessionHandle == NULL) return SDR_INARGERR;
    *phSessionHandle = (HANDLE)1;
    return SDR_OK;
}

LONG SDF_CloseSession(HANDLE hSessionHandle) {
    return SDR_OK;
}

// Device info structure
typedef struct {
    BYTE IssuerName[40];
    BYTE DeviceName[16];
    BYTE DeviceSerial[16];
    ULONG DeviceVersion;
    ULONG StandardVersion;
    ULONG AsymAlgAbility[2];
    ULONG SymAlgAbility;
    ULONG HashAlgAbility;
    ULONG BufferSize;
} DEVICEINFO;

LONG SDF_GetDeviceInfo(HANDLE hSessionHandle, DEVICEINFO *pstDeviceInfo) {
    if (pstDeviceInfo == NULL) return SDR_INARGERR;
    memset(pstDeviceInfo, 0, sizeof(DEVICEINFO));
    strcpy((char*)pstDeviceInfo->IssuerName, "Mock SDF");
    strcpy((char*)pstDeviceInfo->DeviceName, "Mock Device");
    strcpy((char*)pstDeviceInfo->DeviceSerial, "1234567890");
    pstDeviceInfo->DeviceVersion = 1;
    pstDeviceInfo->StandardVersion = 1;
    return SDR_OK;
}

LONG SDF_GenerateRandom(HANDLE hSessionHandle, ULONG uiLength, BYTE *pucRandom) {
    if (pucRandom == NULL || uiLength == 0) return SDR_INARGERR;
    for (ULONG i = 0; i < uiLength; i++) {
        pucRandom[i] = (BYTE)(rand() % 256);
    }
    return SDR_OK;
}

// Key management (return not supported)
typedef struct {
    ULONG bits;
    BYTE x[64];
    BYTE y[64];
} ECCrefPublicKey;

typedef struct {
    BYTE x[64];
    BYTE y[64];
    BYTE C[96];
    BYTE M[32];
    ULONG L;
} ECCCipher;

LONG SDF_GenerateKeyWithIPK_ECC(HANDLE hSessionHandle, ULONG uiIPKIndex,
                                ULONG uiKeyBits, ECCCipher *pucKey,
                                HANDLE *phKeyHandle) {
    return SDR_NOTSUPPORT;
}

LONG SDF_DestroyKey(HANDLE hSessionHandle, HANDLE hKeyHandle) {
    return SDR_NOTSUPPORT;
}

// Symmetric encryption functions - CHECK PARAMETERS!
LONG SDF_Encrypt(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                BYTE *pucIV, BYTE *pucData, ULONG uiDataLength,
                BYTE *pucEncData, ULONG *puiEncDataLength) {
    // Check for invalid parameters
    if (pucData == NULL || pucEncData == NULL || puiEncDataLength == NULL) {
        return SDR_INARGERR;
    }
    if (uiDataLength == 0) {
        return SDR_INARGERR;
    }
    return SDR_NOTSUPPORT;
}

LONG SDF_Decrypt(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                BYTE *pucIV, BYTE *pucEncData, ULONG uiEncDataLength,
                BYTE *pucData, ULONG *puiDataLength) {
    // Check for invalid parameters
    if (pucEncData == NULL || pucData == NULL || puiDataLength == NULL) {
        return SDR_INARGERR;
    }
    if (uiEncDataLength == 0) {
        return SDR_INARGERR;
    }
    return SDR_NOTSUPPORT;
}

LONG SDF_CalculateMAC(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                     BYTE *pucIV, BYTE *pucData, ULONG uiDataLength,
                     BYTE *pucMac, ULONG *puiMacLength) {
    // Check for invalid parameters
    if (pucData == NULL || pucMac == NULL || puiMacLength == NULL) {
        return SDR_INARGERR;
    }
    if (uiDataLength == 0) {
        return SDR_INARGERR;
    }
    return SDR_NOTSUPPORT;
}

// Multi-step encryption functions - FIXED SIGNATURE WITH 5 PARAMETERS!
LONG SDF_EncryptInit(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                    BYTE *pucIV, ULONG uiIVLength) {
    // Validate IV length when IV is provided
    if (pucIV != NULL && uiIVLength == 0) {
        return SDR_INARGERR;
    }
    // For ECB mode, IV should be NULL and length should be 0
    // For CBC mode, IV should be non-NULL and length should be 16 for SM4
    return SDR_NOTSUPPORT;
}

LONG SDF_EncryptUpdate(HANDLE hSessionHandle, BYTE *pucData, ULONG uiDataLength,
                      BYTE *pucEncData, ULONG *puiEncDataLength) {
    if (pucData == NULL || pucEncData == NULL || puiEncDataLength == NULL) {
        return SDR_INARGERR;
    }
    return SDR_NOTSUPPORT;
}

LONG SDF_EncryptFinal(HANDLE hSessionHandle, BYTE *pucEncData, ULONG *puiEncDataLength) {
    if (pucEncData == NULL || puiEncDataLength == NULL) {
        return SDR_INARGERR;
    }
    return SDR_NOTSUPPORT;
}

// Multi-step decryption functions - FIXED SIGNATURE WITH 5 PARAMETERS!
LONG SDF_DecryptInit(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                    BYTE *pucIV, ULONG uiIVLength) {
    // Validate IV length when IV is provided
    if (pucIV != NULL && uiIVLength == 0) {
        return SDR_INARGERR;
    }
    return SDR_NOTSUPPORT;
}

LONG SDF_DecryptUpdate(HANDLE hSessionHandle, BYTE *pucEncData, ULONG uiEncDataLength,
                      BYTE *pucData, ULONG *puiDataLength) {
    if (pucEncData == NULL || pucData == NULL || puiDataLength == NULL) {
        return SDR_INARGERR;
    }
    return SDR_NOTSUPPORT;
}

LONG SDF_DecryptFinal(HANDLE hSessionHandle, BYTE *pucData, ULONG *puiDataLength) {
    if (pucData == NULL || puiDataLength == NULL) {
        return SDR_INARGERR;
    }
    return SDR_NOTSUPPORT;
}

// Multi-step MAC functions - FIXED SIGNATURE WITH 5 PARAMETERS!
LONG SDF_CalculateMACInit(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                         BYTE *pucIV, ULONG uiIVLength) {
    // Validate IV length when IV is provided
    if (pucIV != NULL && uiIVLength == 0) {
        return SDR_INARGERR;
    }
    return SDR_NOTSUPPORT;
}

LONG SDF_CalculateMACUpdate(HANDLE hSessionHandle, BYTE *pucData, ULONG uiDataLength) {
    if (pucData == NULL) {
        return SDR_INARGERR;
    }
    return SDR_NOTSUPPORT;
}

LONG SDF_CalculateMACFinal(HANDLE hSessionHandle, BYTE *pucMac, ULONG *puiMacLength) {
    if (pucMac == NULL || puiMacLength == NULL) {
        return SDR_INARGERR;
    }
    return SDR_NOTSUPPORT;
}

// Additional functions for completeness
LONG SDF_GetPrivateKeyAccessRight(HANDLE hSessionHandle, ULONG uiKeyIndex,
                                  char *pucPassword, ULONG uiPwdLength) {
    return SDR_NOTSUPPORT;
}

LONG SDF_ReleasePrivateKeyAccessRight(HANDLE hSessionHandle, ULONG uiKeyIndex) {
    return SDR_NOTSUPPORT;
}