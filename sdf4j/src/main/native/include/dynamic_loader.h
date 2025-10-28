/*
 * Copyright (c) 2025 OpenHitls
 * SDF4J is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef SDF4J_DYNAMIC_LOADER_H
#define SDF4J_DYNAMIC_LOADER_H

#include "sdf.h"
#include <stdbool.h>

/**
 * SDF函数指针类型定义
 */

/* 设备管理函数 */
typedef LONG (*SDF_OpenDevice_FN)(HANDLE *phDeviceHandle);
typedef LONG (*SDF_CloseDevice_FN)(HANDLE hDeviceHandle);
typedef LONG (*SDF_OpenSession_FN)(HANDLE hDeviceHandle, HANDLE *phSessionHandle);
typedef LONG (*SDF_CloseSession_FN)(HANDLE hSessionHandle);
typedef LONG (*SDF_GetDeviceInfo_FN)(HANDLE hSessionHandle, DEVICEINFO *pstDeviceInfo);
typedef LONG (*SDF_GenerateRandom_FN)(HANDLE hSessionHandle, ULONG uiLength, BYTE *pucRandom);
typedef LONG (*SDF_GetPrivateKeyAccessRight_FN)(HANDLE hSessionHandle, ULONG uiKeyIndex,
                                                LPSTR pucPassword, ULONG uiPwdLength);
typedef LONG (*SDF_ReleasePrivateKeyAccessRight_FN)(HANDLE hSessionHandle, ULONG uiKeyIndex);

/* 密钥管理函数 */
typedef LONG (*SDF_ExportSignPublicKey_RSA_FN)(HANDLE hSessionHandle, ULONG uiKeyIndex,
                                               RSArefPublicKey *pucPublicKey);
typedef LONG (*SDF_ExportEncPublicKey_RSA_FN)(HANDLE hSessionHandle, ULONG uiKeyIndex,
                                              RSArefPublicKey *pucPublicKey);
typedef LONG (*SDF_ExportSignPublicKey_ECC_FN)(HANDLE hSessionHandle, ULONG uiKeyIndex,
                                               ECCrefPublicKey *pucPublicKey);
typedef LONG (*SDF_ExportEncPublicKey_ECC_FN)(HANDLE hSessionHandle, ULONG uiKeyIndex,
                                              ECCrefPublicKey *pucPublicKey);
typedef LONG (*SDF_GenerateKeyWithIPK_RSA_FN)(HANDLE hSessionHandle, ULONG uiIPKIndex,
                                              ULONG uiKeyBits, BYTE *pucKey,
                                              ULONG *puiKeyLength, HANDLE *phKeyHandle);
typedef LONG (*SDF_GenerateKeyWithEPK_RSA_FN)(HANDLE hSessionHandle, ULONG uiKeyBits,
                                              RSArefPublicKey *pucPublicKey,
                                              BYTE *pucKey, ULONG *puiKeyLength,
                                              HANDLE *phKeyHandle);
typedef LONG (*SDF_ImportKeyWithISK_RSA_FN)(HANDLE hSessionHandle, ULONG uiISKIndex,
                                           BYTE *pucKey, ULONG uiKeyLength,
                                           HANDLE *phKeyHandle);
typedef LONG (*SDF_GenerateKeyWithIPK_ECC_FN)(HANDLE hSessionHandle, ULONG uiIPKIndex,
                                              ULONG uiKeyBits, ECCCipher *pucKey,
                                              HANDLE *phKeyHandle);
typedef LONG (*SDF_GenerateKeyWithEPK_ECC_FN)(HANDLE hSessionHandle, ULONG uiKeyBits,
                                              ULONG uiAlgID, ECCrefPublicKey *pucPublicKey,
                                              ECCCipher *pucKey, HANDLE *phKeyHandle);
typedef LONG (*SDF_ImportKeyWithISK_ECC_FN)(HANDLE hSessionHandle, ULONG uiISKIndex,
                                           ECCCipher *pucKey, HANDLE *phKeyHandle);
typedef LONG (*SDF_GenerateAgreementDataWithECC_FN)(HANDLE hSessionHandle, ULONG uiISKIndex,
                                                    ULONG uiKeyBits, BYTE *pucSponsorID,
                                                    ULONG uiSponsorIDLength,
                                                    ECCrefPublicKey *pucSponsorPublicKey,
                                                    ECCrefPublicKey *pucSponsorTmpPublicKey,
                                                    HANDLE *phAgreementHandle);
typedef LONG (*SDF_GenerateKeyWithECC_FN)(HANDLE hSessionHandle, BYTE *pucResponseID,
                                         ULONG uiResponseIDLength,
                                         ECCrefPublicKey *pucResponsePublicKey,
                                         ECCrefPublicKey *pucResponseTmpPublicKey,
                                         HANDLE hAgreementHandle, HANDLE *phKeyHandle);
typedef LONG (*SDF_GenerateAgreementDataAndKeyWithECC_FN)(HANDLE hSessionHandle, ULONG uiISKIndex,
                                                          ULONG uiKeyBits, BYTE *pucResponseID,
                                                          ULONG uiResponseIDLength,
                                                          BYTE *pucSponsorID,
                                                          ULONG uiSponsorIDLength,
                                                          ECCrefPublicKey *pucSponsorPublicKey,
                                                          ECCrefPublicKey *pucSponsorTmpPublicKey,
                                                          ECCrefPublicKey *pucResponsePublicKey,
                                                          ECCrefPublicKey *pucResponseTmpPublicKey,
                                                          HANDLE *phKeyHandle);
typedef LONG (*SDF_GenerateKeyWithKEK_FN)(HANDLE hSessionHandle, ULONG uiKeyBits,
                                         ULONG uiAlgID, ULONG uiKEKIndex,
                                         BYTE *pucKey, ULONG *puiKeyLength,
                                         HANDLE *phKeyHandle);
typedef LONG (*SDF_ImportKeyWithKEK_FN)(HANDLE hSessionHandle, ULONG uiAlgID,
                                       ULONG uiKEKIndex, BYTE *pucKey,
                                       ULONG uiKeyLength, HANDLE *phKeyHandle);
typedef LONG (*SDF_DestroyKey_FN)(HANDLE hSessionHandle, HANDLE hKeyHandle);

/* 非对称算法函数 */
typedef LONG (*SDF_ExternalPublicKeyOperation_RSA_FN)(HANDLE hSessionHandle,
                                                      RSArefPublicKey *pucPublicKey,
                                                      BYTE *pucDataInput,
                                                      ULONG uiInputLength,
                                                      BYTE *pucDataOutput,
                                                      ULONG *puiOutputLength);
typedef LONG (*SDF_InternalPublicKeyOperation_RSA_FN)(HANDLE hSessionHandle,
                                                      ULONG uiKeyIndex,
                                                      BYTE *pucDataInput,
                                                      ULONG uiInputLength,
                                                      BYTE *pucDataOutput,
                                                      ULONG *puiOutputLength);
typedef LONG (*SDF_InternalPrivateKeyOperation_RSA_FN)(HANDLE hSessionHandle,
                                                       ULONG uiKeyIndex,
                                                       BYTE *pucDataInput,
                                                       ULONG uiInputLength,
                                                       BYTE *pucDataOutput,
                                                       ULONG *puiOutputLength);
typedef LONG (*SDF_InternalSign_ECC_FN)(HANDLE hSessionHandle, ULONG uiISKIndex,
                                        BYTE *pucData, ULONG uiDataLength,
                                        ECCSignature *pucSignature);
typedef LONG (*SDF_InternalVerify_ECC_FN)(HANDLE hSessionHandle, ULONG uiISKIndex,
                                          BYTE *pucData, ULONG uiDataLength,
                                          ECCSignature *pucSignature);
typedef LONG (*SDF_ExternalVerify_ECC_FN)(HANDLE hSessionHandle, ULONG uiAlgID,
                                          ECCrefPublicKey *pucPublicKey,
                                          BYTE *pucDataInput, ULONG uiInputLength,
                                          ECCSignature *pucSignature);
typedef LONG (*SDF_ExternalEncrypt_ECC_FN)(HANDLE hSessionHandle, ULONG uiAlgID,
                                           ECCrefPublicKey *pucPublicKey,
                                           BYTE *pucData, ULONG uiDataLength,
                                           ECCCipher *pucEncData);

/* 对称算法函数 */
typedef LONG (*SDF_Encrypt_FN)(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                               BYTE *pucIV, BYTE *pucData, ULONG uiDataLength,
                               BYTE *pucEncData, ULONG *puiEncDataLength);
typedef LONG (*SDF_Decrypt_FN)(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                               BYTE *pucIV, BYTE *pucEncData, ULONG uiEncDataLength,
                               BYTE *pucData, ULONG *puiDataLength);
typedef LONG (*SDF_CalculateMAC_FN)(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                                    BYTE *pucIV, BYTE *pucData, ULONG uiDataLength,
                                    BYTE *pucMac, ULONG *puiMacLength);
/* 单包认证加解密 */
typedef LONG (*SDF_AuthEnc_FN)(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                               BYTE *pucStartVar, ULONG uiStartVarLength,
                               BYTE *pucAad, ULONG uiAadLength,
                               BYTE *pucData, ULONG uiDataLength,
                               BYTE *pucEncData, ULONG *puiEncDataLength,
                               BYTE *pucAuthData, ULONG *puiAuthDataLength);
typedef LONG (*SDF_AuthDec_FN)(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                               BYTE *pucStartVar, ULONG uiStartVarLength,
                               BYTE *pucAad, ULONG uiAadLength,
                               BYTE *pucAuthData, ULONG uiAuthDataLength,
                               BYTE *pucEncData, ULONG uiEncDataLength,
                               BYTE *pucData, ULONG *puiDataLength);
/* 多包加密 */
typedef LONG (*SDF_EncryptInit_FN)(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                                   BYTE *pucIV, ULONG uiIVLength);
typedef LONG (*SDF_EncryptUpdate_FN)(HANDLE hSessionHandle, BYTE *pucData, ULONG uiDataLength,
                                     BYTE *pucEncData, ULONG *puiEncDataLength);
typedef LONG (*SDF_EncryptFinal_FN)(HANDLE hSessionHandle, BYTE *pucEncData,
                                    ULONG *puiEncDataLength);
/* 多包解密 */
typedef LONG (*SDF_DecryptInit_FN)(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                                   BYTE *pucIV, ULONG uiIVLength);
typedef LONG (*SDF_DecryptUpdate_FN)(HANDLE hSessionHandle, BYTE *pucEncData,
                                     ULONG uiEncDataLength, BYTE *pucData,
                                     ULONG *puiDataLength);
typedef LONG (*SDF_DecryptFinal_FN)(HANDLE hSessionHandle, BYTE *pucData, ULONG *puiDataLength);
/* 多包MAC */
typedef LONG (*SDF_CalculateMACInit_FN)(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                                        BYTE *pucIV, ULONG uiIVLength);
typedef LONG (*SDF_CalculateMACUpdate_FN)(HANDLE hSessionHandle, BYTE *pucData,
                                          ULONG uiDataLength);
typedef LONG (*SDF_CalculateMACFinal_FN)(HANDLE hSessionHandle, BYTE *pucMac,
                                         ULONG *puiMacLength);
/* 多包认证加密 */
typedef LONG (*SDF_AuthEncInit_FN)(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                                   BYTE *pucStartVar, ULONG uiStartVarLength,
                                   BYTE *pucAad, ULONG uiAadLength, ULONG uiDataLength);
typedef LONG (*SDF_AuthEncUpdate_FN)(HANDLE hSessionHandle, BYTE *pucData, ULONG uiDataLength,
                                     BYTE *pucEncData, ULONG *puiEncDataLength);
typedef LONG (*SDF_AuthEncFinal_FN)(HANDLE hSessionHandle, BYTE *pucLastEncData,
                                    ULONG *puiLastEncDataLength, BYTE *pucAuthData,
                                    ULONG *puiAuthDataLength);
/* 多包认证解密 */
typedef LONG (*SDF_AuthDecInit_FN)(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                                   BYTE *pucStartVar, ULONG uiStartVarLength,
                                   BYTE *pucAad, ULONG uiAadLength,
                                   BYTE *pucAuthData, ULONG uiAuthDataLength, ULONG uiDataLength);
typedef LONG (*SDF_AuthDecUpdate_FN)(HANDLE hSessionHandle, BYTE *pucEncData,
                                     ULONG uiEncDataLength, BYTE *pucData,
                                     ULONG *puiDataLength);
typedef LONG (*SDF_AuthDecFinal_FN)(HANDLE hSessionHandle, BYTE *pucLastData,
                                    ULONG *puiLastDataLength);

/* 杂凑算法函数 */
typedef LONG (*SDF_HashInit_FN)(HANDLE hSessionHandle, ULONG uiAlgID,
                                ECCrefPublicKey *pucPublicKey, BYTE *pucID, ULONG uiIDLength);
typedef LONG (*SDF_HashUpdate_FN)(HANDLE hSessionHandle, BYTE *pucData, ULONG uiDataLength);
typedef LONG (*SDF_HashFinal_FN)(HANDLE hSessionHandle, BYTE *pucHash, ULONG *puiHashLength);
/* HMAC */
typedef LONG (*SDF_HMACInit_FN)(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID);
typedef LONG (*SDF_HMACUpdate_FN)(HANDLE hSessionHandle, BYTE *pucData, ULONG uiDataLength);
typedef LONG (*SDF_HMACFinal_FN)(HANDLE hSessionHandle, BYTE *pucHMAC, ULONG *puiHMACLength);

/* 文件操作函数 */
typedef LONG (*SDF_CreateFile_FN)(HANDLE hSessionHandle, LPSTR pucFileName, ULONG uiFileSize);
typedef LONG (*SDF_ReadFile_FN)(HANDLE hSessionHandle, LPSTR pucFileName, ULONG uiOffset,
                                ULONG uiLength, BYTE *pucBuffer, ULONG *puiReadLength);
typedef LONG (*SDF_WriteFile_FN)(HANDLE hSessionHandle, LPSTR pucFileName, ULONG uiNameLen,
                                 ULONG uiOffset, ULONG uiFileLength, BYTE *pucBuffer);
typedef LONG (*SDF_DeleteFile_FN)(HANDLE hSessionHandle, LPSTR pucFileName, ULONG uiNameLen);

/* 验证调试类函数 */
typedef LONG (*SDF_GenerateKeyPair_RSA_FN)(HANDLE hSessionHandle, ULONG uiKeyBits,
                                           RSArefPublicKey *pucPublicKey,
                                           RSArefPrivateKey *pucPrivateKey);
typedef LONG (*SDF_GenerateKeyPair_ECC_FN)(HANDLE hSessionHandle, ULONG uiAlgID, ULONG uiKeyBits,
                                           ECCrefPublicKey *pucPublicKey,
                                           ECCrefPrivateKey *pucPrivateKey);
typedef LONG (*SDF_ExternalPrivateKeyOperation_RSA_FN)(HANDLE hSessionHandle,
                                                       RSArefPrivateKey *pucPrivateKey,
                                                       BYTE *pucDataInput,
                                                       ULONG uiInputLength,
                                                       BYTE *pucDataOutput,
                                                       ULONG *puiOutputLength);
typedef LONG (*SDF_ExternalSign_ECC_FN)(HANDLE hSessionHandle, ULONG uiAlgID,
                                        ECCrefPrivateKey *pucPrivateKey,
                                        BYTE *pucData, ULONG uiDataLength,
                                        ECCSignature *pucSignature);
typedef LONG (*SDF_ExternalDecrypt_ECC_FN)(HANDLE hSessionHandle, ULONG uiAlgID,
                                           ECCrefPrivateKey *pucPrivateKey,
                                           ECCCipher *pucEncData,
                                           BYTE *pucData, ULONG *puiDataLength);
typedef LONG (*SDF_ExternalKeyEncrypt_FN)(HANDLE hSessionHandle, ULONG uiAlgID,
                                          BYTE *pucKey, ULONG uiKeyLength,
                                          BYTE *pucIV, ULONG uiIVLength,
                                          BYTE *pucData, ULONG uiDataLength,
                                          BYTE *pucEncData, ULONG *puiEncDataLength);
typedef LONG (*SDF_ExternalKeyDecrypt_FN)(HANDLE hSessionHandle, ULONG uiAlgID,
                                          BYTE *pucKey, ULONG uiKeyLength,
                                          BYTE *pucIV, ULONG uiIVLength,
                                          BYTE *pucEncData, ULONG uiEncDataLength,
                                          BYTE *pucData, ULONG *puiDataLength);
typedef LONG (*SDF_ExternalKeyEncryptInit_FN)(HANDLE hSessionHandle, ULONG uiAlgID,
                                              BYTE *pucKey, ULONG uiKeyLength,
                                              BYTE *pucIV, ULONG uiIVLength);
typedef LONG (*SDF_ExternalKeyDecryptInit_FN)(HANDLE hSessionHandle, ULONG uiAlgID,
                                              BYTE *pucKey, ULONG uiKeyLength,
                                              BYTE *pucIV, ULONG uiIVLength);
typedef LONG (*SDF_ExternalKeyHMACInit_FN)(HANDLE hSessionHandle, ULONG uiAlgID,
                                           BYTE *pucKey, ULONG uiKeyLength);

/**
 * SDF函数指针表
 */
typedef struct {
    /* 设备管理 */
    SDF_OpenDevice_FN                       SDF_OpenDevice;
    SDF_CloseDevice_FN                      SDF_CloseDevice;
    SDF_OpenSession_FN                      SDF_OpenSession;
    SDF_CloseSession_FN                     SDF_CloseSession;
    SDF_GetDeviceInfo_FN                    SDF_GetDeviceInfo;
    SDF_GenerateRandom_FN                   SDF_GenerateRandom;
    SDF_GetPrivateKeyAccessRight_FN         SDF_GetPrivateKeyAccessRight;
    SDF_ReleasePrivateKeyAccessRight_FN     SDF_ReleasePrivateKeyAccessRight;

    /* 密钥管理 */
    SDF_ExportSignPublicKey_RSA_FN          SDF_ExportSignPublicKey_RSA;
    SDF_ExportEncPublicKey_RSA_FN           SDF_ExportEncPublicKey_RSA;
    SDF_ExportSignPublicKey_ECC_FN          SDF_ExportSignPublicKey_ECC;
    SDF_ExportEncPublicKey_ECC_FN           SDF_ExportEncPublicKey_ECC;
    SDF_GenerateKeyWithIPK_RSA_FN           SDF_GenerateKeyWithIPK_RSA;
    SDF_GenerateKeyWithEPK_RSA_FN           SDF_GenerateKeyWithEPK_RSA;
    SDF_ImportKeyWithISK_RSA_FN             SDF_ImportKeyWithISK_RSA;
    SDF_GenerateKeyWithIPK_ECC_FN           SDF_GenerateKeyWithIPK_ECC;
    SDF_GenerateKeyWithEPK_ECC_FN           SDF_GenerateKeyWithEPK_ECC;
    SDF_ImportKeyWithISK_ECC_FN             SDF_ImportKeyWithISK_ECC;
    SDF_GenerateAgreementDataWithECC_FN     SDF_GenerateAgreementDataWithECC;
    SDF_GenerateKeyWithECC_FN               SDF_GenerateKeyWithECC;
    SDF_GenerateAgreementDataAndKeyWithECC_FN SDF_GenerateAgreementDataAndKeyWithECC;
    SDF_GenerateKeyWithKEK_FN               SDF_GenerateKeyWithKEK;
    SDF_ImportKeyWithKEK_FN                 SDF_ImportKeyWithKEK;
    SDF_DestroyKey_FN                       SDF_DestroyKey;

    /* 非对称算法 */
    SDF_ExternalPublicKeyOperation_RSA_FN   SDF_ExternalPublicKeyOperation_RSA;
    SDF_InternalPublicKeyOperation_RSA_FN   SDF_InternalPublicKeyOperation_RSA;
    SDF_InternalPrivateKeyOperation_RSA_FN  SDF_InternalPrivateKeyOperation_RSA;
    SDF_InternalSign_ECC_FN                 SDF_InternalSign_ECC;
    SDF_InternalVerify_ECC_FN               SDF_InternalVerify_ECC;
    SDF_ExternalVerify_ECC_FN               SDF_ExternalVerify_ECC;
    SDF_ExternalEncrypt_ECC_FN              SDF_ExternalEncrypt_ECC;

    /* 对称算法 */
    SDF_Encrypt_FN                          SDF_Encrypt;
    SDF_Decrypt_FN                          SDF_Decrypt;
    SDF_CalculateMAC_FN                     SDF_CalculateMAC;
    SDF_AuthEnc_FN                          SDF_AuthEnc;
    SDF_AuthDec_FN                          SDF_AuthDec;
    SDF_EncryptInit_FN                      SDF_EncryptInit;
    SDF_EncryptUpdate_FN                    SDF_EncryptUpdate;
    SDF_EncryptFinal_FN                     SDF_EncryptFinal;
    SDF_DecryptInit_FN                      SDF_DecryptInit;
    SDF_DecryptUpdate_FN                    SDF_DecryptUpdate;
    SDF_DecryptFinal_FN                     SDF_DecryptFinal;
    SDF_CalculateMACInit_FN                 SDF_CalculateMACInit;
    SDF_CalculateMACUpdate_FN               SDF_CalculateMACUpdate;
    SDF_CalculateMACFinal_FN                SDF_CalculateMACFinal;
    SDF_AuthEncInit_FN                      SDF_AuthEncInit;
    SDF_AuthEncUpdate_FN                    SDF_AuthEncUpdate;
    SDF_AuthEncFinal_FN                     SDF_AuthEncFinal;
    SDF_AuthDecInit_FN                      SDF_AuthDecInit;
    SDF_AuthDecUpdate_FN                    SDF_AuthDecUpdate;
    SDF_AuthDecFinal_FN                     SDF_AuthDecFinal;

    /* 杂凑算法 */
    SDF_HashInit_FN                         SDF_HashInit;
    SDF_HashUpdate_FN                       SDF_HashUpdate;
    SDF_HashFinal_FN                        SDF_HashFinal;
    SDF_HMACInit_FN                         SDF_HMACInit;
    SDF_HMACUpdate_FN                       SDF_HMACUpdate;
    SDF_HMACFinal_FN                        SDF_HMACFinal;

    /* 文件操作 */
    SDF_CreateFile_FN                       SDF_CreateFile;
    SDF_ReadFile_FN                         SDF_ReadFile;
    SDF_WriteFile_FN                        SDF_WriteFile;
    SDF_DeleteFile_FN                       SDF_DeleteFile;

    /* 验证调试 */
    SDF_GenerateKeyPair_RSA_FN              SDF_GenerateKeyPair_RSA;
    SDF_GenerateKeyPair_ECC_FN              SDF_GenerateKeyPair_ECC;
    SDF_ExternalPrivateKeyOperation_RSA_FN  SDF_ExternalPrivateKeyOperation_RSA;
    SDF_ExternalSign_ECC_FN                 SDF_ExternalSign_ECC;
    SDF_ExternalDecrypt_ECC_FN              SDF_ExternalDecrypt_ECC;
    SDF_ExternalKeyEncrypt_FN               SDF_ExternalKeyEncrypt;
    SDF_ExternalKeyDecrypt_FN               SDF_ExternalKeyDecrypt;
    SDF_ExternalKeyEncryptInit_FN           SDF_ExternalKeyEncryptInit;
    SDF_ExternalKeyDecryptInit_FN           SDF_ExternalKeyDecryptInit;
    SDF_ExternalKeyHMACInit_FN              SDF_ExternalKeyHMACInit;
} SDFFunctionTable;

/**
 * 全局SDF函数表
 */
extern SDFFunctionTable g_sdf_functions;

/**
 * 加载SDF库
 *
 * @param library_path 库文件路径
 * @return 成功返回true，失败返回false
 */
bool sdf_load_library(const char *library_path);

/**
 * 卸载SDF库
 */
void sdf_unload_library(void);

/**
 * 检查库是否已加载
 *
 * @return 已加载返回true，否则返回false
 */
bool sdf_is_loaded(void);

/**
 * 获取加载错误信息
 *
 * @return 错误信息字符串
 */
const char* sdf_get_load_error(void);

#endif /* SDF4J_DYNAMIC_LOADER_H */
