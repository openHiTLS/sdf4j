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

#ifndef SDF4J_JNI_FUNCTIONS_H
#define SDF4J_JNI_FUNCTIONS_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * JNI Function Declarations
 * All native method implementations used with RegisterNatives.
 * ======================================================================== */

/* ========================================================================
 * 6.2 设备管理类函数 (Device Management)
 * ======================================================================== */
JNIEXPORT jlong JNICALL JNI_SDF_OpenDevice(JNIEnv *env, jobject obj);
JNIEXPORT jlong JNICALL JNI_SDF_OpenDeviceWithConf(JNIEnv *env, jobject obj, jstring configFile);
JNIEXPORT void JNICALL JNI_SDF_CloseDevice(JNIEnv *env, jobject obj, jlong deviceHandle);
JNIEXPORT jlong JNICALL JNI_SDF_OpenSession(JNIEnv *env, jobject obj, jlong deviceHandle);
JNIEXPORT void JNICALL JNI_SDF_CloseSession(JNIEnv *env, jobject obj, jlong sessionHandle);
JNIEXPORT jobject JNICALL JNI_SDF_GetDeviceInfo(JNIEnv *env, jobject obj, jlong sessionHandle);
JNIEXPORT jbyteArray JNICALL JNI_SDF_GenerateRandom(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint length);
JNIEXPORT void JNICALL JNI_SDF_GetPrivateKeyAccessRight(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint keyIndex, jstring password);
JNIEXPORT void JNICALL JNI_SDF_ReleasePrivateKeyAccessRight(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint keyIndex);
JNIEXPORT void JNICALL JNI_SDF_GetKEKAccessRight(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint keyIndex, jstring password);
JNIEXPORT void JNICALL JNI_SDF_ReleaseKEKAccessRight(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint keyIndex);

/* ========================================================================
 * 6.3 密钥管理类函数 (Key Management)
 * ======================================================================== */
JNIEXPORT jobject JNICALL JNI_SDF_ExportSignPublicKey_RSA(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint keyIndex);
JNIEXPORT jobject JNICALL JNI_SDF_ExportEncPublicKey_RSA(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint keyIndex);
JNIEXPORT jobject JNICALL JNI_SDF_ExportSignPublicKey_ECC(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint keyIndex);
JNIEXPORT jobject JNICALL JNI_SDF_ExportEncPublicKey_ECC(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint keyIndex);
JNIEXPORT jobject JNICALL JNI_SDF_GenerateKeyWithIPK_RSA(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint keyIndex, jint keyBits);
JNIEXPORT jobject JNICALL JNI_SDF_GenerateKeyWithEPK_RSA(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint keyBits, jobject publicKey);
JNIEXPORT jlong JNICALL JNI_SDF_ImportKeyWithISK_RSA(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint keyIndex, jbyteArray encryptedKey);
JNIEXPORT jobject JNICALL JNI_SDF_GenerateKeyWithIPK_ECC(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint keyIndex, jint keyBits);
JNIEXPORT jobject JNICALL JNI_SDF_GenerateKeyWithEPK_ECC(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint keyBits, jint algID, jobject publicKey);
JNIEXPORT jlong JNICALL JNI_SDF_ImportKeyWithISK_ECC(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint keyIndex, jobject cipher);
JNIEXPORT jlong JNICALL JNI_SDF_GenerateAgreementDataWithECC(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint keyIndex, jint keyBits, jbyteArray sponsorID,
    jobject sponsorPublicKey, jobject sponsorTmpPublicKey);
JNIEXPORT jlong JNICALL JNI_SDF_GenerateKeyWithECC(JNIEnv *env, jobject obj, jlong sessionHandle,
    jbyteArray responseID, jobject responsePublicKey, jobject responseTmpPublicKey,
    jlong agreementHandle);
JNIEXPORT jlong JNICALL JNI_SDF_GenerateAgreementDataAndKeyWithECC(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint keyIndex, jint keyBits, jbyteArray responseID, jbyteArray sponsorID,
    jobject sponsorPublicKey, jobject sponsorTmpPublicKey, jobject responsePublicKey,
    jobject responseTmpPublicKey);
JNIEXPORT jobject JNICALL JNI_SDF_GenerateKeyWithKEK(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint keyBits, jint algID, jint kekIndex);
JNIEXPORT jlong JNICALL JNI_SDF_ImportKeyWithKEK(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint algID, jint kekIndex, jbyteArray encryptedKey);
JNIEXPORT void JNICALL JNI_SDF_DestroyKey(JNIEnv *env, jobject obj, jlong sessionHandle,
    jlong keyHandle);
JNIEXPORT jlong JNICALL JNI_SDF_ImportKey(JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray encryptedKey);
JNIEXPORT jobject JNICALL JNI_SDF_ExchangeDigitEnvelopeBaseOnECC(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint keyIndex, jint algID, jobject publicKey, jobject encDataIn);
    
/* ========================================================================
 * 6.4 非对称算法类函数 (Asymmetric Algorithms)
 * ======================================================================== */
JNIEXPORT jbyteArray JNICALL JNI_SDF_ExternalPublicKeyOperation_RSA(JNIEnv *env, jobject obj,
    jlong sessionHandle, jobject publicKey, jbyteArray dataInput);
JNIEXPORT jbyteArray JNICALL JNI_SDF_InternalPublicKeyOperation_RSA(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint keyIndex, jbyteArray dataInput);
JNIEXPORT jbyteArray JNICALL JNI_SDF_InternalPrivateKeyOperation_RSA(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint keyIndex, jbyteArray dataInput);
JNIEXPORT jobject JNICALL JNI_SDF_InternalSign_ECC(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint keyIndex, jbyteArray data);
JNIEXPORT void JNICALL JNI_SDF_InternalVerify_ECC(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint keyIndex, jbyteArray data, jobject signature);
JNIEXPORT void JNICALL JNI_SDF_ExternalVerify_ECC(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint algID, jobject publicKey, jbyteArray data, jobject signature);
JNIEXPORT jobject JNICALL JNI_SDF_ExternalEncrypt_ECC(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint algID, jobject publicKey, jbyteArray data);
JNIEXPORT jobject JNICALL JNI_SDF_InternalEncrypt_ECC(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint keyIndex, jbyteArray data);
JNIEXPORT jbyteArray JNICALL JNI_SDF_InternalDecrypt_ECC(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint keyIndex, jint eccKeyType, jobject cipher);

/* ========================================================================
 * 6.5 对称算法类函数 (Symmetric Algorithms)
 * ======================================================================== */
JNIEXPORT jbyteArray JNICALL JNI_SDF_Encrypt(JNIEnv *env, jobject obj, jlong sessionHandle,
    jlong keyHandle, jint algID, jbyteArray iv, jbyteArray data);
JNIEXPORT jbyteArray JNICALL JNI_SDF_Decrypt(JNIEnv *env, jobject obj, jlong sessionHandle,
    jlong keyHandle, jint algID, jbyteArray iv, jbyteArray encData);
JNIEXPORT jbyteArray JNICALL JNI_SDF_CalculateMAC(JNIEnv *env, jobject obj, jlong sessionHandle,
    jlong keyHandle, jint algID, jbyteArray iv, jbyteArray data);
JNIEXPORT jobjectArray JNICALL JNI_SDF_AuthEnc(JNIEnv *env, jobject obj, jlong sessionHandle,
    jlong keyHandle, jint algID, jbyteArray iv, jbyteArray aad, jbyteArray data);
JNIEXPORT jbyteArray JNICALL JNI_SDF_AuthDec(JNIEnv *env, jobject obj, jlong sessionHandle,
    jlong keyHandle, jint algID, jbyteArray iv, jbyteArray aad, jbyteArray authTag,
    jbyteArray encData);

/* 多包加密解密 (Multi-part Encryption/Decryption) */
JNIEXPORT void JNICALL JNI_SDF_EncryptInit(JNIEnv *env, jobject obj, jlong sessionHandle,
    jlong keyHandle, jint algID, jbyteArray iv);
JNIEXPORT jbyteArray JNICALL JNI_SDF_EncryptUpdate(JNIEnv *env, jobject obj, jlong sessionHandle,
    jbyteArray data);
JNIEXPORT jbyteArray JNICALL JNI_SDF_EncryptFinal(JNIEnv *env, jobject obj, jlong sessionHandle);
JNIEXPORT void JNICALL JNI_SDF_DecryptInit(JNIEnv *env, jobject obj, jlong sessionHandle,
    jlong keyHandle, jint algID, jbyteArray iv);
JNIEXPORT jbyteArray JNICALL JNI_SDF_DecryptUpdate(JNIEnv *env, jobject obj, jlong sessionHandle,
    jbyteArray encData);
JNIEXPORT jbyteArray JNICALL JNI_SDF_DecryptFinal(JNIEnv *env, jobject obj, jlong sessionHandle);

/* 多包MAC (Multi-part MAC) */
JNIEXPORT void JNICALL JNI_SDF_CalculateMACInit(JNIEnv *env, jobject obj, jlong sessionHandle,
    jlong keyHandle, jint algID, jbyteArray iv);
JNIEXPORT void JNICALL JNI_SDF_CalculateMACUpdate(JNIEnv *env, jobject obj, jlong sessionHandle,
    jbyteArray data);
JNIEXPORT jbyteArray JNICALL JNI_SDF_CalculateMACFinal(JNIEnv *env, jobject obj,
    jlong sessionHandle);

/* 多包认证加密解密 (Multi-part Authenticated Encryption/Decryption) */
JNIEXPORT void JNICALL JNI_SDF_AuthEncInit(JNIEnv *env, jobject obj, jlong sessionHandle,
    jlong keyHandle, jint algID, jbyteArray iv, jbyteArray aad, jint dataLength);
JNIEXPORT jbyteArray JNICALL JNI_SDF_AuthEncUpdate(JNIEnv *env, jobject obj, jlong sessionHandle,
    jbyteArray data);
JNIEXPORT jobjectArray JNICALL JNI_SDF_AuthEncFinal(JNIEnv *env, jobject obj, jlong sessionHandle,
    jbyteArray pucEncData);
JNIEXPORT void JNICALL JNI_SDF_AuthDecInit(JNIEnv *env, jobject obj, jlong sessionHandle,
    jlong keyHandle, jint algID, jbyteArray iv, jbyteArray aad, jbyteArray authTag,
    jint dataLength);
JNIEXPORT jbyteArray JNICALL JNI_SDF_AuthDecUpdate(JNIEnv *env, jobject obj, jlong sessionHandle,
    jbyteArray data);
JNIEXPORT jbyteArray JNICALL JNI_SDF_AuthDecFinal(JNIEnv *env, jobject obj, jlong sessionHandle);

/* ========================================================================
 * 6.6 杂凑算法 (Hash Algorithms)
 * ======================================================================== */
JNIEXPORT void JNICALL JNI_SDF_HashInit(JNIEnv *env, jobject obj, jlong sessionHandle, jint algID,
    jobject publicKey, jbyteArray id);
JNIEXPORT void JNICALL JNI_SDF_HashUpdate(JNIEnv *env, jobject obj, jlong sessionHandle,
    jbyteArray data);
JNIEXPORT jbyteArray JNICALL JNI_SDF_HashFinal(JNIEnv *env, jobject obj, jlong sessionHandle);
JNIEXPORT void JNICALL JNI_SDF_HMACInit(JNIEnv *env, jobject obj, jlong sessionHandle,
    jlong keyHandle, jint algID);
JNIEXPORT void JNICALL JNI_SDF_HMACUpdate(JNIEnv *env, jobject obj, jlong sessionHandle,
    jbyteArray data);
JNIEXPORT jbyteArray JNICALL JNI_SDF_HMACFinal(JNIEnv *env, jobject obj, jlong sessionHandle);

/* ========================================================================
 * 6.7 文件操作 (File Operations)
 * ======================================================================== */
JNIEXPORT void JNICALL JNI_SDF_CreateFile(JNIEnv *env, jobject obj, jlong sessionHandle,
    jstring fileName, jint fileSize);
JNIEXPORT jbyteArray JNICALL JNI_SDF_ReadFile(JNIEnv *env, jobject obj, jlong sessionHandle,
    jstring fileName, jint offset, jint length);
JNIEXPORT void JNICALL JNI_SDF_WriteFile(JNIEnv *env, jobject obj, jlong sessionHandle,
    jstring fileName, jint offset, jbyteArray data);
JNIEXPORT void JNICALL JNI_SDF_DeleteFile(JNIEnv *env, jobject obj, jlong sessionHandle,
    jstring fileName);

/* ========================================================================
 * 6.8 验证调试类函数 (Testing/Debugging)
 * ======================================================================== */
JNIEXPORT jobjectArray JNICALL JNI_SDF_GenerateKeyPair_RSA(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint keyBits);
JNIEXPORT jobjectArray JNICALL JNI_SDF_GenerateKeyPair_ECC(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint algID, jint keyBits);
JNIEXPORT jbyteArray JNICALL JNI_SDF_ExternalPrivateKeyOperation_RSA(JNIEnv *env, jobject obj,
    jlong sessionHandle, jobject privateKey, jbyteArray dataInput);
JNIEXPORT jobject JNICALL JNI_SDF_ExternalSign_ECC(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint algID, jobject privateKey, jbyteArray data);
JNIEXPORT jbyteArray JNICALL JNI_SDF_ExternalDecrypt_ECC(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint algID, jobject privateKey, jobject cipher);
JNIEXPORT jbyteArray JNICALL JNI_SDF_ExternalKeyEncrypt(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint algID, jbyteArray key, jbyteArray iv, jbyteArray data);
JNIEXPORT jbyteArray JNICALL JNI_SDF_ExternalKeyDecrypt(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint algID, jbyteArray key, jbyteArray iv, jbyteArray encData);

/* 多包外部密钥加解密 (Multi-part External Key Encryption/Decryption) */
JNIEXPORT void JNICALL JNI_SDF_ExternalKeyEncryptInit(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint algID, jbyteArray key, jbyteArray iv);
JNIEXPORT jbyteArray JNICALL JNI_SDF_ExternalKeyEncryptUpdate(JNIEnv *env, jobject obj,
    jlong sessionHandle, jbyteArray data);
JNIEXPORT jbyteArray JNICALL JNI_SDF_ExternalKeyEncryptFinal(JNIEnv *env, jobject obj,
    jlong sessionHandle);
JNIEXPORT void JNICALL JNI_SDF_ExternalKeyDecryptInit(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint algID, jbyteArray key, jbyteArray iv);
JNIEXPORT jbyteArray JNICALL JNI_SDF_ExternalKeyDecryptUpdate(JNIEnv *env, jobject obj,
    jlong sessionHandle, jbyteArray encData);
JNIEXPORT jbyteArray JNICALL JNI_SDF_ExternalKeyDecryptFinal(JNIEnv *env, jobject obj,
    jlong sessionHandle);
JNIEXPORT void JNICALL JNI_SDF_ExternalKeyHMACInit(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint algID, jbyteArray key);

/* ========================================================================
 * NativeLibraryLoader 内部类函数
 * ======================================================================== */
JNIEXPORT jboolean JNICALL JNI_NativeLibraryLoader_loadSDFLibrary(JNIEnv *env, jclass cls,
    jstring library_path);

#ifdef __cplusplus
}
#endif

#endif /* SDF4J_JNI_FUNCTIONS_H */
