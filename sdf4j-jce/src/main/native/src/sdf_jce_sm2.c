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

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include "jce_common.h"
#include "dynamic_loader.h"

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm2GenerateKeyPair
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm2GenerateKeyPair(JNIEnv *env, jclass cls, jlong sessionHandle)
{
    (void)cls;
    CHECK_INIT_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_GenerateKeyPair_ECC, env, "SDF_GenerateKeyPair_ECC", NULL);

    ECCrefPublicKey pubKey = {0};
    ECCrefPrivateKey privKey = {0};

    LONG ret = g_sdf_functions.SDF_GenerateKeyPair_ECC(
        (HANDLE)sessionHandle, SGD_SM2_1, SM2_KEY_BITS, &pubKey, &privKey);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM2 key pair generation failed");
        return NULL;
    }

    /* 组装结果: privKey(32) || pubX(32) || pubY(32) = 96 bytes */
    jbyteArray result = (*env)->NewByteArray(env, 96);
    if (result == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to create byte array");
        memset(&privKey, 0, sizeof(privKey));
        return NULL;
    }
    /* 96 > 0 is guaranteed */
    /* 私钥取有效部分（右对齐） */
    (*env)->SetByteArrayRegion(env, result, 0, 32,
                               (jbyte *)(privKey.K + ECCref_MAX_LEN - SM2_KEY_BYTES));
    /* 公钥X */
    (*env)->SetByteArrayRegion(env, result, 32, 32,
                               (jbyte *)(pubKey.x + ECCref_MAX_LEN - SM2_KEY_BYTES));
    /* 公钥Y */
    (*env)->SetByteArrayRegion(env, result, 64, 32,
                               (jbyte *)(pubKey.y + ECCref_MAX_LEN - SM2_KEY_BYTES));

    /* 清除敏感数据 */
    memset(&privKey, 0, sizeof(privKey));
    return result;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm2Sign
 * Signature: ([B[B)[B
 */
JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm2Sign(JNIEnv *env, jclass cls, jlong sessionHandle, jbyteArray privateKey, jbyteArray data)
{
    (void)cls;
    CHECK_INIT_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_ExternalSign_ECC, env, "SDF_ExternalSign_ECC", NULL);

    if (privateKey == NULL || data == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "privateKey or data is null");
        return NULL;
    }

    jsize privKeyLen = (*env)->GetArrayLength(env, privateKey);
    if (privKeyLen != SM2_KEY_BYTES) {
        throw_exception(env, "java/lang/IllegalArgumentException", "Private key must be 32 bytes");
        return NULL;
    }

    jbyte *privKeyBytes = (*env)->GetByteArrayElements(env, privateKey, NULL);
    jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
    jsize dataLen = (*env)->GetArrayLength(env, data);
    if (privKeyBytes == NULL || dataBytes == NULL) {
        if (privKeyBytes) {
            memset(privKeyBytes, 0, (size_t)privKeyLen);
            (*env)->ReleaseByteArrayElements(env, privateKey, privKeyBytes, JNI_ABORT);
        }
        if (dataBytes) (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get byte arrays");
        return NULL;
    }

    /* 构造SDF私钥结构（右对齐） */
    ECCrefPrivateKey eccPrivKey = {0};
    eccPrivKey.bits = SM2_KEY_BITS;
    memcpy(eccPrivKey.K + ECCref_MAX_LEN - SM2_KEY_BYTES, privKeyBytes, SM2_KEY_BYTES);

    ECCSignature signature = {0};
    jbyteArray result = NULL;

    LONG ret = g_sdf_functions.SDF_ExternalSign_ECC(
        (HANDLE)sessionHandle, SGD_SM2_1, &eccPrivKey,
        (BYTE *)dataBytes, (ULONG)dataLen, &signature);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM2 external sign failed");
        goto ERR;
    }

    /* 返回 r(32) || s(32) = 64 bytes */
    result = (*env)->NewByteArray(env, SM2_SIGNATURE_BYTES);
    if (result == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to create byte array");
        goto ERR;
    }
    /* SM2_SIGNATURE_BYTES > 0 is guaranteed */
    (*env)->SetByteArrayRegion(env, result, 0, 32,
                               (jbyte *)(signature.r + ECCref_MAX_LEN - SM2_KEY_BYTES));
    (*env)->SetByteArrayRegion(env, result, 32, 32,
                               (jbyte *)(signature.s + ECCref_MAX_LEN - SM2_KEY_BYTES));

ERR:
    /* Clear sensitive data in JNI buffer before releasing */
    memset(privKeyBytes, 0, (size_t)privKeyLen);
    (*env)->ReleaseByteArrayElements(env, privateKey, privKeyBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
    memset(&eccPrivKey, 0, sizeof(eccPrivKey));
    return result;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm2Verify
 * Signature: ([B[B[B[B)Z
 */
JNIEXPORT jboolean JNICALL JNI_SDFJceNative_sm2Verify(JNIEnv *env, jclass cls, jlong sessionHandle, jbyteArray publicKeyX,
    jbyteArray publicKeyY, jbyteArray data, jbyteArray signature)
{
    (void)cls;
    CHECK_INIT_RET(env, JNI_FALSE);
    CHECK_FUNCTION_RET(SDF_ExternalVerify_ECC, env, "SDF_ExternalVerify_ECC", JNI_FALSE);

    if (publicKeyX == NULL || publicKeyY == NULL || data == NULL || signature == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "Parameters cannot be null");
        return JNI_FALSE;
    }
    jsize xLen = (*env)->GetArrayLength(env, publicKeyX);
    jsize yLen = (*env)->GetArrayLength(env, publicKeyY);
    jsize sigLen = (*env)->GetArrayLength(env, signature);
    if (xLen != SM2_KEY_BYTES || yLen != SM2_KEY_BYTES || sigLen != SM2_SIGNATURE_BYTES) {
        throw_exception(env, "java/lang/IllegalArgumentException",
                        "SM2 public key/signature length is invalid");
        return JNI_FALSE;
    }

    jbyte *xBytes = (*env)->GetByteArrayElements(env, publicKeyX, NULL);
    if (xBytes == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get publicKeyX bytes");
        return JNI_FALSE;
    }

    jbyte *yBytes = (*env)->GetByteArrayElements(env, publicKeyY, NULL);
    if (yBytes == NULL) {
        (*env)->ReleaseByteArrayElements(env, publicKeyX, xBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get publicKeyY bytes");
        return JNI_FALSE;
    }

    jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (dataBytes == NULL) {
        (*env)->ReleaseByteArrayElements(env, publicKeyX, xBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, publicKeyY, yBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get data bytes");
        return JNI_FALSE;
    }

    jbyte *sigBytes = (*env)->GetByteArrayElements(env, signature, NULL);
    if (sigBytes == NULL) {
        (*env)->ReleaseByteArrayElements(env, publicKeyX, xBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, publicKeyY, yBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get signature bytes");
        return JNI_FALSE;
    }
    jsize dataLen = (*env)->GetArrayLength(env, data);

    /* 构造公钥 */
    ECCrefPublicKey eccPubKey = {0};
    eccPubKey.bits = SM2_KEY_BITS;
    memcpy(eccPubKey.x + ECCref_MAX_LEN - SM2_KEY_BYTES, xBytes, SM2_KEY_BYTES);
    memcpy(eccPubKey.y + ECCref_MAX_LEN - SM2_KEY_BYTES, yBytes, SM2_KEY_BYTES);

    /* 构造签名 */
    ECCSignature eccSig = {0};
    memcpy(eccSig.r + ECCref_MAX_LEN - SM2_KEY_BYTES, sigBytes, SM2_KEY_BYTES);
    memcpy(eccSig.s + ECCref_MAX_LEN - SM2_KEY_BYTES, sigBytes + SM2_KEY_BYTES, SM2_KEY_BYTES);

    LONG ret = g_sdf_functions.SDF_ExternalVerify_ECC(
        (HANDLE)sessionHandle, SGD_SM2_1, &eccPubKey,
        (BYTE *)dataBytes, (ULONG)dataLen, &eccSig);

    (*env)->ReleaseByteArrayElements(env, publicKeyX, xBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, publicKeyY, yBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, signature, sigBytes, JNI_ABORT);

    return (ret == SDR_OK) ? JNI_TRUE : JNI_FALSE;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm2Encrypt
 * Signature: ([B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm2Encrypt(JNIEnv *env, jclass cls, jlong sessionHandle, jbyteArray publicKeyX,
    jbyteArray publicKeyY, jbyteArray plaintext)
{
    (void)cls;
    CHECK_INIT_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_ExternalEncrypt_ECC, env, "SDF_ExternalEncrypt_ECC", NULL);

    if (publicKeyX == NULL || publicKeyY == NULL || plaintext == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "Parameters cannot be null");
        return NULL;
    }
    jsize xLen = (*env)->GetArrayLength(env, publicKeyX);
    jsize yLen = (*env)->GetArrayLength(env, publicKeyY);
    if (xLen != SM2_KEY_BYTES || yLen != SM2_KEY_BYTES) {
        throw_exception(env, "java/lang/IllegalArgumentException",
                        "SM2 public key/signature length is invalid");
        return NULL;
    }

    jbyte *xBytes = (*env)->GetByteArrayElements(env, publicKeyX, NULL);
    if (xBytes == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get publicKeyX bytes");
        return NULL;
    }

    jbyte *yBytes = (*env)->GetByteArrayElements(env, publicKeyY, NULL);
    if (yBytes == NULL) {
        (*env)->ReleaseByteArrayElements(env, publicKeyX, xBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get publicKeyY bytes");
        return NULL;
    }

    jbyte *plainBytes = (*env)->GetByteArrayElements(env, plaintext, NULL);
    if (plainBytes == NULL) {
        (*env)->ReleaseByteArrayElements(env, publicKeyX, xBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, publicKeyY, yBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get plaintext bytes");
        return NULL;
    }
    jsize plainLen = (*env)->GetArrayLength(env, plaintext);
    if (plainLen == 0) {
        (*env)->ReleaseByteArrayElements(env, plaintext, plainBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, publicKeyX, xBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, publicKeyY, yBytes, JNI_ABORT);
        throw_exception(env, "java/lang/IllegalArgumentException", "plain len is invalid");
        return NULL;
    }
    
    /* 构造公钥 */
    ECCrefPublicKey eccPubKey = {0};
    eccPubKey.bits = SM2_KEY_BITS;
    memcpy(eccPubKey.x + ECCref_MAX_LEN - SM2_KEY_BYTES, xBytes, SM2_KEY_BYTES);
    memcpy(eccPubKey.y + ECCref_MAX_LEN - SM2_KEY_BYTES, yBytes, SM2_KEY_BYTES);

    /* 分配密文结构 */
    size_t cipherStructSize = sizeof(ECCCipher) + (size_t)plainLen;
    ECCCipher *cipher = (ECCCipher *)malloc(cipherStructSize);
    if (cipher == NULL) {
        (*env)->ReleaseByteArrayElements(env, plaintext, plainBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, publicKeyX, xBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, publicKeyY, yBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to allocate cipher");
        return NULL;
    }
    memset(cipher, 0, cipherStructSize);
    cipher->L = (ULONG)plainLen;
    jbyteArray result = NULL;

    LONG ret = g_sdf_functions.SDF_ExternalEncrypt_ECC(
        (HANDLE)sessionHandle, SGD_SM2_3, &eccPubKey,
        (BYTE *)plainBytes, (ULONG)plainLen, cipher);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM2 encrypt failed");
        goto ERR;
    }

    /* 组装输出: C1(04||X||Y) || C3 || C2 */
    /* C1: 1(04) + 32(X) + 32(Y) = 65字节 */
    /* C3: 32字节 */
    /* C2: L字节 */
    jint cipherLen = 65 + 32 + (jint)cipher->L;
    result = (*env)->NewByteArray(env, cipherLen);
    if (result == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to create byte array");
        goto ERR;
    }
    /* 写入04前缀 */
    BYTE c1Prefix = 0x04;
    (*env)->SetByteArrayRegion(env, result, 0, 1, (jbyte *)&c1Prefix);
    /* 写入X坐标 */
    (*env)->SetByteArrayRegion(env, result, 1, 32,
                                (jbyte *)(cipher->x + ECCref_MAX_LEN - SM2_KEY_BYTES));
    /* 写入Y坐标 */
    (*env)->SetByteArrayRegion(env, result, 33, 32,
                                (jbyte *)(cipher->y + ECCref_MAX_LEN - SM2_KEY_BYTES));
    /* 写入C3 (hash) */
    (*env)->SetByteArrayRegion(env, result, 65, 32, (jbyte *)cipher->M);
    /* 写入C2 (密文) */
    (*env)->SetByteArrayRegion(env, result, 97, (jsize)cipher->L, (jbyte *)cipher->C);
ERR:
    free(cipher);
    (*env)->ReleaseByteArrayElements(env, publicKeyX, xBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, publicKeyY, yBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, plaintext, plainBytes, JNI_ABORT);
    return result;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm2Decrypt
 * Signature: ([B[B)[B
 */
JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm2Decrypt(JNIEnv *env, jclass cls, jlong sessionHandle,
    jbyteArray privateKey, jbyteArray ciphertext)
{
    (void)cls;
    CHECK_INIT_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_ExternalDecrypt_ECC, env, "SDF_ExternalDecrypt_ECC", NULL);

    if (privateKey == NULL || ciphertext == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "privateKey or ciphertext is null");
        return NULL;
    }

    jsize privKeyLen = (*env)->GetArrayLength(env, privateKey);
    if (privKeyLen != SM2_KEY_BYTES) {
        throw_exception(env, "java/lang/IllegalArgumentException", "Private key must be 32 bytes");
        return NULL;
    }
    jbyte *privKeyBytes = (*env)->GetByteArrayElements(env, privateKey, NULL);
    jbyte *cipherBytes = (*env)->GetByteArrayElements(env, ciphertext, NULL);
    jsize cipherLen = (*env)->GetArrayLength(env, ciphertext);
    if (privKeyBytes == NULL || cipherBytes == NULL) {
        if (privKeyBytes) {
            memset(privKeyBytes, 0, (size_t)privKeyLen);
            (*env)->ReleaseByteArrayElements(env, privateKey, privKeyBytes, JNI_ABORT);
        }
        if (cipherBytes) {
            (*env)->ReleaseByteArrayElements(env, ciphertext, cipherBytes, JNI_ABORT);
        }
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get byte arrays");
        return NULL;
    }

    /* 构造私钥 */
    ECCrefPrivateKey eccPrivKey;
    memset(&eccPrivKey, 0, sizeof(eccPrivKey));
    eccPrivKey.bits = SM2_KEY_BITS;
    memcpy(eccPrivKey.K + ECCref_MAX_LEN - SM2_KEY_BYTES, privKeyBytes, SM2_KEY_BYTES);

    /* 解析密文结构: C1(04||X||Y) || C3 || C2 */
    /* C1: 1(04) + 32(X) + 32(Y) = 65字节 */
    /* C3: 32字节 */
    /* C2: L字节 */
    int c2Len = cipherLen - 97;  /* 65 + 32 = 97 */
    ECCCipher *cipher = NULL;
    BYTE *plaintext = NULL;
    jbyteArray result = NULL;

    if (cipherLen < 97 || c2Len <= 0) {
        memset(privKeyBytes, 0, (size_t)privKeyLen);
        (*env)->ReleaseByteArrayElements(env, privateKey, privKeyBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, ciphertext, cipherBytes, JNI_ABORT);
        memset(&eccPrivKey, 0, sizeof(eccPrivKey));
        throw_exception(env, "java/lang/IllegalArgumentException", "Ciphertext too short");
        return NULL;
    }

    /* 检查04前缀 */
    if (cipherBytes[0] != 0x04) {
        memset(privKeyBytes, 0, (size_t)privKeyLen);
        (*env)->ReleaseByteArrayElements(env, privateKey, privKeyBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, ciphertext, cipherBytes, JNI_ABORT);
        memset(&eccPrivKey, 0, sizeof(eccPrivKey));
        throw_exception(env, "java/lang/IllegalArgumentException", "Invalid ciphertext format (missing 0x04 prefix)");
        return NULL;
    }

    size_t cipherStructSize = sizeof(ECCCipher) + (size_t)c2Len;
    cipher = (ECCCipher *)malloc(cipherStructSize);
    if (cipher == NULL) {
        memset(privKeyBytes, 0, (size_t)privKeyLen);
        (*env)->ReleaseByteArrayElements(env, privateKey, privKeyBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, ciphertext, cipherBytes, JNI_ABORT);
        memset(&eccPrivKey, 0, sizeof(eccPrivKey));
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to allocate cipher");
        return NULL;
    }
    memset(cipher, 0, cipherStructSize);

    /* 解析C1点 (跳过04前缀) */
    memcpy(cipher->x + ECCref_MAX_LEN - SM2_KEY_BYTES, cipherBytes + 1, SM2_KEY_BYTES);
    memcpy(cipher->y + ECCref_MAX_LEN - SM2_KEY_BYTES, cipherBytes + 33, SM2_KEY_BYTES);
    /* 解析C3 (hash) */
    memcpy(cipher->M, cipherBytes + 65, 32);
    /* 设置C2长度和内容 */
    cipher->L = (ULONG)c2Len;
    memcpy(cipher->C, cipherBytes + 97, (size_t)c2Len);

    plaintext = (BYTE *)malloc((size_t)c2Len);
    if (plaintext == NULL) {
        free(cipher);
        memset(privKeyBytes, 0, (size_t)privKeyLen);
        (*env)->ReleaseByteArrayElements(env, privateKey, privKeyBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, ciphertext, cipherBytes, JNI_ABORT);
        memset(&eccPrivKey, 0, sizeof(eccPrivKey));
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to allocate plaintext");
        return NULL;
    }
    ULONG plainLen = (ULONG)c2Len;

    LONG ret = g_sdf_functions.SDF_ExternalDecrypt_ECC(
        (HANDLE)sessionHandle, SGD_SM2_3, &eccPrivKey, cipher, plaintext, &plainLen);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM2 decrypt failed");
        goto ERR;
    }

    result = (*env)->NewByteArray(env, (jsize)plainLen);
    if (result == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to create byte array");
        goto ERR;
    }
    (*env)->SetByteArrayRegion(env, result, 0, (jsize)plainLen, (jbyte *)plaintext);
ERR:
    /* 清除敏感数据 */
    memset(privKeyBytes, 0, (size_t)privKeyLen);
    (*env)->ReleaseByteArrayElements(env, privateKey, privKeyBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, ciphertext, cipherBytes, JNI_ABORT);
    memset(&eccPrivKey, 0, sizeof(eccPrivKey));
    free(cipher);
    free(plaintext);
    return result;
}
