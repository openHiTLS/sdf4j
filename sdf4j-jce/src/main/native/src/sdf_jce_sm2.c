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
#include "session_pool.h"
#include "auth_manager.h"
#include "dynamic_loader.h"
#include "sdf_log.h"

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm2GenerateKeyPair
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_jce_native_1_SDFJceNative_sm2GenerateKeyPair(
    JNIEnv *env, jclass cls)
{
    (void)cls;

    CHECK_INITIALIZED_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_GenerateKeyPair_ECC, env, "SDF_GenerateKeyPair_ECC", NULL);

    HANDLE session = session_pool_acquire();
    if (session == NULL) {
        throw_jce_exception(env, SDR_OPENSESSION, "Failed to acquire session");
        return NULL;
    }

    ECCrefPublicKey pubKey;
    ECCrefPrivateKey privKey;
    memset(&pubKey, 0, sizeof(pubKey));
    memset(&privKey, 0, sizeof(privKey));

    LONG ret = g_sdf_functions.SDF_GenerateKeyPair_ECC(
        session, SGD_SM2_1, SM2_KEY_BITS, &pubKey, &privKey);

    session_pool_release(session);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM2 key pair generation failed");
        return NULL;
    }

    /* 组装结果: privKey(32) || pubX(32) || pubY(32) = 96 bytes */
    jbyteArray result = (*env)->NewByteArray(env, 96);
    if (result != NULL) {
        /* 私钥取有效部分（右对齐） */
        (*env)->SetByteArrayRegion(env, result, 0, 32,
                                   (jbyte *)(privKey.K + ECCref_MAX_LEN - SM2_KEY_BYTES));
        /* 公钥X */
        (*env)->SetByteArrayRegion(env, result, 32, 32,
                                   (jbyte *)(pubKey.x + ECCref_MAX_LEN - SM2_KEY_BYTES));
        /* 公钥Y */
        (*env)->SetByteArrayRegion(env, result, 64, 32,
                                   (jbyte *)(pubKey.y + ECCref_MAX_LEN - SM2_KEY_BYTES));
    }

    /* 清除敏感数据 */
    memset(&privKey, 0, sizeof(privKey));

    return result;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm2Sign
 * Signature: ([B[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_jce_native_1_SDFJceNative_sm2Sign(
    JNIEnv *env, jclass cls, jbyteArray privateKey, jbyteArray data)
{
    (void)cls;

    CHECK_INITIALIZED_RET(env, NULL);
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
            /* Clear sensitive data before releasing */
            memset(privKeyBytes, 0, (size_t)privKeyLen);
            (*env)->ReleaseByteArrayElements(env, privateKey, privKeyBytes, 0);
        }
        if (dataBytes) (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get byte arrays");
        return NULL;
    }

    /* 构造SDF私钥结构（右对齐） */
    ECCrefPrivateKey eccPrivKey;
    memset(&eccPrivKey, 0, sizeof(eccPrivKey));
    eccPrivKey.bits = SM2_KEY_BITS;
    memcpy(eccPrivKey.K + ECCref_MAX_LEN - SM2_KEY_BYTES, privKeyBytes, SM2_KEY_BYTES);

    HANDLE session = session_pool_acquire();
    if (session == NULL) {
        (*env)->ReleaseByteArrayElements(env, privateKey, privKeyBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
        memset(&eccPrivKey, 0, sizeof(eccPrivKey));
        throw_jce_exception(env, SDR_OPENSESSION, "Failed to acquire session");
        return NULL;
    }

    ECCSignature signature;
    memset(&signature, 0, sizeof(signature));

    LONG ret = g_sdf_functions.SDF_ExternalSign_ECC(
        session, SGD_SM2_1, &eccPrivKey,
        (BYTE *)dataBytes, (ULONG)dataLen, &signature);

    session_pool_release(session);

    /* Clear sensitive data in JNI buffer before releasing */
    memset(privKeyBytes, 0, (size_t)privKeyLen);
    (*env)->ReleaseByteArrayElements(env, privateKey, privKeyBytes, 0);
    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);

    /* 清除敏感数据 */
    memset(&eccPrivKey, 0, sizeof(eccPrivKey));

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM2 sign failed");
        return NULL;
    }

    /* 返回 r(32) || s(32) = 64 bytes */
    jbyteArray result = (*env)->NewByteArray(env, SM2_SIGNATURE_BYTES);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, 32,
                                   (jbyte *)(signature.r + ECCref_MAX_LEN - SM2_KEY_BYTES));
        (*env)->SetByteArrayRegion(env, result, 32, 32,
                                   (jbyte *)(signature.s + ECCref_MAX_LEN - SM2_KEY_BYTES));
    }

    return result;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm2SignWithIndex
 * Signature: (I[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_jce_native_1_SDFJceNative_sm2SignWithIndex(
    JNIEnv *env, jclass cls, jint keyIndex, jbyteArray data, jbyteArray pin)
{
    (void)cls;

    CHECK_INITIALIZED_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_InternalSign_ECC, env, "SDF_InternalSign_ECC", NULL);

    if (data == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "data is null");
        return NULL;
    }

    jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
    jsize dataLen = (*env)->GetArrayLength(env, data);

    /* 获取PIN */
    char *pinStr = NULL;
    int pinLen = 0;
    if (pin != NULL) {
        pinLen = (*env)->GetArrayLength(env, pin);
        pinStr = (char *)malloc((size_t)(pinLen + 1));
        if (pinStr != NULL) {
            (*env)->GetByteArrayRegion(env, pin, 0, pinLen, (jbyte *)pinStr);
            pinStr[pinLen] = '\0';
        }
    }

    HANDLE session = session_pool_acquire();
    if (session == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
        if (pinStr) {
            memset(pinStr, 0, (size_t)pinLen);
            free(pinStr);
        }
        throw_jce_exception(env, SDR_OPENSESSION, "Failed to acquire session");
        return NULL;
    }

    /* 获取私钥访问权限 */
    if (pinStr != NULL) {
        int authRet = auth_manager_get_private_key_access(session, keyIndex, pinStr, pinLen);
        memset(pinStr, 0, (size_t)pinLen);
        free(pinStr);
        pinStr = NULL;

        if (authRet != SDR_OK) {
            session_pool_release(session);
            (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
            throw_jce_exception(env, authRet, "Failed to get private key access");
            return NULL;
        }
    }

    ECCSignature signature;
    memset(&signature, 0, sizeof(signature));

    LONG ret = g_sdf_functions.SDF_InternalSign_ECC(
        session, (ULONG)keyIndex,
        (BYTE *)dataBytes, (ULONG)dataLen, &signature);

    session_pool_release(session);
    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM2 internal sign failed");
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, SM2_SIGNATURE_BYTES);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, 32,
                                   (jbyte *)(signature.r + ECCref_MAX_LEN - SM2_KEY_BYTES));
        (*env)->SetByteArrayRegion(env, result, 32, 32,
                                   (jbyte *)(signature.s + ECCref_MAX_LEN - SM2_KEY_BYTES));
    }

    return result;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm2Verify
 * Signature: ([B[B[B[B)Z
 */
JNIEXPORT jboolean JNICALL
Java_org_openhitls_sdf4j_jce_native_1_SDFJceNative_sm2Verify(
    JNIEnv *env, jclass cls, jbyteArray publicKeyX, jbyteArray publicKeyY,
    jbyteArray data, jbyteArray signature)
{
    (void)cls;

    CHECK_INITIALIZED_RET(env, JNI_FALSE);
    CHECK_FUNCTION_RET(SDF_ExternalVerify_ECC, env, "SDF_ExternalVerify_ECC", JNI_FALSE);

    if (publicKeyX == NULL || publicKeyY == NULL || data == NULL || signature == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "Parameters cannot be null");
        return JNI_FALSE;
    }

    jbyte *xBytes = (*env)->GetByteArrayElements(env, publicKeyX, NULL);
    jbyte *yBytes = (*env)->GetByteArrayElements(env, publicKeyY, NULL);
    jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
    jbyte *sigBytes = (*env)->GetByteArrayElements(env, signature, NULL);
    jsize dataLen = (*env)->GetArrayLength(env, data);

    /* 构造公钥 */
    ECCrefPublicKey eccPubKey;
    memset(&eccPubKey, 0, sizeof(eccPubKey));
    eccPubKey.bits = SM2_KEY_BITS;
    memcpy(eccPubKey.x + ECCref_MAX_LEN - SM2_KEY_BYTES, xBytes, SM2_KEY_BYTES);
    memcpy(eccPubKey.y + ECCref_MAX_LEN - SM2_KEY_BYTES, yBytes, SM2_KEY_BYTES);

    /* 构造签名 */
    ECCSignature eccSig;
    memset(&eccSig, 0, sizeof(eccSig));
    memcpy(eccSig.r + ECCref_MAX_LEN - SM2_KEY_BYTES, sigBytes, SM2_KEY_BYTES);
    memcpy(eccSig.s + ECCref_MAX_LEN - SM2_KEY_BYTES, sigBytes + SM2_KEY_BYTES, SM2_KEY_BYTES);

    HANDLE session = session_pool_acquire();

    LONG ret = g_sdf_functions.SDF_ExternalVerify_ECC(
        session, SGD_SM2_1, &eccPubKey,
        (BYTE *)dataBytes, (ULONG)dataLen, &eccSig);

    session_pool_release(session);

    (*env)->ReleaseByteArrayElements(env, publicKeyX, xBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, publicKeyY, yBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, signature, sigBytes, JNI_ABORT);

    return (ret == SDR_OK) ? JNI_TRUE : JNI_FALSE;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm2VerifyWithIndex
 * Signature: (I[B[B)Z
 */
JNIEXPORT jboolean JNICALL
Java_org_openhitls_sdf4j_jce_native_1_SDFJceNative_sm2VerifyWithIndex(
    JNIEnv *env, jclass cls, jint keyIndex, jbyteArray data, jbyteArray signature)
{
    (void)cls;

    CHECK_INITIALIZED_RET(env, JNI_FALSE);
    CHECK_FUNCTION_RET(SDF_InternalVerify_ECC, env, "SDF_InternalVerify_ECC", JNI_FALSE);

    if (data == NULL || signature == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "data or signature is null");
        return JNI_FALSE;
    }

    jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
    jbyte *sigBytes = (*env)->GetByteArrayElements(env, signature, NULL);
    jsize dataLen = (*env)->GetArrayLength(env, data);

    /* 构造签名 */
    ECCSignature eccSig;
    memset(&eccSig, 0, sizeof(eccSig));
    memcpy(eccSig.r + ECCref_MAX_LEN - SM2_KEY_BYTES, sigBytes, SM2_KEY_BYTES);
    memcpy(eccSig.s + ECCref_MAX_LEN - SM2_KEY_BYTES, sigBytes + SM2_KEY_BYTES, SM2_KEY_BYTES);

    HANDLE session = session_pool_acquire();

    LONG ret = g_sdf_functions.SDF_InternalVerify_ECC(
        session, (ULONG)keyIndex,
        (BYTE *)dataBytes, (ULONG)dataLen, &eccSig);

    session_pool_release(session);

    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, signature, sigBytes, JNI_ABORT);

    return (ret == SDR_OK) ? JNI_TRUE : JNI_FALSE;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm2Encrypt
 * Signature: ([B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_jce_native_1_SDFJceNative_sm2Encrypt(
    JNIEnv *env, jclass cls, jbyteArray publicKeyX, jbyteArray publicKeyY, jbyteArray plaintext)
{
    (void)cls;

    CHECK_INITIALIZED_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_ExternalEncrypt_ECC, env, "SDF_ExternalEncrypt_ECC", NULL);

    if (publicKeyX == NULL || publicKeyY == NULL || plaintext == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "Parameters cannot be null");
        return NULL;
    }

    jbyte *xBytes = (*env)->GetByteArrayElements(env, publicKeyX, NULL);
    jbyte *yBytes = (*env)->GetByteArrayElements(env, publicKeyY, NULL);
    jbyte *plainBytes = (*env)->GetByteArrayElements(env, plaintext, NULL);
    jsize plainLen = (*env)->GetArrayLength(env, plaintext);

    /* 构造公钥 */
    ECCrefPublicKey eccPubKey;
    memset(&eccPubKey, 0, sizeof(eccPubKey));
    eccPubKey.bits = SM2_KEY_BITS;
    memcpy(eccPubKey.x + ECCref_MAX_LEN - SM2_KEY_BYTES, xBytes, SM2_KEY_BYTES);
    memcpy(eccPubKey.y + ECCref_MAX_LEN - SM2_KEY_BYTES, yBytes, SM2_KEY_BYTES);

    HANDLE session = session_pool_acquire();
    if (session == NULL) {
        (*env)->ReleaseByteArrayElements(env, publicKeyX, xBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, publicKeyY, yBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, plaintext, plainBytes, JNI_ABORT);
        throw_jce_exception(env, SDR_OPENSESSION, "Failed to acquire session");
        return NULL;
    }

    /* 分配密文结构 */
    size_t cipherStructSize = sizeof(ECCCipher) + (size_t)plainLen;
    ECCCipher *cipher = (ECCCipher *)malloc(cipherStructSize);
    memset(cipher, 0, cipherStructSize);

    LONG ret = g_sdf_functions.SDF_ExternalEncrypt_ECC(
        session, SGD_SM2_3, &eccPubKey,
        (BYTE *)plainBytes, (ULONG)plainLen, cipher);

    session_pool_release(session);

    (*env)->ReleaseByteArrayElements(env, publicKeyX, xBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, publicKeyY, yBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, plaintext, plainBytes, JNI_ABORT);

    if (ret != SDR_OK) {
        free(cipher);
        throw_jce_exception(env, (int)ret, "SM2 encrypt failed");
        return NULL;
    }

    /* 组装输出: C1_X(32) || C1_Y(32) || C3(32) || C2(L) */
    int totalLen = 32 + 32 + 32 + (int)cipher->L;
    jbyteArray result = (*env)->NewByteArray(env, totalLen);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, 32,
                                   (jbyte *)(cipher->x + ECCref_MAX_LEN - SM2_KEY_BYTES));
        (*env)->SetByteArrayRegion(env, result, 32, 32,
                                   (jbyte *)(cipher->y + ECCref_MAX_LEN - SM2_KEY_BYTES));
        (*env)->SetByteArrayRegion(env, result, 64, 32, (jbyte *)cipher->M);
        (*env)->SetByteArrayRegion(env, result, 96, (jsize)cipher->L, (jbyte *)cipher->C);
    }

    free(cipher);
    return result;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm2Decrypt
 * Signature: ([B[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_jce_native_1_SDFJceNative_sm2Decrypt(
    JNIEnv *env, jclass cls, jbyteArray privateKey, jbyteArray ciphertext)
{
    (void)cls;

    CHECK_INITIALIZED_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_ExternalDecrypt_ECC, env, "SDF_ExternalDecrypt_ECC", NULL);

    if (privateKey == NULL || ciphertext == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "privateKey or ciphertext is null");
        return NULL;
    }

    jsize privKeyLen = (*env)->GetArrayLength(env, privateKey);
    jbyte *privKeyBytes = (*env)->GetByteArrayElements(env, privateKey, NULL);
    jbyte *cipherBytes = (*env)->GetByteArrayElements(env, ciphertext, NULL);
    jsize cipherLen = (*env)->GetArrayLength(env, ciphertext);

    if (privKeyBytes == NULL || cipherBytes == NULL) {
        if (privKeyBytes) {
            memset(privKeyBytes, 0, (size_t)privKeyLen);
            (*env)->ReleaseByteArrayElements(env, privateKey, privKeyBytes, 0);
        }
        if (cipherBytes) (*env)->ReleaseByteArrayElements(env, ciphertext, cipherBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get byte arrays");
        return NULL;
    }

    /* 构造私钥 */
    ECCrefPrivateKey eccPrivKey;
    memset(&eccPrivKey, 0, sizeof(eccPrivKey));
    eccPrivKey.bits = SM2_KEY_BITS;
    memcpy(eccPrivKey.K + ECCref_MAX_LEN - SM2_KEY_BYTES, privKeyBytes, SM2_KEY_BYTES);

    /* 解析密文结构: C1_X(32) || C1_Y(32) || C3(32) || C2(L) */
    int c2Len = cipherLen - 96;
    if (c2Len <= 0) {
        memset(privKeyBytes, 0, (size_t)privKeyLen);
        (*env)->ReleaseByteArrayElements(env, privateKey, privKeyBytes, 0);
        (*env)->ReleaseByteArrayElements(env, ciphertext, cipherBytes, JNI_ABORT);
        memset(&eccPrivKey, 0, sizeof(eccPrivKey));
        throw_exception(env, "java/lang/IllegalArgumentException", "Ciphertext too short");
        return NULL;
    }

    size_t cipherStructSize = sizeof(ECCCipher) + (size_t)c2Len;
    ECCCipher *cipher = (ECCCipher *)malloc(cipherStructSize);
    memset(cipher, 0, cipherStructSize);

    memcpy(cipher->x + ECCref_MAX_LEN - SM2_KEY_BYTES, cipherBytes, SM2_KEY_BYTES);
    memcpy(cipher->y + ECCref_MAX_LEN - SM2_KEY_BYTES, cipherBytes + 32, SM2_KEY_BYTES);
    memcpy(cipher->M, cipherBytes + 64, 32);
    cipher->L = (ULONG)c2Len;
    memcpy(cipher->C, cipherBytes + 96, (size_t)c2Len);

    HANDLE session = session_pool_acquire();
    if (session == NULL) {
        memset(privKeyBytes, 0, (size_t)privKeyLen);
        (*env)->ReleaseByteArrayElements(env, privateKey, privKeyBytes, 0);
        (*env)->ReleaseByteArrayElements(env, ciphertext, cipherBytes, JNI_ABORT);
        memset(&eccPrivKey, 0, sizeof(eccPrivKey));
        free(cipher);
        throw_jce_exception(env, SDR_OPENSESSION, "Failed to acquire session");
        return NULL;
    }

    BYTE *plaintext = (BYTE *)malloc((size_t)c2Len);
    ULONG plainLen = (ULONG)c2Len;

    LONG ret = g_sdf_functions.SDF_ExternalDecrypt_ECC(
        session, SGD_SM2_3, &eccPrivKey, cipher, plaintext, &plainLen);

    session_pool_release(session);

    /* Clear sensitive data in JNI buffer before releasing */
    memset(privKeyBytes, 0, (size_t)privKeyLen);
    (*env)->ReleaseByteArrayElements(env, privateKey, privKeyBytes, 0);
    (*env)->ReleaseByteArrayElements(env, ciphertext, cipherBytes, JNI_ABORT);

    /* 清除敏感数据 */
    memset(&eccPrivKey, 0, sizeof(eccPrivKey));
    free(cipher);

    if (ret != SDR_OK) {
        free(plaintext);
        throw_jce_exception(env, (int)ret, "SM2 decrypt failed");
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, (jsize)plainLen);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)plainLen, (jbyte *)plaintext);
    }

    free(plaintext);
    return result;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm2DecryptWithIndex
 * Signature: (I[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_jce_native_1_SDFJceNative_sm2DecryptWithIndex(
    JNIEnv *env, jclass cls, jint keyIndex, jbyteArray ciphertext, jbyteArray pin)
{
    (void)cls;

    CHECK_INITIALIZED_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_InternalDecrypt_ECC, env, "SDF_InternalDecrypt_ECC", NULL);

    if (ciphertext == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "ciphertext is null");
        return NULL;
    }

    jbyte *cipherBytes = (*env)->GetByteArrayElements(env, ciphertext, NULL);
    jsize cipherLen = (*env)->GetArrayLength(env, ciphertext);

    /* 获取PIN */
    char *pinStr = NULL;
    int pinLen = 0;
    if (pin != NULL) {
        pinLen = (*env)->GetArrayLength(env, pin);
        pinStr = (char *)malloc((size_t)(pinLen + 1));
        if (pinStr != NULL) {
            (*env)->GetByteArrayRegion(env, pin, 0, pinLen, (jbyte *)pinStr);
            pinStr[pinLen] = '\0';
        }
    }

    /* 解析密文结构 */
    int c2Len = cipherLen - 96;
    if (c2Len <= 0) {
        (*env)->ReleaseByteArrayElements(env, ciphertext, cipherBytes, JNI_ABORT);
        if (pinStr) {
            memset(pinStr, 0, (size_t)pinLen);
            free(pinStr);
        }
        throw_exception(env, "java/lang/IllegalArgumentException", "Ciphertext too short");
        return NULL;
    }

    size_t cipherStructSize = sizeof(ECCCipher) + (size_t)c2Len;
    ECCCipher *cipher = (ECCCipher *)malloc(cipherStructSize);
    memset(cipher, 0, cipherStructSize);

    memcpy(cipher->x + ECCref_MAX_LEN - SM2_KEY_BYTES, cipherBytes, SM2_KEY_BYTES);
    memcpy(cipher->y + ECCref_MAX_LEN - SM2_KEY_BYTES, cipherBytes + 32, SM2_KEY_BYTES);
    memcpy(cipher->M, cipherBytes + 64, 32);
    cipher->L = (ULONG)c2Len;
    memcpy(cipher->C, cipherBytes + 96, (size_t)c2Len);

    HANDLE session = session_pool_acquire();
    if (session == NULL) {
        (*env)->ReleaseByteArrayElements(env, ciphertext, cipherBytes, JNI_ABORT);
        if (pinStr) {
            memset(pinStr, 0, (size_t)pinLen);
            free(pinStr);
        }
        free(cipher);
        throw_jce_exception(env, SDR_OPENSESSION, "Failed to acquire session");
        return NULL;
    }

    /* 获取私钥访问权限 */
    if (pinStr != NULL) {
        int authRet = auth_manager_get_private_key_access(session, keyIndex, pinStr, pinLen);
        memset(pinStr, 0, (size_t)pinLen);
        free(pinStr);
        pinStr = NULL;

        if (authRet != SDR_OK) {
            session_pool_release(session);
            (*env)->ReleaseByteArrayElements(env, ciphertext, cipherBytes, JNI_ABORT);
            free(cipher);
            throw_jce_exception(env, authRet, "Failed to get private key access");
            return NULL;
        }
    }

    BYTE *plaintext = (BYTE *)malloc((size_t)c2Len);
    ULONG plainLen = (ULONG)c2Len;

    /* 注：第三个参数是密钥类型，通常为1表示加密密钥 */
    LONG ret = g_sdf_functions.SDF_InternalDecrypt_ECC(
        session, (ULONG)keyIndex, 1, cipher, plaintext, &plainLen);

    session_pool_release(session);
    (*env)->ReleaseByteArrayElements(env, ciphertext, cipherBytes, JNI_ABORT);
    free(cipher);

    if (ret != SDR_OK) {
        free(plaintext);
        throw_jce_exception(env, (int)ret, "SM2 internal decrypt failed");
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, (jsize)plainLen);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)plainLen, (jbyte *)plaintext);
    }

    free(plaintext);
    return result;
}
