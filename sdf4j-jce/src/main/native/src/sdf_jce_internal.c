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
 * SM2 Internal Sign
 * Signature: (JI[B)[B
 */
JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm2InternalSign(JNIEnv *env, jclass cls,
    jlong sessionHandle, jint keyIndex, jbyteArray data)
{
    (void)cls;
    CHECK_INIT_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_InternalSign_ECC, env, "SDF_InternalSign_ECC", NULL);

    if (data == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "data is null");
        return NULL;
    }

    jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
    jsize dataLen = (*env)->GetArrayLength(env, data);
    if (dataBytes == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get data bytes");
        return NULL;
    }

    ECCSignature signature = {0};
    jbyteArray result = NULL;

    LONG ret = g_sdf_functions.SDF_InternalSign_ECC(
        (HANDLE)sessionHandle, (ULONG)keyIndex,
        (BYTE *)dataBytes, (ULONG)dataLen, &signature);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM2 internal sign failed");
        goto ERR;
    }

    /* Return r(32) || s(32) = 64 bytes */
    result = (*env)->NewByteArray(env, SM2_SIGNATURE_BYTES);
    if (result == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to create byte array");
        goto ERR;
    }
    (*env)->SetByteArrayRegion(env, result, 0, 32,
                               (jbyte *)(signature.r + ECCref_MAX_LEN - SM2_KEY_BYTES));
    (*env)->SetByteArrayRegion(env, result, 32, 32,
                               (jbyte *)(signature.s + ECCref_MAX_LEN - SM2_KEY_BYTES));

ERR:
    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
    return result;
}

/*
 * SM2 Internal Verify
 * Signature: (JI[B[B)Z
 */
JNIEXPORT jboolean JNICALL JNI_SDFJceNative_sm2InternalVerify(JNIEnv *env, jclass cls,
    jlong sessionHandle, jint keyIndex, jbyteArray data, jbyteArray signature)
{
    (void)cls;
    CHECK_INIT_RET(env, JNI_FALSE);
    CHECK_FUNCTION_RET(SDF_InternalVerify_ECC, env, "SDF_InternalVerify_ECC", JNI_FALSE);

    if (data == NULL || signature == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "data or signature is null");
        return JNI_FALSE;
    }

    jsize sigLen = (*env)->GetArrayLength(env, signature);
    if (sigLen != SM2_SIGNATURE_BYTES) {
        throw_exception(env, "java/lang/IllegalArgumentException",
                        "Signature must be 64 bytes");
        return JNI_FALSE;
    }

    jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (dataBytes == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get data bytes");
        return JNI_FALSE;
    }

    jbyte *sigBytes = (*env)->GetByteArrayElements(env, signature, NULL);
    if (sigBytes == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get signature bytes");
        return JNI_FALSE;
    }
    jsize dataLen = (*env)->GetArrayLength(env, data);

    /* Construct signature structure */
    ECCSignature eccSig = {0};
    memcpy(eccSig.r + ECCref_MAX_LEN - SM2_KEY_BYTES, sigBytes, SM2_KEY_BYTES);
    memcpy(eccSig.s + ECCref_MAX_LEN - SM2_KEY_BYTES, sigBytes + SM2_KEY_BYTES, SM2_KEY_BYTES);

    LONG ret = g_sdf_functions.SDF_InternalVerify_ECC(
        (HANDLE)sessionHandle, (ULONG)keyIndex,
        (BYTE *)dataBytes, (ULONG)dataLen, &eccSig);

    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, signature, sigBytes, JNI_ABORT);

    return (ret == SDR_OK) ? JNI_TRUE : JNI_FALSE;
}

/*
 * SM2 Internal Encrypt
 * Signature: (JI[B)[B
 */
JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm2InternalEncrypt(JNIEnv *env, jclass cls,
    jlong sessionHandle, jint keyIndex, jbyteArray plaintext)
{
    (void)cls;
    CHECK_INIT_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_InternalEncrypt_ECC, env, "SDF_InternalEncrypt_ECC", NULL);

    if (plaintext == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "plaintext is null");
        return NULL;
    }

    jbyte *plainBytes = (*env)->GetByteArrayElements(env, plaintext, NULL);
    jsize plainLen = (*env)->GetArrayLength(env, plaintext);
    if (plainBytes == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get plaintext bytes");
        return NULL;
    }
    if (plainLen == 0) {
        (*env)->ReleaseByteArrayElements(env, plaintext, plainBytes, JNI_ABORT);
        throw_exception(env, "java/lang/IllegalArgumentException", "plaintext is empty");
        return NULL;
    }

    /* Allocate cipher structure */
    size_t cipherStructSize = sizeof(ECCCipher) + (size_t)plainLen;
    ECCCipher *cipher = (ECCCipher *)malloc(cipherStructSize);
    if (cipher == NULL) {
        (*env)->ReleaseByteArrayElements(env, plaintext, plainBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to allocate cipher");
        return NULL;
    }
    memset(cipher, 0, cipherStructSize);
    cipher->L = (ULONG)plainLen;
    jbyteArray result = NULL;

    LONG ret = g_sdf_functions.SDF_InternalEncrypt_ECC(
        (HANDLE)sessionHandle, (ULONG)keyIndex,
        (BYTE *)plainBytes, (ULONG)plainLen, cipher);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM2 internal encrypt failed");
        goto ERR;
    }

    /* Output: 0x04 || C1_X(32) || C1_Y(32) || C3(32) || C2(L) */
    jint cipherLen = 65 + 32 + (jint)cipher->L;
    result = (*env)->NewByteArray(env, cipherLen);
    if (result == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to create byte array");
        goto ERR;
    }
    BYTE c1Prefix = 0x04;
    (*env)->SetByteArrayRegion(env, result, 0, 1, (jbyte *)&c1Prefix);
    (*env)->SetByteArrayRegion(env, result, 1, 32,
                                (jbyte *)(cipher->x + ECCref_MAX_LEN - SM2_KEY_BYTES));
    (*env)->SetByteArrayRegion(env, result, 33, 32,
                                (jbyte *)(cipher->y + ECCref_MAX_LEN - SM2_KEY_BYTES));
    (*env)->SetByteArrayRegion(env, result, 65, 32, (jbyte *)cipher->M);
    (*env)->SetByteArrayRegion(env, result, 97, (jsize)cipher->L, (jbyte *)cipher->C);

ERR:
    free(cipher);
    (*env)->ReleaseByteArrayElements(env, plaintext, plainBytes, JNI_ABORT);
    return result;
}

/*
 * SM2 Internal Decrypt
 * Signature: (JII[B)[B
 */
JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm2InternalDecrypt(JNIEnv *env, jclass cls,
    jlong sessionHandle, jint keyIndex, jint eccKeyType, jbyteArray ciphertext)
{
    (void)cls;
    CHECK_INIT_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_InternalDecrypt_ECC, env, "SDF_InternalDecrypt_ECC", NULL);

    if (ciphertext == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "ciphertext is null");
        return NULL;
    }

    jbyte *cipherBytes = (*env)->GetByteArrayElements(env, ciphertext, NULL);
    jsize cipherLen = (*env)->GetArrayLength(env, ciphertext);
    if (cipherBytes == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get ciphertext bytes");
        return NULL;
    }
    if (cipherLen < 97) {
        (*env)->ReleaseByteArrayElements(env, ciphertext, cipherBytes, JNI_ABORT);
        throw_exception(env, "java/lang/IllegalArgumentException", "Ciphertext too short");
        return NULL;
    }
    if (cipherBytes[0] != 0x04) {
        (*env)->ReleaseByteArrayElements(env, ciphertext, cipherBytes, JNI_ABORT);
        throw_exception(env, "java/lang/IllegalArgumentException",
                        "Invalid ciphertext format (missing 0x04 prefix)");
        return NULL;
    }

    int c2Len = cipherLen - 97;
    size_t cipherStructSize = sizeof(ECCCipher) + (size_t)c2Len;
    ECCCipher *cipher = (ECCCipher *)malloc(cipherStructSize);
    BYTE *plainBuf = NULL;
    jbyteArray result = NULL;

    if (cipher == NULL) {
        (*env)->ReleaseByteArrayElements(env, ciphertext, cipherBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to allocate cipher");
        return NULL;
    }
    memset(cipher, 0, cipherStructSize);

    /* Parse C1 point (skip 0x04 prefix) */
    memcpy(cipher->x + ECCref_MAX_LEN - SM2_KEY_BYTES, cipherBytes + 1, SM2_KEY_BYTES);
    memcpy(cipher->y + ECCref_MAX_LEN - SM2_KEY_BYTES, cipherBytes + 33, SM2_KEY_BYTES);
    /* Parse C3 (hash) */
    memcpy(cipher->M, cipherBytes + 65, 32);
    /* Set C2 */
    cipher->L = (ULONG)c2Len;
    memcpy(cipher->C, cipherBytes + 97, (size_t)c2Len);

    plainBuf = (BYTE *)malloc((size_t)c2Len);
    if (plainBuf == NULL) {
        free(cipher);
        (*env)->ReleaseByteArrayElements(env, ciphertext, cipherBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to allocate plaintext");
        return NULL;
    }
    ULONG plainLen = (ULONG)c2Len;

    LONG ret = g_sdf_functions.SDF_InternalDecrypt_ECC(
        (HANDLE)sessionHandle, (ULONG)keyIndex, (ULONG)eccKeyType,
        cipher, plainBuf, &plainLen);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM2 internal decrypt failed");
        goto ERR;
    }

    result = (*env)->NewByteArray(env, (jsize)plainLen);
    if (result == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to create byte array");
        goto ERR;
    }
    (*env)->SetByteArrayRegion(env, result, 0, (jsize)plainLen, (jbyte *)plainBuf);

ERR:
    (*env)->ReleaseByteArrayElements(env, ciphertext, cipherBytes, JNI_ABORT);
    free(cipher);
    free(plainBuf);
    return result;
}

/*
 * Export Sign Public Key ECC
 * Signature: (JI)[B
 * Returns 64 bytes (X(32) || Y(32))
 */
JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_exportSignPublicKeyECC(JNIEnv *env, jclass cls,
    jlong sessionHandle, jint keyIndex)
{
    (void)cls;
    CHECK_INIT_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_ExportSignPublicKey_ECC, env, "SDF_ExportSignPublicKey_ECC", NULL);

    ECCrefPublicKey pubKey = {0};
    LONG ret = g_sdf_functions.SDF_ExportSignPublicKey_ECC(
        (HANDLE)sessionHandle, (ULONG)keyIndex, &pubKey);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "Export sign public key ECC failed");
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, 64);
    if (result == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to create byte array");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, result, 0, 32,
                               (jbyte *)(pubKey.x + ECCref_MAX_LEN - SM2_KEY_BYTES));
    (*env)->SetByteArrayRegion(env, result, 32, 32,
                               (jbyte *)(pubKey.y + ECCref_MAX_LEN - SM2_KEY_BYTES));
    return result;
}

/*
 * Export Enc Public Key ECC
 * Signature: (JI)[B
 */
JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_exportEncPublicKeyECC(JNIEnv *env, jclass cls,
    jlong sessionHandle, jint keyIndex)
{
    (void)cls;
    CHECK_INIT_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_ExportEncPublicKey_ECC, env, "SDF_ExportEncPublicKey_ECC", NULL);

    ECCrefPublicKey pubKey = {0};
    LONG ret = g_sdf_functions.SDF_ExportEncPublicKey_ECC(
        (HANDLE)sessionHandle, (ULONG)keyIndex, &pubKey);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "Export enc public key ECC failed");
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, 64);
    if (result == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to create byte array");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, result, 0, 32,
                               (jbyte *)(pubKey.x + ECCref_MAX_LEN - SM2_KEY_BYTES));
    (*env)->SetByteArrayRegion(env, result, 32, 32,
                               (jbyte *)(pubKey.y + ECCref_MAX_LEN - SM2_KEY_BYTES));
    return result;
}

/*
 * Get Private Key Access Right
 * Signature: (JILjava/lang/String;)V
 */
JNIEXPORT void JNICALL JNI_SDFJceNative_getPrivateKeyAccessRight(JNIEnv *env, jclass cls,
    jlong sessionHandle, jint keyIndex, jbyteArray password)
{
    (void)cls;
    CHECK_INIT(env);
    CHECK_FUNCTION(SDF_GetPrivateKeyAccessRight, env, "SDF_GetPrivateKeyAccessRight");

    if (password == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "password is null");
        return;
    }

    jbyte *pwdBytes = (*env)->GetByteArrayElements(env, password, NULL);
    if (pwdBytes == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get password bytes");
        return;
    }
    jsize pwdLen = (*env)->GetArrayLength(env, password);

    LONG ret = g_sdf_functions.SDF_GetPrivateKeyAccessRight(
        (HANDLE)sessionHandle, (ULONG)keyIndex, (LPSTR)pwdBytes, (ULONG)pwdLen);

    /* Clear password in memory as soon as possible */
    memset(pwdBytes, 0, (size_t)pwdLen);
    (*env)->ReleaseByteArrayElements(env, password, pwdBytes, JNI_ABORT);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "Get private key access right failed");
    }
}

/*
 * Release Private Key Access Right
 * Signature: (JI)V
 */
JNIEXPORT void JNICALL JNI_SDFJceNative_releasePrivateKeyAccessRight(JNIEnv *env, jclass cls,
    jlong sessionHandle, jint keyIndex)
{
    (void)cls;
    CHECK_INIT(env);
    CHECK_FUNCTION(SDF_ReleasePrivateKeyAccessRight, env, "SDF_ReleasePrivateKeyAccessRight");

    LONG ret = g_sdf_functions.SDF_ReleasePrivateKeyAccessRight(
        (HANDLE)sessionHandle, (ULONG)keyIndex);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "Release private key access right failed");
    }
}

/*
 * Get KEK Access Right
 * Signature: (JILjava/lang/String;)V
 */
JNIEXPORT void JNICALL JNI_SDFJceNative_getKEKAccessRight(JNIEnv *env, jclass cls,
    jlong sessionHandle, jint keyIndex, jbyteArray password)
{
    (void)cls;
    CHECK_INIT(env);
    CHECK_FUNCTION(SDF_GetKEKAccessRight, env, "SDF_GetKEKAccessRight");

    if (password == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "password is null");
        return;
    }

    jbyte *pwdBytes = (*env)->GetByteArrayElements(env, password, NULL);
    if (pwdBytes == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get password bytes");
        return;
    }
    jsize pwdLen = (*env)->GetArrayLength(env, password);

    LONG ret = g_sdf_functions.SDF_GetKEKAccessRight(
        (HANDLE)sessionHandle, (ULONG)keyIndex, (LPSTR)pwdBytes, (ULONG)pwdLen);

    /* Clear password in memory */
    memset(pwdBytes, 0, (size_t)pwdLen);
    (*env)->ReleaseByteArrayElements(env, password, pwdBytes, JNI_ABORT);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "Get KEK access right failed");
    }
}

/*
 * Release KEK Access Right
 * Signature: (JI)V
 */
JNIEXPORT void JNICALL JNI_SDFJceNative_releaseKEKAccessRight(JNIEnv *env, jclass cls,
    jlong sessionHandle, jint keyIndex)
{
    (void)cls;
    CHECK_INIT(env);
    CHECK_FUNCTION(SDF_ReleaseKEKAccessRight, env, "SDF_ReleaseKEKAccessRight");

    LONG ret = g_sdf_functions.SDF_ReleaseKEKAccessRight(
        (HANDLE)sessionHandle, (ULONG)keyIndex);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "Release KEK access right failed");
    }
}

/*
 * SM4 Generate Key With KEK
 * Signature: (JIII)[B
 * Returns wrappedKey(N) || keyHandle(8 bytes big-endian)
 */
JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm4GenerateKeyWithKEK(JNIEnv *env, jclass cls,
    jlong sessionHandle, jint keyBits, jint algID, jint kekIndex)
{
    (void)cls;
    CHECK_INIT_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_GenerateKeyWithKEK, env, "SDF_GenerateKeyWithKEK", NULL);
    CHECK_FUNCTION_RET(SDF_DestroyKey, env, "SDF_DestroyKey", NULL);

    BYTE wrappedKey[256] = {0};
    ULONG wrappedKeyLen = sizeof(wrappedKey);
    HANDLE keyHandle = 0;

    LONG ret = g_sdf_functions.SDF_GenerateKeyWithKEK(
        (HANDLE)sessionHandle, (ULONG)keyBits, (ULONG)algID,
        (ULONG)kekIndex, wrappedKey, &wrappedKeyLen, &keyHandle);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 generate key with KEK failed");
        return NULL;
    }

    /* Pack result: wrappedKey(wrappedKeyLen) || keyHandle(8 bytes) */
    jsize resultLen = (jsize)wrappedKeyLen + 8;
    jbyteArray result = (*env)->NewByteArray(env, resultLen);
    if (result == NULL) {
        g_sdf_functions.SDF_DestroyKey((HANDLE)sessionHandle, keyHandle);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to create byte array");
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, result, 0, (jsize)wrappedKeyLen, (jbyte *)wrappedKey);

    /* Encode keyHandle as big-endian 8 bytes */
    jlong handleVal = (jlong)(uintptr_t)keyHandle;
    BYTE handleBytes[8];
    for (int i = 7; i >= 0; i--) {
        handleBytes[i] = (BYTE)(handleVal & 0xFF);
        handleVal >>= 8;
    }
    (*env)->SetByteArrayRegion(env, result, (jsize)wrappedKeyLen, 8, (jbyte *)handleBytes);

    return result;
}

/*
 * SM4 Import Key With KEK
 * Signature: (JII[B)J
 */
JNIEXPORT jlong JNICALL JNI_SDFJceNative_sm4ImportKeyWithKEK(JNIEnv *env, jclass cls,
    jlong sessionHandle, jint algID, jint kekIndex, jbyteArray wrappedKey)
{
    (void)cls;
    CHECK_INIT_RET(env, 0);
    CHECK_FUNCTION_RET(SDF_ImportKeyWithKEK, env, "SDF_ImportKeyWithKEK", 0);

    if (wrappedKey == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "wrappedKey is null");
        return 0;
    }

    jbyte *keyBytes = (*env)->GetByteArrayElements(env, wrappedKey, NULL);
    jsize keyLen = (*env)->GetArrayLength(env, wrappedKey);
    if (keyBytes == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get wrappedKey bytes");
        return 0;
    }

    HANDLE keyHandle = 0;
    LONG ret = g_sdf_functions.SDF_ImportKeyWithKEK(
        (HANDLE)sessionHandle, (ULONG)algID, (ULONG)kekIndex,
        (BYTE *)keyBytes, (ULONG)keyLen, &keyHandle);

    (*env)->ReleaseByteArrayElements(env, wrappedKey, keyBytes, JNI_ABORT);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 import key with KEK failed");
        return 0;
    }

    return (jlong)(uintptr_t)keyHandle;
}

/*
 * SM4 Encrypt Init With Key Handle
 * Signature: (JJI[B)J
 */
JNIEXPORT jlong JNICALL JNI_SDFJceNative_sm4EncryptInitWithKeyHandle(JNIEnv *env, jclass cls,
    jlong sessionHandle, jlong keyHandle, jint mode, jbyteArray iv)
{
    (void)cls;
    CHECK_INIT_RET(env, 0);
    CHECK_FUNCTION_RET(SDF_EncryptInit, env, "SDF_EncryptInit", 0);

    jbyte *ivBytes = NULL;
    jsize ivLen = 0;
    if (iv != NULL) {
        ivLen = (*env)->GetArrayLength(env, iv);
        ivBytes = (*env)->GetByteArrayElements(env, iv, NULL);
        if (ivBytes == NULL) {
            throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get iv bytes");
            return 0;
        }
    }

    SM4Context *ctx = (SM4Context *)malloc(sizeof(SM4Context));
    if (ctx == NULL) {
        if (ivBytes) (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to allocate context");
        return 0;
    }
    memset(ctx, 0, sizeof(SM4Context));
    ctx->session_handle = (HANDLE)sessionHandle;
    ctx->key_handle = (HANDLE)(uintptr_t)keyHandle;

    ULONG algId;
    switch (mode) {
        case SM4_MODE_ECB: algId = SGD_SM4_ECB; break;
        case SM4_MODE_CBC: algId = SGD_SM4_CBC; break;
        case SM4_MODE_GCM: algId = SGD_SM4_GCM; break;
        case SM4_MODE_CCM: algId = SGD_SM4_CCM; break;
        default: algId = SGD_SM4_CBC; break;
    }

    LONG ret = g_sdf_functions.SDF_EncryptInit(
        ctx->session_handle, ctx->key_handle, algId,
        (BYTE *)ivBytes, (ULONG)ivLen);

    if (ivBytes) (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);

    if (ret != SDR_OK) {
        free(ctx);
        throw_jce_exception(env, (int)ret, "SM4 encrypt init with key handle failed");
        return 0;
    }

    ctx->initialized = 1;
    return (jlong)(uintptr_t)ctx;
}

/*
 * SM4 Decrypt Init With Key Handle
 * Signature: (JJI[B)J
 */
JNIEXPORT jlong JNICALL JNI_SDFJceNative_sm4DecryptInitWithKeyHandle(JNIEnv *env, jclass cls,
    jlong sessionHandle, jlong keyHandle, jint mode, jbyteArray iv)
{
    (void)cls;
    CHECK_INIT_RET(env, 0);
    CHECK_FUNCTION_RET(SDF_DecryptInit, env, "SDF_DecryptInit", 0);

    jbyte *ivBytes = NULL;
    jsize ivLen = 0;
    if (iv != NULL) {
        ivLen = (*env)->GetArrayLength(env, iv);
        ivBytes = (*env)->GetByteArrayElements(env, iv, NULL);
        if (ivBytes == NULL) {
            throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get iv bytes");
            return 0;
        }
    }

    SM4Context *ctx = (SM4Context *)malloc(sizeof(SM4Context));
    if (ctx == NULL) {
        if (ivBytes) (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to allocate context");
        return 0;
    }
    memset(ctx, 0, sizeof(SM4Context));
    ctx->session_handle = (HANDLE)sessionHandle;
    ctx->key_handle = (HANDLE)(uintptr_t)keyHandle;

    ULONG algId;
    switch (mode) {
        case SM4_MODE_ECB: algId = SGD_SM4_ECB; break;
        case SM4_MODE_CBC: algId = SGD_SM4_CBC; break;
        case SM4_MODE_GCM: algId = SGD_SM4_GCM; break;
        case SM4_MODE_CCM: algId = SGD_SM4_CCM; break;
        default: algId = SGD_SM4_CBC; break;
    }

    LONG ret = g_sdf_functions.SDF_DecryptInit(
        ctx->session_handle, ctx->key_handle, algId,
        (BYTE *)ivBytes, (ULONG)ivLen);

    if (ivBytes) (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);

    if (ret != SDR_OK) {
        free(ctx);
        throw_jce_exception(env, (int)ret, "SM4 decrypt init with key handle failed");
        return 0;
    }

    ctx->initialized = 1;
    return (jlong)(uintptr_t)ctx;
}

/*
 * Destroy Key
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL JNI_SDFJceNative_destroyKey(JNIEnv *env, jclass cls,
    jlong sessionHandle, jlong keyHandle)
{
    (void)cls;
    CHECK_INIT(env);
    CHECK_FUNCTION(SDF_DestroyKey, env, "SDF_DestroyKey");

    LONG ret = g_sdf_functions.SDF_DestroyKey(
        (HANDLE)sessionHandle, (HANDLE)(uintptr_t)keyHandle);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "Destroy key failed");
    }
}
