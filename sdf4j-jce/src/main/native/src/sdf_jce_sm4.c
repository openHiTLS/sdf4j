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

static ULONG sm4_mode_to_alg_id(int mode) {
    switch (mode) {
        case SM4_MODE_ECB: return SGD_SM4_ECB;
        case SM4_MODE_CBC: return SGD_SM4_CBC;
        case SM4_MODE_GCM: return SGD_SM4_GCM;
        case SM4_MODE_CCM: return SGD_SM4_CCM;
        default: return SGD_SM4_CBC;
    }
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm4AuthEnc
 * Signature: (JI[B[B[B[B)[B
 *
 * Authenticated encryption (GCM/CCM) using SDF_AuthEnc.
 * Returns byte[] = ciphertext || tag
 */
JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm4AuthEnc(JNIEnv *env, jclass cls,
    jlong sessionHandle, jint mode, jbyteArray key, jbyteArray iv, jbyteArray aad, jbyteArray data)
{
    (void)cls;
    jbyteArray result = NULL;
    BYTE *encOutput = NULL;
    BYTE *authOutput = NULL;
    ULONG algId = 0;
    HANDLE keyHandle = 0;
    LONG ret = 0;
    ULONG encOutputLen = 0;
    ULONG authOutputLen = 0;

    CHECK_INIT_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_ImportKey, env, "SDF_ImportKey", NULL);
    CHECK_FUNCTION_RET(SDF_AuthEnc, env, "SDF_AuthEnc", NULL);
    CHECK_FUNCTION_RET(SDF_DestroyKey, env, "SDF_DestroyKey", NULL);

    if (key == NULL || data == NULL || iv == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "key, iv, or data is null");
        return NULL;
    }

    jsize keyLen = (*env)->GetArrayLength(env, key);
    if (keyLen != SM4_KEY_LENGTH) {
        throw_exception(env, "java/lang/IllegalArgumentException", "Key must be 16 bytes");
        return NULL;
    }

    /* Sequential get with individual NULL checks */
    jbyte *keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
    if (keyBytes == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get key bytes");
        return NULL;
    }

    jbyte *ivBytes = (*env)->GetByteArrayElements(env, iv, NULL);
    if (ivBytes == NULL) {
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get iv bytes");
        return NULL;
    }

    jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (dataBytes == NULL) {
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get data bytes");
        return NULL;
    }

    jbyte *aadBytes = NULL;
    jsize aadLen = 0;
    if (aad != NULL) {
        aadLen = (*env)->GetArrayLength(env, aad);
        aadBytes = (*env)->GetByteArrayElements(env, aad, NULL);
        if (aadBytes == NULL) {
            (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
            (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
            (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
            throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get aad bytes");
            return NULL;
        }
    }

    jsize ivLen = (*env)->GetArrayLength(env, iv);
    jsize dataLen = (*env)->GetArrayLength(env, data);

    algId = sm4_mode_to_alg_id(mode);

    ret = g_sdf_functions.SDF_ImportKey((HANDLE)sessionHandle, (BYTE *)keyBytes, SM4_KEY_LENGTH, &keyHandle);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 auth enc import key failed");
        goto ERR;
    }
    /* Allocate output buffers */
    encOutputLen = (ULONG)(dataLen + SM4_BLOCK_SIZE);
    encOutput = (BYTE *)malloc((size_t)encOutputLen);
    authOutputLen = SM4_GCM_TAG_LENGTH;
    authOutput = (BYTE *)malloc((size_t)authOutputLen);
    if (encOutput == NULL || authOutput == NULL) {
        g_sdf_functions.SDF_DestroyKey((HANDLE)sessionHandle, keyHandle);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to allocate output buffers");
        goto ERR;
    }

    ret = g_sdf_functions.SDF_AuthEnc(
        (HANDLE)sessionHandle, keyHandle, algId,
        (BYTE *)ivBytes, (ULONG)ivLen,
        (BYTE *)aadBytes, (ULONG)aadLen,
        (BYTE *)dataBytes, (ULONG)dataLen,
        encOutput, &encOutputLen,
        authOutput, &authOutputLen);

    g_sdf_functions.SDF_DestroyKey((HANDLE)sessionHandle, keyHandle);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 auth encrypt failed");
        goto ERR;
    }

    /* Return ciphertext || tag as single byte[] */
    result = (*env)->NewByteArray(env, (jsize)(encOutputLen + authOutputLen));
    if (result == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to create result array");
        goto ERR;
    }
    (*env)->SetByteArrayRegion(env, result, 0, (jsize)encOutputLen, (jbyte *)encOutput);
    (*env)->SetByteArrayRegion(env, result, (jsize)encOutputLen, (jsize)authOutputLen, (jbyte *)authOutput);

ERR:
    if (encOutput != NULL) free(encOutput);
    if (authOutput != NULL) free(authOutput);
    (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
    if (aadBytes) (*env)->ReleaseByteArrayElements(env, aad, aadBytes, JNI_ABORT);
    return result;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm4AuthDec
 * Signature: (JI[B[B[B[B[B)[B
 *
 * Authenticated decryption (GCM/CCM) using SDF_AuthDec.
 */
JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm4AuthDec(JNIEnv *env, jclass cls,
    jlong sessionHandle, jint mode, jbyteArray key, jbyteArray iv,
    jbyteArray aad, jbyteArray tag, jbyteArray ciphertext)
{
    (void)cls;
    jbyteArray result = NULL;
    BYTE *output = NULL;
    ULONG algId = 0;
    HANDLE keyHandle = 0;
    LONG ret = 0;
    ULONG outputLen = 0;
    ULONG authTagLen = 0;

    CHECK_INIT_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_ImportKey, env, "SDF_ImportKey", NULL);
    CHECK_FUNCTION_RET(SDF_AuthDec, env, "SDF_AuthDec", NULL);
    CHECK_FUNCTION_RET(SDF_DestroyKey, env, "SDF_DestroyKey", NULL);

    if (key == NULL || ciphertext == NULL || iv == NULL || tag == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "key, iv, tag, or ciphertext is null");
        return NULL;
    }

    jsize keyLen = (*env)->GetArrayLength(env, key);
    if (keyLen != SM4_KEY_LENGTH) {
        throw_exception(env, "java/lang/IllegalArgumentException", "Key must be 16 bytes");
        return NULL;
    }

    /* Sequential get with individual NULL checks */
    jbyte *keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
    if (keyBytes == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get key bytes");
        return NULL;
    }

    jbyte *ivBytes = (*env)->GetByteArrayElements(env, iv, NULL);
    if (ivBytes == NULL) {
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get iv bytes");
        return NULL;
    }

    jbyte *cipherBytes = (*env)->GetByteArrayElements(env, ciphertext, NULL);
    if (cipherBytes == NULL) {
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get ciphertext bytes");
        return NULL;
    }

    jbyte *tagBytes = (*env)->GetByteArrayElements(env, tag, NULL);
    if (tagBytes == NULL) {
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, ciphertext, cipherBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get tag bytes");
        return NULL;
    }

    jbyte *aadBytes = NULL;
    jsize aadLen = 0;
    if (aad != NULL) {
        aadLen = (*env)->GetArrayLength(env, aad);
        aadBytes = (*env)->GetByteArrayElements(env, aad, NULL);
        if (aadBytes == NULL) {
            (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
            (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
            (*env)->ReleaseByteArrayElements(env, ciphertext, cipherBytes, JNI_ABORT);
            (*env)->ReleaseByteArrayElements(env, tag, tagBytes, JNI_ABORT);
            throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get aad bytes");
            return NULL;
        }
    }

    jsize ivLen = (*env)->GetArrayLength(env, iv);
    jsize cipherLen = (*env)->GetArrayLength(env, ciphertext);
    jsize tagLen = (*env)->GetArrayLength(env, tag);

    algId = sm4_mode_to_alg_id(mode);

    ret = g_sdf_functions.SDF_ImportKey((HANDLE)sessionHandle, (BYTE *)keyBytes, SM4_KEY_LENGTH, &keyHandle);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 auth dec import key failed");
        goto ERR;
    }

    outputLen = (ULONG)cipherLen;
    output = (BYTE *)malloc((size_t)outputLen);
    if (output == NULL) {
        g_sdf_functions.SDF_DestroyKey((HANDLE)sessionHandle, keyHandle);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to allocate output buffer");
        goto ERR;
    }

    authTagLen = (ULONG)tagLen;
    ret = g_sdf_functions.SDF_AuthDec(
        (HANDLE)sessionHandle, keyHandle, algId,
        (BYTE *)ivBytes, (ULONG)ivLen,
        (BYTE *)aadBytes, (ULONG)aadLen,
        (BYTE *)tagBytes, &authTagLen,
        (BYTE *)cipherBytes, (ULONG)cipherLen,
        output, &outputLen);

    g_sdf_functions.SDF_DestroyKey((HANDLE)sessionHandle, keyHandle);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 auth decrypt failed");
        goto ERR;
    }

    result = (*env)->NewByteArray(env, (jsize)outputLen);
    if (result == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to create byte array");
        goto ERR;
    }
    (*env)->SetByteArrayRegion(env, result, 0, (jsize)outputLen, (jbyte *)output);

ERR:
    if (output != NULL) free(output);
    (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, ciphertext, cipherBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, tag, tagBytes, JNI_ABORT);
    if (aadBytes != NULL) (*env)->ReleaseByteArrayElements(env, aad, aadBytes, JNI_ABORT);
    return result;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm4EncryptInit
 * Signature: (I[B[B)J
 */
JNIEXPORT jlong JNICALL JNI_SDFJceNative_sm4EncryptInit(JNIEnv *env, jclass cls, jlong sessionHandle, jint mode, jbyteArray key,
    jbyteArray iv)
{
    (void)cls;
    ULONG algId = 0;
    HANDLE keyHandle = 0;
    LONG ret = 0;
    CHECK_INIT_RET(env, 0);
    CHECK_FUNCTION_RET(SDF_ImportKey, env, "SDF_ImportKey", 0);
    CHECK_FUNCTION_RET(SDF_EncryptInit, env, "SDF_EncryptInit", 0);
    CHECK_FUNCTION_RET(SDF_DestroyKey, env, "SDF_DestroyKey", 0);

    if (key == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "key is null");
        return 0;
    }

    jbyte *keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
    if (keyBytes == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get key bytes");
        return 0;
    }
    jsize keyLen = (*env)->GetArrayLength(env, key);
    if (keyLen != SM4_KEY_LENGTH) {
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        throw_exception(env, "java/lang/IllegalArgumentException", "Key must be 16 bytes");
        return 0;
    }
    jbyte *ivBytes = NULL;
    jsize ivLen = 0;
    if (iv != NULL) {
        ivLen = (*env)->GetArrayLength(env, iv);
        ivBytes = (*env)->GetByteArrayElements(env, iv, NULL);
        if (ivBytes == NULL) {
            (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
            throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get iv bytes");
            return 0;
        }
    }

    SM4Context *ctx = (SM4Context *)malloc(sizeof(SM4Context));
    if (ctx == NULL) {
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        if (ivBytes) (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to allocate context");
        return 0;
    }
    memset(ctx, 0, sizeof(SM4Context));

    ctx->session_handle = (HANDLE)sessionHandle;

    algId = sm4_mode_to_alg_id(mode);

    ret = g_sdf_functions.SDF_ImportKey(ctx->session_handle, (BYTE *)keyBytes, SM4_KEY_LENGTH, &keyHandle);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 import key failed");
        goto ERR;
    }
    ctx->key_handle = keyHandle;

    ret = g_sdf_functions.SDF_EncryptInit(ctx->session_handle, keyHandle, algId, (BYTE *)ivBytes, (ULONG)ivLen);
    if (ret != SDR_OK) {
        g_sdf_functions.SDF_DestroyKey(ctx->session_handle, keyHandle);
        throw_jce_exception(env, (int)ret, "SM4 encrypt init failed");
        goto ERR;
    }

    (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
    if (ivBytes) (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);

    ctx->initialized = 1;
    return (jlong)(uintptr_t)ctx;
ERR:
    (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
    if (ivBytes) (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
    free(ctx);
    return 0;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm4EncryptUpdate
 * Signature: (J[BII)[B
 */
JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm4EncryptUpdate(JNIEnv *env, jclass cls, jlong ctxHandle,
    jbyteArray data, jint offset, jint len)
{
    (void)cls;
    CHECK_INIT_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_EncryptUpdate, env, "SDF_EncryptUpdate", NULL);

    SM4Context *ctx = (SM4Context *)(uintptr_t)ctxHandle;
    if (ctx == NULL || !ctx->initialized) {
        throw_exception(env, "java/lang/IllegalStateException", "Context not initialized");
        return NULL;
    }

    if (data == NULL || len <= 0) {
        return (*env)->NewByteArray(env, 0);
    }

    jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (dataBytes == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get data bytes");
        return NULL;
    }
    ULONG outputBufLen = (ULONG)(len + SM4_BLOCK_SIZE);
    BYTE *output = (BYTE *)malloc((size_t)outputBufLen);
    if (output == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to allocate output buffer");
        return NULL;
    }
    ULONG outputLen = outputBufLen;
    jbyteArray result = NULL;

    LONG ret = g_sdf_functions.SDF_EncryptUpdate(ctx->session_handle, (BYTE *)(dataBytes + offset), (ULONG)len,
        output, &outputLen);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 encrypt update failed");
        goto ERR;
    }

    result = (*env)->NewByteArray(env, (jsize)outputLen);
    if (result == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to create byte array");
        goto ERR;
    }
    (*env)->SetByteArrayRegion(env, result, 0, (jsize)outputLen, (jbyte *)output);

ERR:
    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
    free(output);
    return result;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm4EncryptFinal
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm4EncryptFinal(JNIEnv *env, jclass cls, jlong ctxHandle)
{
    (void)cls;
    CHECK_INIT_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_EncryptFinal, env, "SDF_EncryptFinal", NULL);

    SM4Context *ctx = (SM4Context *)(uintptr_t)ctxHandle;
    if (ctx == NULL || !ctx->initialized) {
        throw_exception(env, "java/lang/IllegalStateException", "Context not initialized");
        return NULL;
    }

    BYTE output[SM4_BLOCK_SIZE * 2];
    ULONG outputLen = sizeof(output);  /* 设置输出缓冲区大小 */

    LONG ret = g_sdf_functions.SDF_EncryptFinal(ctx->session_handle, output, &outputLen);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 encrypt final failed");
        return NULL;
    }

    ctx->initialized = 0;
    jbyteArray result = (*env)->NewByteArray(env, (jsize)outputLen);
    if (result == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to create byte array");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, result, 0, (jsize)outputLen, (jbyte *)output);
    return result;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm4DecryptInit
 * Signature: (I[B[B)J
 */
JNIEXPORT jlong JNICALL JNI_SDFJceNative_sm4DecryptInit(JNIEnv *env, jclass cls, jlong sessionHandle, jint mode, jbyteArray key,
    jbyteArray iv)
{
    (void)cls;
    ULONG algId = 0;
    HANDLE keyHandle = 0;
    LONG ret = 0;
    CHECK_INIT_RET(env, 0);
    CHECK_FUNCTION_RET(SDF_ImportKey, env, "SDF_ImportKey", 0);
    CHECK_FUNCTION_RET(SDF_DecryptInit, env, "SDF_DecryptInit", 0);
    CHECK_FUNCTION_RET(SDF_DestroyKey, env, "SDF_DestroyKey", 0);

    if (key == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "key is null");
        return 0;
    }

    jbyte *keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
    if (keyBytes == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get key bytes");
        return 0;
    }

    jbyte *ivBytes = NULL;
    jsize ivLen = 0;
    if (iv != NULL) {
        ivLen = (*env)->GetArrayLength(env, iv);
        ivBytes = (*env)->GetByteArrayElements(env, iv, NULL);
        if (ivBytes == NULL) {
            (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
            throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get iv bytes");
            return 0;
        }
    }

    SM4Context *ctx = (SM4Context *)malloc(sizeof(SM4Context));
    if (ctx == NULL) {
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        if (ivBytes) (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to allocate context");
        return 0;
    }
    memset(ctx, 0, sizeof(SM4Context));

    ctx->session_handle = (HANDLE)sessionHandle;

    algId = sm4_mode_to_alg_id(mode);

    ret = g_sdf_functions.SDF_ImportKey(ctx->session_handle, (BYTE *)keyBytes, SM4_KEY_LENGTH, &keyHandle);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 import key failed");
        goto ERR;
    }
    ctx->key_handle = keyHandle;

    ret = g_sdf_functions.SDF_DecryptInit(ctx->session_handle, keyHandle, algId, (BYTE *)ivBytes, (ULONG)ivLen);
    if (ret != SDR_OK) {
        g_sdf_functions.SDF_DestroyKey(ctx->session_handle, keyHandle);
        throw_jce_exception(env, (int)ret, "SM4 decrypt init failed");
        goto ERR;
    }

    (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
    if (ivBytes) (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);

    ctx->initialized = 1;
    return (jlong)(uintptr_t)ctx;

ERR:
    (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
    if (ivBytes) (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
    free(ctx);
    return 0;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm4DecryptUpdate
 * Signature: (J[BII)[B
 */
JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm4DecryptUpdate(JNIEnv *env, jclass cls, jlong ctxHandle,
    jbyteArray data, jint offset, jint len)
{
    (void)cls;
    CHECK_INIT_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_DecryptUpdate, env, "SDF_DecryptUpdate", NULL);

    SM4Context *ctx = (SM4Context *)(uintptr_t)ctxHandle;
    if (ctx == NULL || !ctx->initialized) {
        throw_exception(env, "java/lang/IllegalStateException", "Context not initialized");
        return NULL;
    }

    if (data == NULL || len <= 0) {
        return (*env)->NewByteArray(env, 0);
    }

    jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (dataBytes == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get data bytes");
        return NULL;
    }
    ULONG outputBufLen = (ULONG)(len + SM4_BLOCK_SIZE);
    BYTE *output = (BYTE *)malloc((size_t)outputBufLen);
    if (output == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to allocate output buffer");
        return NULL;
    }
    ULONG outputLen = outputBufLen;  /* 设置输出缓冲区大小 */
    jbyteArray result = NULL;

    LONG ret = g_sdf_functions.SDF_DecryptUpdate(
        ctx->session_handle,
        (BYTE *)(dataBytes + offset), (ULONG)len,
        output, &outputLen);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 decrypt update failed");
        goto ERR;
    }

    result = (*env)->NewByteArray(env, (jsize)outputLen);
    if (result == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to create byte array");
        goto ERR;
    }
    (*env)->SetByteArrayRegion(env, result, 0, (jsize)outputLen, (jbyte *)output);
ERR:
    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
    free(output);
    return result;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm4DecryptFinal
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm4DecryptFinal(JNIEnv *env, jclass cls, jlong ctxHandle)
{
    (void)cls;
    CHECK_INIT_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_DecryptFinal, env, "SDF_DecryptFinal", NULL);

    SM4Context *ctx = (SM4Context *)(uintptr_t)ctxHandle;
    if (ctx == NULL || !ctx->initialized) {
        throw_exception(env, "java/lang/IllegalStateException", "Context not initialized");
        return NULL;
    }

    BYTE output[SM4_BLOCK_SIZE * 2];
    ULONG outputLen = sizeof(output);  /* 设置输出缓冲区大小 */

    LONG ret = g_sdf_functions.SDF_DecryptFinal(ctx->session_handle, output, &outputLen);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 decrypt final failed");
        return NULL;
    }

    ctx->initialized = 0;
    jbyteArray result = (*env)->NewByteArray(env, (jsize)outputLen);
    if (result == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to create byte array");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, result, 0, (jsize)outputLen, (jbyte *)output);
    return result;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm4Free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL JNI_SDFJceNative_sm4Free(JNIEnv *env, jclass cls, jlong ctxHandle)
{
    (void)env;
    (void)cls;

    SM4Context *ctx = (SM4Context *)(uintptr_t)ctxHandle;
    if (ctx == NULL) {
        return;
    }

    /* Destroy the cached key handle */
    if (ctx->key_handle != 0 && g_sdf_functions.SDF_DestroyKey != NULL) {
        g_sdf_functions.SDF_DestroyKey(ctx->session_handle, ctx->key_handle);
    }

    memset(ctx, 0, sizeof(SM4Context));
    free(ctx);
}
