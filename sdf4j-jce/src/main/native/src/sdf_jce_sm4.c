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
#include "dynamic_loader.h"
#include "sdf_log.h"

/* SM4上下文 */
typedef struct {
    HANDLE session;
    int mode;
    int encrypt;
    BYTE iv[SM4_IV_LENGTH];
    int initialized;
} SM4Context;

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm4Encrypt
 * Signature: (I[B[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_jce_native_1_SDFJceNative_sm4Encrypt(
    JNIEnv *env, jclass cls, jint mode, jbyteArray key, jbyteArray iv,
    jbyteArray data, jbyteArray aad)
{
    (void)cls;

    CHECK_INITIALIZED_RET(env, NULL);

    if (key == NULL || data == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "key or data is null");
        return NULL;
    }

    jsize keyLen = (*env)->GetArrayLength(env, key);
    if (keyLen != SM4_KEY_LENGTH) {
        throw_exception(env, "java/lang/IllegalArgumentException", "Key must be 16 bytes");
        return NULL;
    }

    jbyte *keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
    jbyte *ivBytes = iv ? (*env)->GetByteArrayElements(env, iv, NULL) : NULL;
    jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
    jbyte *aadBytes = aad ? (*env)->GetByteArrayElements(env, aad, NULL) : NULL;

    jsize dataLen = (*env)->GetArrayLength(env, data);
    (void)aadBytes; /* Reserved for future AEAD support */

    if (keyBytes == NULL || dataBytes == NULL) {
        if (keyBytes) (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        if (ivBytes) (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
        if (dataBytes) (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
        if (aadBytes) (*env)->ReleaseByteArrayElements(env, aad, aadBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get byte arrays");
        return NULL;
    }

    HANDLE session = session_pool_acquire();
    if (session == NULL) {
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        if (ivBytes) (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
        if (aadBytes) (*env)->ReleaseByteArrayElements(env, aad, aadBytes, JNI_ABORT);
        throw_jce_exception(env, SDR_OPENSESSION, "Failed to acquire session");
        return NULL;
    }

    ULONG algId = sm4_mode_to_alg_id(mode);
    BYTE *output = (BYTE *)malloc((size_t)(dataLen + SM4_BLOCK_SIZE + SM4_GCM_TAG_LENGTH));
    ULONG outputLen = 0;
    LONG ret;

    if (mode == SM4_MODE_GCM || mode == SM4_MODE_CCM) {
        /* AEAD模式 */
        if (g_sdf_functions.SDF_AuthEnc == NULL) {
            free(output);
            session_pool_release(session);
            (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
            if (ivBytes) (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
            (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
            if (aadBytes) (*env)->ReleaseByteArrayElements(env, aad, aadBytes, JNI_ABORT);
            throw_jce_exception(env, SDR_NOTSUPPORT, "AEAD not supported");
            return NULL;
        }

        /* 使用外部密钥加密不直接支持AEAD，需要先导入密钥 */
        /* 这里简化实现，使用 SDF_ExternalKeyEncrypt（如果支持） */
        throw_jce_exception(env, SDR_NOTSUPPORT, "AEAD with external key not implemented yet");
        free(output);
        session_pool_release(session);
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        if (ivBytes) (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
        if (aadBytes) (*env)->ReleaseByteArrayElements(env, aad, aadBytes, JNI_ABORT);
        return NULL;
    } else {
        /* 常规模式 */
        CHECK_FUNCTION_RET(SDF_ExternalKeyEncrypt, env, "SDF_ExternalKeyEncrypt", NULL);

        BYTE ivCopy[SM4_IV_LENGTH] = {0};
        if (ivBytes && mode != SM4_MODE_ECB) {
            memcpy(ivCopy, ivBytes, SM4_IV_LENGTH);
        }

        ret = g_sdf_functions.SDF_ExternalKeyEncrypt(
            session, algId,
            (BYTE *)keyBytes, SM4_KEY_LENGTH,
            ivCopy, SM4_IV_LENGTH,
            (BYTE *)dataBytes, (ULONG)dataLen,
            output, &outputLen);
    }

    session_pool_release(session);
    (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
    if (ivBytes) (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
    if (aadBytes) (*env)->ReleaseByteArrayElements(env, aad, aadBytes, JNI_ABORT);

    if (ret != SDR_OK) {
        free(output);
        throw_jce_exception(env, (int)ret, "SM4 encrypt failed");
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, (jsize)outputLen);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)outputLen, (jbyte *)output);
    }
    free(output);

    return result;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm4Decrypt
 * Signature: (I[B[B[B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_jce_native_1_SDFJceNative_sm4Decrypt(
    JNIEnv *env, jclass cls, jint mode, jbyteArray key, jbyteArray iv,
    jbyteArray ciphertext, jbyteArray aad, jbyteArray tag)
{
    (void)cls;
    (void)aad;
    (void)tag;

    CHECK_INITIALIZED_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_ExternalKeyDecrypt, env, "SDF_ExternalKeyDecrypt", NULL);

    if (key == NULL || ciphertext == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "key or ciphertext is null");
        return NULL;
    }

    jsize keyLen = (*env)->GetArrayLength(env, key);
    if (keyLen != SM4_KEY_LENGTH) {
        throw_exception(env, "java/lang/IllegalArgumentException", "Key must be 16 bytes");
        return NULL;
    }

    jbyte *keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
    jbyte *ivBytes = iv ? (*env)->GetByteArrayElements(env, iv, NULL) : NULL;
    jbyte *cipherBytes = (*env)->GetByteArrayElements(env, ciphertext, NULL);
    jsize cipherLen = (*env)->GetArrayLength(env, ciphertext);

    HANDLE session = session_pool_acquire();
    if (session == NULL) {
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        if (ivBytes) (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, ciphertext, cipherBytes, JNI_ABORT);
        throw_jce_exception(env, SDR_OPENSESSION, "Failed to acquire session");
        return NULL;
    }

    ULONG algId = sm4_mode_to_alg_id(mode);
    BYTE *output = (BYTE *)malloc((size_t)cipherLen);
    ULONG outputLen = 0;

    BYTE ivCopy[SM4_IV_LENGTH] = {0};
    if (ivBytes && mode != SM4_MODE_ECB) {
        memcpy(ivCopy, ivBytes, SM4_IV_LENGTH);
    }

    LONG ret = g_sdf_functions.SDF_ExternalKeyDecrypt(
        session, algId,
        (BYTE *)keyBytes, SM4_KEY_LENGTH,
        ivCopy, SM4_IV_LENGTH,
        (BYTE *)cipherBytes, (ULONG)cipherLen,
        output, &outputLen);

    session_pool_release(session);
    (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
    if (ivBytes) (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, ciphertext, cipherBytes, JNI_ABORT);

    if (ret != SDR_OK) {
        free(output);
        throw_jce_exception(env, (int)ret, "SM4 decrypt failed");
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, (jsize)outputLen);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)outputLen, (jbyte *)output);
    }
    free(output);

    return result;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm4EncryptInit
 * Signature: (I[B[B)J
 */
JNIEXPORT jlong JNICALL
Java_org_openhitls_sdf4j_jce_native_1_SDFJceNative_sm4EncryptInit(
    JNIEnv *env, jclass cls, jint mode, jbyteArray key, jbyteArray iv)
{
    (void)cls;

    CHECK_INITIALIZED_RET(env, 0);
    CHECK_FUNCTION_RET(SDF_ExternalKeyEncryptInit, env, "SDF_ExternalKeyEncryptInit", 0);

    if (key == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "key is null");
        return 0;
    }

    SM4Context *ctx = (SM4Context *)malloc(sizeof(SM4Context));
    if (ctx == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to allocate context");
        return 0;
    }
    memset(ctx, 0, sizeof(SM4Context));

    ctx->session = session_pool_acquire();
    if (ctx->session == NULL) {
        free(ctx);
        throw_jce_exception(env, SDR_OPENSESSION, "Failed to acquire session");
        return 0;
    }

    jbyte *keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
    jbyte *ivBytes = iv ? (*env)->GetByteArrayElements(env, iv, NULL) : NULL;

    ctx->mode = mode;
    ctx->encrypt = 1;
    if (ivBytes) {
        memcpy(ctx->iv, ivBytes, SM4_IV_LENGTH);
    }

    ULONG algId = sm4_mode_to_alg_id(mode);

    LONG ret = g_sdf_functions.SDF_ExternalKeyEncryptInit(
        ctx->session, algId,
        (BYTE *)keyBytes, SM4_KEY_LENGTH,
        ctx->iv, SM4_IV_LENGTH);

    (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
    if (ivBytes) (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);

    if (ret != SDR_OK) {
        session_pool_release(ctx->session);
        free(ctx);
        throw_jce_exception(env, (int)ret, "SM4 encrypt init failed");
        return 0;
    }

    ctx->initialized = 1;
    return (jlong)(uintptr_t)ctx;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm4EncryptUpdate
 * Signature: (J[BII)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_jce_native_1_SDFJceNative_sm4EncryptUpdate(
    JNIEnv *env, jclass cls, jlong ctxHandle, jbyteArray data, jint offset, jint len)
{
    (void)cls;

    CHECK_INITIALIZED_RET(env, NULL);
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
    BYTE *output = (BYTE *)malloc((size_t)(len + SM4_BLOCK_SIZE));
    ULONG outputLen = 0;

    LONG ret = g_sdf_functions.SDF_EncryptUpdate(
        ctx->session,
        (BYTE *)(dataBytes + offset), (ULONG)len,
        output, &outputLen);

    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);

    if (ret != SDR_OK) {
        free(output);
        throw_jce_exception(env, (int)ret, "SM4 encrypt update failed");
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, (jsize)outputLen);
    if (result != NULL && outputLen > 0) {
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)outputLen, (jbyte *)output);
    }
    free(output);

    return result;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm4EncryptFinal
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_jce_native_1_SDFJceNative_sm4EncryptFinal(
    JNIEnv *env, jclass cls, jlong ctxHandle)
{
    (void)cls;

    CHECK_INITIALIZED_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_EncryptFinal, env, "SDF_EncryptFinal", NULL);

    SM4Context *ctx = (SM4Context *)(uintptr_t)ctxHandle;
    if (ctx == NULL || !ctx->initialized) {
        throw_exception(env, "java/lang/IllegalStateException", "Context not initialized");
        return NULL;
    }

    BYTE output[SM4_BLOCK_SIZE * 2];
    ULONG outputLen = 0;

    LONG ret = g_sdf_functions.SDF_EncryptFinal(ctx->session, output, &outputLen);

    session_pool_release(ctx->session);
    ctx->initialized = 0;
    free(ctx);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 encrypt final failed");
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, (jsize)outputLen);
    if (result != NULL && outputLen > 0) {
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)outputLen, (jbyte *)output);
    }
    return result;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm4DecryptInit
 * Signature: (I[B[B)J
 */
JNIEXPORT jlong JNICALL
Java_org_openhitls_sdf4j_jce_native_1_SDFJceNative_sm4DecryptInit(
    JNIEnv *env, jclass cls, jint mode, jbyteArray key, jbyteArray iv)
{
    (void)cls;

    CHECK_INITIALIZED_RET(env, 0);
    CHECK_FUNCTION_RET(SDF_ExternalKeyDecryptInit, env, "SDF_ExternalKeyDecryptInit", 0);

    if (key == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "key is null");
        return 0;
    }

    SM4Context *ctx = (SM4Context *)malloc(sizeof(SM4Context));
    if (ctx == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to allocate context");
        return 0;
    }
    memset(ctx, 0, sizeof(SM4Context));

    ctx->session = session_pool_acquire();
    if (ctx->session == NULL) {
        free(ctx);
        throw_jce_exception(env, SDR_OPENSESSION, "Failed to acquire session");
        return 0;
    }

    jbyte *keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
    jbyte *ivBytes = iv ? (*env)->GetByteArrayElements(env, iv, NULL) : NULL;

    ctx->mode = mode;
    ctx->encrypt = 0;
    if (ivBytes) {
        memcpy(ctx->iv, ivBytes, SM4_IV_LENGTH);
    }

    ULONG algId = sm4_mode_to_alg_id(mode);

    LONG ret = g_sdf_functions.SDF_ExternalKeyDecryptInit(
        ctx->session, algId,
        (BYTE *)keyBytes, SM4_KEY_LENGTH,
        ctx->iv, SM4_IV_LENGTH);

    (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
    if (ivBytes) (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);

    if (ret != SDR_OK) {
        session_pool_release(ctx->session);
        free(ctx);
        throw_jce_exception(env, (int)ret, "SM4 decrypt init failed");
        return 0;
    }

    ctx->initialized = 1;
    return (jlong)(uintptr_t)ctx;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm4DecryptUpdate
 * Signature: (J[BII)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_jce_native_1_SDFJceNative_sm4DecryptUpdate(
    JNIEnv *env, jclass cls, jlong ctxHandle, jbyteArray data, jint offset, jint len)
{
    (void)cls;

    CHECK_INITIALIZED_RET(env, NULL);
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
    BYTE *output = (BYTE *)malloc((size_t)(len + SM4_BLOCK_SIZE));
    ULONG outputLen = 0;

    LONG ret = g_sdf_functions.SDF_DecryptUpdate(
        ctx->session,
        (BYTE *)(dataBytes + offset), (ULONG)len,
        output, &outputLen);

    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);

    if (ret != SDR_OK) {
        free(output);
        throw_jce_exception(env, (int)ret, "SM4 decrypt update failed");
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, (jsize)outputLen);
    if (result != NULL && outputLen > 0) {
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)outputLen, (jbyte *)output);
    }
    free(output);

    return result;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm4DecryptFinal
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_jce_native_1_SDFJceNative_sm4DecryptFinal(
    JNIEnv *env, jclass cls, jlong ctxHandle)
{
    (void)cls;

    CHECK_INITIALIZED_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_DecryptFinal, env, "SDF_DecryptFinal", NULL);

    SM4Context *ctx = (SM4Context *)(uintptr_t)ctxHandle;
    if (ctx == NULL || !ctx->initialized) {
        throw_exception(env, "java/lang/IllegalStateException", "Context not initialized");
        return NULL;
    }

    BYTE output[SM4_BLOCK_SIZE * 2];
    ULONG outputLen = 0;

    LONG ret = g_sdf_functions.SDF_DecryptFinal(ctx->session, output, &outputLen);

    session_pool_release(ctx->session);
    ctx->initialized = 0;
    free(ctx);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 decrypt final failed");
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, (jsize)outputLen);
    if (result != NULL && outputLen > 0) {
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)outputLen, (jbyte *)output);
    }
    return result;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm4Free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_jce_native_1_SDFJceNative_sm4Free(
    JNIEnv *env, jclass cls, jlong ctxHandle)
{
    (void)env;
    (void)cls;

    SM4Context *ctx = (SM4Context *)(uintptr_t)ctxHandle;
    if (ctx == NULL) {
        return;
    }

    if (ctx->initialized && ctx->session != NULL) {
        session_pool_release(ctx->session);
    }
    memset(ctx, 0, sizeof(SM4Context));
    free(ctx);
}
