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
 * Method:    sm3Digest
 * Signature: ([B)[B
 */
JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm3Digest(JNIEnv *env, jclass cls, jlong sessionHandle, jbyteArray data)
{
    (void)cls;
    CHECK_INIT_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_HashInit, env, "SDF_HashInit", NULL);
    CHECK_FUNCTION_RET(SDF_HashUpdate, env, "SDF_HashUpdate", NULL);
    CHECK_FUNCTION_RET(SDF_HashFinal, env, "SDF_HashFinal", NULL);

    if (data == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "data is null");
        return NULL;
    }

    jsize dataLen = (*env)->GetArrayLength(env, data);
    jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (dataBytes == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get byte array");
        return NULL;
    }

    BYTE hash[SM3_DIGEST_LENGTH];
    ULONG hashLen = SM3_DIGEST_LENGTH;
    jbyteArray result = NULL;
    LONG ret = g_sdf_functions.SDF_HashInit((HANDLE)sessionHandle, SGD_SM3, NULL, NULL, 0);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM3 digest init failed");
        goto ERR;
    }

    ret = g_sdf_functions.SDF_HashUpdate((HANDLE)sessionHandle, (BYTE *)dataBytes, (ULONG)dataLen);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM3 digest update failed");
        goto ERR;
    }

    ret = g_sdf_functions.SDF_HashFinal((HANDLE)sessionHandle, hash, &hashLen);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM3 digest final failed");
        goto ERR;
    }

    result = (*env)->NewByteArray(env, (jsize)hashLen);
    if (result == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to create byte array");
        goto ERR;
    }
    (*env)->SetByteArrayRegion(env, result, 0, (jsize)hashLen, (jbyte *)hash);
ERR:
    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
    return result;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm3Init
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL JNI_SDFJceNative_sm3Init(JNIEnv *env, jclass cls, jlong sessionHandle)
{
    (void)cls;
    CHECK_INIT_RET(env, 0);
    CHECK_FUNCTION_RET(SDF_HashInit, env, "SDF_HashInit", 0);

    SM3Context *ctx = (SM3Context *)malloc(sizeof(SM3Context));
    if (ctx == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to allocate context");
        return 0;
    }
    memset(ctx, 0, sizeof(SM3Context));

    ctx->session_handle = (HANDLE)sessionHandle;
    LONG ret = g_sdf_functions.SDF_HashInit(ctx->session_handle, SGD_SM3, NULL, NULL, 0);
    if (ret != SDR_OK) {
        free(ctx);
        throw_jce_exception(env, (int)ret, "SM3 init failed");
        return 0;
    }

    ctx->initialized = 1;
    return (jlong)(uintptr_t)ctx;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm3Update
 * Signature: (J[BII)V
 */
JNIEXPORT void JNICALL JNI_SDFJceNative_sm3Update(JNIEnv *env, jclass cls, jlong ctxHandle, jbyteArray data,
    jint offset, jint len)
{
    (void)cls;

    CHECK_INIT(env);
    CHECK_FUNCTION(SDF_HashUpdate, env, "SDF_HashUpdate");

    SM3Context *ctx = (SM3Context *)(uintptr_t)ctxHandle;
    if (ctx == NULL || !ctx->initialized) {
        throw_exception(env, "java/lang/IllegalStateException", "Context not initialized");
        return;
    }

    jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (dataBytes == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get byte array");
        return;
    }

    LONG ret = g_sdf_functions.SDF_HashUpdate(ctx->session_handle,
                                               (BYTE *)(dataBytes + offset),
                                               (ULONG)len);

    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM3 update failed");
    }
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm3Final
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm3Final(JNIEnv *env, jclass cls, jlong ctxHandle)
{
    (void)cls;
    CHECK_INIT_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_HashFinal, env, "SDF_HashFinal", NULL);

    SM3Context *ctx = (SM3Context *)(uintptr_t)ctxHandle;
    if (ctx == NULL || !ctx->initialized) {
        throw_exception(env, "java/lang/IllegalStateException", "Context not initialized");
        return NULL;
    }

    BYTE hash[SM3_DIGEST_LENGTH];
    ULONG hashLen = SM3_DIGEST_LENGTH;

    LONG ret = g_sdf_functions.SDF_HashFinal(ctx->session_handle, hash, &hashLen);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM3 final failed");
        return NULL;
    }

    ctx->initialized = 0;
    jbyteArray result = (*env)->NewByteArray(env, (jsize)hashLen);
    if (result == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to create byte array");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, result, 0, (jsize)hashLen, (jbyte *)hash);
    return result;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm3Free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL JNI_SDFJceNative_sm3Free(JNIEnv *env, jclass cls, jlong ctxHandle)
{
    (void)env;
    (void)cls;

    SM3Context *ctx = (SM3Context *)(uintptr_t)ctxHandle;
    if (ctx == NULL) {
        return;
    }

    free(ctx);
}
