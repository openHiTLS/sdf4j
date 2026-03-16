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
 * Method:    sm4Mac
 * Signature: ([B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm4Mac(JNIEnv *env, jclass cls, jlong sessionHandle, jbyteArray key, jbyteArray iv,
    jbyteArray data)
{
    (void)cls;
    CHECK_INIT_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_ImportKey, env, "SDF_ImportKey", NULL);
    CHECK_FUNCTION_RET(SDF_CalculateMAC, env, "SDF_CalculateMAC", NULL);
    CHECK_FUNCTION_RET(SDF_DestroyKey, env, "SDF_DestroyKey", NULL);

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
    if (keyBytes == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get key bytes");
        return NULL;
    }

    jbyte *ivBytes = NULL;
    if (iv != NULL) {
        ivBytes = (*env)->GetByteArrayElements(env, iv, NULL);
        if (ivBytes == NULL) {
            (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
            throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get iv bytes");
            return NULL;
        }
    }

    jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (dataBytes == NULL) {
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        if (ivBytes) (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get data bytes");
        return NULL;
    }
    jsize dataLen = (*env)->GetArrayLength(env, data);

    BYTE mac[SM4_BLOCK_SIZE];
    ULONG macLen = SM4_BLOCK_SIZE;
    HANDLE keyHandle = 0;
    jbyteArray result = NULL;

    /* 导入密钥 */
    LONG ret = g_sdf_functions.SDF_ImportKey((HANDLE)sessionHandle, (BYTE *)keyBytes, SM4_KEY_LENGTH, &keyHandle);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 import key failed");
        goto ERR;
    }

    /* 计算MAC */
    ret = g_sdf_functions.SDF_CalculateMAC((HANDLE)sessionHandle, keyHandle, SGD_SM4_MAC,
        (BYTE *)ivBytes, (BYTE *)dataBytes, (ULONG)dataLen, mac, &macLen);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 MAC calculation failed");
        goto ERR;
    }

    result = (*env)->NewByteArray(env, (jsize)macLen);
    if (result == NULL && macLen > 0) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to create byte array");
        goto ERR;
    }
    if (result != NULL && macLen > 0) {
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)macLen, (jbyte *)mac);
    }

ERR:
    if (keyHandle != 0) {
        g_sdf_functions.SDF_DestroyKey((HANDLE)sessionHandle, keyHandle);
    }
    (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
    if (ivBytes) (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
    return result;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    hmacSm3
 * Signature: ([B[B)[B
 */
JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_hmacSm3(JNIEnv *env, jclass cls, jlong sessionHandle, jbyteArray key, jbyteArray data)
{
    (void)cls;
    CHECK_INIT_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_ImportKey, env, "SDF_ImportKey", NULL);
    CHECK_FUNCTION_RET(SDF_HMACInit, env, "SDF_HMACInit", NULL);
    CHECK_FUNCTION_RET(SDF_HMACUpdate, env, "SDF_HMACUpdate", NULL);
    CHECK_FUNCTION_RET(SDF_HMACFinal, env, "SDF_HMACFinal", NULL);
    CHECK_FUNCTION_RET(SDF_DestroyKey, env, "SDF_DestroyKey", NULL);

    if (key == NULL || data == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "key or data is null");
        return NULL;
    }

    jbyte *keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
    if (keyBytes == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get key bytes");
        return NULL;
    }

    jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (dataBytes == NULL) {
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get data bytes");
        return NULL;
    }
    jsize keyLen = (*env)->GetArrayLength(env, key);
    jsize dataLen = (*env)->GetArrayLength(env, data);

    BYTE hmac[SM3_DIGEST_LENGTH];
    ULONG hmacLen = SM3_DIGEST_LENGTH;
    HANDLE keyHandle = 0;
    jbyteArray result = NULL;

    /* 导入密钥 */
    LONG ret = g_sdf_functions.SDF_ImportKey((HANDLE)sessionHandle, (BYTE *)keyBytes, (ULONG)keyLen, &keyHandle);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "HMAC-SM3 import key failed");
        goto ERR;
    }

    /* HMAC Init */
    ret = g_sdf_functions.SDF_HMACInit((HANDLE)sessionHandle, keyHandle, SGD_SM3);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "HMAC-SM3 init failed");
        goto ERR;
    }

    ret = g_sdf_functions.SDF_HMACUpdate((HANDLE)sessionHandle, (BYTE *)dataBytes, (ULONG)dataLen);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "HMAC-SM3 update failed");
        goto ERR;
    }

    ret = g_sdf_functions.SDF_HMACFinal((HANDLE)sessionHandle, hmac, &hmacLen);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "HMAC-SM3 final failed");
        goto ERR;
    }

    result = (*env)->NewByteArray(env, (jsize)hmacLen);
    if (result == NULL && hmacLen > 0) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to create byte array");
        goto ERR;
    }
    if (result != NULL && hmacLen > 0) {
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)hmacLen, (jbyte *)hmac);
    }

ERR:
    if (keyHandle != 0) {
        g_sdf_functions.SDF_DestroyKey((HANDLE)sessionHandle, keyHandle);
    }
    (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
    return result;
}
