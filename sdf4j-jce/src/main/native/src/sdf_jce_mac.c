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

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    sm4Mac
 * Signature: ([B[B[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_jce_native_1_SDFJceNative_sm4Mac(
    JNIEnv *env, jclass cls, jbyteArray key, jbyteArray iv, jbyteArray data)
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
    jsize dataLen = (*env)->GetArrayLength(env, data);

    HANDLE session = session_pool_acquire();
    if (session == NULL) {
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        if (ivBytes) (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
        throw_jce_exception(env, SDR_OPENSESSION, "Failed to acquire session");
        return NULL;
    }

    BYTE mac[SM4_BLOCK_SIZE];
    ULONG macLen = SM4_BLOCK_SIZE;
    LONG ret;

    /* 使用外部密钥HMAC初始化（如果支持） */
    if (g_sdf_functions.SDF_ExternalKeyHMACInit != NULL) {
        BYTE ivCopy[SM4_IV_LENGTH] = {0};
        if (ivBytes) {
            memcpy(ivCopy, ivBytes, SM4_IV_LENGTH);
        }

        ret = g_sdf_functions.SDF_ExternalKeyHMACInit(
            session, SGD_SM4_MAC, (BYTE *)keyBytes, SM4_KEY_LENGTH);

        if (ret == SDR_OK && g_sdf_functions.SDF_HMACUpdate != NULL) {
            ret = g_sdf_functions.SDF_HMACUpdate(session, (BYTE *)dataBytes, (ULONG)dataLen);
        }

        if (ret == SDR_OK && g_sdf_functions.SDF_HMACFinal != NULL) {
            ret = g_sdf_functions.SDF_HMACFinal(session, mac, &macLen);
        }
    } else {
        /* 备选：使用CalculateMAC（需要密钥句柄） */
        ret = SDR_NOTSUPPORT;
    }

    session_pool_release(session);
    (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
    if (ivBytes) (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "SM4 MAC failed");
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, (jsize)macLen);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)macLen, (jbyte *)mac);
    }
    return result;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    hmacSm3
 * Signature: ([B[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_jce_native_1_SDFJceNative_hmacSm3(
    JNIEnv *env, jclass cls, jbyteArray key, jbyteArray data)
{
    (void)cls;

    CHECK_INITIALIZED_RET(env, NULL);

    if (key == NULL || data == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "key or data is null");
        return NULL;
    }

    jbyte *keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
    jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
    jsize keyLen = (*env)->GetArrayLength(env, key);
    jsize dataLen = (*env)->GetArrayLength(env, data);

    HANDLE session = session_pool_acquire();
    if (session == NULL) {
        (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
        throw_jce_exception(env, SDR_OPENSESSION, "Failed to acquire session");
        return NULL;
    }

    BYTE hmac[SM3_DIGEST_LENGTH];
    ULONG hmacLen = SM3_DIGEST_LENGTH;
    LONG ret;

    /* 使用外部密钥HMAC */
    if (g_sdf_functions.SDF_ExternalKeyHMACInit != NULL &&
        g_sdf_functions.SDF_HMACUpdate != NULL &&
        g_sdf_functions.SDF_HMACFinal != NULL) {

        ret = g_sdf_functions.SDF_ExternalKeyHMACInit(
            session, SGD_SM3, (BYTE *)keyBytes, (ULONG)keyLen);

        if (ret == SDR_OK) {
            ret = g_sdf_functions.SDF_HMACUpdate(session, (BYTE *)dataBytes, (ULONG)dataLen);
        }

        if (ret == SDR_OK) {
            ret = g_sdf_functions.SDF_HMACFinal(session, hmac, &hmacLen);
        }
    } else {
        ret = SDR_NOTSUPPORT;
    }

    session_pool_release(session);
    (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "HMAC-SM3 failed");
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, (jsize)hmacLen);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)hmacLen, (jbyte *)hmac);
    }
    return result;
}
