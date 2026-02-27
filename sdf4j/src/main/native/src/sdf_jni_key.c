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

#include "sdf_jni_common.h"

/* ========================================================================
 * 密钥管理函数 JNI 实现
 * ======================================================================== */

JNIEXPORT jobject JNICALL JNI_SDF_ExportSignPublicKey_RSA(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint keyIndex) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_ExportSignPublicKey_RSA == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return NULL;
    }

    RSArefPublicKey publicKey;
    memset(&publicKey, 0, sizeof(publicKey));

    LONG ret = g_sdf_functions.SDF_ExportSignPublicKey_RSA((HANDLE)sessionHandle,
                                                           keyIndex, &publicKey);

    if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to handle key operation");
        return NULL;
    }
    return native_to_java_RSAPublicKey(env, &publicKey);
}

JNIEXPORT jobject JNICALL JNI_SDF_ExportEncPublicKey_RSA(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_ExportEncPublicKey_RSA == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return NULL;
    }

    RSArefPublicKey publicKey = {0};
    LONG ret = g_sdf_functions.SDF_ExportEncPublicKey_RSA((HANDLE)sessionHandle,
                                                          keyIndex, &publicKey);

    
    if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to handle key operation");
        return NULL;
    }
    return native_to_java_RSAPublicKey(env, &publicKey);
}

JNIEXPORT jobject JNICALL JNI_SDF_ExportSignPublicKey_ECC(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint keyIndex) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_ExportSignPublicKey_ECC == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return NULL;
    }

    ECCrefPublicKey publicKey;
    memset(&publicKey, 0, sizeof(publicKey));

    LONG ret = g_sdf_functions.SDF_ExportSignPublicKey_ECC((HANDLE)sessionHandle,
                                                           keyIndex, &publicKey);

    if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to handle key operation");
        return NULL;
    }

    return native_to_java_ECCPublicKey(env, &publicKey);
}

JNIEXPORT jobject JNICALL JNI_SDF_ExportEncPublicKey_ECC(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_ExportEncPublicKey_ECC == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return NULL;
    }

    ECCrefPublicKey publicKey;
    memset(&publicKey, 0, sizeof(publicKey));

    LONG ret = g_sdf_functions.SDF_ExportEncPublicKey_ECC((HANDLE)sessionHandle,
                                                          keyIndex, &publicKey);

    if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to handle key operation");
        return NULL;
    }

    return native_to_java_ECCPublicKey(env, &publicKey);
}

JNIEXPORT jlong JNICALL JNI_SDF_ImportKey(JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray encryptedKey) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_ImportKey == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return 0;
    }

    if (encryptedKey == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Invalid argument");
        return 0;
    }

    jsize key_len = (*env)->GetArrayLength(env, encryptedKey);
    if (key_len <= 0) {
        THROW_SDF_EXCEPTION(env, 0x0100001D, "Invalid argument"); /* SDR_INARGERR */
        return 0;
    }

    jbyte *key_buf = (*env)->GetPrimitiveArrayCritical(env, encryptedKey, NULL);
    if (key_buf == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed"); /* SDR_NOBUFFER */
        return 0;
    }

    HANDLE key_handle = 0;
    LONG ret = g_sdf_functions.SDF_ImportKey(
        (HANDLE)sessionHandle,
        (BYTE*)key_buf,
        (ULONG)key_len,
        &key_handle
    );

    (*env)->ReleasePrimitiveArrayCritical(env, encryptedKey, key_buf, JNI_ABORT);

    if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to import key operation");
        return 0;
    }
    return (jlong)key_handle;
}

JNIEXPORT void JNICALL JNI_SDF_DestroyKey(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_DestroyKey == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return;
    }
    LONG ret = g_sdf_functions.SDF_DestroyKey((HANDLE)sessionHandle, (HANDLE)keyHandle);
    if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to destroy key operation");
    }
}

