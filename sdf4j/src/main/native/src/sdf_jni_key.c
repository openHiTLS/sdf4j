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

JNIEXPORT jobject JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ExportSignPublicKey_1RSA
  (JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex) {
    UNUSED(obj);

    SDF_LOG_ENTER("SDF_ExportSignPublicKey_RSA");
    SDF_JNI_LOG("SDF_ExportSignPublicKey_RSA: hSession=0x%lX, keyIndex=%d",
                (unsigned long)sessionHandle, (int)keyIndex);

    if (!sdf_is_loaded()) {
        SDF_LOG_ERROR("SDF_ExportSignPublicKey_RSA", "SDF library not loaded");
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_ExportSignPublicKey_RSA == NULL) {
        SDF_LOG_ERROR("SDF_ExportSignPublicKey_RSA", "Function not supported");
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    RSArefPublicKey publicKey;
    memset(&publicKey, 0, sizeof(publicKey));

    LONG ret = g_sdf_functions.SDF_ExportSignPublicKey_RSA((HANDLE)sessionHandle,
                                                           keyIndex, &publicKey);

    SDF_LOG_EXIT("SDF_ExportSignPublicKey_RSA", ret);
    if (ret == SDR_OK) {
        SDF_JNI_LOG("SDF_ExportSignPublicKey_RSA: key_bits=%d", publicKey.bits);
    }

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return NULL;
    }

    return native_to_java_RSAPublicKey(env, &publicKey);
}

JNIEXPORT jobject JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ExportEncPublicKey_1RSA
  (JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex) {
    UNUSED(obj);

    SDF_LOG_ENTER("SDF_ExportEncPublicKey_RSA");
    SDF_JNI_LOG("SDF_ExportEncPublicKey_RSA: hSession=0x%lX, keyIndex=%d",
                (unsigned long)sessionHandle, (int)keyIndex);

    if (!sdf_is_loaded()) {
        SDF_LOG_ERROR("SDF_ExportEncPublicKey_RSA", "SDF library not loaded");
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_ExportEncPublicKey_RSA == NULL) {
        SDF_LOG_ERROR("SDF_ExportEncPublicKey_RSA", "Function not supported");
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    RSArefPublicKey publicKey;
    memset(&publicKey, 0, sizeof(publicKey));

    LONG ret = g_sdf_functions.SDF_ExportEncPublicKey_RSA((HANDLE)sessionHandle,
                                                          keyIndex, &publicKey);

    SDF_LOG_EXIT("SDF_ExportEncPublicKey_RSA", ret);
    if (ret == SDR_OK) {
        SDF_JNI_LOG("SDF_ExportEncPublicKey_RSA: key_bits=%d", publicKey.bits);
    }

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return NULL;
    }

    return native_to_java_RSAPublicKey(env, &publicKey);
}

JNIEXPORT jobject JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ExportSignPublicKey_1ECC
  (JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex) {
    UNUSED(obj);

    SDF_LOG_ENTER("SDF_ExportSignPublicKey_ECC");
    SDF_JNI_LOG("SDF_ExportSignPublicKey_ECC: hSession=0x%lX, keyIndex=%d",
                (unsigned long)sessionHandle, (int)keyIndex);

    if (!sdf_is_loaded()) {
        SDF_LOG_ERROR("SDF_ExportSignPublicKey_ECC", "SDF library not loaded");
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_ExportSignPublicKey_ECC == NULL) {
        SDF_LOG_ERROR("SDF_ExportSignPublicKey_ECC", "Function not supported");
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    ECCrefPublicKey publicKey;
    memset(&publicKey, 0, sizeof(publicKey));

    LONG ret = g_sdf_functions.SDF_ExportSignPublicKey_ECC((HANDLE)sessionHandle,
                                                           keyIndex, &publicKey);

    SDF_LOG_EXIT("SDF_ExportSignPublicKey_ECC", ret);
    if (ret == SDR_OK) {
        SDF_JNI_LOG("SDF_ExportSignPublicKey_ECC: key_bits=%d", publicKey.bits);
        SDF_LOG_HEX("SDF_ExportSignPublicKey_ECC x", publicKey.x, 32);
        SDF_LOG_HEX("SDF_ExportSignPublicKey_ECC y", publicKey.y, 32);
    }

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return NULL;
    }

    return native_to_java_ECCPublicKey(env, &publicKey);
}

JNIEXPORT jobject JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ExportEncPublicKey_1ECC
  (JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex) {
    UNUSED(obj);

    SDF_LOG_ENTER("SDF_ExportEncPublicKey_ECC");
    SDF_JNI_LOG("SDF_ExportEncPublicKey_ECC: hSession=0x%lX, keyIndex=%d",
                (unsigned long)sessionHandle, (int)keyIndex);

    if (!sdf_is_loaded()) {
        SDF_LOG_ERROR("SDF_ExportEncPublicKey_ECC", "SDF library not loaded");
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_ExportEncPublicKey_ECC == NULL) {
        SDF_LOG_ERROR("SDF_ExportEncPublicKey_ECC", "Function not supported");
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    ECCrefPublicKey publicKey;
    memset(&publicKey, 0, sizeof(publicKey));

    LONG ret = g_sdf_functions.SDF_ExportEncPublicKey_ECC((HANDLE)sessionHandle,
                                                          keyIndex, &publicKey);

    SDF_LOG_EXIT("SDF_ExportEncPublicKey_ECC", ret);
    if (ret == SDR_OK) {
        SDF_JNI_LOG("SDF_ExportEncPublicKey_ECC: key_bits=%d", publicKey.bits);
        SDF_LOG_HEX("SDF_ExportEncPublicKey_ECC x", publicKey.x, 32);
        SDF_LOG_HEX("SDF_ExportEncPublicKey_ECC y", publicKey.y, 32);
    }

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return NULL;
    }

    return native_to_java_ECCPublicKey(env, &publicKey);
}

JNIEXPORT jlong JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ImportKey
  (JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray key) {
    UNUSED(obj);

    SDF_LOG_ENTER("SDF_ImportKey");
    SDF_JNI_LOG("SDF_ImportKey: hSession=0x%lX", (unsigned long)sessionHandle);

    if (!sdf_is_loaded()) {
        SDF_LOG_ERROR("SDF_ImportKey", "SDF library not loaded");
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return 0;
    }

    if (g_sdf_functions.SDF_ImportKey == NULL) {
        SDF_LOG_ERROR("SDF_ImportKey", "Function not supported");
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return 0;
    }

    if (key == NULL) {
        SDF_LOG_ERROR("SDF_ImportKey", "Key is NULL");
        throw_sdf_exception(env, SDR_INARGERR);
        return 0;
    }

    jsize keyLength = (*env)->GetArrayLength(env, key);
    jbyte *keyData = (*env)->GetByteArrayElements(env, key, NULL);
    if (keyData == NULL) {
        SDF_LOG_ERROR("SDF_ImportKey", "Failed to get key data");
        throw_sdf_exception(env, SDR_INARGERR);
        return 0;
    }

    SDF_JNI_LOG("SDF_ImportKey: keyLength=%d", (int)keyLength);

    HANDLE keyHandle = NULL;
    LONG ret = g_sdf_functions.SDF_ImportKey((HANDLE)sessionHandle,
                                              (BYTE *)keyData,
                                              (ULONG)keyLength,
                                              &keyHandle);

    (*env)->ReleaseByteArrayElements(env, key, keyData, JNI_ABORT);

    SDF_LOG_EXIT("SDF_ImportKey", ret);
    if (ret == SDR_OK) {
        SDF_JNI_LOG("SDF_ImportKey: keyHandle=0x%lX", (unsigned long)keyHandle);
    }

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return 0;
    }

    return (jlong)keyHandle;
}

JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1DestroyKey
  (JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_DestroyKey == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    LONG ret = g_sdf_functions.SDF_DestroyKey((HANDLE)sessionHandle, (HANDLE)keyHandle);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

