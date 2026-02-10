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

#define HYBRIDENCref_ECC_MAX_LEN 141
#define HYBRID_PUBKEY_MAX_BYTES 2660

JNIEXPORT jbyteArray JNICALL JNI_SDF_ExportPublicKey_Hybrid(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint keyIndex) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_ExportPublicKey_Hybrid == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return NULL;
    }

    ULONG pub_key_len = HYBRID_PUBKEY_MAX_BYTES;
    BYTE *pub_key_buf = (BYTE*)malloc(pub_key_len);
    if (pub_key_buf == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOBUFFER, "Memory allocation failed");
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_ExportPublicKey_Hybrid(
        (HANDLE)sessionHandle, (ULONG)keyIndex, pub_key_buf, &pub_key_len);

    if (ret != SDR_OK) {
        free(pub_key_buf);
        THROW_SDF_EXCEPTION(env, ret, "Failed to export public key");
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, pub_key_buf, pub_key_len);
    free(pub_key_buf);
    return result;
}

JNIEXPORT jlong JNICALL JNI_SDF_ImportKeyWithISK_Hybrid(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint keyIndex, jobject hybridCipher) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_ImportKeyWithISK_Hybrid == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return 0;
    }

    if (hybridCipher == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "hybridCipher is NULL");
        return 0;
    }

    /* 转换Java HybridCipher到C结构 */
    HybridCipher *native_cipher = java_to_native_HybridCipher_alloc(env, hybridCipher);
    if (native_cipher == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to convert HybridCipher");
        return 0;
    }

    HANDLE key_handle = 0;
    LONG ret = g_sdf_functions.SDF_ImportKeyWithISK_Hybrid(
        (HANDLE)sessionHandle, keyIndex, native_cipher, &key_handle);

    free(native_cipher);
    if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to import key with ISK");
        return 0;
    }

    return (jlong)key_handle;
}

JNIEXPORT jobject JNICALL JNI_SDF_GenerateKeyWithEPK_Hybrid(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint algID, jbyteArray publicKey) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_GenerateKeyWithEPK_Hybrid == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return NULL;
    }

    if (publicKey == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "publicKey is NULL");
        return NULL;
    }

    /* 获取公钥数据和长度 */
    ULONG pub_key_len = (ULONG)(*env)->GetArrayLength(env, publicKey);
    jbyte *pub_key_buf = (*env)->GetPrimitiveArrayCritical(env, publicKey, NULL);
    if (pub_key_buf == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOBUFFER, "GetPrimitiveArrayCritical failed");
        return NULL;
    }

    HybridCipher *cipher = (HybridCipher*)malloc(sizeof(HybridCipher) + HYBRIDENCref_ECC_MAX_LEN);
    if (cipher == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, publicKey, pub_key_buf, JNI_ABORT);
        THROW_SDF_EXCEPTION(env, SDR_NOBUFFER, "Memory allocation failed for cipher");
        return NULL;
    }

    HANDLE key_handle = 0;
    LONG ret = g_sdf_functions.SDF_GenerateKeyWithEPK_Hybrid(
        (HANDLE)sessionHandle, algID,
        (BYTE*)pub_key_buf, &pub_key_len,
        cipher, &key_handle);

    (*env)->ReleasePrimitiveArrayCritical(env, publicKey, pub_key_buf, JNI_ABORT);

    if (ret != SDR_OK) {
        free(cipher);
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform external encrypt");
        return NULL;
    }

    jobject result = native_to_java_HybridCipher(env, cipher, cipher->ct_s.L, key_handle);
    free(cipher);
    return result;
}

JNIEXPORT jobject JNICALL JNI_SDF_InternalSign_Composite(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint keyIndex, jbyteArray data) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_InternalSign_Composite == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return NULL;
    }

    if (data == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Invalid argument: data is NULL");
        return NULL;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);
    jbyte *data_buf = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    if (data_buf == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOBUFFER, "GetPrimitiveArrayCritical failed");
        return NULL;
    }

    HybridSignature *signature = (HybridSignature*)malloc(sizeof(HybridSignature));
    if (signature == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
        THROW_SDF_EXCEPTION(env, SDR_NOBUFFER, "Memory allocation failed for signature");
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_InternalSign_Composite(
        (HANDLE)sessionHandle, keyIndex,
        (BYTE*)data_buf, data_len, signature);

    (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);

    if (ret != SDR_OK) {
        free(signature);
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform internal sign");
        return NULL;
    }

    jobject result = native_to_java_HybridSignature(env, signature, signature->L);
    free(signature);

    return result;
}

JNIEXPORT void JNICALL JNI_SDF_ExternalVerify_Composite(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint algID, jbyteArray publicKey, jbyteArray data, jobject signature) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_ExternalVerify_Composite == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return;
    }

    if (publicKey == NULL || data == NULL || signature == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Invalid argument: NULL parameter");
        return;
    }

    HybridSignature *native_sig = java_to_native_HybridSignature_alloc(env, signature);
    if (native_sig == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to convert HybridSignature");
        return;
    }

    /* 获取公钥数据 */
    ULONG pub_key_len = (ULONG)(*env)->GetArrayLength(env, publicKey);
    jbyte *pub_key_buf = (*env)->GetPrimitiveArrayCritical(env, publicKey, NULL);
    if (pub_key_buf == NULL) {
        free(native_sig);
        THROW_SDF_EXCEPTION(env, SDR_NOBUFFER, "GetPrimitiveArrayCritical failed for publicKey");
        return;
    }

    /* 获取待验签数据 */
    ULONG data_len = (ULONG)(*env)->GetArrayLength(env, data);
    jbyte *data_buf = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    if (data_buf == NULL) {
        free(native_sig);
        (*env)->ReleasePrimitiveArrayCritical(env, publicKey, pub_key_buf, JNI_ABORT);
        THROW_SDF_EXCEPTION(env, SDR_NOBUFFER, "GetPrimitiveArrayCritical failed for data");
        return;
    }

    LONG ret = g_sdf_functions.SDF_ExternalVerify_Composite(
        (HANDLE)sessionHandle, algID,
        (BYTE*)pub_key_buf, &pub_key_len,
        (BYTE*)data_buf, data_len, native_sig);

    (*env)->ReleasePrimitiveArrayCritical(env, publicKey, pub_key_buf, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
    free(native_sig);

    if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform external verify");
    }
}
