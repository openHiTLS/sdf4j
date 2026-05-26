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

#define PQC_PUBLIC_KEY_MAX_BYTES 3692 // add asn1 space
#define PQC_SIGNATURE_MAX_BYTES HYBRIDSIGref_MAX_LEN
#define PQC_CIPHER_MAX_BYTES 4627

JNIEXPORT jbyteArray JNICALL JNI_SDF_ExportPublicKey_PQC(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint keyIndex, jint algID, jint format)
{
    UNUSED(obj);

    if (g_sdf_functions.SDF_ExportPublicKey_PQC == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return NULL;
    }

    ULONG public_key_len = PQC_PUBLIC_KEY_MAX_BYTES;
    BYTE *public_key = (BYTE*)malloc(public_key_len);
    if (public_key == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOBUFFER, "Memory allocation failed");
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_ExportPublicKey_PQC(
        (HANDLE)sessionHandle, (ULONG)keyIndex, (ULONG)algID, (ULONG)format,
        public_key, &public_key_len);
    if (ret != SDR_OK) {
        free(public_key);
        THROW_SDF_EXCEPTION(env, ret, "Failed to export PQC public key");
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, public_key, public_key_len);
    free(public_key);
    return result;
}

JNIEXPORT jbyteArray JNICALL JNI_SDF_InternalSign_PQC(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint keyIndex, jint algID, jint format, jbyteArray data)
{
    UNUSED(obj);

    if (g_sdf_functions.SDF_InternalSign_PQC == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return NULL;
    }
    if (data == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "data is NULL");
        return NULL;
    }

    ULONG data_len = (ULONG)(*env)->GetArrayLength(env, data);
    jbyte *data_buf = (*env)->GetByteArrayElements(env, data, NULL);
    if (data_buf == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOBUFFER, "Memory allocation failed for data");
        return NULL;
    }

    ULONG sign_len = PQC_SIGNATURE_MAX_BYTES;
    BYTE *sign = (BYTE*)malloc(sign_len);
    if (sign == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, data_buf, JNI_ABORT);
        THROW_SDF_EXCEPTION(env, SDR_NOBUFFER, "Memory allocation failed for signature");
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_InternalSign_PQC(
        (HANDLE)sessionHandle, (ULONG)keyIndex, (ULONG)algID, (ULONG)format,
        (BYTE*)data_buf, data_len, sign, &sign_len);

    (*env)->ReleaseByteArrayElements(env, data, data_buf, JNI_ABORT);
    if (ret != SDR_OK) {
        free(sign);
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform PQC internal sign");
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, sign, sign_len);
    free(sign);
    return result;
}

JNIEXPORT void JNICALL JNI_SDF_InternalVerify_PQC(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint keyIndex, jint algID, jint format, jbyteArray data, jbyteArray signature)
{
    UNUSED(obj);

    if (g_sdf_functions.SDF_InternalVerify_PQC == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return;
    }
    if (data == NULL || signature == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "data or signature is NULL");
        return;
    }

    ULONG data_len = (ULONG)(*env)->GetArrayLength(env, data);
    ULONG sign_len = (ULONG)(*env)->GetArrayLength(env, signature);
    jbyte *data_buf = (*env)->GetByteArrayElements(env, data, NULL);
    if (data_buf == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOBUFFER, "Memory allocation failed for data");
        return;
    }
    jbyte *sign_buf = (*env)->GetByteArrayElements(env, signature, NULL);
    if (sign_buf == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, data_buf, JNI_ABORT);
        THROW_SDF_EXCEPTION(env, SDR_NOBUFFER, "Memory allocation failed for signature");
        return;
    }

    LONG ret = g_sdf_functions.SDF_InternalVerify_PQC(
        (HANDLE)sessionHandle, (ULONG)keyIndex, (ULONG)algID, (ULONG)format,
        (BYTE*)data_buf, data_len, (BYTE*)sign_buf, sign_len);

    (*env)->ReleaseByteArrayElements(env, data, data_buf, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, signature, sign_buf, JNI_ABORT);
    if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform PQC internal verify");
    }
}

JNIEXPORT void JNICALL JNI_SDF_ExternalVerify_PQC(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint algID, jbyteArray publicKey, jint format, jbyteArray data, jbyteArray signature)
{
    UNUSED(obj);

    if (g_sdf_functions.SDF_ExternalVerify_PQC == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return;
    }
    if (publicKey == NULL || data == NULL || signature == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "publicKey, data or signature is NULL");
        return;
    }

    ULONG public_key_len = (ULONG)(*env)->GetArrayLength(env, publicKey);
    ULONG data_len = (ULONG)(*env)->GetArrayLength(env, data);
    ULONG sign_len = (ULONG)(*env)->GetArrayLength(env, signature);
    jbyte *public_key_buf = (*env)->GetByteArrayElements(env, publicKey, NULL);
    if (public_key_buf == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOBUFFER, "Memory allocation failed for publicKey");
        return;
    }
    jbyte *data_buf = (*env)->GetByteArrayElements(env, data, NULL);
    if (data_buf == NULL) {
        (*env)->ReleaseByteArrayElements(env, publicKey, public_key_buf, JNI_ABORT);
        THROW_SDF_EXCEPTION(env, SDR_NOBUFFER, "Memory allocation failed for data");
        return;
    }
    jbyte *sign_buf = (*env)->GetByteArrayElements(env, signature, NULL);
    if (sign_buf == NULL) {
        (*env)->ReleaseByteArrayElements(env, publicKey, public_key_buf, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, data, data_buf, JNI_ABORT);
        THROW_SDF_EXCEPTION(env, SDR_NOBUFFER, "Memory allocation failed for signature");
        return;
    }

    LONG ret = g_sdf_functions.SDF_ExternalVerify_PQC(
        (HANDLE)sessionHandle, (ULONG)algID, (BYTE*)public_key_buf, public_key_len,
        (ULONG)format, (BYTE*)data_buf, data_len, (BYTE*)sign_buf, sign_len);

    (*env)->ReleaseByteArrayElements(env, publicKey, public_key_buf, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, data, data_buf, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, signature, sign_buf, JNI_ABORT);
    if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform PQC external verify");
    }
}

JNIEXPORT jobject JNICALL JNI_SDF_GenerateKeyWithIPK_PQC(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint keyIndex, jint algID, jint keyBits, jint format)
{
    UNUSED(obj);

    if (g_sdf_functions.SDF_GenerateKeyWithIPK_PQC == NULL ||
        g_sdf_functions.SDF_DestroyKey == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return NULL;
    }

    ULONG key_len = PQC_CIPHER_MAX_BYTES;
    BYTE *key = (BYTE*)malloc(key_len);
    if (key == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOBUFFER, "Memory allocation failed");
        return NULL;
    }

    HANDLE key_handle = 0;
    LONG ret = g_sdf_functions.SDF_GenerateKeyWithIPK_PQC(
        (HANDLE)sessionHandle, (ULONG)keyIndex, (ULONG)algID,
        (ULONG)keyBits, (ULONG)format, key, &key_len, &key_handle);
    if (ret != SDR_OK) {
        free(key);
        THROW_SDF_EXCEPTION(env, ret, "Failed to generate key with PQC IPK");
        return NULL;
    }

    jobject result = create_key_encryption_result(env, key, key_len, key_handle);
    if (result == NULL) {
        (void)g_sdf_functions.SDF_DestroyKey((HANDLE)sessionHandle, key_handle);
    }
    free(key);
    return result;
}

JNIEXPORT jobject JNICALL JNI_SDF_GenerateKeyWithEPK_PQC(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint algID, jint keyBits, jint format, jbyteArray publicKey)
{
    UNUSED(obj);

    if (g_sdf_functions.SDF_GenerateKeyWithEPK_PQC == NULL ||
        g_sdf_functions.SDF_DestroyKey == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return NULL;
    }
    if (publicKey == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "publicKey is NULL");
        return NULL;
    }

    ULONG public_key_len = (ULONG)(*env)->GetArrayLength(env, publicKey);
    jbyte *public_key_buf = (*env)->GetByteArrayElements(env, publicKey, NULL);
    if (public_key_buf == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOBUFFER, "Memory allocation failed for publicKey");
        return NULL;
    }

    ULONG key_len = PQC_CIPHER_MAX_BYTES;
    BYTE *key = (BYTE*)malloc(key_len);
    if (key == NULL) {
        (*env)->ReleaseByteArrayElements(env, publicKey, public_key_buf, JNI_ABORT);
        THROW_SDF_EXCEPTION(env, SDR_NOBUFFER, "Memory allocation failed");
        return NULL;
    }

    HANDLE key_handle = 0;
    LONG ret = g_sdf_functions.SDF_GenerateKeyWithEPK_PQC(
        (HANDLE)sessionHandle, (ULONG)algID, (ULONG)keyBits, (ULONG)format,
        (BYTE*)public_key_buf, public_key_len, key, &key_len, &key_handle);

    (*env)->ReleaseByteArrayElements(env, publicKey, public_key_buf, JNI_ABORT);
    if (ret != SDR_OK) {
        free(key);
        THROW_SDF_EXCEPTION(env, ret, "Failed to generate key with PQC EPK");
        return NULL;
    }

    jobject result = create_key_encryption_result(env, key, key_len, key_handle);
    if (result == NULL) {
        (void)g_sdf_functions.SDF_DestroyKey((HANDLE)sessionHandle, key_handle);
    }
    free(key);
    return result;
}

JNIEXPORT jlong JNICALL JNI_SDF_ImportKeyWithISK_PQC(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint keyIndex, jint algID, jint format, jbyteArray encryptedKey)
{
    UNUSED(obj);

    if (g_sdf_functions.SDF_ImportKeyWithISK_PQC == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return 0;
    }
    if (encryptedKey == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "encryptedKey is NULL");
        return 0;
    }

    ULONG key_len = (ULONG)(*env)->GetArrayLength(env, encryptedKey);
    jbyte *key_buf = (*env)->GetByteArrayElements(env, encryptedKey, NULL);
    if (key_buf == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOBUFFER, "Memory allocation failed for encryptedKey");
        return 0;
    }

    HANDLE key_handle = 0;
    LONG ret = g_sdf_functions.SDF_ImportKeyWithISK_PQC(
        (HANDLE)sessionHandle, (ULONG)keyIndex, (ULONG)algID,
        (ULONG)format, (BYTE*)key_buf, key_len, &key_handle);

    (*env)->ReleaseByteArrayElements(env, encryptedKey, key_buf, JNI_ABORT);
    if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to import key with PQC ISK");
        return 0;
    }

    return (jlong)key_handle;
}
