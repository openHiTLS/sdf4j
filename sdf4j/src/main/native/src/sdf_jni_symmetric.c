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
 * Symmetric Algorithm Functions
 * All symmetric encryption, decryption, MAC, HMAC, and hash operations
 * ======================================================================== */

/* ========================================================================
 * Multi-package Encrypt Operations (Init/Update/Final)
 * ======================================================================== */
JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1EncryptInit
(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle, jint algID, jbyteArray iv) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_EncryptInit == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    /* 转换IV参数（可能为NULL，ECB模式不需要IV）*/
    BYTE *iv_buf = NULL;
    jsize iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (BYTE*)malloc(iv_len);
        if (iv_buf == NULL) {
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
        (*env)->GetByteArrayRegion(env, iv, 0, iv_len, (jbyte*)iv_buf);
    }

    LONG ret = g_sdf_functions.SDF_EncryptInit(
        (HANDLE)sessionHandle,
        (HANDLE)keyHandle,
        (ULONG)algID,
        iv_buf,
        (ULONG)iv_len
    );

    if (iv_buf != NULL) {
        free(iv_buf);
    }

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/**
 * 6.5.8 多包对称加密更新
 * Pattern: Byte array I/O with dynamic output length
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1EncryptUpdate
(JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray data) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_EncryptUpdate == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (data == NULL) {
        throw_sdf_exception_with_message(env, 0x01000001, "Data is null");
        return NULL;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, data, 0, data_len, (jbyte*)data_buf);

    /* 密文长度可能大于明文（填充），分配足够空间 */
    ULONG enc_len = data_len + 32;  /* 预留填充空间 */
    BYTE *enc_buf = (BYTE*)malloc(enc_len);
    if (enc_buf == NULL) {
        free(data_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_EncryptUpdate(
        (HANDLE)sessionHandle,
        data_buf,
        (ULONG)data_len,
        enc_buf,
        &enc_len
    );

    free(data_buf);

    if (ret != SDR_OK) {
        free(enc_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, enc_buf, enc_len);
    free(enc_buf);

    return result;
}

/**
 * 6.5.9 多包对称加密结束
 * Pattern: Final function with output buffer
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1EncryptFinal
(JNIEnv *env, jobject obj, jlong sessionHandle) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_EncryptFinal == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* 分配最终块缓冲区（最多一个块大小 + 填充）*/
    ULONG enc_len = 64;  /* 预留足够空间 */
    BYTE *enc_buf = (BYTE*)malloc(enc_len);
    if (enc_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_EncryptFinal(
        (HANDLE)sessionHandle,
        enc_buf,
        &enc_len
    );

    if (ret != SDR_OK) {
        free(enc_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, enc_buf, enc_len);
    free(enc_buf);

    return result;
}

/* ========================================================================
 * HMAC Init Operation
 * ======================================================================== */
JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1HMACInit
(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle, jint algID) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_HMACInit == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    LONG ret = g_sdf_functions.SDF_HMACInit(
        (HANDLE)sessionHandle,
        (HANDLE)keyHandle,
        (ULONG)algID
    );

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/* ========================================================================
 * Single-package Encrypt/Decrypt Operations
 * ======================================================================== */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1Encrypt
  (JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle, jint algID, jbyteArray iv, jbyteArray data) {
    UNUSED(obj);

    SDF_LOG_ENTER("SDF_Encrypt");
    SDF_JNI_LOG("SDF_Encrypt: hSession=0x%lX, hKey=0x%lX, algID=0x%08X",
                (unsigned long)sessionHandle, (unsigned long)keyHandle, (unsigned int)algID);

    if (!sdf_is_loaded()) {
        SDF_LOG_ERROR("SDF_Encrypt", "SDF library not loaded");
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_Encrypt == NULL) {
        SDF_LOG_ERROR("SDF_Encrypt", "Function not supported");
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (data == NULL) {
        SDF_LOG_ERROR("SDF_Encrypt", "Invalid argument: data is NULL");
        throw_sdf_exception(env, 0x0100001D);
        return NULL;
    }

    /* 获取输入数据 */
    jsize data_len = (*env)->GetArrayLength(env, data);
    SDF_JNI_LOG("SDF_Encrypt: data_len=%d", (int)data_len);

    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        SDF_LOG_ERROR("SDF_Encrypt", "Memory allocation failed for data");
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, data, 0, data_len, (jbyte*)data_buf);
    SDF_LOG_HEX("SDF_Encrypt plaintext", data_buf, data_len);

    /* 获取IV（可选）*/
    BYTE *iv_buf = NULL;
    if (iv != NULL) {
        jsize iv_len = (*env)->GetArrayLength(env, iv);
        SDF_JNI_LOG("SDF_Encrypt: iv_len=%d", (int)iv_len);
        iv_buf = (BYTE*)malloc(iv_len);
        if (iv_buf == NULL) {
            free(data_buf);
            SDF_LOG_ERROR("SDF_Encrypt", "Memory allocation failed for IV");
            throw_sdf_exception(env, 0x0100001C);
            return NULL;
        }
        (*env)->GetByteArrayRegion(env, iv, 0, iv_len, (jbyte*)iv_buf);
        SDF_LOG_HEX("SDF_Encrypt IV", iv_buf, iv_len);
    }

    /* 分配输出缓冲区（预留足够空间用于填充）*/
    ULONG enc_data_len = data_len + 16;  /* 预留填充空间 */
    BYTE *enc_data_buf = (BYTE*)malloc(enc_data_len);
    if (enc_data_buf == NULL) {
        free(data_buf);
        if (iv_buf) free(iv_buf);
        SDF_LOG_ERROR("SDF_Encrypt", "Memory allocation failed for output");
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_Encrypt((HANDLE)sessionHandle, (HANDLE)keyHandle,
                                            algID, iv_buf, data_buf, data_len,
                                            enc_data_buf, &enc_data_len);

    SDF_LOG_EXIT("SDF_Encrypt", ret);
    if (ret == SDR_OK) {
        SDF_JNI_LOG("SDF_Encrypt: output_len=%lu", enc_data_len);
        SDF_LOG_HEX("SDF_Encrypt ciphertext", enc_data_buf, enc_data_len);
    }

    free(data_buf);
    if (iv_buf) free(iv_buf);

    if (ret != SDR_OK) {
        free(enc_data_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, enc_data_buf, enc_data_len);
    free(enc_data_buf);
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1Decrypt
  (JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle, jint algID, jbyteArray iv, jbyteArray encData) {
    UNUSED(obj);

    SDF_LOG_ENTER("SDF_Decrypt");
    SDF_JNI_LOG("SDF_Decrypt: hSession=0x%lX, hKey=0x%lX, algID=0x%08X",
                (unsigned long)sessionHandle, (unsigned long)keyHandle, (unsigned int)algID);

    if (!sdf_is_loaded()) {
        SDF_LOG_ERROR("SDF_Decrypt", "SDF library not loaded");
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_Decrypt == NULL) {
        SDF_LOG_ERROR("SDF_Decrypt", "Function not supported");
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (encData == NULL) {
        SDF_LOG_ERROR("SDF_Decrypt", "Invalid argument: encData is NULL");
        throw_sdf_exception(env, 0x0100001D);
        return NULL;
    }

    /* 获取加密数据 */
    jsize enc_data_len = (*env)->GetArrayLength(env, encData);
    SDF_JNI_LOG("SDF_Decrypt: enc_data_len=%d", (int)enc_data_len);

    BYTE *enc_data_buf = (BYTE*)malloc(enc_data_len);
    if (enc_data_buf == NULL) {
        SDF_LOG_ERROR("SDF_Decrypt", "Memory allocation failed for encrypted data");
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, encData, 0, enc_data_len, (jbyte*)enc_data_buf);
    SDF_LOG_HEX("SDF_Decrypt ciphertext", enc_data_buf, enc_data_len);

    /* 获取IV（可选）*/
    BYTE *iv_buf = NULL;
    if (iv != NULL) {
        jsize iv_len = (*env)->GetArrayLength(env, iv);
        SDF_JNI_LOG("SDF_Decrypt: iv_len=%d", (int)iv_len);
        iv_buf = (BYTE*)malloc(iv_len);
        if (iv_buf == NULL) {
            free(enc_data_buf);
            SDF_LOG_ERROR("SDF_Decrypt", "Memory allocation failed for IV");
            throw_sdf_exception(env, 0x0100001C);
            return NULL;
        }
        (*env)->GetByteArrayRegion(env, iv, 0, iv_len, (jbyte*)iv_buf);
        SDF_LOG_HEX("SDF_Decrypt IV", iv_buf, iv_len);
    }

    /* 分配输出缓冲区 */
    ULONG data_len = enc_data_len;
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        free(enc_data_buf);
        if (iv_buf) free(iv_buf);
        SDF_LOG_ERROR("SDF_Decrypt", "Memory allocation failed for output");
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_Decrypt((HANDLE)sessionHandle, (HANDLE)keyHandle,
                                            algID, iv_buf, enc_data_buf, enc_data_len,
                                            data_buf, &data_len);

    SDF_LOG_EXIT("SDF_Decrypt", ret);
    if (ret == SDR_OK) {
        SDF_JNI_LOG("SDF_Decrypt: output_len=%lu", data_len);
        SDF_LOG_HEX("SDF_Decrypt plaintext", data_buf, data_len);
    }

    free(enc_data_buf);
    if (iv_buf) free(iv_buf);

    if (ret != SDR_OK) {
        free(data_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, data_buf, data_len);
    free(data_buf);
    return result;
}

/* ========================================================================
 * Multi-package Decrypt Operations (Init/Update/Final)
 * ======================================================================== */
JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1DecryptInit
(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle, jint algID, jbyteArray iv) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_DecryptInit == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    BYTE *iv_buf = NULL;
    jsize iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (BYTE*)malloc(iv_len);
        if (iv_buf == NULL) {
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
        (*env)->GetByteArrayRegion(env, iv, 0, iv_len, (jbyte*)iv_buf);
    }

    LONG ret = g_sdf_functions.SDF_DecryptInit(
        (HANDLE)sessionHandle,
        (HANDLE)keyHandle,
        (ULONG)algID,
        iv_buf,
        (ULONG)iv_len
    );

    if (iv_buf != NULL) {
        free(iv_buf);
    }

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/**
 * 6.5.11 多包对称解密更新
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1DecryptUpdate
(JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray encData) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_DecryptUpdate == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (encData == NULL) {
        throw_sdf_exception_with_message(env, 0x01000001, "Encrypted data is null");
        return NULL;
    }

    jsize enc_len = (*env)->GetArrayLength(env, encData);
    BYTE *enc_buf = (BYTE*)malloc(enc_len);
    if (enc_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, encData, 0, enc_len, (jbyte*)enc_buf);

    ULONG data_len = enc_len + 32;
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        free(enc_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_DecryptUpdate(
        (HANDLE)sessionHandle,
        enc_buf,
        (ULONG)enc_len,
        data_buf,
        &data_len
    );

    free(enc_buf);

    if (ret != SDR_OK) {
        free(data_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, data_buf, data_len);
    free(data_buf);

    return result;
}

/**
 * 6.5.12 多包对称解密结束
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1DecryptFinal
(JNIEnv *env, jobject obj, jlong sessionHandle) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_DecryptFinal == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    ULONG data_len = 64;
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_DecryptFinal(
        (HANDLE)sessionHandle,
        data_buf,
        &data_len
    );

    if (ret != SDR_OK) {
        free(data_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, data_buf, data_len);
    free(data_buf);

    return result;
}

/* ========================================================================
 * MAC Operations
 * ======================================================================== */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1CalculateMAC
  (JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle, jint algID, jbyteArray iv, jbyteArray data) {
    UNUSED(obj);

    SDF_LOG_ENTER("SDF_CalculateMAC");
    SDF_JNI_LOG("=== SDF_CalculateMAC Input Parameters ===");
    SDF_JNI_LOG("  sessionHandle: 0x%lX", (unsigned long)sessionHandle);
    SDF_JNI_LOG("  keyHandle: 0x%lX", (unsigned long)keyHandle);
    SDF_JNI_LOG("  algID: 0x%08X (%d)", (unsigned int)algID, (int)algID);

    if (!sdf_is_loaded()) {
        SDF_LOG_ERROR("SDF_CalculateMAC", "SDF library not loaded");
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_CalculateMAC == NULL) {
        SDF_LOG_ERROR("SDF_CalculateMAC", "Function not supported");
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (data == NULL) {
        SDF_LOG_ERROR("SDF_CalculateMAC", "Input data is NULL");
        throw_sdf_exception(env, 0x0100001D);
        return NULL;
    }

    /* 获取输入数据 */
    jsize data_len = (*env)->GetArrayLength(env, data);
    SDF_JNI_LOG("  data length: %d bytes", (int)data_len);

    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        SDF_LOG_ERROR("SDF_CalculateMAC", "Failed to allocate memory for data buffer");
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, data, 0, data_len, (jbyte*)data_buf);
    SDF_LOG_HEX("  data", data_buf, data_len);

    /* 获取IV（可选）*/
    BYTE *iv_buf = NULL;
    jsize iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        SDF_JNI_LOG("  iv length: %d bytes", (int)iv_len);

        iv_buf = (BYTE*)malloc(iv_len);
        if (iv_buf == NULL) {
            SDF_LOG_ERROR("SDF_CalculateMAC", "Failed to allocate memory for IV buffer");
            free(data_buf);
            throw_sdf_exception(env, 0x0100001C);
            return NULL;
        }
        (*env)->GetByteArrayRegion(env, iv, 0, iv_len, (jbyte*)iv_buf);
        SDF_LOG_HEX("  iv", iv_buf, iv_len);
    } else {
        SDF_JNI_LOG("  iv: NULL (no IV provided)");
    }

    /* 分配MAC缓冲区 */
    ULONG mac_len = 64;  /* SM4-CBC-MAC 通常为16字节,可能是必须要传入固定64 TODO */
    SDF_JNI_LOG("  Allocated MAC buffer size: %lu bytes", mac_len);

    BYTE *mac_buf = (BYTE*)malloc(mac_len);
    if (mac_buf == NULL) {
        SDF_LOG_ERROR("SDF_CalculateMAC", "Failed to allocate memory for MAC buffer");
        free(data_buf);
        if (iv_buf) free(iv_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    SDF_JNI_LOG("=== Calling native SDF_CalculateMAC ===");
    SDF_JNI_LOG("  Parameters: hSession=0x%lX, hKey=0x%lX, algID=0x%08X, ivLen=%d, dataLen=%d, macBufSize=%lu",
                (unsigned long)sessionHandle, (unsigned long)keyHandle,
                (unsigned int)algID, (int)iv_len, (int)data_len, mac_len);

    LONG ret = g_sdf_functions.SDF_CalculateMAC((HANDLE)sessionHandle, (HANDLE)keyHandle,
                                                 algID, iv_buf, data_buf, data_len,
                                                 mac_buf, &mac_len);

    SDF_JNI_LOG("=== Native SDF_CalculateMAC returned ===");
    SDF_JNI_LOG("  Return code: 0x%08X", (unsigned int)ret);
    SDF_JNI_LOG("  Output MAC length: %lu bytes", mac_len);

    free(data_buf);
    if (iv_buf) free(iv_buf);

    if (ret != SDR_OK) {
        SDF_LOG_ERROR("SDF_CalculateMAC", "Native function failed");
        SDF_LOG_EXIT("SDF_CalculateMAC", ret);
        free(mac_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    SDF_LOG_HEX("  Output MAC", mac_buf, mac_len);

    jbyteArray result = native_to_java_byte_array(env, mac_buf, mac_len);
    free(mac_buf);

    if (result != NULL) {
        SDF_JNI_LOG("Successfully created Java byte array for MAC result");
    } else {
        SDF_LOG_ERROR("SDF_CalculateMAC", "Failed to create Java byte array");
    }

    SDF_LOG_EXIT("SDF_CalculateMAC", SDR_OK);
    return result;
}

/* ========================================================================
 * Multi-package MAC Operations (Init/Update/Final)
 * ======================================================================== */
JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1CalculateMACInit
(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle, jint algID, jbyteArray iv) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_CalculateMACInit == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    BYTE *iv_buf = NULL;
    jsize iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (BYTE*)malloc(iv_len);
        if (iv_buf == NULL) {
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
        (*env)->GetByteArrayRegion(env, iv, 0, iv_len, (jbyte*)iv_buf);
    }

    LONG ret = g_sdf_functions.SDF_CalculateMACInit(
        (HANDLE)sessionHandle,
        (HANDLE)keyHandle,
        (ULONG)algID,
        iv_buf,
        (ULONG)iv_len
    );

    if (iv_buf != NULL) {
        free(iv_buf);
    }

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/**
 * 6.5.14 多包MAC计算更新
 */
JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1CalculateMACUpdate
(JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray data) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_CalculateMACUpdate == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    if (data == NULL) {
        throw_sdf_exception_with_message(env, 0x01000001, "Data is null");
        return;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return;
    }
    (*env)->GetByteArrayRegion(env, data, 0, data_len, (jbyte*)data_buf);

    LONG ret = g_sdf_functions.SDF_CalculateMACUpdate(
        (HANDLE)sessionHandle,
        data_buf,
        (ULONG)data_len
    );

    free(data_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/**
 * 6.5.15 多包MAC计算结束
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1CalculateMACFinal
(JNIEnv *env, jobject obj, jlong sessionHandle) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_CalculateMACFinal == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    ULONG mac_len = 32;
    BYTE *mac_buf = (BYTE*)malloc(mac_len);
    if (mac_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_CalculateMACFinal(
        (HANDLE)sessionHandle,
        mac_buf,
        &mac_len
    );

    if (ret != SDR_OK) {
        free(mac_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, mac_buf, mac_len);
    free(mac_buf);

    return result;
}

/* ========================================================================
 * HMAC Update/Final Operations
 * ======================================================================== */
JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1HMACUpdate
(JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray data) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_HMACUpdate == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    if (data == NULL) {
        throw_sdf_exception_with_message(env, 0x01000001, "Data is null");
        return;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return;
    }
    (*env)->GetByteArrayRegion(env, data, 0, data_len, (jbyte*)data_buf);

    LONG ret = g_sdf_functions.SDF_HMACUpdate(
        (HANDLE)sessionHandle,
        data_buf,
        (ULONG)data_len
    );

    free(data_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/**
 * 6.6.7 HMAC结束
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1HMACFinal
(JNIEnv *env, jobject obj, jlong sessionHandle) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_HMACFinal == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    ULONG hmac_len = 64;
    BYTE *hmac_buf = (BYTE*)malloc(hmac_len);
    if (hmac_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_HMACFinal(
        (HANDLE)sessionHandle,
        hmac_buf,
        &hmac_len
    );

    if (ret != SDR_OK) {
        free(hmac_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, hmac_buf, hmac_len);
    free(hmac_buf);

    return result;
}

/* ========================================================================
 * Authenticated Encryption Operations
 * ======================================================================== */
JNIEXPORT jobjectArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1AuthEnc
(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle, jint algID,
 jbyteArray iv, jbyteArray aad, jbyteArray data) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_AuthEnc == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (data == NULL) {
        throw_sdf_exception_with_message(env, 0x01000006, "Data is null");
        return NULL;
    }

    /* Convert IV */
    BYTE *iv_buf = NULL;
    jsize iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (BYTE*)malloc(iv_len);
        if (iv_buf == NULL) {
            throw_sdf_exception(env, 0x0100001C);
            return NULL;
        }
        (*env)->GetByteArrayRegion(env, iv, 0, iv_len, (jbyte*)iv_buf);
    }

    /* Convert AAD */
    BYTE *aad_buf = NULL;
    jsize aad_len = 0;
    if (aad != NULL) {
        aad_len = (*env)->GetArrayLength(env, aad);
        aad_buf = (BYTE*)malloc(aad_len);
        if (aad_buf == NULL) {
            if (iv_buf != NULL) free(iv_buf);
            throw_sdf_exception(env, 0x0100001C);
            return NULL;
        }
        (*env)->GetByteArrayRegion(env, aad, 0, aad_len, (jbyte*)aad_buf);
    }

    /* Convert data */
    jsize data_len = (*env)->GetArrayLength(env, data);
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        if (iv_buf != NULL) free(iv_buf);
        if (aad_buf != NULL) free(aad_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, data, 0, data_len, (jbyte*)data_buf);

    /* Allocate output buffers */
    ULONG enc_len = data_len;  /* Data + possible padding + extra space */
    BYTE *enc_buf = (BYTE*)malloc(enc_len);
    if (enc_buf == NULL) {
        if (iv_buf != NULL) free(iv_buf);
        if (aad_buf != NULL) free(aad_buf);
        free(data_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    ULONG tag_len = 16;  /* GCM tag size is 16 bytes */
    BYTE *tag_buf = (BYTE*)malloc(tag_len);
    if (tag_buf == NULL) {
        if (iv_buf != NULL) free(iv_buf);
        if (aad_buf != NULL) free(aad_buf);
        free(data_buf);
        free(enc_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_AuthEnc(
        (HANDLE)sessionHandle,
        (HANDLE)keyHandle,
        (ULONG)algID,
        iv_buf,
        (ULONG)iv_len,
        aad_buf,
        (ULONG)aad_len,
        data_buf,
        (ULONG)data_len,
        enc_buf,
        &enc_len,
        tag_buf,
        &tag_len
    );

    if (iv_buf != NULL) free(iv_buf);
    if (aad_buf != NULL) free(aad_buf);
    free(data_buf);

    if (ret != SDR_OK) {
        free(enc_buf);
        free(tag_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    /* Create 2D array to return [encrypted data, auth tag] */
    jclass byteArrayClass = (*env)->FindClass(env, "[B");
    if (byteArrayClass == NULL) {
        free(enc_buf);
        free(tag_buf);
        return NULL;
    }

    jobjectArray result = (*env)->NewObjectArray(env, 2, byteArrayClass, NULL);
    if (result == NULL) {
        free(enc_buf);
        free(tag_buf);
        return NULL;
    }

    /* Set [0] = encrypted data */
    jbyteArray encData = native_to_java_byte_array(env, enc_buf, enc_len);
    if (encData != NULL) {
        (*env)->SetObjectArrayElement(env, result, 0, encData);
    }

    /* Set [1] = auth tag */
    jbyteArray authTag = native_to_java_byte_array(env, tag_buf, tag_len);
    if (authTag != NULL) {
        (*env)->SetObjectArrayElement(env, result, 1, authTag);
    }

    free(enc_buf);
    free(tag_buf);

    return result;
}

/**
 * 6.5.6 单包可鉴别解密
 * SDF_AuthDec
 * Returns decrypted plaintext data
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1AuthDec
(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle, jint algID,
 jbyteArray iv, jbyteArray aad, jbyteArray authTag, jbyteArray encData) {
    UNUSED(obj);

    SDF_LOG_ENTER("SDF_AuthDec");
    SDF_JNI_LOG("SDF_AuthDec: hSession=0x%lX, keyIndex=%lX",
                (unsigned long)sessionHandle, (unsigned long)keyHandle);
    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_AuthDec == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (encData == NULL || authTag == NULL) {
        throw_sdf_exception_with_message(env, 0x01000006, "Encrypted data or auth tag is null");
        return NULL;
    }

    /* Convert IV */
    BYTE *iv_buf = NULL;
    jsize iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (BYTE*)malloc(iv_len);
        if (iv_buf == NULL) {
            throw_sdf_exception(env, 0x0100001C);
            return NULL;
        }
        (*env)->GetByteArrayRegion(env, iv, 0, iv_len, (jbyte*)iv_buf);
    }

    /* Convert AAD */
    BYTE *aad_buf = NULL;
    jsize aad_len = 0;
    if (aad != NULL) {
        aad_len = (*env)->GetArrayLength(env, aad);
        aad_buf = (BYTE*)malloc(aad_len);
        if (aad_buf == NULL) {
            if (iv_buf != NULL) free(iv_buf);
            throw_sdf_exception(env, 0x0100001C);
            return NULL;
        }
        (*env)->GetByteArrayRegion(env, aad, 0, aad_len, (jbyte*)aad_buf);
    }

    /* Convert auth tag */
    jsize tag_len = (*env)->GetArrayLength(env, authTag);
    BYTE *tag_buf = (BYTE*)malloc(tag_len);
    if (tag_buf == NULL) {
        if (iv_buf != NULL) free(iv_buf);
        if (aad_buf != NULL) free(aad_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, authTag, 0, tag_len, (jbyte*)tag_buf);

    /* Convert encrypted data */
    jsize enc_len = (*env)->GetArrayLength(env, encData);
    BYTE *enc_buf = (BYTE*)malloc(enc_len);
    if (enc_buf == NULL) {
        if (iv_buf != NULL) free(iv_buf);
        if (aad_buf != NULL) free(aad_buf);
        free(tag_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, encData, 0, enc_len, (jbyte*)enc_buf);

    /* Allocate output buffer for plaintext */
    ULONG plaintext_len = enc_len;
    BYTE *plaintext_buf = (BYTE*)malloc(plaintext_len);
    if (plaintext_buf == NULL) {
        if (iv_buf != NULL) free(iv_buf);
        if (aad_buf != NULL) free(aad_buf);
        free(tag_buf);
        free(enc_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    printf("-----------------iv-------------\n");
    for (int i = 0; i < iv_len; i++) {
	    printf("%02x", iv_buf[i]);
    }
    printf("\n\n");

    printf("-----------------aad-------------\n");
    for (int i = 0; i < aad_len; i++) {
            printf("%02x", aad_buf[i]);
    }
    printf("\n\n");

    printf("-----------------tag-------------\n");
    for (int i = 0; i < tag_len; i++) {
            printf("%02x", tag_buf[i]);
    }
    printf("\n\n");

    printf("-----------------enc-------------\n");
    for (int i = 0; i < enc_len; i++) {
            printf("%02x", enc_buf[i]);
    }
    printf("\n\n");

    LONG ret = g_sdf_functions.SDF_AuthDec(
        (HANDLE)sessionHandle,
        (HANDLE)keyHandle,
        (ULONG)algID,
        iv_buf,
        (ULONG)iv_len,
        aad_buf,
        (ULONG)aad_len,
        tag_buf,
        (ULONG *)&tag_len,
        enc_buf,
        (ULONG)enc_len,
        plaintext_buf,
        &plaintext_len
    );

    if (iv_buf != NULL) free(iv_buf);
    if (aad_buf != NULL) free(aad_buf);
    free(tag_buf);
    free(enc_buf);

    if (ret != SDR_OK) {
        free(plaintext_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, plaintext_buf, plaintext_len);
    free(plaintext_buf);

    return result;
}

/* ========================================================================
 * Multi-package Authenticated Encryption Operations
 * ======================================================================== */
JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1AuthEncInit
(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle, jint algID, jbyteArray iv, jbyteArray aad, jint dataLength) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_AuthEncInit == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    /* Convert IV */
    BYTE *iv_buf = NULL;
    jsize iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (BYTE*)malloc(iv_len);
        if (iv_buf == NULL) {
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
        (*env)->GetByteArrayRegion(env, iv, 0, iv_len, (jbyte*)iv_buf);
    }

    /* Convert AAD (Additional Authenticated Data) */
    BYTE *aad_buf = NULL;
    jsize aad_len = 0;
    if (aad != NULL) {
        aad_len = (*env)->GetArrayLength(env, aad);
        aad_buf = (BYTE*)malloc(aad_len);
        if (aad_buf == NULL) {
            if (iv_buf != NULL) free(iv_buf);
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
        (*env)->GetByteArrayRegion(env, aad, 0, aad_len, (jbyte*)aad_buf);
    }

    LONG ret = g_sdf_functions.SDF_AuthEncInit(
        (HANDLE)sessionHandle,
        (HANDLE)keyHandle,
        (ULONG)algID,
        iv_buf,
        (ULONG)iv_len,
        aad_buf,
        (ULONG)aad_len,
        (ULONG)dataLength
    );

    if (iv_buf != NULL) free(iv_buf);
    if (aad_buf != NULL) free(aad_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/**
 * 认证加密更新
 * SDF_AuthEncUpdate
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1AuthEncUpdate
(JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray data) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_AuthEncUpdate == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (data == NULL) {
        throw_sdf_exception_with_message(env, 0x01000006, "Data is null");
        return NULL;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, data, 0, data_len, (jbyte*)data_buf);

    /* Allocate output buffer (worst case: same size as input + block size) */
    ULONG output_len = data_len + 128;
    BYTE *output_buf = (BYTE*)malloc(output_len);
    if (output_buf == NULL) {
        free(data_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_AuthEncUpdate(
        (HANDLE)sessionHandle,
        data_buf,
        (ULONG)data_len,
        output_buf,
        &output_len
    );

    free(data_buf);

    if (ret != SDR_OK) {
        free(output_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, output_buf, output_len);
    free(output_buf);

    return result;
}

/**
 * 认证加密结束
 * SDF_AuthEncFinal
 * Java signature: (long sessionHandle, byte[] pucEncData) -> byte[][]
 * Returns: [0] = final encrypted data, [1] = authentication tag
 */
JNIEXPORT jobjectArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1AuthEncFinal
(JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray pucEncData) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_AuthEncFinal == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* Convert pucEncData to native buffer */
    BYTE *output_buf = NULL;
    ULONG output_len = 0;
    if (pucEncData != NULL) {
        output_len = (*env)->GetArrayLength(env, pucEncData);
        output_buf = (BYTE*)malloc(output_len);
        if (output_buf == NULL) {
            throw_sdf_exception(env, 0x0100001C);
            return NULL;
        }
        (*env)->GetByteArrayRegion(env, pucEncData, 0, output_len, (jbyte*)output_buf);
    }

    /* Allocate tag buffer */
    ULONG tag_len = 16;  /* GCM tag size is 16 bytes */
    BYTE *tag_buf = (BYTE*)malloc(tag_len);
    if (tag_buf == NULL) {
        if (output_buf != NULL) free(output_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    /* Print output_buf before calling SDF_AuthEncFinal */
    SDF_JNI_LOG("=== Before SDF_AuthEncFinal ===");
    SDF_JNI_LOG("  output_len: %lu", output_len);
    if (output_buf != NULL && output_len > 0) {
        SDF_LOG_HEX("  output_buf (before)", output_buf, output_len);
    } else {
        SDF_JNI_LOG("  output_buf: NULL or empty");
    }

    LONG ret = g_sdf_functions.SDF_AuthEncFinal(
        (HANDLE)sessionHandle,
        output_buf,
        &output_len,
        tag_buf,
        &tag_len
    );

    /* Print output_buf after calling SDF_AuthEncFinal */
    SDF_JNI_LOG("=== After SDF_AuthEncFinal ===");
    SDF_JNI_LOG("  ret: 0x%08X", (unsigned int)ret);
    SDF_JNI_LOG("  output_len: %lu", output_len);
    if (output_buf != NULL && output_len > 0) {
        SDF_LOG_HEX("  output_buf (after)", output_buf, output_len);
    } else {
        SDF_JNI_LOG("  output_buf: NULL or empty (len=%lu)", output_len);
    }
    SDF_JNI_LOG("  tag_len: %lu", tag_len);
    if (tag_buf != NULL && tag_len > 0) {
        SDF_LOG_HEX("  tag_buf (after)", tag_buf, tag_len);
    }

    if (ret != SDR_OK) {
        if (output_buf != NULL) free(output_buf);
        free(tag_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    /* Create 2D byte array to return both outputs */
    jclass byteArrayClass = (*env)->FindClass(env, "[B");
    if (byteArrayClass == NULL) {
        if (output_buf != NULL) free(output_buf);
        free(tag_buf);
        return NULL;
    }

    jobjectArray result = (*env)->NewObjectArray(env, 2, byteArrayClass, NULL);
    if (result == NULL) {
        if (output_buf != NULL) free(output_buf);
        free(tag_buf);
        return NULL;
    }

    /* Set [0] = final encrypted data */
    jbyteArray encData = native_to_java_byte_array(env, output_buf, output_len);
    if (encData != NULL) {
        (*env)->SetObjectArrayElement(env, result, 0, encData);
    }

    /* Set [1] = authentication tag */
    jbyteArray authTag = native_to_java_byte_array(env, tag_buf, tag_len);
    if (authTag != NULL) {
        (*env)->SetObjectArrayElement(env, result, 1, authTag);
    }

    if (output_buf != NULL) free(output_buf);
    free(tag_buf);

    return result;
}

/**
 * 认证解密初始化
 * SDF_AuthDecInit
 * Java signature: (long sessionHandle, long keyHandle, int algID, byte[] iv, byte[] aad, byte[] authTag, int dataLength)
 */
JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1AuthDecInit
(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle, jint algID, jbyteArray iv, jbyteArray aad, jbyteArray authTag, jint dataLength) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_AuthDecInit == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    /* Convert IV */
    BYTE *iv_buf = NULL;
    jsize iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (BYTE*)malloc(iv_len);
        if (iv_buf == NULL) {
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
        (*env)->GetByteArrayRegion(env, iv, 0, iv_len, (jbyte*)iv_buf);
    }

    /* Convert AAD */
    BYTE *aad_buf = NULL;
    jsize aad_len = 0;
    if (aad != NULL) {
        aad_len = (*env)->GetArrayLength(env, aad);
        aad_buf = (BYTE*)malloc(aad_len);
        if (aad_buf == NULL) {
            if (iv_buf != NULL) free(iv_buf);
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
        (*env)->GetByteArrayRegion(env, aad, 0, aad_len, (jbyte*)aad_buf);
    }

    /* Convert auth tag */
    BYTE *tag_buf = NULL;
    jsize tag_len = 0;
    if (authTag != NULL) {
        tag_len = (*env)->GetArrayLength(env, authTag);
        tag_buf = (BYTE*)malloc(tag_len);
        if (tag_buf == NULL) {
            if (iv_buf != NULL) free(iv_buf);
            if (aad_buf != NULL) free(aad_buf);
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
        (*env)->GetByteArrayRegion(env, authTag, 0, tag_len, (jbyte*)tag_buf);
    }

    LONG ret = g_sdf_functions.SDF_AuthDecInit(
        (HANDLE)sessionHandle,
        (HANDLE)keyHandle,
        (ULONG)algID,
        iv_buf,
        (ULONG)iv_len,
        aad_buf,
        (ULONG)aad_len,
        tag_buf,
        (ULONG)tag_len,
        (ULONG)dataLength
    );

    if (iv_buf != NULL) free(iv_buf);
    if (aad_buf != NULL) free(aad_buf);
    if (tag_buf != NULL) free(tag_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/**
 * 认证解密更新
 * SDF_AuthDecUpdate
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1AuthDecUpdate
(JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray data) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_AuthDecUpdate == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (data == NULL) {
        throw_sdf_exception_with_message(env, 0x01000006, "Data is null");
        return NULL;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, data, 0, data_len, (jbyte*)data_buf);

    /* Allocate output buffer */
    ULONG output_len = data_len + 128;
    BYTE *output_buf = (BYTE*)malloc(output_len);
    if (output_buf == NULL) {
        free(data_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_AuthDecUpdate(
        (HANDLE)sessionHandle,
        data_buf,
        (ULONG)data_len,
        output_buf,
        &output_len
    );

    free(data_buf);

    if (ret != SDR_OK) {
        free(output_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, output_buf, output_len);
    free(output_buf);

    return result;
}

/**
 * 认证解密结束
 * SDF_AuthDecFinal
 * Java signature: (long sessionHandle) -> byte[]
 * Note: auth tag was already passed in AuthDecInit
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1AuthDecFinal
(JNIEnv *env, jobject obj, jlong sessionHandle) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_AuthDecFinal == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* Allocate output buffer - must be large enough for plaintext data */
    ULONG output_len = 4096;  /* Allocate sufficient buffer size */
    BYTE *output_buf = (BYTE*)malloc(output_len);
    if (output_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    /* Print before calling SDF_AuthDecFinal */
    SDF_JNI_LOG("=== Before SDF_AuthDecFinal ===");
    SDF_JNI_LOG("  output_len (buffer size): %lu", output_len);

    LONG ret = g_sdf_functions.SDF_AuthDecFinal(
        (HANDLE)sessionHandle,
        output_buf,
        &output_len
    );

    /* Print output_buf after calling SDF_AuthDecFinal */
    SDF_JNI_LOG("=== After SDF_AuthDecFinal ===");
    SDF_JNI_LOG("  ret: 0x%08X", (unsigned int)ret);
    SDF_JNI_LOG("  output_len: %lu", output_len);
    if (output_buf != NULL && output_len > 0) {
        SDF_LOG_HEX("  output_buf (after)", output_buf, output_len);
    } else {
        SDF_JNI_LOG("  output_buf: empty (len=%lu)", output_len);
    }

    if (ret != SDR_OK) {
        free(output_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, output_buf, output_len);
    free(output_buf);

    return result;
}

/* ========================================================================
 * Hash Operations (Init/Update/Final)
 * ======================================================================== */
JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1HashInit
  (JNIEnv *env, jobject obj, jlong sessionHandle, jint algID, jobject publicKey, jbyteArray id) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_HashInit == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    /* 转换ECC公钥（可选，用于SM3 Z值计算）*/
    ECCrefPublicKey *native_key_ptr = NULL;
    ECCrefPublicKey native_key;
    if (publicKey != NULL) {
        if (!java_to_native_ECCPublicKey(env, publicKey, &native_key)) {
            throw_sdf_exception(env, 0x0100001D);
            return;
        }
        native_key_ptr = &native_key;
    }

    /* 获取用户ID（可选，用于SM3）*/
    BYTE *id_buf = NULL;
    ULONG id_len = 0;
    if (id != NULL) {
        id_len = (*env)->GetArrayLength(env, id);
        id_buf = (BYTE*)malloc(id_len);
        if (id_buf == NULL) {
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
        (*env)->GetByteArrayRegion(env, id, 0, id_len, (jbyte*)id_buf);
    }

    LONG ret = g_sdf_functions.SDF_HashInit((HANDLE)sessionHandle, algID,
                                             native_key_ptr, id_buf, id_len);

    if (id_buf) free(id_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1HashUpdate
  (JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray data) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_HashUpdate == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    if (data == NULL) {
        throw_sdf_exception(env, 0x0100001D);
        return;
    }

    /* 获取输入数据 */
    jsize data_len = (*env)->GetArrayLength(env, data);
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return;
    }
    (*env)->GetByteArrayRegion(env, data, 0, data_len, (jbyte*)data_buf);

    LONG ret = g_sdf_functions.SDF_HashUpdate((HANDLE)sessionHandle, data_buf, data_len);

    free(data_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1HashFinal
  (JNIEnv *env, jobject obj, jlong sessionHandle) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_HashFinal == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* 分配哈希值缓冲区（SM3为32字节，SHA256也是32字节）*/
    ULONG hash_len = 64;  /* 预留足够空间 */
    BYTE *hash_buf = (BYTE*)malloc(hash_len);
    if (hash_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_HashFinal((HANDLE)sessionHandle, hash_buf, &hash_len);

    if (ret != SDR_OK) {
        free(hash_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, hash_buf, hash_len);
    free(hash_buf);
    return result;
}

