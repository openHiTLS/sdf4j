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
#include "jni_cache.h"

/* ========================================================================
 * Symmetric Algorithm Functions
 * All symmetric encryption, decryption, MAC, HMAC, and hash operations
 * ======================================================================== */

/* ========================================================================
 * Multi-package Encrypt Operations (Init/Update/Final)
 * ======================================================================== */
JNIEXPORT void JNICALL JNI_SDF_EncryptInit(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle,
    jint algID, jbyteArray iv) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_EncryptInit == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    /* 转换IV参数（可能为NULL，ECB模式不需要IV）*/
    jbyte *iv_buf = NULL;
    jsize iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (*env)->GetPrimitiveArrayCritical(env, iv, NULL);
        if (iv_buf == NULL) {
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
    }

    LONG ret = g_sdf_functions.SDF_EncryptInit(
        (HANDLE)sessionHandle,
        (HANDLE)keyHandle,
        (ULONG)algID,
        (BYTE*)iv_buf,
        (ULONG)iv_len
    );

    if (iv_buf != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
    }

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/**
 * 6.5.8 多包对称加密更新
 * Pattern: Byte array I/O with dynamic output length
 */
JNIEXPORT jbyteArray JNICALL JNI_SDF_EncryptUpdate(JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray data) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_EncryptUpdate == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (data == NULL) {
        throw_sdf_exception_with_message(env, 0x01000001, "Data is null");
        return NULL;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);
    jbyte *data_buf = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    /* 密文长度可能大于明文（填充），分配足够空间 */
    ULONG enc_len = data_len + 32;  /* 预留填充空间 */
    BYTE *enc_buf = (BYTE*)malloc(enc_len);
    if (enc_buf == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_EncryptUpdate(
        (HANDLE)sessionHandle,
        (BYTE*)data_buf,
        (ULONG)data_len,
        enc_buf,
        &enc_len
    );

    (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);

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
JNIEXPORT jbyteArray JNICALL JNI_SDF_EncryptFinal(JNIEnv *env, jobject obj, jlong sessionHandle) {
    UNUSED(obj);

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
JNIEXPORT void JNICALL JNI_SDF_HMACInit(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle, jint algID) {
    UNUSED(obj);

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
JNIEXPORT jbyteArray JNICALL JNI_SDF_Encrypt(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle,
    jint algID, jbyteArray iv, jbyteArray data) {
    UNUSED(obj);

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

    jbyte *data_buf = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    if (data_buf == NULL) {
        SDF_LOG_ERROR("SDF_Encrypt", "Memory allocation failed for data");
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    /* 获取IV（可选）*/
    jbyte *iv_buf = NULL;
    if (iv != NULL) {
        iv_buf = (*env)->GetPrimitiveArrayCritical(env, iv, NULL);
        if (iv_buf == NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
            SDF_LOG_ERROR("SDF_Encrypt", "GetPrimitiveArrayCritical failed for iv");
            throw_sdf_exception(env, 0x0100001C);
            return NULL;
        }
    }

    /* 分配输出内存，入参保证为16的整数倍，接口不负责填充*/
    ULONG enc_data_len = data_len;
    jbyteArray result = (*env)->NewByteArray(env, data_len);
    if (result == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
        if (iv_buf != NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
        }
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    /* 获取输出数组指针 */
    BYTE *enc_data_buf = (BYTE*)(*env)->GetPrimitiveArrayCritical(env, result, NULL);
    if (enc_data_buf == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
        if (iv_buf != NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
        }
        (*env)->DeleteLocalRef(env, result);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_Encrypt((HANDLE)sessionHandle, (HANDLE)keyHandle,
                                            algID, (BYTE*)iv_buf, (BYTE*)data_buf, data_len,
                                            enc_data_buf, &enc_data_len);

    (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
    if (iv_buf != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
    }

    if (ret != SDR_OK) {
        (*env)->ReleasePrimitiveArrayCritical(env, result, enc_data_buf, JNI_ABORT);
        (*env)->DeleteLocalRef(env, result);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    (*env)->ReleasePrimitiveArrayCritical(env, result, enc_data_buf, 0);
    SDF_JNI_LOG("SDF_Encrypt: output_len=%lu", enc_data_len);
    SDF_LOG_HEX("SDF_Encrypt ciphertext", enc_data_buf, enc_data_len);
    return result;
}

JNIEXPORT jbyteArray JNICALL JNI_SDF_Decrypt(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle,
    jint algID, jbyteArray iv, jbyteArray encData) {
    UNUSED(obj);

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

    jbyte *enc_data_buf = (*env)->GetPrimitiveArrayCritical(env, encData, NULL);
    if (enc_data_buf == NULL) {
        SDF_LOG_ERROR("SDF_Decrypt", "GetPrimitiveArrayCritical failed for encData");
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    /* 获取IV（可选）*/
    jbyte *iv_buf = NULL;
    if (iv != NULL) {
        iv_buf = (*env)->GetPrimitiveArrayCritical(env, iv, NULL);
        if (iv_buf == NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, encData, enc_data_buf, JNI_ABORT);
            SDF_LOG_ERROR("SDF_Decrypt", "GetPrimitiveArrayCritical failed for iv");
            throw_sdf_exception(env, 0x0100001C);
            return NULL;
        }
    }

    /* 分配输出缓冲区 */
    ULONG data_len = enc_data_len;

    /* 直接创建 Java 数组 */
    jbyteArray result = (*env)->NewByteArray(env, data_len);
    if (result == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, encData, enc_data_buf, JNI_ABORT);
        if (iv_buf != NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
        }
        SDF_LOG_ERROR("SDF_Decrypt", "Failed to create result array");
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    /* 获取输出数组指针 */
    BYTE *data_buf = (BYTE*)(*env)->GetPrimitiveArrayCritical(env, result, NULL);
    if (data_buf == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, encData, enc_data_buf, JNI_ABORT);
        if (iv_buf != NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
        }
        (*env)->DeleteLocalRef(env, result);
        SDF_LOG_ERROR("SDF_Decrypt", "GetPrimitiveArrayCritical failed for result array");
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_Decrypt((HANDLE)sessionHandle, (HANDLE)keyHandle,
                                            algID, (BYTE*)iv_buf, (BYTE*)enc_data_buf, enc_data_len,
                                            data_buf, &data_len);

    (*env)->ReleasePrimitiveArrayCritical(env, encData, enc_data_buf, JNI_ABORT);
    if (iv_buf != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
    }

    if (ret != SDR_OK) {
        (*env)->ReleasePrimitiveArrayCritical(env, result, data_buf, JNI_ABORT);
        (*env)->DeleteLocalRef(env, result);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    (*env)->ReleasePrimitiveArrayCritical(env, result, data_buf, 0);
    SDF_JNI_LOG("SDF_Decrypt: output_len=%lu", data_len);
    SDF_LOG_HEX("SDF_Decrypt plaintext", data_buf, data_len);
    return result;
}

/* ========================================================================
 * Multi-package Decrypt Operations (Init/Update/Final)
 * ======================================================================== */
JNIEXPORT void JNICALL JNI_SDF_DecryptInit(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle,
    jint algID, jbyteArray iv) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_DecryptInit == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    BYTE *iv_buf = NULL;
    jsize iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (*env)->GetPrimitiveArrayCritical(env, iv, NULL);
        if (iv_buf == NULL) {
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
    }

    LONG ret = g_sdf_functions.SDF_DecryptInit(
        (HANDLE)sessionHandle,
        (HANDLE)keyHandle,
        (ULONG)algID,
        (BYTE*)iv_buf,
        (ULONG)iv_len
    );

    if (iv_buf != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
    }

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/**
 * 6.5.11 多包对称解密更新
 */
JNIEXPORT jbyteArray JNICALL JNI_SDF_DecryptUpdate(JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray encData) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_DecryptUpdate == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (encData == NULL) {
        throw_sdf_exception_with_message(env, 0x01000001, "Encrypted data is null");
        return NULL;
    }

    jsize enc_len = (*env)->GetArrayLength(env, encData);
    jbyte *enc_buf = (*env)->GetPrimitiveArrayCritical(env, encData, NULL);
    if (enc_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    ULONG data_len = enc_len + 32;
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, encData, enc_buf, JNI_ABORT);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_DecryptUpdate(
        (HANDLE)sessionHandle,
        (BYTE*)enc_buf,
        (ULONG)enc_len,
        data_buf,
        &data_len
    );

    (*env)->ReleasePrimitiveArrayCritical(env, encData, enc_buf, JNI_ABORT);

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
JNIEXPORT jbyteArray JNICALL JNI_SDF_DecryptFinal(JNIEnv *env, jobject obj, jlong sessionHandle) {
    UNUSED(obj);

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
JNIEXPORT jbyteArray JNICALL JNI_SDF_CalculateMAC(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle,
    jint algID, jbyteArray iv, jbyteArray data) {
    UNUSED(obj);

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
    jbyte *data_buf = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    if (data_buf == NULL) {
        SDF_LOG_ERROR("SDF_CalculateMAC", "Failed to allocate memory for data buffer");
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    /* 获取IV（可选）*/
    jbyte *iv_buf = NULL;
    if (iv != NULL) {
        iv_buf = (*env)->GetPrimitiveArrayCritical(env, iv, NULL);
        if (iv_buf == NULL) {
            SDF_LOG_ERROR("SDF_CalculateMAC", "Failed to allocate memory for IV buffer");
            (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
            throw_sdf_exception(env, 0x0100001C);
            return NULL;
        }
    } else {
        SDF_JNI_LOG("  iv: NULL (no IV provided)");
    }

    /* 分配MAC缓冲区 */
    ULONG mac_len = 64;  /* SM4-CBC-MAC 通常为16字节,可能是必须要传入固定64 TODO */

    BYTE *mac_buf = (BYTE*)malloc(mac_len);
    if (mac_buf == NULL) {
        SDF_LOG_ERROR("SDF_CalculateMAC", "Failed to allocate memory for MAC buffer");
        (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
        if (iv_buf) {
            (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
        }
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_CalculateMAC((HANDLE)sessionHandle, (HANDLE)keyHandle,
                                                 algID, (BYTE *)iv_buf, (BYTE *)data_buf, data_len,
                                                 mac_buf, &mac_len);

    (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
    if (iv_buf) {
        (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
    }

    if (ret != SDR_OK) {
        SDF_LOG_ERROR("SDF_CalculateMAC", "Native function failed");
        SDF_LOG_EXIT("SDF_CalculateMAC", ret);
        free(mac_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, mac_buf, mac_len);
    free(mac_buf);

    if (result != NULL) {
        SDF_JNI_LOG("Successfully created Java byte array for MAC result");
    } else {
        SDF_LOG_ERROR("SDF_CalculateMAC", "Failed to create Java byte array");
    }

    return result;
}

/* ========================================================================
 * Multi-package MAC Operations (Init/Update/Final)
 * ======================================================================== */
JNIEXPORT void JNICALL JNI_SDF_CalculateMACInit(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle,
    jint algID, jbyteArray iv) {
    UNUSED(obj);


    if (g_sdf_functions.SDF_CalculateMACInit == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    jbyte *iv_buf = NULL;
    jsize iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (*env)->GetPrimitiveArrayCritical(env, iv, NULL);
        if (iv_buf == NULL) {
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
    }

    LONG ret = g_sdf_functions.SDF_CalculateMACInit(
        (HANDLE)sessionHandle,
        (HANDLE)keyHandle,
        (ULONG)algID,
        (BYTE*)iv_buf,
        (ULONG)iv_len
    );

    if (iv_buf != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
    }

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/**
 * 6.5.14 多包MAC计算更新
 */
JNIEXPORT void JNICALL JNI_SDF_CalculateMACUpdate(JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray data) {
    UNUSED(obj);


    if (g_sdf_functions.SDF_CalculateMACUpdate == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    if (data == NULL) {
        throw_sdf_exception_with_message(env, 0x01000001, "Data is null");
        return;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);
    jbyte *data_buf = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return;
    }

    LONG ret = g_sdf_functions.SDF_CalculateMACUpdate(
        (HANDLE)sessionHandle,
        (BYTE*)data_buf,
        (ULONG)data_len
    );

    (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/**
 * 6.5.15 多包MAC计算结束
 */
JNIEXPORT jbyteArray JNICALL JNI_SDF_CalculateMACFinal(JNIEnv *env, jobject obj, jlong sessionHandle) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_CalculateMACFinal == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    ULONG mac_len = 32;
    BYTE mac_buf[32];

    LONG ret = g_sdf_functions.SDF_CalculateMACFinal(
        (HANDLE)sessionHandle,
        mac_buf,
        &mac_len
    );

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return NULL;
    }

    return native_to_java_byte_array(env, mac_buf, mac_len);
}

/* ========================================================================
 * HMAC Update/Final Operations
 * ======================================================================== */
JNIEXPORT void JNICALL JNI_SDF_HMACUpdate(JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray data) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_HMACUpdate == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    if (data == NULL) {
        throw_sdf_exception_with_message(env, 0x01000001, "Data is null");
        return;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);
    jbyte *data_buf = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return;
    }

    LONG ret = g_sdf_functions.SDF_HMACUpdate(
        (HANDLE)sessionHandle,
        (BYTE*)data_buf,
        (ULONG)data_len
    );

    (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/**
 * 6.6.7 HMAC结束
 */
JNIEXPORT jbyteArray JNICALL JNI_SDF_HMACFinal(JNIEnv *env, jobject obj, jlong sessionHandle) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_HMACFinal == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    ULONG hmac_len = 64;
    BYTE hmac_buf[64];
    LONG ret = g_sdf_functions.SDF_HMACFinal(
        (HANDLE)sessionHandle,
        hmac_buf,
        &hmac_len
    );

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return NULL;
    }

    return native_to_java_byte_array(env, hmac_buf, hmac_len);
}

/* ========================================================================
 * Authenticated Encryption Operations
 * ======================================================================== */
JNIEXPORT jobjectArray JNICALL JNI_SDF_AuthEnc(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle,
    jint algID, jbyteArray iv, jbyteArray aad, jbyteArray data) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_AuthEnc == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (data == NULL) {
        throw_sdf_exception_with_message(env, 0x01000006, "Data is null");
        return NULL;
    }

    /* Convert IV */
    jbyte *iv_buf = NULL;
    jsize iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (*env)->GetPrimitiveArrayCritical(env, iv, NULL);
        if (iv_buf == NULL) {
            throw_sdf_exception(env, 0x0100001C);
            return NULL;
        }
    }

    /* Convert AAD */
    jbyte *aad_buf = NULL;
    jsize aad_len = 0;
    if (aad != NULL) {
        aad_len = (*env)->GetArrayLength(env, aad);
        aad_buf = (*env)->GetPrimitiveArrayCritical(env, aad, NULL);
        if (aad_buf == NULL) {
            if (iv_buf != NULL) {
                (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
            }
            throw_sdf_exception(env, 0x0100001C);
            return NULL;
        }
    }

    /* Convert data */
    jsize data_len = (*env)->GetArrayLength(env, data);
    jbyte *data_buf = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    if (data_buf == NULL) {
        if (iv_buf != NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
        }
        if (aad_buf != NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, aad, aad_buf, JNI_ABORT);
        }
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    /* Allocate output buffers */
    ULONG enc_len = data_len;  /* Data + possible padding + extra space */
    BYTE *enc_buf = (BYTE*)malloc(enc_len);
    if (enc_buf == NULL) {
        if (iv_buf != NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
        }
        if (aad_buf != NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, aad, aad_buf, JNI_ABORT);
        }
        (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    ULONG tag_len = 16;  /* GCM tag size is 16 bytes */
    BYTE *tag_buf = (BYTE*)malloc(tag_len);
    if (tag_buf == NULL) {
        if (iv_buf != NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
        }
        if (aad_buf != NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, aad, aad_buf, JNI_ABORT);
        }
        (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
        free(enc_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_AuthEnc(
        (HANDLE)sessionHandle,
        (HANDLE)keyHandle,
        (ULONG)algID,
        (BYTE*)iv_buf,
        (ULONG)iv_len,
        (BYTE*)aad_buf,
        (ULONG)aad_len,
        (BYTE*)data_buf,
        (ULONG)data_len,
        enc_buf,
        &enc_len,
        tag_buf,
        &tag_len
    );

    if (iv_buf != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
    }
    if (aad_buf != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aad_buf, JNI_ABORT);
    }
    (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);

    if (ret != SDR_OK) {
        free(enc_buf);
        free(tag_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jobjectArray result = (*env)->NewObjectArray(env, 2, g_jni_cache.common.byteArrayClass, NULL);
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
JNIEXPORT jbyteArray JNICALL JNI_SDF_AuthDec(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle,
    jint algID, jbyteArray iv, jbyteArray aad, jbyteArray authTag,
    jbyteArray encData) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_AuthDec == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (encData == NULL || authTag == NULL) {
        throw_sdf_exception_with_message(env, 0x01000006, "Encrypted data or auth tag is null");
        return NULL;
    }

    /* Convert IV */
    jbyte *iv_buf = NULL;
    jsize iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (*env)->GetPrimitiveArrayCritical(env, iv, NULL);
        if (iv_buf == NULL) {
            throw_sdf_exception(env, 0x0100001C);
            return NULL;
        }
    }

    /* Convert AAD */
    jbyte *aad_buf = NULL;
    jsize aad_len = 0;
    if (aad != NULL) {
        aad_len = (*env)->GetArrayLength(env, aad);
        aad_buf = (*env)->GetPrimitiveArrayCritical(env, aad, NULL);
        if (aad_buf == NULL) {
            if (iv_buf != NULL) {
                (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
            }
            throw_sdf_exception(env, 0x0100001C);
            return NULL;
        }
    }

    /* Convert auth tag */
    jsize tag_len = (*env)->GetArrayLength(env, authTag);
    jbyte *tag_buf = (*env)->GetPrimitiveArrayCritical(env, authTag, NULL);
    if (tag_buf == NULL) {
        if (iv_buf != NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
        }
        if (aad_buf != NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, aad, aad_buf, JNI_ABORT);
        }
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    /* Convert encrypted data */
    jsize enc_len = (*env)->GetArrayLength(env, encData);
    jbyte *enc_buf = (*env)->GetPrimitiveArrayCritical(env, encData, NULL);
    if (enc_buf == NULL) {
        if (iv_buf != NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
        }
        if (aad_buf != NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, aad, aad_buf, JNI_ABORT);
        }
        (*env)->ReleasePrimitiveArrayCritical(env, authTag, tag_buf, JNI_ABORT);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    /* Allocate output buffer for plaintext */
    ULONG plaintext_len = enc_len;
    BYTE *plaintext_buf = (BYTE*)malloc(plaintext_len);
    if (plaintext_buf == NULL) {
        if (iv_buf != NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
        }
        if (aad_buf != NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, aad, aad_buf, JNI_ABORT);
        }
        (*env)->ReleasePrimitiveArrayCritical(env, authTag, tag_buf, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, encData, enc_buf, JNI_ABORT);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_AuthDec(
        (HANDLE)sessionHandle,
        (HANDLE)keyHandle,
        (ULONG)algID,
        (BYTE*)iv_buf,
        (ULONG)iv_len,
        (BYTE*)aad_buf,
        (ULONG)aad_len,
        (BYTE*)tag_buf,
        (ULONG *)&tag_len,
        (BYTE*)enc_buf,
        (ULONG)enc_len,
        plaintext_buf,
        &plaintext_len
    );

    if (iv_buf != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
    }
    if (aad_buf != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aad_buf, JNI_ABORT);
    }
    (*env)->ReleasePrimitiveArrayCritical(env, authTag, tag_buf, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, encData, enc_buf, JNI_ABORT);

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
JNIEXPORT void JNICALL JNI_SDF_AuthEncInit(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle,
    jint algID, jbyteArray iv, jbyteArray aad, jint dataLength) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_AuthEncInit == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    /* Convert IV */
    jbyte *iv_buf = NULL;
    jsize iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (*env)->GetPrimitiveArrayCritical(env, iv, NULL);
        if (iv_buf == NULL) {
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
    }

    /* Convert AAD (Additional Authenticated Data) */
    jbyte *aad_buf = NULL;
    jsize aad_len = 0;
    if (aad != NULL) {
        aad_len = (*env)->GetArrayLength(env, aad);
        aad_buf = (*env)->GetPrimitiveArrayCritical(env, aad, NULL);
        if (aad_buf == NULL) {
            if (iv_buf != NULL) {
                (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
            }
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
    }

    LONG ret = g_sdf_functions.SDF_AuthEncInit(
        (HANDLE)sessionHandle,
        (HANDLE)keyHandle,
        (ULONG)algID,
        (BYTE*)iv_buf,
        (ULONG)iv_len,
        (BYTE*)aad_buf,
        (ULONG)aad_len,
        (ULONG)dataLength
    );

    if (iv_buf != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
    }
    if (aad_buf != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aad_buf, JNI_ABORT);
    }

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/**
 * 认证加密更新
 * SDF_AuthEncUpdate
 */
JNIEXPORT jbyteArray JNICALL JNI_SDF_AuthEncUpdate(JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray data) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_AuthEncUpdate == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (data == NULL) {
        throw_sdf_exception_with_message(env, 0x01000006, "Data is null");
        return NULL;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);
    jbyte *data_buf = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    /* Allocate output buffer (worst case: same size as input + block size) */
    ULONG output_len = data_len + 128;
    BYTE *output_buf = (BYTE*)malloc(output_len);
    if (output_buf == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_AuthEncUpdate(
        (HANDLE)sessionHandle,
        (BYTE*)data_buf,
        (ULONG)data_len,
        output_buf,
        &output_len
    );

    (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);

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
JNIEXPORT jobjectArray JNICALL JNI_SDF_AuthEncFinal(JNIEnv *env, jobject obj, jlong sessionHandle,
    jbyteArray pucEncData) {
    UNUSED(obj);

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

    LONG ret = g_sdf_functions.SDF_AuthEncFinal(
        (HANDLE)sessionHandle,
        output_buf,
        &output_len,
        tag_buf,
        &tag_len
    );

    if (ret != SDR_OK) {
        if (output_buf != NULL) free(output_buf);
        free(tag_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jobjectArray result = (*env)->NewObjectArray(env, 2, g_jni_cache.common.byteArrayClass, NULL);
    if (result == NULL) {
        if (output_buf != NULL) free(output_buf);
        free(tag_buf);
        return NULL;
    }

    /* Set [0] = final encrypted data */
    jbyteArray encData = (output_buf != NULL) ? native_to_java_byte_array(env, output_buf, output_len) : NULL;
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
JNIEXPORT void JNICALL JNI_SDF_AuthDecInit(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle,
    jint algID, jbyteArray iv, jbyteArray aad, jbyteArray authTag,
    jint dataLength) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_AuthDecInit == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    /* Convert IV */
    jbyte *iv_buf = NULL;
    jsize iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (*env)->GetPrimitiveArrayCritical(env, iv, NULL);
        if (iv_buf == NULL) {
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
    }

    /* Convert AAD */
    jbyte *aad_buf = NULL;
    jsize aad_len = 0;
    if (aad != NULL) {
        aad_len = (*env)->GetArrayLength(env, aad);
        aad_buf = (*env)->GetPrimitiveArrayCritical(env, aad, NULL);
        if (aad_buf == NULL) {
            if (iv_buf != NULL) {
                (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
            }
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
    }

    /* Convert auth tag */
    jbyte *tag_buf = NULL;
    jsize tag_len = 0;
    if (authTag != NULL) {
        tag_len = (*env)->GetArrayLength(env, authTag);
        tag_buf = (*env)->GetPrimitiveArrayCritical(env, authTag, NULL);
        if (tag_buf == NULL) {
            if (iv_buf != NULL) {
                (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
            }
            if (aad_buf != NULL) {
                (*env)->ReleasePrimitiveArrayCritical(env, aad, aad_buf, JNI_ABORT);
            }
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
    }

    LONG ret = g_sdf_functions.SDF_AuthDecInit(
        (HANDLE)sessionHandle,
        (HANDLE)keyHandle,
        (ULONG)algID,
        (BYTE*)iv_buf,
        (ULONG)iv_len,
        (BYTE*)aad_buf,
        (ULONG)aad_len,
        (BYTE*)tag_buf,
        (ULONG)tag_len,
        (ULONG)dataLength
    );

    if (iv_buf != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
    }
    if (aad_buf != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aad_buf, JNI_ABORT);
    }
    if (tag_buf != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, authTag, tag_buf, JNI_ABORT);
    }

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/**
 * 认证解密更新
 * SDF_AuthDecUpdate
 */
JNIEXPORT jbyteArray JNICALL JNI_SDF_AuthDecUpdate(JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray data) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_AuthDecUpdate == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (data == NULL) {
        throw_sdf_exception_with_message(env, 0x01000006, "Data is null");
        return NULL;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);
    jbyte *data_buf = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    /* Allocate output buffer */
    ULONG output_len = data_len + 128;
    BYTE *output_buf = (BYTE*)malloc(output_len);
    if (output_buf == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_AuthDecUpdate(
        (HANDLE)sessionHandle,
        (BYTE*)data_buf,
        (ULONG)data_len,
        output_buf,
        &output_len
    );

    (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);

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
JNIEXPORT jbyteArray JNICALL JNI_SDF_AuthDecFinal(JNIEnv *env, jobject obj, jlong sessionHandle) {
    UNUSED(obj);

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

    LONG ret = g_sdf_functions.SDF_AuthDecFinal(
        (HANDLE)sessionHandle,
        output_buf,
        &output_len
    );

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
JNIEXPORT void JNICALL JNI_SDF_HashInit(JNIEnv *env, jobject obj, jlong sessionHandle, jint algID, jobject publicKey,
    jbyteArray id) {
    UNUSED(obj);


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
        id_buf = (*env)->GetPrimitiveArrayCritical(env, id, NULL);
        if (id_buf == NULL) {
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
    }

    LONG ret = g_sdf_functions.SDF_HashInit((HANDLE)sessionHandle, algID,
                                             native_key_ptr, id_buf, id_len);

    if (id_buf != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, id, id_buf, JNI_ABORT);
    }

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

JNIEXPORT void JNICALL JNI_SDF_HashUpdate(JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray data) {
    UNUSED(obj);
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
    jbyte *data_buf = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return;
    }

    LONG ret = g_sdf_functions.SDF_HashUpdate((HANDLE)sessionHandle, (BYTE *)data_buf, data_len);

    (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

JNIEXPORT jbyteArray JNICALL JNI_SDF_HashFinal(JNIEnv *env, jobject obj, jlong sessionHandle) {
    UNUSED(obj);
    if (g_sdf_functions.SDF_HashFinal == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* 分配哈希值缓冲区（SM3为32字节，SHA256也是32字节）*/
    ULONG hash_len = 64;  /* 预留足够空间 */
    BYTE hash_buf[64];

    LONG ret = g_sdf_functions.SDF_HashFinal((HANDLE)sessionHandle, hash_buf, &hash_len);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return NULL;
    }
    return native_to_java_byte_array(env, hash_buf, hash_len);
}

