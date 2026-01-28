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
 * Asymmetric Algorithm Functions - ECC and RSA Operations
 * ======================================================================== */

/* ========================================================================
 * ECC Operations (Sign/Verify/Encrypt)
 * ======================================================================== */
JNIEXPORT jobject JNICALL JNI_SDF_InternalSign_ECC(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex,
    jbyteArray data) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_InternalSign_ECC == NULL) {
        SDF_LOG_ERROR("SDF_InternalSign_ECC", "Function not supported");
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (data == NULL) {
        SDF_LOG_ERROR("SDF_InternalSign_ECC", "Invalid argument: data is NULL");
        throw_sdf_exception(env, 0x0100001D);  /* SDR_INARGERR */
        return NULL;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);

    jbyte *data_buf = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    if (data_buf == NULL) {
        SDF_LOG_ERROR("SDF_InternalSign_ECC", "GetPrimitiveArrayCritical failed");
        throw_sdf_exception(env, 0x0100001C);  /* SDR_NOBUFFER */
        return NULL;
    }

    ECCSignature signature = {0};
    LONG ret = g_sdf_functions.SDF_InternalSign_ECC((HANDLE)sessionHandle, keyIndex,
                                                     (BYTE*)data_buf, data_len, &signature);
    (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return NULL;
    }
    SDF_LOG_HEX("SDF_InternalSign_ECC signature.r", signature.r, ECCref_MAX_LEN);
    SDF_LOG_HEX("SDF_InternalSign_ECC signature.s", signature.s, ECCref_MAX_LEN);
    return native_to_java_ECCSignature(env, &signature);
}

JNIEXPORT void JNICALL JNI_SDF_InternalVerify_ECC(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex,
    jbyteArray data, jobject signature) {
    UNUSED(obj);
    if (g_sdf_functions.SDF_InternalVerify_ECC == NULL) {
        SDF_LOG_ERROR("SDF_InternalVerify_ECC", "Function not supported");
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    if (data == NULL || signature == NULL) {
        SDF_LOG_ERROR("SDF_InternalVerify_ECC", "Invalid argument: data or signature is NULL");
        throw_sdf_exception(env, 0x0100001D);  /* SDR_INARGERR */
        return;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);

    jbyte *data_buf = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    if (data_buf == NULL) {
        SDF_LOG_ERROR("SDF_InternalVerify_ECC", "GetPrimitiveArrayCritical failed");
        throw_sdf_exception(env, 0x0100001C);  /* SDR_NOBUFFER */
        return;
    }

    ECCSignature native_sig = {0};
    if (!java_to_native_ECCSignature(env, signature, &native_sig)) {
        (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
        SDF_LOG_ERROR("SDF_InternalVerify_ECC", "Failed to convert signature");
        throw_sdf_exception(env, 0x0100001D);  /* SDR_INARGERR */
        return;
    }

    LONG ret = g_sdf_functions.SDF_InternalVerify_ECC((HANDLE)sessionHandle, keyIndex,
                                                       (BYTE*)data_buf, data_len, &native_sig);

    (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

JNIEXPORT void JNICALL JNI_SDF_ExternalVerify_ECC(JNIEnv *env, jobject obj, jlong sessionHandle, jint algID,
    jobject publicKey, jbyteArray data, jobject signature) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_ExternalVerify_ECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    if (publicKey == NULL || data == NULL || signature == NULL) {
        throw_sdf_exception(env, 0x0100001D);  /* SDR_INARGERR */
        return;
    }

    ECCrefPublicKey native_key;
    if (!java_to_native_ECCPublicKey(env, publicKey, &native_key)) {
        throw_sdf_exception(env, 0x0100001D);
        return;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);
    jbyte *data_buf = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return;
    }

    ECCSignature native_sig = {0};
    if (!java_to_native_ECCSignature(env, signature, &native_sig)) {
        (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
        throw_sdf_exception(env, 0x0100001D);
        return;
    }

    LONG ret = g_sdf_functions.SDF_ExternalVerify_ECC((HANDLE)sessionHandle, algID,
                                                       &native_key, (BYTE*)data_buf, data_len,
                                                       &native_sig);

    (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

JNIEXPORT jobject JNICALL JNI_SDF_ExternalEncrypt_ECC(JNIEnv *env, jobject obj, jlong sessionHandle, jint algID,
    jobject publicKey, jbyteArray data) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_ExternalEncrypt_ECC == NULL) {
        SDF_LOG_ERROR("SDF_ExternalEncrypt_ECC", "Function not supported");
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (publicKey == NULL || data == NULL) {
        SDF_LOG_ERROR("SDF_ExternalEncrypt_ECC", "Invalid argument: publicKey or data is NULL");
        throw_sdf_exception(env, 0x0100001D);
        return NULL;
    }

    ECCrefPublicKey native_key;
    if (!java_to_native_ECCPublicKey(env, publicKey, &native_key)) {
        SDF_LOG_ERROR("SDF_ExternalEncrypt_ECC", "Failed to convert ECCPublicKey");
        throw_sdf_exception(env, 0x0100001D);
        return NULL;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);

    jbyte *data_buf = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    if (data_buf == NULL) {
        SDF_LOG_ERROR("SDF_ExternalEncrypt_ECC", "GetPrimitiveArrayCritical failed");
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    /* 分配ECCCipher结构 + 密文空间 + 额外空间*/
    ECCCipher *cipher = (ECCCipher*)calloc(1,sizeof(ECCCipher) + data_len);
    if (cipher == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
        SDF_LOG_ERROR("SDF_ExternalEncrypt_ECC", "Memory allocation failed for cipher");
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    cipher->L = data_len;
    LONG ret = g_sdf_functions.SDF_ExternalEncrypt_ECC((HANDLE)sessionHandle, algID,
                                                        &native_key, (BYTE*)data_buf, data_len,
                                                        cipher);

    (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);

    if (ret != SDR_OK) {
        SDF_JNI_LOG("SDF_ExternalEncrypt_ECC: SDF function returned error 0x%08X", (unsigned int)ret);
        free(cipher);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jobject result = native_to_java_ECCCipher(env, cipher, cipher->L);
    free(cipher);
    return result;
}

/**
 * 6.4.9 内部公钥ECC加密
 * SDF_InternalEncrypt_ECC
 */
JNIEXPORT jobject JNICALL JNI_SDF_InternalEncrypt_ECC(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex,
    jbyteArray data) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_InternalEncrypt_ECC == NULL) {
        SDF_LOG_ERROR("SDF_InternalEncrypt_ECC", "Function not supported");
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (data == NULL) {
        SDF_LOG_ERROR("SDF_InternalEncrypt_ECC", "Invalid argument: data is NULL");
        throw_sdf_exception(env, 0x0100001D);  /* SDR_INARGERR */
        return NULL;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);

    jbyte *data_buf = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    if (data_buf == NULL) {
        SDF_LOG_ERROR("SDF_InternalEncrypt_ECC", "GetPrimitiveArrayCritical failed");
        throw_sdf_exception(env, 0x0100001C);  /* SDR_NOBUFFER */
        return NULL;
    }

    /* 分配ECCCipher结构 + 密文空间 */
    ECCCipher *cipher = (ECCCipher*)calloc(1, sizeof(ECCCipher) + data_len);
    if (cipher == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
        SDF_LOG_ERROR("SDF_InternalEncrypt_ECC", "Memory allocation failed for cipher");
        throw_sdf_exception(env, 0x0100001C);  /* SDR_NOBUFFER */
        return NULL;
    }
    cipher->L = data_len ;
    LONG ret = g_sdf_functions.SDF_InternalEncrypt_ECC((HANDLE)sessionHandle, keyIndex,
        (BYTE*)data_buf, data_len, cipher);

    (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
    if (ret != SDR_OK) {
        SDF_JNI_LOG("SDF_InternalEncrypt_ECC: SDF function returned error 0x%08X", (unsigned int)ret);
        free(cipher);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jobject result = native_to_java_ECCCipher(env, cipher, cipher->L);
    free(cipher);
    return result;
}

/**
 * 6.4.10 内部私钥ECC解密
 * SDF_InternalDecrypt_ECC
 */
JNIEXPORT jbyteArray JNICALL JNI_SDF_InternalDecrypt_ECC(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint keyIndex, jint eccKeyType, jobject cipher) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_InternalDecrypt_ECC == NULL) {
        SDF_LOG_ERROR("SDF_InternalDecrypt_ECC", "Function not supported");
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (cipher == NULL) {
        SDF_LOG_ERROR("SDF_InternalDecrypt_ECC", "Invalid argument: cipher is NULL");
        throw_sdf_exception(env, 0x0100001D);  /* SDR_INARGERR */
        return NULL;
    }

    /* 转换Java ECCCipher到C结构 (使用动态分配以支持柔性数组成员) */
    ECCCipher *ecc_cipher = java_to_native_ECCCipher_alloc(env, cipher);
    if (ecc_cipher == NULL) {
        SDF_LOG_ERROR("SDF_InternalDecrypt_ECC", "Failed to convert ECCCipher");
        throw_sdf_exception(env, 0x0100001D);  /* SDR_INARGERR */
        return NULL;
    }

    /* 分配输出缓冲区 */
    ULONG data_len = ecc_cipher->L + 64;
    BYTE *data_buf = (BYTE*)calloc(1, data_len);
    if (data_buf == NULL) {
        SDF_LOG_ERROR("SDF_InternalDecrypt_ECC", "Memory allocation failed for data_buf");
        free(ecc_cipher);
        throw_sdf_exception(env, 0x0100001C);  /* SDR_NOBUFFER */
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_InternalDecrypt_ECC((HANDLE)sessionHandle, keyIndex,
                                                        eccKeyType, ecc_cipher,
                                                        data_buf, &data_len);

    if (ret != SDR_OK) {
        SDF_JNI_LOG("SDF_InternalDecrypt_ECC: SDF function returned error 0x%08X", (unsigned int)ret);
        free(ecc_cipher);
        free(data_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, data_buf, data_len);
    free(ecc_cipher);
    free(data_buf);

    return result;
}

JNIEXPORT jobject JNICALL JNI_SDF_ExchangeDigitEnvelopeBaseOnECC(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint keyIndex, jint algID, jobject publicKey, jobject encDataIn) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_ExchangeDigitEnvelopeBaseOnECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (publicKey == NULL || encDataIn == NULL) {
        throw_sdf_exception(env, 0x0100001D);  /* SDR_INARGERR */
        return NULL;
    }

    ECCrefPublicKey native_pub;
    if (!java_to_native_ECCPublicKey(env, publicKey, &native_pub)) {
        throw_sdf_exception(env, 0x0100001D);
        return NULL;
    }

    ECCCipher *in_cipher = java_to_native_ECCCipher_alloc(env, encDataIn);
    if (in_cipher == NULL) {
        throw_sdf_exception(env, 0x0100001D);
        return NULL;
    }

    ULONG out_len = in_cipher->L;
    ECCCipher *out_cipher = (ECCCipher*)calloc(1, sizeof(ECCCipher) + out_len);
    if (out_cipher == NULL) {
        free(in_cipher);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    out_cipher->L = out_len;
    LONG ret = g_sdf_functions.SDF_ExchangeDigitEnvelopeBaseOnECC(
        (HANDLE)sessionHandle,
        (ULONG)keyIndex,
        (ULONG)algID,
        &native_pub,
        in_cipher,
        out_cipher
    );

    free(in_cipher);

    if (ret != SDR_OK) {
        free(out_cipher);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jobject result = native_to_java_ECCCipher(env, out_cipher, out_cipher->L);
    free(out_cipher);
    return result;
}

/* ========================================================================
 * RSA Operations (Public/Private Key Operations)
 * ======================================================================== */
JNIEXPORT jbyteArray JNICALL JNI_SDF_ExternalPublicKeyOperation_RSA(JNIEnv *env, jobject obj, jlong sessionHandle,
    jobject publicKey, jbyteArray dataInput) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_ExternalPublicKeyOperation_RSA == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (publicKey == NULL || dataInput == NULL) {
        throw_sdf_exception_with_message(env, 0x01000001, "Public key or data is null");
        return NULL;
    }

    /* 转换公钥 */
    RSArefPublicKey native_key;
    memset(&native_key, 0, sizeof(RSArefPublicKey));

    jclass key_class = (*env)->GetObjectClass(env, publicKey);
    
    /* 获取bits字段 */
    jfieldID bits_fid = (*env)->GetFieldID(env, key_class, "bits", "I");
    if (bits_fid == NULL) {
        throw_sdf_exception_with_message(env, 0x01000001, "Cannot get bits field");
        return NULL;
    }
    native_key.bits = (*env)->GetIntField(env, publicKey, bits_fid);

    /* 获取m字段 */
    jfieldID m_fid = (*env)->GetFieldID(env, key_class, "m", "[B");
    if (m_fid != NULL) {
        jbyteArray m_array = (jbyteArray)(*env)->GetObjectField(env, publicKey, m_fid);
        if (m_array != NULL) {
            jsize m_len = (*env)->GetArrayLength(env, m_array);
            if (m_len > RSAref_MAX_LEN) m_len = RSAref_MAX_LEN;
            (*env)->GetByteArrayRegion(env, m_array, 0, m_len, (jbyte*)native_key.m);
        }
    }

    /* 获取e字段 */
    jfieldID e_fid = (*env)->GetFieldID(env, key_class, "e", "[B");
    if (e_fid != NULL) {
        jbyteArray e_array = (jbyteArray)(*env)->GetObjectField(env, publicKey, e_fid);
        if (e_array != NULL) {
            jsize e_len = (*env)->GetArrayLength(env, e_array);
            if (e_len > RSAref_MAX_LEN) e_len = RSAref_MAX_LEN;
            (*env)->GetByteArrayRegion(env, e_array, 0, e_len, (jbyte*)native_key.e);
        }
    }

    /* 转换输入数据 */
    jsize input_len = (*env)->GetArrayLength(env, dataInput);
    BYTE *input_buf = (BYTE*)malloc(input_len);
    if (input_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, dataInput, 0, input_len, (jbyte*)input_buf);

    /* 分配输出缓冲区（RSA输出长度等于模长）*/
    ULONG output_len = (native_key.bits + 7) / 8;
    BYTE *output_buf = (BYTE*)malloc(output_len);
    if (output_buf == NULL) {
        free(input_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_ExternalPublicKeyOperation_RSA(
        (HANDLE)sessionHandle,
        &native_key,
        input_buf,
        (ULONG)input_len,
        output_buf,
        &output_len
    );

    free(input_buf);

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
 * 6.4.3 内部公钥RSA运算
 * SDF_InternalPublicKeyOperation_RSA
 */
JNIEXPORT jbyteArray JNICALL JNI_SDF_InternalPublicKeyOperation_RSA(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint keyIndex, jbyteArray dataInput) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_InternalPublicKeyOperation_RSA == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (dataInput == NULL) {
        throw_sdf_exception_with_message(env, 0x01000006, "Data input is null");
        return NULL;
    }

    /* Get input data */
    jsize input_len = (*env)->GetArrayLength(env, dataInput);
    BYTE *input_buf = (BYTE*)malloc(input_len);
    if (input_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, dataInput, 0, input_len, (jbyte*)input_buf);

    /* Allocate output buffer (RSA output is same size as key) */
    ULONG output_len = 512;  /* Max RSA key size in bytes (4096 bits) */
    BYTE *output_buf = (BYTE*)malloc(output_len);
    if (output_buf == NULL) {
        free(input_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_InternalPublicKeyOperation_RSA(
        (HANDLE)sessionHandle,
        (ULONG)keyIndex,
        input_buf,
        (ULONG)input_len,
        output_buf,
        &output_len
    );

    free(input_buf);

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
 * 6.4.4 内部私钥RSA运算
 * SDF_InternalPrivateKeyOperation_RSA
 */
JNIEXPORT jbyteArray JNICALL JNI_SDF_InternalPrivateKeyOperation_RSA(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint keyIndex, jbyteArray dataInput) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_InternalPrivateKeyOperation_RSA == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (dataInput == NULL) {
        throw_sdf_exception_with_message(env, 0x01000006, "Data input is null");
        return NULL;
    }

    /* Get input data */
    jsize input_len = (*env)->GetArrayLength(env, dataInput);
    BYTE *input_buf = (BYTE*)malloc(input_len);
    if (input_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, dataInput, 0, input_len, (jbyte*)input_buf);

    /* Allocate output buffer (RSA output is same size as key) */
    ULONG output_len = 512;  /* Max RSA key size in bytes (4096 bits) */
    BYTE *output_buf = (BYTE*)malloc(output_len);
    if (output_buf == NULL) {
        free(input_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_InternalPrivateKeyOperation_RSA(
        (HANDLE)sessionHandle,
        (ULONG)keyIndex,
        input_buf,
        (ULONG)input_len,
        output_buf,
        &output_len
    );

    free(input_buf);

    if (ret != SDR_OK) {
        free(output_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, output_buf, output_len);
    free(output_buf);

    return result;
}

