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
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return NULL;
    }

    if (data == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001D, "Invalid argument"); /* SDR_INARGERR */
        return NULL;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);

    jbyte *data_buf = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    if (data_buf == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");  /* SDR_NOBUFFER */
        return NULL;
    }

    ECCSignature signature = {0};
    LONG ret = g_sdf_functions.SDF_InternalSign_ECC((HANDLE)sessionHandle, keyIndex,
                                                     (BYTE*)data_buf, data_len, &signature);
    (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
    if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform ecc sign operation");
        return NULL;
    }
    return native_to_java_ECCSignature(env, &signature);
}

JNIEXPORT void JNICALL JNI_SDF_InternalVerify_ECC(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex,
    jbyteArray data, jobject signature) {
    UNUSED(obj);
    if (g_sdf_functions.SDF_InternalVerify_ECC == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return;
    }

    if (data == NULL || signature == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001D, "Invalid argument"); /* SDR_INARGERR */
        return;
    }

    ECCSignature native_sig = {0};
    if(!java_to_native_ECCSignature(env, signature, &native_sig)) {
        return;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);
    jbyte *data_buf = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    if (data_buf == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");  /* SDR_NOBUFFER */
        return;
    }

    LONG ret = g_sdf_functions.SDF_InternalVerify_ECC((HANDLE)sessionHandle, keyIndex,
                                                       (BYTE*)data_buf, data_len, &native_sig);

    (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);

    if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform ecc verify operation");
    }
}

JNIEXPORT void JNICALL JNI_SDF_ExternalVerify_ECC(JNIEnv *env, jobject obj, jlong sessionHandle, jint algID,
    jobject publicKey, jbyteArray data, jobject signature) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_ExternalVerify_ECC == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return;
    }

    if (publicKey == NULL || data == NULL || signature == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001D, "Invalid argument"); /* SDR_INARGERR */
        return;
    }

    ECCrefPublicKey native_key;
    if (!java_to_native_ECCPublicKey(env, publicKey, &native_key)) {
        return;
    }

    ECCSignature native_sig = {0};
    if(!java_to_native_ECCSignature(env, signature, &native_sig)) {
        return;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);
    jbyte *data_buf = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    if (data_buf == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");
        return;
    }

    LONG ret = g_sdf_functions.SDF_ExternalVerify_ECC((HANDLE)sessionHandle, algID,
                                                       &native_key, (BYTE*)data_buf, data_len,
                                                       &native_sig);

    (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);

    if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform ecc verify operation");
    }
}

JNIEXPORT jobject JNICALL JNI_SDF_ExternalEncrypt_ECC(JNIEnv *env, jobject obj, jlong sessionHandle, jint algID,
    jobject publicKey, jbyteArray data) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_ExternalEncrypt_ECC == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return NULL;
    }

    if (publicKey == NULL || data == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001D, "Invalid argument");
        return NULL;
    }

    ECCrefPublicKey native_key;
    if (!java_to_native_ECCPublicKey(env, publicKey, &native_key)) {
        return NULL;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);

    jbyte *data_buf = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    if (data_buf == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");
        return NULL;
    }

    /* 分配ECCCipher结构 + 密文空间 + 额外空间*/
    ECCCipher *cipher = (ECCCipher*)calloc(1, sizeof(ECCCipher) + data_len);
    if (cipher == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");
        return NULL;
    }

    cipher->L = data_len;
    LONG ret = g_sdf_functions.SDF_ExternalEncrypt_ECC((HANDLE)sessionHandle, algID,
                                                        &native_key, (BYTE*)data_buf, data_len,
                                                        cipher);

    (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);

    if (ret != SDR_OK) {
        free(cipher);
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform ecc enc operation");
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
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return NULL;
    }

    if (data == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001D, "Invalid argument"); /* SDR_INARGERR */
        return NULL;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);

    jbyte *data_buf = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    if (data_buf == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");  /* SDR_NOBUFFER */
        return NULL;
    }

    /* 分配ECCCipher结构 + 密文空间 */
    ECCCipher *cipher = (ECCCipher*)calloc(1, sizeof(ECCCipher) + data_len);
    if (cipher == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");  /* SDR_NOBUFFER */
        return NULL;
    }
    cipher->L = data_len ;
    LONG ret = g_sdf_functions.SDF_InternalEncrypt_ECC((HANDLE)sessionHandle, keyIndex,
        (BYTE*)data_buf, data_len, cipher);

    (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
    if (ret != SDR_OK) {
        free(cipher);
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform ecc enc operation");
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
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return NULL;
    }

    if (cipher == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001D, "Invalid argument"); /* SDR_INARGERR */
        return NULL;
    }

    /* 转换Java ECCCipher到C结构 (使用动态分配以支持柔性数组成员) */
    ECCCipher *ecc_cipher = java_to_native_ECCCipher_alloc(env, cipher);
    if (ecc_cipher == NULL) {
        return NULL;
    }

    /* 分配输出缓冲区 */
    ULONG data_len = ecc_cipher->L + 64;
    BYTE *data_buf = (BYTE*)calloc(1, data_len);
    if (data_buf == NULL) {
        free(ecc_cipher);
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");  /* SDR_NOBUFFER */
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_InternalDecrypt_ECC((HANDLE)sessionHandle, keyIndex,
                                                        eccKeyType, ecc_cipher,
                                                        data_buf, &data_len);

    if (ret != SDR_OK) {
        free(ecc_cipher);
        free(data_buf);
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform ecc dec operation");
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
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return NULL;
    }

    if (publicKey == NULL || encDataIn == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001D, "Invalid argument"); /* SDR_INARGERR */
        return NULL;
    }

    ECCrefPublicKey native_pub;
    if (!java_to_native_ECCPublicKey(env, publicKey, &native_pub)) {
        return NULL;
    }

    ECCCipher *in_cipher = java_to_native_ECCCipher_alloc(env, encDataIn);
    if (in_cipher == NULL) {
        return NULL;
    }

    ULONG out_len = in_cipher->L;
    ECCCipher *out_cipher = (ECCCipher*)calloc(1, sizeof(ECCCipher) + out_len);
    if (out_cipher == NULL) {
        free(in_cipher);
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");
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
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform ecc digit envelope operation");
        return NULL;
    }

    jobject result = native_to_java_ECCCipher(env, out_cipher, out_cipher->L);
    free(out_cipher);
    return result;
}

/**
 * SDF_ExchangeDigitEnvelopeBaseOnRSA
 */
JNIEXPORT jbyteArray JNICALL JNI_SDF_ExchangeDigitEnvelopeBaseOnRSA(JNIEnv *env, jobject obj,
    jlong sessionHandle, jint uiKeyIndex, jobject pucPublicKey, jbyteArray pucDEInput) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_ExchangeDigitEnvelopeBaseOnRSA == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return NULL;
    }

    if (pucPublicKey == NULL || pucDEInput == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Invalid argument");
        return NULL;
    }

    RSArefPublicKey native_key;
    if (!java_to_native_RSAPublicKey(env, pucPublicKey, &native_key)) {
        return NULL;
    }

    jsize input_len = (*env)->GetArrayLength(env, pucDEInput);
    jbyte *input_buf = (*env)->GetPrimitiveArrayCritical(env, pucDEInput, NULL);
    if (input_buf == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOBUFFER, "GetPrimitiveArrayCritical failed");
        return NULL;
    }

    ULONG output_len = (native_key.bits + 7) / 8;
    if (output_len == 0 || output_len > RSAref_MAX_LEN) {
        (*env)->ReleasePrimitiveArrayCritical(env, pucDEInput, input_buf, JNI_ABORT);
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Output length is invalid");
        return NULL;
    }
    BYTE *output_buf = (BYTE*)malloc(output_len);
    if (output_buf == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, pucDEInput, input_buf, JNI_ABORT);
        THROW_SDF_EXCEPTION(env, SDR_NOBUFFER, "Memory allocation failed");
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_ExchangeDigitEnvelopeBaseOnRSA(
        (HANDLE)sessionHandle,
        (ULONG)uiKeyIndex,
        &native_key,
        (BYTE*)input_buf,
        (ULONG)input_len,
        output_buf,
        &output_len
    );

    (*env)->ReleasePrimitiveArrayCritical(env, pucDEInput, input_buf, JNI_ABORT);
    if (ret != SDR_OK) {
        free(output_buf);
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform RSA digit envelope operation");
        return NULL;
    }
    jbyteArray result = native_to_java_byte_array(env, output_buf, output_len);
    free(output_buf);
    return result;
}

/* ========================================================================
 * RSA Operations (Public/Private Key Operations)
 * ======================================================================== */
JNIEXPORT jbyteArray JNICALL JNI_SDF_ExternalPublicKeyOperation_RSA(JNIEnv *env, jobject obj, jlong sessionHandle,
    jobject publicKey, jbyteArray dataInput) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_ExternalPublicKeyOperation_RSA == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return NULL;
    }

    if (publicKey == NULL || dataInput == NULL) {
        THROW_SDF_EXCEPTION(env, 0x01000001, "Public key or data is null");
        return NULL;
    }

    /* 转换公钥 */
    RSArefPublicKey native_key = {0};
    if (!java_to_native_RSAPublicKey(env, publicKey, &native_key)) {
        return NULL;
    }

    /* 转换输入数据 */
    jsize input_len = (*env)->GetArrayLength(env, dataInput);
    BYTE *input_buf = (BYTE*)malloc(input_len);
    if (input_buf == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, dataInput, 0, input_len, (jbyte*)input_buf);

    /* 分配输出缓冲区（RSA输出长度等于模长）*/
    ULONG output_len = (native_key.bits + 7) / 8;
    if (output_len == 0 || output_len > RSAref_MAX_LEN) {
        free(input_buf);
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Output length is invalid");
        return NULL;
    }
    BYTE *output_buf = (BYTE*)malloc(output_len);
    if (output_buf == NULL) {
        free(input_buf);
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");
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
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform rsa operation");
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
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return NULL;
    }

    if (dataInput == NULL) {
        THROW_SDF_EXCEPTION(env, 0x01000006, "Data input is null");
        return NULL;
    }

    /* Get input data */
    jsize input_len = (*env)->GetArrayLength(env, dataInput);
    BYTE *input_buf = (BYTE*)malloc(input_len);
    if (input_buf == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, dataInput, 0, input_len, (jbyte*)input_buf);

    /* Allocate output buffer (RSA output is same size as key) */
    ULONG output_len = 512;  /* Max RSA key size in bytes (4096 bits) */
    BYTE *output_buf = (BYTE*)malloc(output_len);
    if (output_buf == NULL) {
        free(input_buf);
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");
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
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform rsa operation");
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
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return NULL;
    }

    if (dataInput == NULL) {
        THROW_SDF_EXCEPTION(env, 0x01000006, "Data input is null");
        return NULL;
    }

    /* Get input data */
    jsize input_len = (*env)->GetArrayLength(env, dataInput);
    BYTE *input_buf = (BYTE*)malloc(input_len);
    if (input_buf == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, dataInput, 0, input_len, (jbyte*)input_buf);

    /* Allocate output buffer (RSA output is same size as key) */
    ULONG output_len = 512;  /* Max RSA key size in bytes (4096 bits) */
    BYTE *output_buf = (BYTE*)malloc(output_len);
    if (output_buf == NULL) {
        free(input_buf);
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");
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
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform rsa operation");
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, output_buf, output_len);
    free(output_buf);

    return result;
}

