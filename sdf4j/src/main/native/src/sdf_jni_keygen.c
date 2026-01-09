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
 * Key Generation Functions
 * All RSA/ECC key generation and import functions
 * ======================================================================== */

/**
 * 6.3.5 使用内部RSA加密公钥生成会话密钥
 * Pattern: KeyEncryptionResult return (encrypted key + handle)
 */
JNIEXPORT jobject JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1GenerateKeyWithIPK_1RSA
(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex, jint keyBits) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_GenerateKeyWithIPK_RSA == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* 分配密钥缓冲区 */
    ULONG key_len = (keyBits + 7) / 8;  /* RSA密钥长度，按位转字节 */
    BYTE *key_buf = (BYTE*)malloc(key_len);
    if (key_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    HANDLE key_handle = 0;

    LONG ret = g_sdf_functions.SDF_GenerateKeyWithIPK_RSA(
        (HANDLE)sessionHandle,
        (ULONG)keyIndex,
        (ULONG)keyBits,
        key_buf,
        &key_len,
        &key_handle
    );

    if (ret != SDR_OK) {
        free(key_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    /* 创建 KeyEncryptionResult 对象 */
    jobject result = create_key_encryption_result(env, key_buf, key_len, key_handle);
    free(key_buf);

    return result;
}

/**
 * 6.3.6 使用外部RSA公钥生成会话密钥
 * Pattern: KeyEncryptionResult return (encrypted key + handle)
 */
JNIEXPORT jobject JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1GenerateKeyWithEPK_1RSA
(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyBits, jobject publicKey) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_GenerateKeyWithEPK_RSA == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* 转换Java RSAPublicKey到C结构 */
    RSArefPublicKey rsa_pub_key;
    if (!java_to_native_RSAPublicKey(env, publicKey, &rsa_pub_key)) {
        return NULL;  /* Exception already thrown */
    }

    /* 分配密钥缓冲区 */
    ULONG key_len = (keyBits + 7) / 8;
    BYTE *key_buf = (BYTE*)malloc(key_len);
    if (key_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    HANDLE key_handle = 0;

    LONG ret = g_sdf_functions.SDF_GenerateKeyWithEPK_RSA(
        (HANDLE)sessionHandle,
        (ULONG)keyBits,
        &rsa_pub_key,
        key_buf,
        &key_len,
        &key_handle
    );

    if (ret != SDR_OK) {
        free(key_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    /* 创建 KeyEncryptionResult 对象 */
    jobject result = create_key_encryption_result(env, key_buf, key_len, key_handle);
    free(key_buf);

    return result;
}

/**
 * 6.3.7 导入会话密钥并用内部RSA私钥解密
 * Pattern: Returns key handle (long)
 */
JNIEXPORT jlong JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ImportKeyWithISK_1RSA
(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex, jbyteArray encryptedKey) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return 0;
    }

    if (g_sdf_functions.SDF_ImportKeyWithISK_RSA == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return 0;
    }

    /* 转换加密密钥数据 */
    jsize key_len = (*env)->GetArrayLength(env, encryptedKey);
    BYTE *key_buf = (BYTE*)malloc(key_len);
    if (key_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return 0;
    }

    (*env)->GetByteArrayRegion(env, encryptedKey, 0, key_len, (jbyte*)key_buf);

    HANDLE key_handle = 0;

    LONG ret = g_sdf_functions.SDF_ImportKeyWithISK_RSA(
        (HANDLE)sessionHandle,
        (ULONG)keyIndex,
        key_buf,
        (ULONG)key_len,
        &key_handle
    );

    free(key_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return 0;
    }

    return (jlong)key_handle;
}

/**
 * 6.3.9 使用内部ECC公钥生成会话密钥
 * Pattern: KeyEncryptionResult return (ECCCipher + handle)
 */
JNIEXPORT jobject JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1GenerateKeyWithIPK_1ECC
(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex, jint keyBits) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_GenerateKeyWithIPK_ECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* 分配ECCCipher结构 */
    ECCCipher ecc_cipher;
    memset(&ecc_cipher, 0, sizeof(ECCCipher));

    HANDLE key_handle = 0;

    LONG ret = g_sdf_functions.SDF_GenerateKeyWithIPK_ECC(
        (HANDLE)sessionHandle,
        (ULONG)keyIndex,
        (ULONG)keyBits,
        &ecc_cipher,
        &key_handle
    );

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return NULL;
    }


    /* 创建KeyEncryptionResult，其中encryptedKey是ECCCipher的序列化 */
    /* 序列化ECCCipher: x(32) + y(32) + M(32) + C(cipher_len) */
    ULONG cipher_data_len = 32 + 32 + 32 + ecc_cipher.L;
    BYTE *cipher_data = (BYTE*)malloc(cipher_data_len);
    if (cipher_data == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    memcpy(cipher_data, ecc_cipher.x, 32);
    memcpy(cipher_data + 32, ecc_cipher.y, 32);
    memcpy(cipher_data + 64, ecc_cipher.M, 32);
    memcpy(cipher_data + 96, &ecc_cipher.C, ecc_cipher.L);

    jobject result = create_key_encryption_result(env, cipher_data, cipher_data_len, key_handle);
    free(cipher_data);

    return result;
}

/**
 * 6.3.10 使用外部ECC公钥生成会话密钥
 * Pattern: KeyEncryptionResult return (ECCCipher + handle)
 */
JNIEXPORT jobject JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1GenerateKeyWithEPK_1ECC
(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyBits, jint algID, jobject publicKey) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_GenerateKeyWithEPK_ECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* 转换Java ECCPublicKey到C结构 */
    ECCrefPublicKey ecc_pub_key;
    if (!java_to_native_ECCPublicKey(env, publicKey, &ecc_pub_key)) {
        return NULL;  /* Exception already thrown */
    }

    /* 分配ECCCipher结构 */
    ECCCipher ecc_cipher;
    memset(&ecc_cipher, 0, sizeof(ECCCipher));

    HANDLE key_handle = 0;

    LONG ret = g_sdf_functions.SDF_GenerateKeyWithEPK_ECC(
        (HANDLE)sessionHandle,
        (ULONG)keyBits,
        (ULONG)algID,
        &ecc_pub_key,
        &ecc_cipher,
        &key_handle
    );

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return NULL;
    }

    /* 序列化ECCCipher */
    ULONG cipher_data_len = 32 + 32 + 32 + ecc_cipher.L;
    BYTE *cipher_data = (BYTE*)malloc(cipher_data_len);
    if (cipher_data == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    memcpy(cipher_data, ecc_cipher.x, 32);
    memcpy(cipher_data + 32, ecc_cipher.y, 32);
    memcpy(cipher_data + 64, ecc_cipher.M, 32);
    memcpy(cipher_data + 96, &ecc_cipher.C, ecc_cipher.L);

    jobject result = create_key_encryption_result(env, cipher_data, cipher_data_len, key_handle);
    free(cipher_data);

    return result;
}

/**
 * 6.3.11 导入会话密钥并用内部ECC私钥解密
 * Pattern: Returns key handle (long)
 */
JNIEXPORT jlong JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ImportKeyWithISK_1ECC
(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex, jobject cipher) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return 0;
    }

    if (g_sdf_functions.SDF_ImportKeyWithISK_ECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return 0;
    }

    /* 转换Java ECCCipher到C结构 (使用动态分配以支持柔性数组成员) */
    ECCCipher *ecc_cipher = java_to_native_ECCCipher_alloc(env, cipher);
    if (ecc_cipher == NULL) {
        throw_sdf_exception(env, 0x0100001D);  /* SDR_INARGERR */
        return 0;
    }

    HANDLE key_handle = 0;

    LONG ret = g_sdf_functions.SDF_ImportKeyWithISK_ECC(
        (HANDLE)sessionHandle,
        (ULONG)keyIndex,
        ecc_cipher,
        &key_handle
    );

    free(ecc_cipher);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return 0;
    }

    return (jlong)key_handle;
}

/**
 * 6.3.12 生成密钥协商参数并输出
 * Pattern: Returns agreement handle (long)
 * Note: Java API signature differs from C - sponsorTmpPublicKey is output parameter in C, input in Java
 */
JNIEXPORT jlong JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1GenerateAgreementDataWithECC
(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex, jint keyBits,
 jbyteArray sponsorID, jobject sponsorPublicKey, jobject sponsorTmpPublicKey) {
    UNUSED(obj);
    UNUSED(sponsorTmpPublicKey);  /* Output parameter, handled by device */

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return 0;
    }

    if (g_sdf_functions.SDF_GenerateAgreementDataWithECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return 0;
    }

    /* 转换sponsorID */
    jsize sponsor_id_len = (*env)->GetArrayLength(env, sponsorID);
    BYTE *sponsor_id_buf = (BYTE*)malloc(sponsor_id_len);
    if (sponsor_id_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return 0;
    }
    (*env)->GetByteArrayRegion(env, sponsorID, 0, sponsor_id_len, (jbyte*)sponsor_id_buf);

    /* 转换sponsorPublicKey */
    ECCrefPublicKey sponsor_pub_key;
    if (!java_to_native_ECCPublicKey(env, sponsorPublicKey, &sponsor_pub_key)) {
        free(sponsor_id_buf);
        return 0;
    }

    /* 临时公钥由设备生成 */
    ECCrefPublicKey sponsor_tmp_pub_key;
    memset(&sponsor_tmp_pub_key, 0, sizeof(ECCrefPublicKey));

    HANDLE agreement_handle = 0;

    LONG ret = g_sdf_functions.SDF_GenerateAgreementDataWithECC(
        (HANDLE)sessionHandle,
        (ULONG)keyIndex,
        (ULONG)keyBits,
        sponsor_id_buf,
        (ULONG)sponsor_id_len,
        &sponsor_pub_key,
        &sponsor_tmp_pub_key,
        &agreement_handle
    );

    free(sponsor_id_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return 0;
    }

    return (jlong)agreement_handle;
}

/**
 * 6.3.13 计算会话密钥
 * Pattern: Returns key handle (long)
 */
JNIEXPORT jlong JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1GenerateKeyWithECC
(JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray responseID,
 jobject responsePublicKey, jobject responseTmpPublicKey, jlong agreementHandle) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return 0;
    }

    if (g_sdf_functions.SDF_GenerateKeyWithECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return 0;
    }

    /* 转换responseID */
    jsize response_id_len = (*env)->GetArrayLength(env, responseID);
    BYTE *response_id_buf = (BYTE*)malloc(response_id_len);
    if (response_id_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return 0;
    }
    (*env)->GetByteArrayRegion(env, responseID, 0, response_id_len, (jbyte*)response_id_buf);

    /* 转换responsePublicKey */
    ECCrefPublicKey response_pub_key;
    if (!java_to_native_ECCPublicKey(env, responsePublicKey, &response_pub_key)) {
        free(response_id_buf);
        return 0;
    }

    /* 转换responseTmpPublicKey */
    ECCrefPublicKey response_tmp_pub_key;
    if (!java_to_native_ECCPublicKey(env, responseTmpPublicKey, &response_tmp_pub_key)) {
        free(response_id_buf);
        return 0;
    }

    HANDLE key_handle = 0;

    LONG ret = g_sdf_functions.SDF_GenerateKeyWithECC(
        (HANDLE)sessionHandle,
        response_id_buf,
        (ULONG)response_id_len,
        &response_pub_key,
        &response_tmp_pub_key,
        (HANDLE)agreementHandle,
        &key_handle
    );

    free(response_id_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return 0;
    }

    return (jlong)key_handle;
}

/**
 * 6.3.14 产生协商数据并计算会话密钥
 * Pattern: Returns key handle (long)
 */
JNIEXPORT jlong JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1GenerateAgreementDataAndKeyWithECC
(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex, jint keyBits,
 jbyteArray responseID, jbyteArray sponsorID,
 jobject sponsorPublicKey, jobject sponsorTmpPublicKey,
 jobject responsePublicKey, jobject responseTmpPublicKey) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return 0;
    }

    if (g_sdf_functions.SDF_GenerateAgreementDataAndKeyWithECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return 0;
    }

    /* 转换responseID */
    jsize response_id_len = (*env)->GetArrayLength(env, responseID);
    BYTE *response_id_buf = (BYTE*)malloc(response_id_len);
    if (response_id_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return 0;
    }
    (*env)->GetByteArrayRegion(env, responseID, 0, response_id_len, (jbyte*)response_id_buf);

    /* 转换sponsorID */
    jsize sponsor_id_len = (*env)->GetArrayLength(env, sponsorID);
    BYTE *sponsor_id_buf = (BYTE*)malloc(sponsor_id_len);
    if (sponsor_id_buf == NULL) {
        free(response_id_buf);
        throw_sdf_exception(env, 0x0100001C);
        return 0;
    }
    (*env)->GetByteArrayRegion(env, sponsorID, 0, sponsor_id_len, (jbyte*)sponsor_id_buf);

    /* 转换所有ECC公钥 */
    ECCrefPublicKey sponsor_pub_key, sponsor_tmp_pub_key, response_pub_key, response_tmp_pub_key;

    if (!java_to_native_ECCPublicKey(env, sponsorPublicKey, &sponsor_pub_key)) {
        free(response_id_buf);
        free(sponsor_id_buf);
        return 0;
    }
    if (!java_to_native_ECCPublicKey(env, sponsorTmpPublicKey, &sponsor_tmp_pub_key)) {
        free(response_id_buf);
        free(sponsor_id_buf);
        return 0;
    }
    if (!java_to_native_ECCPublicKey(env, responsePublicKey, &response_pub_key)) {
        free(response_id_buf);
        free(sponsor_id_buf);
        return 0;
    }
    if (!java_to_native_ECCPublicKey(env, responseTmpPublicKey, &response_tmp_pub_key)) {
        free(response_id_buf);
        free(sponsor_id_buf);
        return 0;
    }

    HANDLE key_handle = 0;

    LONG ret = g_sdf_functions.SDF_GenerateAgreementDataAndKeyWithECC(
        (HANDLE)sessionHandle,
        (ULONG)keyIndex,
        (ULONG)keyBits,
        response_id_buf,
        (ULONG)response_id_len,
        sponsor_id_buf,
        (ULONG)sponsor_id_len,
        &sponsor_pub_key,
        &sponsor_tmp_pub_key,
        &response_pub_key,
        &response_tmp_pub_key,
        &key_handle
    );

    free(response_id_buf);
    free(sponsor_id_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return 0;
    }

    return (jlong)key_handle;
}

/**
 * 6.3.15 生成会话密钥并用密钥加密密钥加密输出
 * Pattern: KeyEncryptionResult return (encrypted key + handle)
 */
JNIEXPORT jobject JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1GenerateKeyWithKEK
(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyBits, jint algID, jint kekIndex) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_GenerateKeyWithKEK == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* 分配密钥缓冲区 */
    ULONG key_len = (keyBits + 7) / 8;
    /* KEK加密可能需要padding，分配更大空间 */
    ULONG buffer_size = key_len + 16;
    BYTE *key_buf = (BYTE*)malloc(buffer_size);
    if (key_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    key_len = buffer_size;  /* 设置为缓冲区大小 */
    HANDLE key_handle = 0;

    LONG ret = g_sdf_functions.SDF_GenerateKeyWithKEK(
        (HANDLE)sessionHandle,
        (ULONG)keyBits,
        (ULONG)algID,
        (ULONG)kekIndex,
        key_buf,
        &key_len,
        &key_handle
    );

    if (ret != SDR_OK) {
        free(key_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    /* 创建 KeyEncryptionResult 对象 */
    jobject result = create_key_encryption_result(env, key_buf, key_len, key_handle);
    free(key_buf);

    return result;
}

/**
 * 6.3.16 导入会话密钥并用密钥加密密钥解密
 * Pattern: Returns key handle (long)
 */
JNIEXPORT jlong JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ImportKeyWithKEK
(JNIEnv *env, jobject obj, jlong sessionHandle, jint algID, jint kekIndex, jbyteArray encryptedKey) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return 0;
    }

    if (g_sdf_functions.SDF_ImportKeyWithKEK == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return 0;
    }

    /* 转换加密密钥数据 */
    jsize key_len = (*env)->GetArrayLength(env, encryptedKey);
    BYTE *key_buf = (BYTE*)malloc(key_len);
    if (key_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return 0;
    }

    (*env)->GetByteArrayRegion(env, encryptedKey, 0, key_len, (jbyte*)key_buf);

    HANDLE key_handle = 0;

    LONG ret = g_sdf_functions.SDF_ImportKeyWithKEK(
        (HANDLE)sessionHandle,
        (ULONG)algID,
        (ULONG)kekIndex,
        key_buf,
        (ULONG)key_len,
        &key_handle
    );

    free(key_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return 0;
    }

    return (jlong)key_handle;
}