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
JNIEXPORT jobject JNICALL JNI_SDF_GenerateKeyWithIPK_RSA(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex,
    jint keyBits) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_GenerateKeyWithIPK_RSA == NULL || g_sdf_functions.SDF_DestroyKey == NULL) {
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
    if (result == NULL) {
        g_sdf_functions.SDF_DestroyKey((HANDLE)sessionHandle, (HANDLE)key_handle);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    return result;
}

/**
 * 6.3.6 使用外部RSA公钥生成会话密钥
 * Pattern: KeyEncryptionResult return (encrypted key + handle)
 */
JNIEXPORT jobject JNICALL JNI_SDF_GenerateKeyWithEPK_RSA(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyBits,
    jobject publicKey) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_GenerateKeyWithEPK_RSA == NULL || g_sdf_functions.SDF_DestroyKey == NULL) {
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
    if (result == NULL) {
        g_sdf_functions.SDF_DestroyKey((HANDLE)sessionHandle, (HANDLE)key_handle);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    return result;
}

/**
 * 6.3.7 导入会话密钥并用内部RSA私钥解密
 * Pattern: Returns key handle (long)
 */
JNIEXPORT jlong JNICALL JNI_SDF_ImportKeyWithISK_RSA(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex,
    jbyteArray encryptedKey) {
    UNUSED(obj);

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
JNIEXPORT jobject JNICALL JNI_SDF_GenerateKeyWithIPK_ECC(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex,
    jint keyBits) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_GenerateKeyWithIPK_ECC == NULL || g_sdf_functions.SDF_DestroyKey == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* 分配ECCCipher结构 */
    ULONG key_len = (keyBits + 7) / 8;
    ECCCipher *ecc_cipher = (ECCCipher*)calloc(1, sizeof(ECCCipher) + key_len);
    if (ecc_cipher == NULL) {
        throw_sdf_exception(env, SDR_NOBUFFER);
        return NULL;
    }
    ecc_cipher->L = key_len;

    HANDLE key_handle = 0;

    LONG ret = g_sdf_functions.SDF_GenerateKeyWithIPK_ECC(
        (HANDLE)sessionHandle,
        (ULONG)keyIndex,
        (ULONG)keyBits,
        ecc_cipher,
        &key_handle
    );

    if (ret != SDR_OK) {
        free(ecc_cipher);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jobject result = create_ecc_key_encryption_result(env, ecc_cipher, key_len, key_handle);
    if (result == NULL) {
        free(ecc_cipher);
        g_sdf_functions.SDF_DestroyKey((HANDLE)sessionHandle, (HANDLE)key_handle);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    free(ecc_cipher);

    return result;
}

/**
 * 6.3.10 使用外部ECC公钥生成会话密钥
 * Pattern: KeyEncryptionResult return (ECCCipher + handle)
 */
JNIEXPORT jobject JNICALL JNI_SDF_GenerateKeyWithEPK_ECC(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyBits, jint algID,
    jobject publicKey) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_GenerateKeyWithEPK_ECC == NULL || g_sdf_functions.SDF_DestroyKey == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* 转换Java ECCPublicKey到C结构 */
    ECCrefPublicKey ecc_pub_key;
    if (!java_to_native_ECCPublicKey(env, publicKey, &ecc_pub_key)) {
        return NULL;  /* Exception already thrown */
    }

    /* 分配ECCCipher结构 */
    ULONG key_len = (keyBits + 7) / 8;
    ECCCipher *ecc_cipher = (ECCCipher*)calloc(1, sizeof(ECCCipher) + key_len);
    if (ecc_cipher == NULL) {
        throw_sdf_exception(env, SDR_NOBUFFER);
        return NULL;
    }
    ecc_cipher->L = key_len;

    HANDLE key_handle = 0;

    LONG ret = g_sdf_functions.SDF_GenerateKeyWithEPK_ECC(
        (HANDLE)sessionHandle,
        (ULONG)keyBits,
        (ULONG)algID,
        &ecc_pub_key,
        ecc_cipher,
        &key_handle
    );

    if (ret != SDR_OK) {
        free(ecc_cipher);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jobject result = create_ecc_key_encryption_result(env, ecc_cipher, key_len, key_handle);
    if (result == NULL) {
        free(ecc_cipher);
        g_sdf_functions.SDF_DestroyKey((HANDLE)sessionHandle, (HANDLE)key_handle);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    free(ecc_cipher);

    return result;
}

/**
 * 6.3.11 导入会话密钥并用内部ECC私钥解密
 * Pattern: Returns key handle (long)
 */
JNIEXPORT jlong JNICALL JNI_SDF_ImportKeyWithISK_ECC(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex,
    jobject cipher) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_ImportKeyWithISK_ECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return 0;
    }
    if (cipher == NULL) {
        throw_sdf_exception(env, 0x0100001D);  /* SDR_INARGERR */
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
JNIEXPORT jlong JNICALL JNI_SDF_GenerateAgreementDataWithECC(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex, jint keyBits, jbyteArray sponsorID,
    jobject sponsorPublicKey, jobject sponsorTmpPublicKey) {
    UNUSED(obj);
    UNUSED(sponsorTmpPublicKey);  /* Output parameter, handled by device */

    if (g_sdf_functions.SDF_GenerateAgreementDataWithECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return 0;
    }
    if (sponsorPublicKey == NULL) {
        throw_sdf_exception(env, 0x0100001D);  /* SDR_INARGERR */
        return 0;
    }

    /* 转换sponsorID */
    jsize sponsor_id_len = (*env)->GetArrayLength(env, sponsorID);
    jbyte *sponsor_id_buf = (*env)->GetPrimitiveArrayCritical(env, sponsorID, NULL);
    if (sponsor_id_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return 0;
    }

    /* 转换sponsorPublicKey */
    ECCrefPublicKey sponsor_pub_key;
    if (!java_to_native_ECCPublicKey(env, sponsorPublicKey, &sponsor_pub_key)) {
        (*env)->ReleasePrimitiveArrayCritical(env, sponsorID, sponsor_id_buf, JNI_ABORT);
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
        (BYTE*)sponsor_id_buf,
        (ULONG)sponsor_id_len,
        &sponsor_pub_key,
        &sponsor_tmp_pub_key,
        &agreement_handle
    );

    (*env)->ReleasePrimitiveArrayCritical(env, sponsorID, sponsor_id_buf, JNI_ABORT);

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
JNIEXPORT jlong JNICALL JNI_SDF_GenerateKeyWithECC(JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray responseID, jobject responsePublicKey,
    jobject responseTmpPublicKey, jlong agreementHandle) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_GenerateKeyWithECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return 0;
    }
    if (responsePublicKey == NULL || responseTmpPublicKey == NULL) {
        throw_sdf_exception(env, 0x0100001D);  /* SDR_INARGERR */
        return 0;
    }
    /* 转换responseID */
    jsize response_id_len = (*env)->GetArrayLength(env, responseID);
    jbyte *response_id_buf = (*env)->GetPrimitiveArrayCritical(env, responseID, NULL);
    if (response_id_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return 0;
    }

    /* 转换responsePublicKey */
    ECCrefPublicKey response_pub_key;
    if (!java_to_native_ECCPublicKey(env, responsePublicKey, &response_pub_key)) {
        (*env)->ReleasePrimitiveArrayCritical(env, responseID, response_id_buf, JNI_ABORT);
        return 0;
    }

    /* 转换responseTmpPublicKey */
    ECCrefPublicKey response_tmp_pub_key;
    if (!java_to_native_ECCPublicKey(env, responseTmpPublicKey, &response_tmp_pub_key)) {
        (*env)->ReleasePrimitiveArrayCritical(env, responseID, response_id_buf, JNI_ABORT);
        return 0;
    }

    HANDLE key_handle = 0;

    LONG ret = g_sdf_functions.SDF_GenerateKeyWithECC(
        (HANDLE)sessionHandle,
        (BYTE*)response_id_buf,
        (ULONG)response_id_len,
        &response_pub_key,
        &response_tmp_pub_key,
        (HANDLE)agreementHandle,
        &key_handle
    );

    (*env)->ReleasePrimitiveArrayCritical(env, responseID, response_id_buf, JNI_ABORT);

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
JNIEXPORT jlong JNICALL JNI_SDF_GenerateAgreementDataAndKeyWithECC(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex, jint keyBits, jbyteArray responseID, jbyteArray sponsorID,
    jobject sponsorPublicKey, jobject sponsorTmpPublicKey, jobject responsePublicKey, jobject responseTmpPublicKey) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_GenerateAgreementDataAndKeyWithECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return 0;
    }
    if (sponsorPublicKey == NULL || sponsorTmpPublicKey == NULL || responsePublicKey == NULL ||
        responseTmpPublicKey == NULL) {
        throw_sdf_exception(env, 0x0100001D);  /* SDR_INARGERR */
        return 0;
    }
    /* 转换responseID */
    jsize response_id_len = (*env)->GetArrayLength(env, responseID);
    jbyte *response_id_buf = (*env)->GetPrimitiveArrayCritical(env, responseID, NULL);
    if (response_id_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return 0;
    }

    /* 转换sponsorID */
    jsize sponsor_id_len = (*env)->GetArrayLength(env, sponsorID);
    jbyte *sponsor_id_buf = (*env)->GetPrimitiveArrayCritical(env, sponsorID, NULL);
    if (sponsor_id_buf == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, responseID, response_id_buf, JNI_ABORT);
        throw_sdf_exception(env, 0x0100001C);
        return 0;
    }

    /* 转换所有ECC公钥 */
    ECCrefPublicKey sponsor_pub_key, sponsor_tmp_pub_key, response_pub_key, response_tmp_pub_key;

    if (!java_to_native_ECCPublicKey(env, sponsorPublicKey, &sponsor_pub_key)) {
        (*env)->ReleasePrimitiveArrayCritical(env, responseID, response_id_buf, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, sponsorID, sponsor_id_buf, JNI_ABORT);
        return 0;
    }
    if (!java_to_native_ECCPublicKey(env, sponsorTmpPublicKey, &sponsor_tmp_pub_key)) {
        (*env)->ReleasePrimitiveArrayCritical(env, responseID, response_id_buf, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, sponsorID, sponsor_id_buf, JNI_ABORT);
        return 0;
    }
    if (!java_to_native_ECCPublicKey(env, responsePublicKey, &response_pub_key)) {
        (*env)->ReleasePrimitiveArrayCritical(env, responseID, response_id_buf, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, sponsorID, sponsor_id_buf, JNI_ABORT);
        return 0;
    }
    if (!java_to_native_ECCPublicKey(env, responseTmpPublicKey, &response_tmp_pub_key)) {
        (*env)->ReleasePrimitiveArrayCritical(env, responseID, response_id_buf, JNI_ABORT);
        (*env)->ReleasePrimitiveArrayCritical(env, sponsorID, sponsor_id_buf, JNI_ABORT);
        return 0;
    }

    HANDLE key_handle = 0;

    LONG ret = g_sdf_functions.SDF_GenerateAgreementDataAndKeyWithECC(
        (HANDLE)sessionHandle,
        (ULONG)keyIndex,
        (ULONG)keyBits,
        (BYTE*)response_id_buf,
        (ULONG)response_id_len,
        (BYTE*)sponsor_id_buf,
        (ULONG)sponsor_id_len,
        &sponsor_pub_key,
        &sponsor_tmp_pub_key,
        &response_pub_key,
        &response_tmp_pub_key,
        &key_handle
    );

    (*env)->ReleasePrimitiveArrayCritical(env, responseID, response_id_buf, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, sponsorID, sponsor_id_buf, JNI_ABORT);

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
JNIEXPORT jobject JNICALL JNI_SDF_GenerateKeyWithKEK(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyBits, jint algID,
    jint kekIndex) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_GenerateKeyWithKEK == NULL || g_sdf_functions.SDF_DestroyKey == NULL) {
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
    if (result == NULL) {
        g_sdf_functions.SDF_DestroyKey((HANDLE)sessionHandle, (HANDLE)key_handle);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    return result;
}

/**
 * 6.3.16 导入会话密钥并用密钥加密密钥解密
 * Pattern: Returns key handle (long)
 */
JNIEXPORT jlong JNICALL JNI_SDF_ImportKeyWithKEK(JNIEnv *env, jobject obj, jlong sessionHandle, jint algID, jint kekIndex,
    jbyteArray encryptedKey) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_ImportKeyWithKEK == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return 0;
    }

    /* 转换加密密钥数据 */
    jsize key_len = (*env)->GetArrayLength(env, encryptedKey);
    jbyte *key_buf = (*env)->GetPrimitiveArrayCritical(env, encryptedKey, NULL);
    if (key_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return 0;
    }

    HANDLE key_handle = 0;

    LONG ret = g_sdf_functions.SDF_ImportKeyWithKEK(
        (HANDLE)sessionHandle,
        (ULONG)algID,
        (ULONG)kekIndex,
        (BYTE*)key_buf,
        (ULONG)key_len,
        &key_handle
    );

    (*env)->ReleasePrimitiveArrayCritical(env, encryptedKey, key_buf, JNI_ABORT);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return 0;
    }

    return (jlong)key_handle;
}

