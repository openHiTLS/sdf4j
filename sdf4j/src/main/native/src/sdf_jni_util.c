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
 * Category 6.8 验证调试类函数 (Verification and Debug Functions)
 * ======================================================================== */

/**
 * 6.8.2 产生RSA非对称密钥对并输出
 * Pattern: Returns Object[] {RSAPublicKey, RSAPrivateKey}
 */
JNIEXPORT jobjectArray JNICALL JNI_SDF_GenerateKeyPair_RSA(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint keyBits) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_GenerateKeyPair_RSA == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    RSArefPublicKey pub_key;
    RSArefPrivateKey priv_key;
    memset(&pub_key, 0, sizeof(RSArefPublicKey));
    memset(&priv_key, 0, sizeof(RSArefPrivateKey));

    LONG ret = g_sdf_functions.SDF_GenerateKeyPair_RSA(
        (HANDLE)sessionHandle,
        (ULONG)keyBits,
        &pub_key,
        &priv_key
    );

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return NULL;
    }

    /* Convert to Java objects */
    jobject java_pub = native_to_java_RSAPublicKey(env, &pub_key);
    jobject java_priv = native_to_java_RSAPrivateKey(env, &priv_key);

    if (java_pub == NULL || java_priv == NULL) {
        return NULL;  /* Exception already thrown */
    }

    /* Create Object array */
    if (!jni_cache_is_initialized()) {
        return NULL;
    }
    jobjectArray result = (*env)->NewObjectArray(env, 2, g_jni_cache.common.objectClass, NULL);
    if (result != NULL) {
        (*env)->SetObjectArrayElement(env, result, 0, java_pub);
        (*env)->SetObjectArrayElement(env, result, 1, java_priv);
    }
    return result;
}

/**
 * 6.8.3 产生ECC非对称密钥对并输出
 * Pattern: Returns Object[] {ECCPublicKey, ECCPrivateKey}
 */
JNIEXPORT jobjectArray JNICALL JNI_SDF_GenerateKeyPair_ECC(JNIEnv *env, jobject obj, jlong sessionHandle, jint algID,
    jint keyBits) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_GenerateKeyPair_ECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    ECCrefPublicKey pub_key;
    ECCrefPrivateKey priv_key;
    memset(&pub_key, 0, sizeof(ECCrefPublicKey));
    memset(&priv_key, 0, sizeof(ECCrefPrivateKey));

    LONG ret = g_sdf_functions.SDF_GenerateKeyPair_ECC(
        (HANDLE)sessionHandle,
        (ULONG)algID,
        (ULONG)keyBits,
        &pub_key,
        &priv_key
    );

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return NULL;
    }

    /* Convert to Java objects */
    jobject java_pub = native_to_java_ECCPublicKey(env, &pub_key);
    jobject java_priv = native_to_java_ECCPrivateKey(env, &priv_key);

    if (java_pub == NULL || java_priv == NULL) {
        return NULL;  /* Exception already thrown */
    }

    /* Create Object array */
    if (!jni_cache_is_initialized()) {
        return NULL;
    }
    jobjectArray result = (*env)->NewObjectArray(env, 2, g_jni_cache.common.objectClass, NULL);
    (*env)->SetObjectArrayElement(env, result, 0, java_pub);
    (*env)->SetObjectArrayElement(env, result, 1, java_priv);

    return result;
}

/**
 * 6.8.4 外部私钥RSA运算
 * Pattern: Returns byte[] output data
 */
JNIEXPORT jbyteArray JNICALL JNI_SDF_ExternalPrivateKeyOperation_RSA(JNIEnv *env, jobject obj, jlong sessionHandle,
    jobject privateKey, jbyteArray dataInput) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_ExternalPrivateKeyOperation_RSA == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* Convert private key */
    RSArefPrivateKey priv_key;
    if (!java_to_native_RSAPrivateKey(env, privateKey, &priv_key)) {
        return NULL;
    }

    /* Convert input data */
    jsize input_len = (*env)->GetArrayLength(env, dataInput);
    BYTE *input_buf = (BYTE*)malloc(input_len);
    if (input_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, dataInput, 0, input_len, (jbyte*)input_buf);

    /* Allocate output buffer */
    ULONG output_len = 512;  /* Max RSA key size */
    BYTE *output_buf = (BYTE*)malloc(output_len);
    if (output_buf == NULL) {
        free(input_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_ExternalPrivateKeyOperation_RSA(
        (HANDLE)sessionHandle,
        &priv_key,
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
 * 6.8.5 外部私钥ECC签名
 * Pattern: Returns ECCSignature
 */
JNIEXPORT jobject JNICALL JNI_SDF_ExternalSign_ECC(JNIEnv *env, jobject obj, jlong sessionHandle, jint algID,
    jobject privateKey, jbyteArray data) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_ExternalSign_ECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }
    if (privateKey == NULL) {
        throw_sdf_exception(env, 0x0100001D);  /* SDR_INARGERR */
        return NULL;
    }
    /* Convert private key */
    ECCrefPrivateKey priv_key = {0};
    if (!java_to_native_ECCPrivateKey(env, privateKey, &priv_key)) {
        return NULL;
    }

    /* Convert data */
    jsize data_len = (*env)->GetArrayLength(env, data);
    jbyte *data_buf = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    ECCSignature signature = {0};

    LONG ret = g_sdf_functions.SDF_ExternalSign_ECC(
        (HANDLE)sessionHandle,
        (ULONG)algID,
        &priv_key,
        (BYTE*)data_buf,
        (ULONG)data_len,
        &signature
    );

    (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return NULL;
    }

    return native_to_java_ECCSignature(env, &signature);
}

/**
 * 6.8.6 外部私钥ECC解密
 * Pattern: Returns byte[] plaintext
 */
JNIEXPORT jbyteArray JNICALL JNI_SDF_ExternalDecrypt_ECC(JNIEnv *env, jobject obj, jlong sessionHandle, jint algID,
    jobject privateKey, jobject cipher) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_ExternalDecrypt_ECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }
    if (cipher == NULL || privateKey == NULL) {
        throw_sdf_exception(env, 0x0100001D);  /* SDR_INARGERR */
        return NULL;
    }
    /* Convert private key */
    ECCrefPrivateKey priv_key = {0};
    if (!java_to_native_ECCPrivateKey(env, privateKey, &priv_key)) {
        SDF_JNI_LOG("SDF_ExternalDecrypt_ECC: java to native ECCPrivateKey fail.");
	return NULL;
    }
    
    /* Convert cipher (使用动态分配以支持柔性数组成员) */
    ECCCipher *ecc_cipher = java_to_native_ECCCipher_alloc(env, cipher);
    if (ecc_cipher == NULL) {
        SDF_JNI_LOG("SDF_ExternalDecrypt_ECC: java to native ECCCipher fail.");
        return NULL;
    }

    /* Allocate output buffer */
    ULONG plaintext_len = ecc_cipher->L + 64;
    if (plaintext_len < 256) plaintext_len = 256;  /* Reasonable min */
    BYTE *plaintext_buf = (BYTE*)malloc(plaintext_len);
    if (plaintext_buf == NULL) {
        free(ecc_cipher);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_ExternalDecrypt_ECC(
        (HANDLE)sessionHandle,
        (ULONG)algID,
        &priv_key,
        ecc_cipher,
        plaintext_buf,
        &plaintext_len
    );

    if (ret != SDR_OK) {
        free(ecc_cipher);
        free(plaintext_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, plaintext_buf, plaintext_len);
    free(ecc_cipher);
    free(plaintext_buf);

    return result;
}

/**
 * 6.8.9 外部密钥单包对称加密
 * Pattern: Returns byte[] encrypted data
 */
JNIEXPORT jbyteArray JNICALL JNI_SDF_ExternalKeyEncrypt(JNIEnv *env, jobject obj, jlong sessionHandle, jint algID,
    jbyteArray key, jbyteArray iv, jbyteArray data) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_ExternalKeyEncrypt == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* Convert key */
    jsize key_len = (*env)->GetArrayLength(env, key);
    jbyte *key_buf = (*env)->GetPrimitiveArrayCritical(env, key, NULL);
    if (key_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    /* Convert IV (may be NULL) */
    jbyte *iv_buf = NULL;
    ULONG iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (*env)->GetPrimitiveArrayCritical(env, iv, NULL);
        if (iv_buf == NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, key, key_buf, JNI_ABORT);
            throw_sdf_exception(env, 0x0100001C);
            return NULL;
        }
    }

    /* Convert data */
    jsize data_len = (*env)->GetArrayLength(env, data);
    jbyte *data_buf = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    if (data_buf == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, key, key_buf, JNI_ABORT);
        if (iv_buf != NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
        }
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    /* Allocate encrypted buffer (may need padding) */
    ULONG enc_len = data_len + 32;
    BYTE *enc_buf = (BYTE*)malloc(enc_len);
    if (enc_buf == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, key, key_buf, JNI_ABORT);
        if (iv_buf != NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
        }
        (*env)->ReleasePrimitiveArrayCritical(env, data, data_buf, JNI_ABORT);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_ExternalKeyEncrypt(
        (HANDLE)sessionHandle,
        (ULONG)algID,
        (BYTE*)key_buf,
        (ULONG)key_len,
        (BYTE*)iv_buf,
        iv_len,
        (BYTE*)data_buf,
        (ULONG)data_len,
        enc_buf,
        &enc_len
    );

    (*env)->ReleasePrimitiveArrayCritical(env, key, key_buf, JNI_ABORT);
    if (iv_buf != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
    }
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
 * 6.8.10 外部密钥单包对称解密
 * Pattern: Returns byte[] decrypted data
 */
JNIEXPORT jbyteArray JNICALL JNI_SDF_ExternalKeyDecrypt(JNIEnv *env, jobject obj, jlong sessionHandle, jint algID,
    jbyteArray key, jbyteArray iv, jbyteArray encData) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_ExternalKeyDecrypt == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* Convert key */
    jsize key_len = (*env)->GetArrayLength(env, key);
    jbyte *key_buf = (*env)->GetPrimitiveArrayCritical(env, key, NULL);
    if (key_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    /* Convert IV (may be NULL) */
    BYTE *iv_buf = NULL;
    ULONG iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (*env)->GetPrimitiveArrayCritical(env, iv, NULL);
        if (iv_buf == NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, key, key_buf, JNI_ABORT);
            throw_sdf_exception(env, 0x0100001C);
            return NULL;
        }
    }

    /* Convert encrypted data */
    jsize enc_len = (*env)->GetArrayLength(env, encData);
    jbyte *enc_buf = (*env)->GetPrimitiveArrayCritical(env, encData, NULL);
    if (enc_buf == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, key, key_buf, JNI_ABORT);
        if (iv_buf) {
            (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
        }
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    /* Allocate plaintext buffer */
    ULONG plaintext_len = enc_len;
    BYTE *plaintext_buf = (BYTE*)malloc(plaintext_len);
    if (plaintext_buf == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, key, key_buf, JNI_ABORT);
        if (iv_buf) {
            (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
        }
        (*env)->ReleasePrimitiveArrayCritical(env, encData, enc_buf, JNI_ABORT);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_ExternalKeyDecrypt(
        (HANDLE)sessionHandle,
        (ULONG)algID,
        (BYTE *)key_buf,
        (ULONG)key_len,
        (BYTE *)iv_buf,
        iv_len,
        (BYTE *)enc_buf,
        (ULONG)enc_len,
        plaintext_buf,
        &plaintext_len
    );

    (*env)->ReleasePrimitiveArrayCritical(env, key, key_buf, JNI_ABORT);
    if (iv_buf) {
        (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
    }
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

/**
 * 6.8.11 外部密钥多包对称加密初始化
 * Pattern: Void function
 */
JNIEXPORT void JNICALL JNI_SDF_ExternalKeyEncryptInit(JNIEnv *env, jobject obj, jlong sessionHandle, jint algID,
    jbyteArray key, jbyteArray iv) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_ExternalKeyEncryptInit == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    /* Convert key */
    jsize key_len = (*env)->GetArrayLength(env, key);
    jbyte *key_buf = (*env)->GetPrimitiveArrayCritical(env, key, NULL);
    if (key_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return;
    }

    /* Convert IV (may be NULL) */
    jbyte *iv_buf = NULL;
    ULONG iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (*env)->GetPrimitiveArrayCritical(env, iv, NULL);
        if (iv_buf == NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, key, key_buf, JNI_ABORT);
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
    }

    LONG ret = g_sdf_functions.SDF_ExternalKeyEncryptInit(
        (HANDLE)sessionHandle,
        (ULONG)algID,
        (BYTE*)key_buf,
        (ULONG)key_len,
        (BYTE*)iv_buf,
        iv_len
    );

    (*env)->ReleasePrimitiveArrayCritical(env, key, key_buf, JNI_ABORT);
    if (iv_buf != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
    }

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/**
 * 6.8.12 外部密钥多包对称解密初始化
 * Pattern: Void function
 */
JNIEXPORT void JNICALL JNI_SDF_ExternalKeyDecryptInit(JNIEnv *env, jobject obj, jlong sessionHandle, jint algID,
    jbyteArray key, jbyteArray iv) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_ExternalKeyDecryptInit == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    /* Convert key */
    jsize key_len = (*env)->GetArrayLength(env, key);
    jbyte *key_buf = (*env)->GetPrimitiveArrayCritical(env, key, NULL);
    if (key_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return;
    }

    /* Convert IV (may be NULL) */
    jbyte *iv_buf = NULL;
    ULONG iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (*env)->GetPrimitiveArrayCritical(env, iv, NULL);
        if (iv_buf == NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, key, key_buf, JNI_ABORT);
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
    }

    LONG ret = g_sdf_functions.SDF_ExternalKeyDecryptInit(
        (HANDLE)sessionHandle,
        (ULONG)algID,
        (BYTE*)key_buf,
        (ULONG)key_len,
        (BYTE*)iv_buf,
        iv_len
    );

    (*env)->ReleasePrimitiveArrayCritical(env, key, key_buf, JNI_ABORT);
    if (iv_buf != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_buf, JNI_ABORT);
    }

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/**
 * 6.8.13 带外部密钥的杂凑运算初始化
 * Pattern: Void function
 */
JNIEXPORT void JNICALL JNI_SDF_ExternalKeyHMACInit(JNIEnv *env, jobject obj, jlong sessionHandle, jint algID,
    jbyteArray key) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_ExternalKeyHMACInit == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    /* Convert key */
    jsize key_len = (*env)->GetArrayLength(env, key);
    jbyte *key_buf = (*env)->GetPrimitiveArrayCritical(env, key, NULL);
    if (key_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return;
    }

    LONG ret = g_sdf_functions.SDF_ExternalKeyHMACInit(
        (HANDLE)sessionHandle,
        (ULONG)algID,
        (BYTE*)key_buf,
        (ULONG)key_len
    );

    (*env)->ReleasePrimitiveArrayCritical(env, key, key_buf, JNI_ABORT);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}
