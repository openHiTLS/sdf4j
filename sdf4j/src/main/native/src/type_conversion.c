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

#include "type_conversion.h"
#include "jni_cache.h"
#include "sdf_log.h"
#include <string.h>
#include <stdlib.h>

/* ========================================================================
 * 异常处理
 * ======================================================================== */

void throw_sdf_exception(JNIEnv *env, int error_code) {
    SDF_JNI_LOG("throw_sdf_exception: error_code=0x%08X", (unsigned int)error_code);

    jobject exception = (*env)->NewObject(env, g_jni_cache.sdfException.cls,
                                          g_jni_cache.sdfException.ctor_int, error_code);
    if (exception != NULL) {
        (*env)->Throw(env, (jthrowable)exception);
    } else {
        SDF_LOG_ERROR("throw_sdf_exception", "Failed to create SDFException object");
    }
}

void throw_sdf_exception_with_message(JNIEnv *env, int error_code, const char *message) {
    SDF_JNI_LOG("throw_sdf_exception_with_message: error_code=0x%08X, message=%s",
                (unsigned int)error_code, message ? message : "NULL");

    jstring jmsg = (*env)->NewStringUTF(env, message);
    jobject exception = (*env)->NewObject(env, g_jni_cache.sdfException.cls,
                                          g_jni_cache.sdfException.ctor_int_string,
                                          error_code, jmsg);
    if (exception != NULL) {
        (*env)->Throw(env, (jthrowable)exception);
    } else {
        SDF_LOG_ERROR("throw_sdf_exception_with_message", "Failed to create SDFException object");
    }
}

/* ========================================================================
 * 辅助函数
 * ======================================================================== */

static jstring native_string_to_java(JNIEnv *env, const CHAR *str, size_t max_len) {
    /* 找到实际字符串长度（去除尾部的0） */
    size_t len = strnlen((const char *)str, max_len);
    char *temp = (char*)malloc(len + 1);
    if (temp == NULL) {
        return NULL;
    }
    memcpy(temp, str, len);
    temp[len] = '\0';

    jstring result = (*env)->NewStringUTF(env, temp);
    free(temp);
    return result;
}

/* ========================================================================
 * C结构体 → Java对象转换
 * ======================================================================== */

jobject native_to_java_DeviceInfo(JNIEnv *env, const DEVICEINFO *native_info) {
    /* 创建对象 */
    jobject obj = (*env)->NewObject(env, g_jni_cache.deviceInfo.cls,
                                    g_jni_cache.deviceInfo.ctor);
    if (obj == NULL) {
        return NULL;
    }

    /* issuerName */
    jstring str = native_string_to_java(env, native_info->IssuerName, 40);
    (*env)->SetObjectField(env, obj, g_jni_cache.deviceInfo.issuerName, str);

    /* deviceName */
    str = native_string_to_java(env, native_info->DeviceName, 16);
    (*env)->SetObjectField(env, obj, g_jni_cache.deviceInfo.deviceName, str);

    /* deviceSerial */
    str = native_string_to_java(env, native_info->DeviceSerial, 16);
    (*env)->SetObjectField(env, obj, g_jni_cache.deviceInfo.deviceSerial, str);

    /* deviceVersion */
    (*env)->SetLongField(env, obj, g_jni_cache.deviceInfo.deviceVersion,
                         native_info->DeviceVersion);

    /* standardVersion */
    (*env)->SetLongField(env, obj, g_jni_cache.deviceInfo.standardVersion,
                         native_info->StandardVersion);

    /* asymAlgAbility */
    jlongArray array = (*env)->NewLongArray(env, 2);
    if (array != NULL) {
        jlong temp[2];
        temp[0] = native_info->AsymAlgAbility[0];
        temp[1] = native_info->AsymAlgAbility[1];
        (*env)->SetLongArrayRegion(env, array, 0, 2, temp);
        (*env)->SetObjectField(env, obj, g_jni_cache.deviceInfo.asymAlgAbility, array);
    }

    /* symAlgAbility */
    (*env)->SetLongField(env, obj, g_jni_cache.deviceInfo.symAlgAbility,
                         native_info->SymAlgAbility);

    /* hashAlgAbility */
    (*env)->SetLongField(env, obj, g_jni_cache.deviceInfo.hashAlgAbility,
                         native_info->HashAlgAbility);

    /* bufferSize */
    (*env)->SetLongField(env, obj, g_jni_cache.deviceInfo.bufferSize,
                         native_info->BufferSize);

    return obj;
}

jobject native_to_java_RSAPublicKey(JNIEnv *env, const RSArefPublicKey *native_key) {

    jobject obj = (*env)->NewObject(env, g_jni_cache.rsaPublicKey.cls,
                                    g_jni_cache.rsaPublicKey.ctor);
    if (obj == NULL) return NULL;

    /* bits */
    (*env)->SetIntField(env, obj, g_jni_cache.rsaPublicKey.bits, native_key->bits);

    /* m */
    jbyteArray m_array = (*env)->NewByteArray(env, RSAref_MAX_LEN);
    if (m_array != NULL) {
        (*env)->SetByteArrayRegion(env, m_array, 0, RSAref_MAX_LEN, (jbyte*)native_key->m);
        (*env)->SetObjectField(env, obj, g_jni_cache.rsaPublicKey.m, m_array);
    }

    /* e */
    jbyteArray e_array = (*env)->NewByteArray(env, RSAref_MAX_LEN);
    if (e_array != NULL) {
        (*env)->SetByteArrayRegion(env, e_array, 0, RSAref_MAX_LEN, (jbyte*)native_key->e);
        (*env)->SetObjectField(env, obj, g_jni_cache.rsaPublicKey.e, e_array);
    }

    return obj;
}

jobject native_to_java_ECCPublicKey(JNIEnv *env, const ECCrefPublicKey *native_key) {
    jobject obj = (*env)->NewObject(env, g_jni_cache.eccPublicKey.cls,
                                    g_jni_cache.eccPublicKey.ctor);
    if (obj == NULL) return NULL;

    /* bits */
    (*env)->SetIntField(env, obj, g_jni_cache.eccPublicKey.bits, native_key->bits);

    /* x */
    jbyteArray x_array = (*env)->NewByteArray(env, ECCref_MAX_LEN);
    if (x_array != NULL) {
        (*env)->SetByteArrayRegion(env, x_array, 0, ECCref_MAX_LEN, (jbyte*)native_key->x);
        (*env)->SetObjectField(env, obj, g_jni_cache.eccPublicKey.x, x_array);
    }

    /* y */
    jbyteArray y_array = (*env)->NewByteArray(env, ECCref_MAX_LEN);
    if (y_array != NULL) {
        (*env)->SetByteArrayRegion(env, y_array, 0, ECCref_MAX_LEN, (jbyte*)native_key->y);
        (*env)->SetObjectField(env, obj, g_jni_cache.eccPublicKey.y, y_array);
    }

    return obj;
}

jobject native_to_java_ECCSignature(JNIEnv *env, const ECCSignature *native_sig) {
    jobject obj = (*env)->NewObject(env, g_jni_cache.eccSignature.cls,
                                    g_jni_cache.eccSignature.ctor);
    if (obj == NULL) return NULL;

    /* r */
    /* 智能检测实际签名长度：从后往前查找非零字节 */
    int r_len = ECCref_MAX_LEN;
    while (r_len > 0 && native_sig->r[r_len - 1] == 0) {
        r_len--;
    }
    /* SM2签名通常是32字节，如果检测到的长度接近32，则使用32 */
    if (r_len > 0 && r_len <= 32) {
        r_len = 32;  /* 标准SM2签名长度 */
    }

    jbyteArray r_array = (*env)->NewByteArray(env, r_len);
    if (r_array != NULL) {
        (*env)->SetByteArrayRegion(env, r_array, 0, r_len, (jbyte*)native_sig->r);
        (*env)->SetObjectField(env, obj, g_jni_cache.eccSignature.r, r_array);
    }

    /* s */
    /* 智能检测实际签名长度：从后往前查找非零字节 */
    int s_len = ECCref_MAX_LEN;
    while (s_len > 0 && native_sig->s[s_len - 1] == 0) {
        s_len--;
    }
    /* SM2签名通常是32字节，如果检测到的长度接近32，则使用32 */
    if (s_len > 0 && s_len <= 32) {
        s_len = 32;  /* 标准SM2签名长度 */
    }

    jbyteArray s_array = (*env)->NewByteArray(env, s_len);
    if (s_array != NULL) {
        (*env)->SetByteArrayRegion(env, s_array, 0, s_len, (jbyte*)native_sig->s);
        (*env)->SetObjectField(env, obj, g_jni_cache.eccSignature.s, s_array);
    }

    return obj;
}

jobject native_to_java_ECCCipher(JNIEnv *env, const ECCCipher *native_cipher, ULONG cipher_len) {
    jobject obj = (*env)->NewObject(env, g_jni_cache.eccCipher.cls,
                                    g_jni_cache.eccCipher.ctor);
    if (obj == NULL) return NULL;

    /* x */
    jbyteArray x_array = (*env)->NewByteArray(env, ECCref_MAX_LEN);
    if (x_array != NULL) {
        (*env)->SetByteArrayRegion(env, x_array, 0, ECCref_MAX_LEN, (jbyte*)native_cipher->x);
        (*env)->SetObjectField(env, obj, g_jni_cache.eccCipher.x, x_array);
    }

    /* y */
    jbyteArray y_array = (*env)->NewByteArray(env, ECCref_MAX_LEN);
    if (y_array != NULL) {
        (*env)->SetByteArrayRegion(env, y_array, 0, ECCref_MAX_LEN, (jbyte*)native_cipher->y);
        (*env)->SetObjectField(env, obj, g_jni_cache.eccCipher.y, y_array);
    }

    /* m */
    jbyteArray m_array = (*env)->NewByteArray(env, 32);
    if (m_array != NULL) {
        (*env)->SetByteArrayRegion(env, m_array, 0, 32, (jbyte*)native_cipher->M);
        (*env)->SetObjectField(env, obj, g_jni_cache.eccCipher.m, m_array);
    }

    /* l - 密文长度 (对应C结构体的ULONG L字段) */
    (*env)->SetLongField(env, obj, g_jni_cache.eccCipher.l, (jlong)native_cipher->L);

    /* c - 变长密文数据 */
    if (cipher_len > 0) {
        jbyteArray c_array = (*env)->NewByteArray(env, cipher_len);
        if (c_array != NULL) {
            (*env)->SetByteArrayRegion(env, c_array, 0, cipher_len, (jbyte*)&native_cipher->C);
            (*env)->SetObjectField(env, obj, g_jni_cache.eccCipher.c, c_array);
        }
    }

    return obj;
}

/* ========================================================================
 * Java对象 → C结构体转换
 * ======================================================================== */

bool java_to_native_RSAPublicKey(JNIEnv *env, jobject java_key, RSArefPublicKey *native_key) {

    memset(native_key, 0, sizeof(RSArefPublicKey));

    /* bits */
    native_key->bits = (*env)->GetIntField(env, java_key, g_jni_cache.rsaPublicKey.bits);

    /* m (modulus) */
    jbyteArray m_array = (jbyteArray)(*env)->GetObjectField(env, java_key,
                                                             g_jni_cache.rsaPublicKey.m);
    if (m_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, m_array);
        if (len > RSAref_MAX_LEN) len = RSAref_MAX_LEN;
        (*env)->GetByteArrayRegion(env, m_array, 0, len, (jbyte*)native_key->m);
    }

    /* e (public exponent) */
    jbyteArray e_array = (jbyteArray)(*env)->GetObjectField(env, java_key,
                                                             g_jni_cache.rsaPublicKey.e);
    if (e_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, e_array);
        if (len > RSAref_MAX_LEN) len = RSAref_MAX_LEN;
        (*env)->GetByteArrayRegion(env, e_array, 0, len, (jbyte*)native_key->e);
    }

    return true;
}

/**
 * Convert Java ECCCipher to native ECCCipher with dynamic memory allocation.
 * This function properly handles the flexible array member C[].
 * Caller MUST free the returned pointer using free().
 */
ECCCipher* java_to_native_ECCCipher_alloc(JNIEnv *env, jobject java_cipher) {
    /* First, get the cipher data length to determine allocation size */
    jbyteArray c_array = (jbyteArray)(*env)->GetObjectField(env, java_cipher,
                                                             g_jni_cache.eccCipher.c);
    jsize c_len = 0;
    if (c_array != NULL) {
        c_len = (*env)->GetArrayLength(env, c_array);
    }

    /* Also check L field */
    jlong l_value = (*env)->GetLongField(env, java_cipher, g_jni_cache.eccCipher.l);
    if (c_len == 0 && l_value > 0) {
        c_len = (jsize)l_value;
    }

    /* Allocate memory for ECCCipher struct + flexible array C[] */
    size_t alloc_size = sizeof(ECCCipher) + c_len;
    ECCCipher *native_cipher = (ECCCipher*)calloc(1, alloc_size);
    if (native_cipher == NULL) {
        return NULL;
    }

    /* x */
    jbyteArray x_array = (jbyteArray)(*env)->GetObjectField(env, java_cipher,
                                                             g_jni_cache.eccCipher.x);
    if (x_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, x_array);
        (*env)->GetByteArrayRegion(env, x_array, 0, len, (jbyte*)native_cipher->x);
    }

    /* y */
    jbyteArray y_array = (jbyteArray)(*env)->GetObjectField(env, java_cipher,
                                                             g_jni_cache.eccCipher.y);
    if (y_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, y_array);
        (*env)->GetByteArrayRegion(env, y_array, 0, len, (jbyte*)native_cipher->y);
    }

    /* m (hash/MAC) */
    jbyteArray m_array = (jbyteArray)(*env)->GetObjectField(env, java_cipher,
                                                             g_jni_cache.eccCipher.m);
    if (m_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, m_array);
        if (len > 32) len = 32;
        (*env)->GetByteArrayRegion(env, m_array, 0, len, (jbyte*)native_cipher->M);
    }

    /* L - cipher data length */
    native_cipher->L = (ULONG)l_value;
    if (native_cipher->L == 0 && c_len > 0) {
        native_cipher->L = c_len;
    }

    /* C - cipher data (now properly allocated) */
    if (c_array != NULL && c_len > 0) {
        (*env)->GetByteArrayRegion(env, c_array, 0, c_len, (jbyte*)native_cipher->C);
    }

    return native_cipher;
}

bool java_to_native_ECCPublicKey(JNIEnv *env, jobject java_key, ECCrefPublicKey *native_key) {

    memset(native_key, 0, sizeof(ECCrefPublicKey));

    /* bits */
    native_key->bits = (*env)->GetIntField(env, java_key, g_jni_cache.eccPublicKey.bits);

    /* x */
    jbyteArray x_array = (jbyteArray)(*env)->GetObjectField(env, java_key,
                                                             g_jni_cache.eccPublicKey.x);
    if (x_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, x_array);
        (*env)->GetByteArrayRegion(env, x_array, 0, len, (jbyte*)native_key->x);
    }

    /* y */
    jbyteArray y_array = (jbyteArray)(*env)->GetObjectField(env, java_key,
                                                             g_jni_cache.eccPublicKey.y);
    if (y_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, y_array);
        (*env)->GetByteArrayRegion(env, y_array, 0, len, (jbyte*)native_key->y);
    }

    return true;
}

bool java_to_native_ECCSignature(JNIEnv *env, jobject java_sig, ECCSignature *native_sig) {

    /* r */
    jbyteArray r_array = (jbyteArray)(*env)->GetObjectField(env, java_sig,
                                                             g_jni_cache.eccSignature.r);
    if (r_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, r_array);
        (*env)->GetByteArrayRegion(env, r_array, 0, len, (jbyte*)native_sig->r);
    }

    /* s */
    jbyteArray s_array = (jbyteArray)(*env)->GetObjectField(env, java_sig,
                                                             g_jni_cache.eccSignature.s);
    if (s_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, s_array);
        (*env)->GetByteArrayRegion(env, s_array, 0, len, (jbyte*)native_sig->s);
    }

    return true;
}

char* java_string_to_native(JNIEnv *env, jstring java_str) {
    if (java_str == NULL) {
        return NULL; 
    }

    const char *str = (*env)->GetStringUTFChars(env, java_str, NULL);
    if (str == NULL) {
        return NULL;
    }

    char *result = strdup(str);
    (*env)->ReleaseStringUTFChars(env, java_str, str);
    return result;
}

jbyteArray native_to_java_byte_array(JNIEnv *env, const BYTE *native_data, ULONG data_len) {

    jbyteArray array = (*env)->NewByteArray(env, data_len);
    if (array == NULL) {
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, array, 0, data_len, (jbyte*)native_data);
    return array;
}

jobject create_key_encryption_result(JNIEnv *env, const BYTE *encrypted_key,
                                     ULONG key_length, HANDLE key_handle) {

    /* Create byte array for encrypted key */
    jbyteArray key_array = (*env)->NewByteArray(env, key_length);
    if (key_array == NULL) {
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, key_array, 0, key_length, (jbyte*)encrypted_key);

    /* Create KeyEncryptionResult object */
    jobject obj = (*env)->NewObject(env, g_jni_cache.keyEncryptionResult.cls,
                                    g_jni_cache.keyEncryptionResult.ctor,
                                    key_array, (jlong)key_handle);
    return obj;
}

jobject native_to_java_RSAPrivateKey(JNIEnv *env, const RSArefPrivateKey *native_key) {

    jobject obj = (*env)->NewObject(env, g_jni_cache.rsaPrivateKey.cls,
                                    g_jni_cache.rsaPrivateKey.ctor);
    if (obj == NULL) return NULL;

    /* bits */
    (*env)->SetIntField(env, obj, g_jni_cache.rsaPrivateKey.bits, (jint)native_key->bits);

    /* m */
    jbyteArray m = (*env)->NewByteArray(env, RSAref_MAX_LEN);
    if (m != NULL) {
        (*env)->SetByteArrayRegion(env, m, 0, RSAref_MAX_LEN, (const jbyte*)native_key->m);
        (*env)->SetObjectField(env, obj, g_jni_cache.rsaPrivateKey.m, m);
    }

    /* e */
    jbyteArray e = (*env)->NewByteArray(env, RSAref_MAX_LEN);
    if (e != NULL) {
        (*env)->SetByteArrayRegion(env, e, 0, RSAref_MAX_LEN, (const jbyte*)native_key->e);
        (*env)->SetObjectField(env, obj, g_jni_cache.rsaPrivateKey.e, e);
    }

    /* d */
    jbyteArray d = (*env)->NewByteArray(env, RSAref_MAX_LEN);
    if (d != NULL) {
        (*env)->SetByteArrayRegion(env, d, 0, RSAref_MAX_LEN, (const jbyte*)native_key->d);
        (*env)->SetObjectField(env, obj, g_jni_cache.rsaPrivateKey.d, d);
    }

    /* prime[2] */
    jobjectArray primeArray = (*env)->NewObjectArray(env, 2,
                                                      g_jni_cache.common.byteArrayClass, NULL);
    if (primeArray != NULL) {
        for (int i = 0; i < 2; i++) {
            jbyteArray p = (*env)->NewByteArray(env, RSAref_MAX_PLEN);
            if (p != NULL) {
                (*env)->SetByteArrayRegion(env, p, 0, RSAref_MAX_PLEN,
                                           (const jbyte*)native_key->prime[i]);
                (*env)->SetObjectArrayElement(env, primeArray, i, p);
            }
        }
        (*env)->SetObjectField(env, obj, g_jni_cache.rsaPrivateKey.prime, primeArray);
    }

    /* pexp[2] */
    jobjectArray pexpArray = (*env)->NewObjectArray(env, 2,
                                                     g_jni_cache.common.byteArrayClass, NULL);
    if (pexpArray != NULL) {
        for (int i = 0; i < 2; i++) {
            jbyteArray p = (*env)->NewByteArray(env, RSAref_MAX_PLEN);
            if (p != NULL) {
                (*env)->SetByteArrayRegion(env, p, 0, RSAref_MAX_PLEN,
                                           (const jbyte*)native_key->pexp[i]);
                (*env)->SetObjectArrayElement(env, pexpArray, i, p);
            }
        }
        (*env)->SetObjectField(env, obj, g_jni_cache.rsaPrivateKey.pexp, pexpArray);
    }

    /* coef */
    jbyteArray coef = (*env)->NewByteArray(env, RSAref_MAX_PLEN);
    if (coef != NULL) {
        (*env)->SetByteArrayRegion(env, coef, 0, RSAref_MAX_PLEN, (const jbyte*)native_key->coef);
        (*env)->SetObjectField(env, obj, g_jni_cache.rsaPrivateKey.coef, coef);
    }

    return obj;
}

jobject native_to_java_ECCPrivateKey(JNIEnv *env, const ECCrefPrivateKey *native_key) {

    jobject obj = (*env)->NewObject(env, g_jni_cache.eccPrivateKey.cls,
                                    g_jni_cache.eccPrivateKey.ctor);
    if (obj == NULL) return NULL;

    /* bits */
    (*env)->SetIntField(env, obj, g_jni_cache.eccPrivateKey.bits, (jint)native_key->bits);

    /* k */
    jbyteArray k = (*env)->NewByteArray(env, ECCref_MAX_LEN);
    if (k != NULL) {
        (*env)->SetByteArrayRegion(env, k, 0, ECCref_MAX_LEN, (const jbyte*)native_key->K);
        (*env)->SetObjectField(env, obj, g_jni_cache.eccPrivateKey.k, k);
    }

    return obj;
}

bool java_to_native_RSAPrivateKey(JNIEnv *env, jobject java_key, RSArefPrivateKey *native_key) {
    if (java_key == NULL) {
        return false;
    }

    memset(native_key, 0, sizeof(RSArefPrivateKey));
    /* bits */
    native_key->bits = (*env)->GetIntField(env, java_key, g_jni_cache.rsaPrivateKey.bits);

    /* m */
    jbyteArray m_array = (jbyteArray)(*env)->GetObjectField(env, java_key,
                                                             g_jni_cache.rsaPrivateKey.m);
    if (m_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, m_array);
        if (len > RSAref_MAX_LEN) len = RSAref_MAX_LEN;
        (*env)->GetByteArrayRegion(env, m_array, 0, len, (jbyte*)native_key->m);
    }

    /* e */
    jbyteArray e_array = (jbyteArray)(*env)->GetObjectField(env, java_key,
                                                             g_jni_cache.rsaPrivateKey.e);
    if (e_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, e_array);
        if (len > RSAref_MAX_LEN) len = RSAref_MAX_LEN;
        (*env)->GetByteArrayRegion(env, e_array, 0, len, (jbyte*)native_key->e);
    }

    /* d */
    jbyteArray d_array = (jbyteArray)(*env)->GetObjectField(env, java_key,
                                                             g_jni_cache.rsaPrivateKey.d);
    if (d_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, d_array);
        if (len > RSAref_MAX_LEN) len = RSAref_MAX_LEN;
        (*env)->GetByteArrayRegion(env, d_array, 0, len, (jbyte*)native_key->d);
    }

    /* prime[2] */
    jobjectArray prime_array = (jobjectArray)(*env)->GetObjectField(env, java_key,
                                                                     g_jni_cache.rsaPrivateKey.prime);
    if (prime_array != NULL) {
        for (int i = 0; i < 2; i++) {
            jbyteArray p = (jbyteArray)(*env)->GetObjectArrayElement(env, prime_array, i);
            if (p != NULL) {
                jsize len = (*env)->GetArrayLength(env, p);
                if (len > RSAref_MAX_PLEN) len = RSAref_MAX_PLEN;
                (*env)->GetByteArrayRegion(env, p, 0, len, (jbyte*)native_key->prime[i]);
            }
        }
    }

    /* pexp[2] */
    jobjectArray pexp_array = (jobjectArray)(*env)->GetObjectField(env, java_key,
                                                                    g_jni_cache.rsaPrivateKey.pexp);
    if (pexp_array != NULL) {
        for (int i = 0; i < 2; i++) {
            jbyteArray p = (jbyteArray)(*env)->GetObjectArrayElement(env, pexp_array, i);
            if (p != NULL) {
                jsize len = (*env)->GetArrayLength(env, p);
                if (len > RSAref_MAX_PLEN) len = RSAref_MAX_PLEN;
                (*env)->GetByteArrayRegion(env, p, 0, len, (jbyte*)native_key->pexp[i]);
            }
        }
    }

    /* coef */
    jbyteArray coef_array = (jbyteArray)(*env)->GetObjectField(env, java_key,
                                                                g_jni_cache.rsaPrivateKey.coef);
    if (coef_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, coef_array);
        if (len > RSAref_MAX_PLEN) len = RSAref_MAX_PLEN;
        (*env)->GetByteArrayRegion(env, coef_array, 0, len, (jbyte*)native_key->coef);
    }

    return true;
}

bool java_to_native_ECCPrivateKey(JNIEnv *env, jobject java_key, ECCrefPrivateKey *native_key) {

    /* bits */
    native_key->bits = (*env)->GetIntField(env, java_key, g_jni_cache.eccPrivateKey.bits);

    /* k */
    jbyteArray k_array = (jbyteArray)(*env)->GetObjectField(env, java_key,
                                                             g_jni_cache.eccPrivateKey.k);
    if (k_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, k_array);
        (*env)->GetByteArrayRegion(env, k_array, 0, len, (jbyte*)native_key->K);
    }

    return true;
}
