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
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

/* ========================================================================
 * 异常处理
 * ======================================================================== */

void throw_sdf_exception_with_format(JNIEnv *env, int error_code, const char *fmt, ...) {
    char buffer[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    jstring jmsg = (*env)->NewStringUTF(env, buffer);
    jobject exception = (*env)->NewObject(env, g_jni_cache.sdfException.cls,
                                          g_jni_cache.sdfException.ctor_int_string,
                                          error_code, jmsg);
    if (exception != NULL) {
        (*env)->Throw(env, (jthrowable)exception);
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
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create DeviceInfo object");
        return NULL;
    }

    /* issuerName */
    jstring str = native_string_to_java(env, native_info->IssuerName, 40);
    if (str == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create issuerName");
        return NULL;
    }
    (*env)->SetObjectField(env, obj, g_jni_cache.deviceInfo.issuerName, str);

    /* deviceName */
    str = native_string_to_java(env, native_info->DeviceName, 16);
    if (str == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create deviceName");
        return NULL;
    }
    (*env)->SetObjectField(env, obj, g_jni_cache.deviceInfo.deviceName, str);

    /* deviceSerial */
    str = native_string_to_java(env, native_info->DeviceSerial, 16);
    if (str == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create deviceSerial");
        return NULL;
    }
    (*env)->SetObjectField(env, obj, g_jni_cache.deviceInfo.deviceSerial, str);

    /* deviceVersion */
    (*env)->SetLongField(env, obj, g_jni_cache.deviceInfo.deviceVersion,
                         native_info->DeviceVersion);

    /* standardVersion */
    (*env)->SetLongField(env, obj, g_jni_cache.deviceInfo.standardVersion,
                         native_info->StandardVersion);

    /* asymAlgAbility */
    jlongArray array = (*env)->NewLongArray(env, 2);
    if (array == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create array object");
        return NULL;
    }
    jlong temp[2];
    temp[0] = native_info->AsymAlgAbility[0];
    temp[1] = native_info->AsymAlgAbility[1];
    (*env)->SetLongArrayRegion(env, array, 0, 2, temp);
    (*env)->SetObjectField(env, obj, g_jni_cache.deviceInfo.asymAlgAbility, array);

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
    jbyteArray m_array = (*env)->NewByteArray(env, RSAref_MAX_LEN);
    if (m_array == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create RSAPublicKey object");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, m_array, 0, RSAref_MAX_LEN, (jbyte*)native_key->m);

    jbyteArray e_array = (*env)->NewByteArray(env, RSAref_MAX_LEN);
    if (e_array == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create RSAPublicKey object");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, e_array, 0, RSAref_MAX_LEN, (jbyte*)native_key->e);

    jobject obj = (*env)->NewObject(env, g_jni_cache.rsaPublicKey.cls,
                            g_jni_cache.rsaPublicKey.ctor,
                            (jint)native_key->bits, m_array, e_array);
    if (obj == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create RSAPublicKey object");
    }
    return obj;
}

jobject native_to_java_ECCPublicKey(JNIEnv *env, const ECCrefPublicKey *native_key) {
    jbyteArray x_array = (*env)->NewByteArray(env, ECCref_MAX_LEN);
    if (x_array == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create ECCPublicKey object");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, x_array, 0, ECCref_MAX_LEN, (jbyte*)native_key->x);

    jbyteArray y_array = (*env)->NewByteArray(env, ECCref_MAX_LEN);
    if (y_array == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create ECCPublicKey object");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, y_array, 0, ECCref_MAX_LEN, (jbyte*)native_key->y);

    jobject obj = (*env)->NewObject(env, g_jni_cache.eccPublicKey.cls,
                            g_jni_cache.eccPublicKey.ctor,
                            (jint)native_key->bits, x_array, y_array);
    if (obj == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create ECCPublicKey object");
    }
    return obj;
}

jobject native_to_java_ECCSignature(JNIEnv *env, const ECCSignature *native_sig) {
    /* Detect actual r length: trim trailing zeros, min 32 bytes for SM2 */
    int r_len = ECCref_MAX_LEN;
    while (r_len > 0 && native_sig->r[r_len - 1] == 0) {
        r_len--;
    }
    if (r_len > 0 && r_len <= 32) {
        r_len = 32;
    }

    /* Detect actual s length: trim trailing zeros, min 32 bytes for SM2 */
    int s_len = ECCref_MAX_LEN;
    while (s_len > 0 && native_sig->s[s_len - 1] == 0) {
        s_len--;
    }
    if (s_len > 0 && s_len <= 32) {
        s_len = 32;
    }

    /* Create byte arrays */
    jbyteArray r_array = (*env)->NewByteArray(env, r_len);
    if (r_array == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create array object");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, r_array, 0, r_len, (jbyte*)native_sig->r);

    jbyteArray s_array = (*env)->NewByteArray(env, s_len);
    if (s_array == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create array object");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, s_array, 0, s_len, (jbyte*)native_sig->s);
    jobject obj = (*env)->NewObject(env, g_jni_cache.eccSignature.cls,
                            g_jni_cache.eccSignature.ctor,
                            r_array, s_array);
    if (obj == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create ECCSignature object");
    }
    return obj;
}

jobject native_to_java_ECCCipher(JNIEnv *env, const ECCCipher *native_cipher, ULONG cipher_len) {
    /* Create byte arrays for constructor parameters */
    jbyteArray x_array = (*env)->NewByteArray(env, ECCref_MAX_LEN);
    if (x_array == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create array object");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, x_array, 0, ECCref_MAX_LEN, (jbyte*)native_cipher->x);

    jbyteArray y_array = (*env)->NewByteArray(env, ECCref_MAX_LEN);
    if (y_array == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create array object");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, y_array, 0, ECCref_MAX_LEN, (jbyte*)native_cipher->y);

    jbyteArray m_array = (*env)->NewByteArray(env, 32);
    if (m_array == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create array object");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, m_array, 0, 32, (jbyte*)native_cipher->M);

    jbyteArray c_array = (*env)->NewByteArray(env, cipher_len);
    if (c_array == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create array object");
        return NULL;
    }
    if (cipher_len > 0) {
        (*env)->SetByteArrayRegion(env, c_array, 0, cipher_len, (jbyte*)&native_cipher->C);
    }
    jobject obj = (*env)->NewObject(env, g_jni_cache.eccCipher.cls,
                            g_jni_cache.eccCipher.ctor,
                            x_array, y_array, m_array,
                            (jlong)native_cipher->L, c_array);
    if (obj == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create ECCCipher object");
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
        if (len > RSAref_MAX_LEN) {
            THROW_SDF_EXCEPTION(env, SDR_INARGERR, "RSA modulus array exceeds 512");
            return false;
        }
        (*env)->GetByteArrayRegion(env, m_array, 0, len, (jbyte*)native_key->m);
    }

    /* e (public exponent) */
    jbyteArray e_array = (jbyteArray)(*env)->GetObjectField(env, java_key,
                                                             g_jni_cache.rsaPublicKey.e);
    if (e_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, e_array);
        if (len > RSAref_MAX_LEN) {
            THROW_SDF_EXCEPTION(env, SDR_INARGERR, "RSA exponent array exceeds 512");
            return false;
        }
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
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "calloc failed");
        return NULL;
    }

    /* x */
    jbyteArray x_array = (jbyteArray)(*env)->GetObjectField(env, java_cipher,
                                                             g_jni_cache.eccCipher.x);
    if (x_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, x_array);
        if (len > ECCref_MAX_LEN) {
            THROW_SDF_EXCEPTION(env, SDR_INARGERR, "X coordinate exceeds 64 bytes");
            free(native_cipher);
            return NULL;
        }
        (*env)->GetByteArrayRegion(env, x_array, 0, len, (jbyte*)native_cipher->x);
    }

    /* y */
    jbyteArray y_array = (jbyteArray)(*env)->GetObjectField(env, java_cipher,
                                                             g_jni_cache.eccCipher.y);
    if (y_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, y_array);
        if (len > ECCref_MAX_LEN) {
            THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Y coordinate exceeds 64 bytes");
            free(native_cipher);
            return NULL;
        }
        (*env)->GetByteArrayRegion(env, y_array, 0, len, (jbyte*)native_cipher->y);
    }

    /* m (hash/MAC) */
    jbyteArray m_array = (jbyteArray)(*env)->GetObjectField(env, java_cipher,
                                                             g_jni_cache.eccCipher.m);
    if (m_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, m_array);
        if (len > 32) {
            THROW_SDF_EXCEPTION(env, SDR_INARGERR, "ECCCipher hash value M exceeds 32 bytes");
            free(native_cipher);
            return NULL;
        }
        (*env)->GetByteArrayRegion(env, m_array, 0, len, (jbyte*)native_cipher->M);
    }

    /* L - cipher data length */
    native_cipher->L = (ULONG)l_value;
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
        if (len > ECCref_MAX_LEN) {
            THROW_SDF_EXCEPTION(env, SDR_INARGERR, "X coordinate exceeds 64 bytes");
            return false;
        }
        (*env)->GetByteArrayRegion(env, x_array, 0, len, (jbyte*)native_key->x);
    }

    /* y */
    jbyteArray y_array = (jbyteArray)(*env)->GetObjectField(env, java_key,
                                                             g_jni_cache.eccPublicKey.y);
    if (y_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, y_array);
        if (len > ECCref_MAX_LEN) {
            THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Y coordinate exceeds 64 bytes");
            return false;
        }
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
        if (len > ECCref_MAX_LEN) {
            THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Signature r exceeds 64 bytes");
            return false;
        }
        (*env)->GetByteArrayRegion(env, r_array, 0, len, (jbyte*)native_sig->r);
    }

    /* s */
    jbyteArray s_array = (jbyteArray)(*env)->GetObjectField(env, java_sig,
                                                             g_jni_cache.eccSignature.s);
    if (s_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, s_array);
        if (len > ECCref_MAX_LEN) {
            THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Signature s exceeds 64 bytes");
            return false;
        }
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
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create byte array");
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
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create byte array");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, key_array, 0, key_length, (jbyte*)encrypted_key);

    /* Create KeyEncryptionResult object */
    jobject obj = (*env)->NewObject(env, g_jni_cache.keyEncryptionResult.cls,
                                    g_jni_cache.keyEncryptionResult.ctor,
                                    key_array, (jlong)key_handle);
    if (obj == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create KeyEncryptionResult object");
    }
    return obj;
}

jobject create_ecc_key_encryption_result(JNIEnv *env, ECCCipher *ecc_cipher,
                                     ULONG key_length, HANDLE key_handle) {
    /* Convert ECCCipher to Java object */
    jobject ecc_cipher_obj = native_to_java_ECCCipher(env, ecc_cipher, key_length);
    if (ecc_cipher_obj == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create ECCCipher object");
        return NULL;
    }

    /* Create ECCKeyEncryptionResult object */
    jobject obj = (*env)->NewObject(env, g_jni_cache.eccKeyEncryptionResult.cls,
                                    g_jni_cache.eccKeyEncryptionResult.ctor,
                                    ecc_cipher_obj, (jlong)key_handle);
    if (obj == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create ECCKeyEncryptionResult object");
    }
    return obj;
}

jobject native_to_java_RSAPrivateKey(JNIEnv *env, const RSArefPrivateKey *native_key) {

    jobject obj = (*env)->NewObject(env, g_jni_cache.rsaPrivateKey.cls,
                                    g_jni_cache.rsaPrivateKey.ctor);
    if (obj == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create RSAPrivateKey object");
        return NULL;
    }

    /* bits */
    (*env)->SetIntField(env, obj, g_jni_cache.rsaPrivateKey.bits, (jint)native_key->bits);

    /* m */
    jbyteArray m = (*env)->NewByteArray(env, RSAref_MAX_LEN);
    if (m == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create array object");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, m, 0, RSAref_MAX_LEN, (const jbyte*)native_key->m);
    (*env)->SetObjectField(env, obj, g_jni_cache.rsaPrivateKey.m, m);

    /* e */
    jbyteArray e = (*env)->NewByteArray(env, RSAref_MAX_LEN);
    if (e == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create array object");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, e, 0, RSAref_MAX_LEN, (const jbyte*)native_key->e);
    (*env)->SetObjectField(env, obj, g_jni_cache.rsaPrivateKey.e, e);

    /* d */
    jbyteArray d = (*env)->NewByteArray(env, RSAref_MAX_LEN);
    if (d == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create array object");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, d, 0, RSAref_MAX_LEN, (const jbyte*)native_key->d);
    (*env)->SetObjectField(env, obj, g_jni_cache.rsaPrivateKey.d, d);

    /* prime[2] */
    jobjectArray primeArray = (*env)->NewObjectArray(env, 2,
                                                      g_jni_cache.common.byteArrayClass, NULL);
    if (primeArray == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create array object");
        return NULL;
    }
    for (int i = 0; i < 2; i++) {
        jbyteArray p = (*env)->NewByteArray(env, RSAref_MAX_PLEN);
        if (p == NULL) {
            THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create array object");
            return NULL;
        }
        (*env)->SetByteArrayRegion(env, p, 0, RSAref_MAX_PLEN,
                                   (const jbyte*)native_key->prime[i]);
        (*env)->SetObjectArrayElement(env, primeArray, i, p);
    }
    (*env)->SetObjectField(env, obj, g_jni_cache.rsaPrivateKey.prime, primeArray);

    /* pexp[2] */
    jobjectArray pexpArray = (*env)->NewObjectArray(env, 2,
                                                     g_jni_cache.common.byteArrayClass, NULL);
    if (pexpArray == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create array object");
        return NULL;
    }
    for (int i = 0; i < 2; i++) {
        jbyteArray p = (*env)->NewByteArray(env, RSAref_MAX_PLEN);
        if (p == NULL) {
            THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create array object");
            return NULL;
        }
        (*env)->SetByteArrayRegion(env, p, 0, RSAref_MAX_PLEN,
                                   (const jbyte*)native_key->pexp[i]);
        (*env)->SetObjectArrayElement(env, pexpArray, i, p);
    }
    (*env)->SetObjectField(env, obj, g_jni_cache.rsaPrivateKey.pexp, pexpArray);

    /* coef */
    jbyteArray coef = (*env)->NewByteArray(env, RSAref_MAX_PLEN);
    if (coef == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create array object");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, coef, 0, RSAref_MAX_PLEN, (const jbyte*)native_key->coef);
    (*env)->SetObjectField(env, obj, g_jni_cache.rsaPrivateKey.coef, coef);
    return obj;
}

jobject native_to_java_ECCPrivateKey(JNIEnv *env, const ECCrefPrivateKey *native_key) {
    /* Create byte array for constructor parameter */
    jbyteArray k_array = (*env)->NewByteArray(env, ECCref_MAX_LEN);
    if (k_array == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create byte array");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, k_array, 0, ECCref_MAX_LEN, (const jbyte*)native_key->K);

    jobject obj = (*env)->NewObject(env, g_jni_cache.eccPrivateKey.cls,
                            g_jni_cache.eccPrivateKey.ctor,
                            (jint)native_key->bits, k_array);
    if (obj == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create ECCPrivateKey object");
    }
    return obj;
}

bool java_to_native_RSAPrivateKey(JNIEnv *env, jobject java_key, RSArefPrivateKey *native_key) {

    memset(native_key, 0, sizeof(RSArefPrivateKey));
    /* bits */
    native_key->bits = (*env)->GetIntField(env, java_key, g_jni_cache.rsaPrivateKey.bits);

    /* m */
    jbyteArray m_array = (jbyteArray)(*env)->GetObjectField(env, java_key,
                                                             g_jni_cache.rsaPrivateKey.m);
    if (m_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, m_array);
        if (len > RSAref_MAX_LEN) {
            THROW_SDF_EXCEPTION(env, SDR_INARGERR, "RSA modulus array exceeds 512 bytes");
            return false;
        }
        (*env)->GetByteArrayRegion(env, m_array, 0, len, (jbyte*)native_key->m);
    }

    /* e */
    jbyteArray e_array = (jbyteArray)(*env)->GetObjectField(env, java_key,
                                                             g_jni_cache.rsaPrivateKey.e);
    if (e_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, e_array);
        if (len > RSAref_MAX_LEN) {
            THROW_SDF_EXCEPTION(env, SDR_INARGERR, "RSA exponent array exceeds 512 bytes");
            return false;
        }
        (*env)->GetByteArrayRegion(env, e_array, 0, len, (jbyte*)native_key->e);
    }

    /* d */
    jbyteArray d_array = (jbyteArray)(*env)->GetObjectField(env, java_key,
                                                             g_jni_cache.rsaPrivateKey.d);
    if (d_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, d_array);
        if (len > RSAref_MAX_LEN) {
            THROW_SDF_EXCEPTION(env, SDR_INARGERR, "RSA private exponent array exceeds 512 bytes");
            return false;
        }
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
                if (len > RSAref_MAX_PLEN) {
                    THROW_SDF_EXCEPTION(env, SDR_INARGERR, "RSA prime array exceeds 512 bytes");
                    return false;
                }
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
                if (len > RSAref_MAX_PLEN) {
                    THROW_SDF_EXCEPTION(env, SDR_INARGERR, "RSA CRT exponent array exceeds 512 bytes");
                    return false;
                }
                (*env)->GetByteArrayRegion(env, p, 0, len, (jbyte*)native_key->pexp[i]);
            }
        }
    }

    /* coef */
    jbyteArray coef_array = (jbyteArray)(*env)->GetObjectField(env, java_key,
                                                                g_jni_cache.rsaPrivateKey.coef);
    if (coef_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, coef_array);
        if (len > RSAref_MAX_PLEN) {
            THROW_SDF_EXCEPTION(env, SDR_INARGERR, "RSA CRT coefficient array exceeds 512 bytes");
            return false;
        }
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
        if (len > ECCref_MAX_LEN) {
            THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Private key K exceeds 64 bytes");
            return false;
        }
        (*env)->GetByteArrayRegion(env, k_array, 0, len, (jbyte*)native_key->K);
    }

    return true;
}

jobject native_to_java_KeyAgreementResult(JNIEnv *env, HANDLE agreement_handle,
                                    const ECCrefPublicKey *pub_key,
                                    const ECCrefPublicKey *tmp_pub_key)
{
    /* Convert ECCrefPublicKey to Java ECCPublicKey objects */
    jobject java_pub_key = native_to_java_ECCPublicKey(env, pub_key);
    if (java_pub_key == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create public key object");
        return NULL;
    }

    jobject java_tmp_pub_key = native_to_java_ECCPublicKey(env, tmp_pub_key);
    if (java_tmp_pub_key == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create temporary public key object");
        return NULL;
    }

    /* Create KeyAgreementResult object */
    jobject obj = (*env)->NewObject(env, g_jni_cache.keyAgreementResult.cls,
                                    g_jni_cache.keyAgreementResult.ctor,
                                    (jlong)agreement_handle,
                                    java_pub_key, java_tmp_pub_key);
    if (obj == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create KeyAgreementResult");
    }
    return obj;
}

jobject native_to_java_HybridCipher(JNIEnv *env, const HybridCipher *native_cipher, ULONG cipher_len,
    HANDLE key_handle)
{
    /* ctM byte array */
    jsize ctm_len = (jsize)native_cipher->L1;
    jbyteArray ctm_array = (*env)->NewByteArray(env, ctm_len);
    if (ctm_array == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create ctM array");
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, ctm_array, 0, ctm_len, (jbyte*)native_cipher->ct_m);

    /* ctS - ECCCipher object */
    jobject ecc_cipher_obj = native_to_java_ECCCipher(env, &native_cipher->ct_s, cipher_len);
    if (ecc_cipher_obj == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create ECCCipher object");
        return NULL;
    }

    /* Create HybridCipher via parameterized constructor */
    jobject obj = (*env)->NewObject(env, g_jni_cache.hybridCipher.cls,
                                    g_jni_cache.hybridCipher.ctor,
                                    (jlong)native_cipher->L1, ctm_array,
                                    (jlong)native_cipher->uiAlgID,
                                    ecc_cipher_obj, (jlong)key_handle);
    if (obj == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create HybridCipher");
    }
    return obj;
}

HybridCipher* java_to_native_HybridCipher_alloc(JNIEnv *env, jobject java_cipher) {
    jobject cts_obj = (*env)->GetObjectField(env, java_cipher, g_jni_cache.hybridCipher.ctS);

    ECCCipher *temp_cts = NULL;
    jsize c_len = 0;
    if (cts_obj != NULL) {
        temp_cts = java_to_native_ECCCipher_alloc(env, cts_obj);
        if (temp_cts != NULL) {
            c_len = (jsize)temp_cts->L;
        }
    }

    size_t alloc_size = sizeof(HybridCipher) + c_len;
    HybridCipher *native_cipher = (HybridCipher*)calloc(1, alloc_size);
    if (native_cipher == NULL) {
        free(temp_cts);
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "calloc failed");
        return NULL;
    }

    /* L1 */
    native_cipher->L1 = (ULONG)(*env)->GetLongField(env, java_cipher, g_jni_cache.hybridCipher.l1);

    /* ct_m */
    jbyteArray ctm_array = (jbyteArray)(*env)->GetObjectField(env, java_cipher,
                                                              g_jni_cache.hybridCipher.ctM);
    if (ctm_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, ctm_array);
        if (len > HYBRIDENCref_MAX_LEN) {
            free(native_cipher);
            free(temp_cts);
            THROW_SDF_EXCEPTION(env, SDR_INARGERR, "cipher len exceeds 1576");
            return NULL;
        }
        (*env)->GetByteArrayRegion(env, ctm_array, 0, len, (jbyte*)native_cipher->ct_m);
    }

    /* uiAlgID */
    native_cipher->uiAlgID = (ULONG)(*env)->GetLongField(env, java_cipher, g_jni_cache.hybridCipher.uiAlgID);

    /* ct_s */
    if (temp_cts != NULL) {
        memcpy(&native_cipher->ct_s, temp_cts, sizeof(ECCCipher) + c_len);
        free(temp_cts);
    }

    return native_cipher;
}

jobject native_to_java_HybridSignature(JNIEnv *env, const HybridSignature *native_sig, ULONG sig_m_len) {

    /* sigS - ECC signature */
    jobject ecc_sig_obj = native_to_java_ECCSignature(env, &native_sig->sig_s);
    if (ecc_sig_obj == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create ECCSignature object");
        return NULL;
    }

    /* sigM byte array */
    jbyteArray sig_m_array = NULL;
    if (sig_m_len > 0) {
        sig_m_array = (*env)->NewByteArray(env, sig_m_len);
        if (sig_m_array == NULL) {
            THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to new byte array");
            return NULL;
        }
        (*env)->SetByteArrayRegion(env, sig_m_array, 0, sig_m_len, (jbyte*)native_sig->sig_m);
    }

    /* Create HybridSignature via parameterized constructor */
    jobject obj = (*env)->NewObject(env, g_jni_cache.hybridSignature.cls,
                                    g_jni_cache.hybridSignature.ctor,
                                    ecc_sig_obj, (jint)native_sig->L, sig_m_array);
    if (obj == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to create HybridSignature");
    }
    return obj;
}

HybridSignature* java_to_native_HybridSignature_alloc(JNIEnv *env, jobject java_sig) {
    /* Get the sig_m array length */
    jbyteArray sig_m_array = (jbyteArray)(*env)->GetObjectField(env, java_sig,
                                                                 g_jni_cache.hybridSignature.sigM);
    /* Also check L field */
    jint l_value = (*env)->GetIntField(env, java_sig, g_jni_cache.hybridSignature.l);

    /* Allocate memory for HybridSignature struct */
    HybridSignature *native_sig = (HybridSignature*)calloc(1, sizeof(HybridSignature));
    if (native_sig == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "calloc failed");
        return NULL;
    }

    /* Get ECC signature part */
    jobject ecc_sig_obj = (jobject)(*env)->GetObjectField(env, java_sig,
                                                          g_jni_cache.hybridSignature.sigS);
    if (ecc_sig_obj != NULL) {
        if (!java_to_native_ECCSignature(env, ecc_sig_obj, &native_sig->sig_s)) {
            free(native_sig);
            return NULL;
        }
    }

    /* L - sig value length */
    if (l_value > HYBRIDSIGref_MAX_LEN) {
        free(native_sig);
        THROW_SDF_EXCEPTION(env, SDR_INARGERR, "cipher len exceeds 4636");
        return NULL;
    }
    native_sig->L = (ULONG)l_value;

    /* sig_m  */
    if (sig_m_array != NULL) {
        (*env)->GetByteArrayRegion(env, sig_m_array, 0, l_value, (jbyte*)native_sig->sig_m);
    }
    return native_sig;
}
