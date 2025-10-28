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
#include "sdf_log.h"
#include <string.h>
#include <stdlib.h>

/* ========================================================================
 * 异常处理
 * ======================================================================== */

void throw_sdf_exception(JNIEnv *env, int error_code) {
    SDF_JNI_LOG("throw_sdf_exception: error_code=0x%08X", (unsigned int)error_code);

    jclass exc_class = (*env)->FindClass(env, "org/openhitls/sdf4j/SDFException");
    if (exc_class == NULL) {
        SDF_LOG_ERROR("throw_sdf_exception", "Failed to find SDFException class");
        return;  /* FindClass已经抛出异常 */
    }

    jmethodID constructor = (*env)->GetMethodID(env, exc_class, "<init>", "(I)V");
    if (constructor == NULL) {
        SDF_LOG_ERROR("throw_sdf_exception", "Failed to get SDFException constructor");
        return;
    }

    jobject exception = (*env)->NewObject(env, exc_class, constructor, error_code);
    if (exception != NULL) {
        (*env)->Throw(env, (jthrowable)exception);
    } else {
        SDF_LOG_ERROR("throw_sdf_exception", "Failed to create SDFException object");
    }
}

void throw_sdf_exception_with_message(JNIEnv *env, int error_code, const char *message) {
    SDF_JNI_LOG("throw_sdf_exception_with_message: error_code=0x%08X, message=%s",
                (unsigned int)error_code, message ? message : "NULL");

    jclass exc_class = (*env)->FindClass(env, "org/openhitls/sdf4j/SDFException");
    if (exc_class == NULL) {
        SDF_LOG_ERROR("throw_sdf_exception_with_message", "Failed to find SDFException class");
        return;
    }

    jmethodID constructor = (*env)->GetMethodID(env, exc_class, "<init>", "(ILjava/lang/String;)V");
    if (constructor == NULL) {
        SDF_LOG_ERROR("throw_sdf_exception_with_message", "Failed to get SDFException constructor");
        return;
    }

    jstring jmsg = (*env)->NewStringUTF(env, message);
    jobject exception = (*env)->NewObject(env, exc_class, constructor, error_code, jmsg);
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
    if (native_info == NULL) {
        return NULL;
    }

    /* 查找DeviceInfo类 */
    jclass cls = (*env)->FindClass(env, "org/openhitls/sdf4j/types/DeviceInfo");
    if (cls == NULL) {
        return NULL;
    }

    /* 获取构造函数 */
    jmethodID constructor = (*env)->GetMethodID(env, cls, "<init>", "()V");
    if (constructor == NULL) {
        return NULL;
    }

    /* 创建对象 */
    jobject obj = (*env)->NewObject(env, cls, constructor);
    if (obj == NULL) {
        return NULL;
    }

    /* 设置字段 */
    jfieldID fid;

    /* issuerName */
    fid = (*env)->GetFieldID(env, cls, "issuerName", "Ljava/lang/String;");
    if (fid != NULL) {
        jstring str = native_string_to_java(env, native_info->IssuerName, 40);
        (*env)->SetObjectField(env, obj, fid, str);
    }

    /* deviceName */
    fid = (*env)->GetFieldID(env, cls, "deviceName", "Ljava/lang/String;");
    if (fid != NULL) {
        jstring str = native_string_to_java(env, native_info->DeviceName, 16);
        (*env)->SetObjectField(env, obj, fid, str);
    }

    /* deviceSerial */
    fid = (*env)->GetFieldID(env, cls, "deviceSerial", "Ljava/lang/String;");
    if (fid != NULL) {
        jstring str = native_string_to_java(env, native_info->DeviceSerial, 16);
        (*env)->SetObjectField(env, obj, fid, str);
    }

    /* deviceVersion */
    fid = (*env)->GetFieldID(env, cls, "deviceVersion", "J");
    if (fid != NULL) {
        (*env)->SetLongField(env, obj, fid, native_info->DeviceVersion);
    }

    /* standardVersion */
    fid = (*env)->GetFieldID(env, cls, "standardVersion", "J");
    if (fid != NULL) {
        (*env)->SetLongField(env, obj, fid, native_info->StandardVersion);
    }

    /* asymAlgAbility */
    fid = (*env)->GetFieldID(env, cls, "asymAlgAbility", "[J");
    if (fid != NULL) {
        jlongArray array = (*env)->NewLongArray(env, 2);
        if (array != NULL) {
            jlong temp[2];
            temp[0] = native_info->AsymAlgAbility[0];
            temp[1] = native_info->AsymAlgAbility[1];
            (*env)->SetLongArrayRegion(env, array, 0, 2, temp);
            (*env)->SetObjectField(env, obj, fid, array);
        }
    }

    /* symAlgAbility */
    fid = (*env)->GetFieldID(env, cls, "symAlgAbility", "J");
    if (fid != NULL) {
        (*env)->SetLongField(env, obj, fid, native_info->SymAlgAbility);
    }

    /* hashAlgAbility */
    fid = (*env)->GetFieldID(env, cls, "hashAlgAbility", "J");
    if (fid != NULL) {
        (*env)->SetLongField(env, obj, fid, native_info->HashAlgAbility);
    }

    /* bufferSize */
    fid = (*env)->GetFieldID(env, cls, "bufferSize", "J");
    if (fid != NULL) {
        (*env)->SetLongField(env, obj, fid, native_info->BufferSize);
    }

    return obj;
}

jobject native_to_java_RSAPublicKey(JNIEnv *env, const RSArefPublicKey *native_key) {
    if (native_key == NULL) {
        return NULL;
    }

    jclass cls = (*env)->FindClass(env, "org/openhitls/sdf4j/types/RSAPublicKey");
    if (cls == NULL) return NULL;

    jmethodID constructor = (*env)->GetMethodID(env, cls, "<init>", "()V");
    if (constructor == NULL) return NULL;

    jobject obj = (*env)->NewObject(env, cls, constructor);
    if (obj == NULL) return NULL;

    jfieldID fid;

    /* bits */
    fid = (*env)->GetFieldID(env, cls, "bits", "I");
    if (fid != NULL) {
        (*env)->SetIntField(env, obj, fid, native_key->bits);
    }

    /* m */
    fid = (*env)->GetFieldID(env, cls, "m", "[B");
    if (fid != NULL) {
        jbyteArray m_array = (*env)->NewByteArray(env, RSAref_MAX_LEN);
        if (m_array != NULL) {
            (*env)->SetByteArrayRegion(env, m_array, 0, RSAref_MAX_LEN, (jbyte*)native_key->m);
            (*env)->SetObjectField(env, obj, fid, m_array);
        }
    }

    /* e */
    fid = (*env)->GetFieldID(env, cls, "e", "[B");
    if (fid != NULL) {
        jbyteArray e_array = (*env)->NewByteArray(env, RSAref_MAX_LEN);
        if (e_array != NULL) {
            (*env)->SetByteArrayRegion(env, e_array, 0, RSAref_MAX_LEN, (jbyte*)native_key->e);
            (*env)->SetObjectField(env, obj, fid, e_array);
        }
    }

    return obj;
}

jobject native_to_java_ECCPublicKey(JNIEnv *env, const ECCrefPublicKey *native_key) {
    if (native_key == NULL) {
        return NULL;
    }

    jclass cls = (*env)->FindClass(env, "org/openhitls/sdf4j/types/ECCPublicKey");
    if (cls == NULL) return NULL;

    jmethodID constructor = (*env)->GetMethodID(env, cls, "<init>", "()V");
    if (constructor == NULL) return NULL;

    jobject obj = (*env)->NewObject(env, cls, constructor);
    if (obj == NULL) return NULL;

    jfieldID fid;

    /* bits */
    fid = (*env)->GetFieldID(env, cls, "bits", "I");
    if (fid != NULL) {
        (*env)->SetIntField(env, obj, fid, native_key->bits);
    }

    /* x */
    fid = (*env)->GetFieldID(env, cls, "x", "[B");
    if (fid != NULL) {
        jbyteArray x_array = (*env)->NewByteArray(env, ECCref_MAX_LEN);
        if (x_array != NULL) {
            (*env)->SetByteArrayRegion(env, x_array, 0, ECCref_MAX_LEN, (jbyte*)native_key->x);
            (*env)->SetObjectField(env, obj, fid, x_array);
        }
    }

    /* y */
    fid = (*env)->GetFieldID(env, cls, "y", "[B");
    if (fid != NULL) {
        jbyteArray y_array = (*env)->NewByteArray(env, ECCref_MAX_LEN);
        if (y_array != NULL) {
            (*env)->SetByteArrayRegion(env, y_array, 0, ECCref_MAX_LEN, (jbyte*)native_key->y);
            (*env)->SetObjectField(env, obj, fid, y_array);
        }
    }

    return obj;
}

jobject native_to_java_ECCSignature(JNIEnv *env, const ECCSignature *native_sig) {
    if (native_sig == NULL) {
        return NULL;
    }

    jclass cls = (*env)->FindClass(env, "org/openhitls/sdf4j/types/ECCSignature");
    if (cls == NULL) return NULL;

    jmethodID constructor = (*env)->GetMethodID(env, cls, "<init>", "()V");
    if (constructor == NULL) return NULL;

    jobject obj = (*env)->NewObject(env, cls, constructor);
    if (obj == NULL) return NULL;

    jfieldID fid;

    /* r */
    fid = (*env)->GetFieldID(env, cls, "r", "[B");
    if (fid != NULL) {
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
            (*env)->SetObjectField(env, obj, fid, r_array);
        }
    }

    /* s */
    fid = (*env)->GetFieldID(env, cls, "s", "[B");
    if (fid != NULL) {
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
            (*env)->SetObjectField(env, obj, fid, s_array);
        }
    }

    return obj;
}

jobject native_to_java_ECCCipher(JNIEnv *env, const ECCCipher *native_cipher, ULONG cipher_len) {
    if (native_cipher == NULL) {
        return NULL;
    }

    jclass cls = (*env)->FindClass(env, "org/openhitls/sdf4j/types/ECCCipher");
    if (cls == NULL) return NULL;

    jmethodID constructor = (*env)->GetMethodID(env, cls, "<init>", "()V");
    if (constructor == NULL) return NULL;

    jobject obj = (*env)->NewObject(env, cls, constructor);
    if (obj == NULL) return NULL;

    jfieldID fid;

    /* x */
    fid = (*env)->GetFieldID(env, cls, "x", "[B");
    if (fid != NULL) {
        jbyteArray x_array = (*env)->NewByteArray(env, ECCref_MAX_LEN);
        if (x_array != NULL) {
            (*env)->SetByteArrayRegion(env, x_array, 0, ECCref_MAX_LEN, (jbyte*)native_cipher->x);
            (*env)->SetObjectField(env, obj, fid, x_array);
        }
    }

    /* y */
    fid = (*env)->GetFieldID(env, cls, "y", "[B");
    if (fid != NULL) {
        jbyteArray y_array = (*env)->NewByteArray(env, ECCref_MAX_LEN);
        if (y_array != NULL) {
            (*env)->SetByteArrayRegion(env, y_array, 0, ECCref_MAX_LEN, (jbyte*)native_cipher->y);
            (*env)->SetObjectField(env, obj, fid, y_array);
        }
    }

    /* m */
    fid = (*env)->GetFieldID(env, cls, "m", "[B");
    if (fid != NULL) {
        jbyteArray m_array = (*env)->NewByteArray(env, 32);
        if (m_array != NULL) {
            (*env)->SetByteArrayRegion(env, m_array, 0, 32, (jbyte*)native_cipher->M);
            (*env)->SetObjectField(env, obj, fid, m_array);
        }
    }

    /* l - 密文长度 (对应C结构体的ULONG L字段) */
    fid = (*env)->GetFieldID(env, cls, "l", "J");
    if (fid != NULL) {
        (*env)->SetLongField(env, obj, fid, (jlong)native_cipher->L);
    }

    /* c - 变长密文数据 */
    fid = (*env)->GetFieldID(env, cls, "c", "[B");
    if (fid != NULL && cipher_len > 0) {
        jbyteArray c_array = (*env)->NewByteArray(env, cipher_len);
        if (c_array != NULL) {
            (*env)->SetByteArrayRegion(env, c_array, 0, cipher_len, (jbyte*)&native_cipher->C);
            (*env)->SetObjectField(env, obj, fid, c_array);
        }
    }

    return obj;
}

/* ========================================================================
 * Java对象 → C结构体转换
 * ======================================================================== */

bool java_to_native_RSAPublicKey(JNIEnv *env, jobject java_key, RSArefPublicKey *native_key) {
    if (java_key == NULL || native_key == NULL) {
        return false;
    }

    memset(native_key, 0, sizeof(RSArefPublicKey));

    jclass cls = (*env)->GetObjectClass(env, java_key);
    if (cls == NULL) return false;

    jfieldID fid;

    /* bits */
    fid = (*env)->GetFieldID(env, cls, "bits", "I");
    if (fid == NULL) return false;
    native_key->bits = (*env)->GetIntField(env, java_key, fid);

    /* m (modulus) */
    fid = (*env)->GetFieldID(env, cls, "m", "[B");
    if (fid == NULL) return false;
    jbyteArray m_array = (jbyteArray)(*env)->GetObjectField(env, java_key, fid);
    if (m_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, m_array);
        if (len > RSAref_MAX_LEN) len = RSAref_MAX_LEN;
        (*env)->GetByteArrayRegion(env, m_array, 0, len, (jbyte*)native_key->m);
    }

    /* e (public exponent) */
    fid = (*env)->GetFieldID(env, cls, "e", "[B");
    if (fid == NULL) return false;
    jbyteArray e_array = (jbyteArray)(*env)->GetObjectField(env, java_key, fid);
    if (e_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, e_array);
        if (len > RSAref_MAX_LEN) len = RSAref_MAX_LEN;
        (*env)->GetByteArrayRegion(env, e_array, 0, len, (jbyte*)native_key->e);
    }

    return true;
}

bool java_to_native_ECCCipher(JNIEnv *env, jobject java_cipher, ECCCipher *native_cipher) {
    if (java_cipher == NULL || native_cipher == NULL) {
        return false;
    }

    memset(native_cipher, 0, sizeof(ECCCipher));

    jclass cls = (*env)->GetObjectClass(env, java_cipher);
    if (cls == NULL) return false;

    jfieldID fid;

    /* x */
    fid = (*env)->GetFieldID(env, cls, "x", "[B");
    if (fid == NULL) return false;
    jbyteArray x_array = (jbyteArray)(*env)->GetObjectField(env, java_cipher, fid);
    if (x_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, x_array);
        if (len > ECCref_MAX_LEN) len = ECCref_MAX_LEN;
        (*env)->GetByteArrayRegion(env, x_array, 0, len, (jbyte*)native_cipher->x);
    }

    /* y */
    fid = (*env)->GetFieldID(env, cls, "y", "[B");
    if (fid == NULL) return false;
    jbyteArray y_array = (jbyteArray)(*env)->GetObjectField(env, java_cipher, fid);
    if (y_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, y_array);
        if (len > ECCref_MAX_LEN) len = ECCref_MAX_LEN;
        (*env)->GetByteArrayRegion(env, y_array, 0, len, (jbyte*)native_cipher->y);
    }

    /* m (hash/MAC) - Note: Java field is lowercase "m" */
    fid = (*env)->GetFieldID(env, cls, "m", "[B");
    if (fid == NULL) return false;
    jbyteArray m_array = (jbyteArray)(*env)->GetObjectField(env, java_cipher, fid);
    if (m_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, m_array);
        if (len > 32) len = 32;
        (*env)->GetByteArrayRegion(env, m_array, 0, len, (jbyte*)native_cipher->M);
    }

    /* l - 密文长度 (对应C结构体的ULONG L字段) */
    fid = (*env)->GetFieldID(env, cls, "l", "J");
    if (fid != NULL) {
        jlong l_value = (*env)->GetLongField(env, java_cipher, fid);
        native_cipher->L = (ULONG)l_value;
    }

    /* c - 密文数据 (cipher data) - Note: Java field is "c" */
    /* Note: ECCCipher has flexible array member, only copy L value here */
    /* The actual cipher data C is not copied since it's a flexible array member */
    /* Caller should handle cipher data separately */
    fid = (*env)->GetFieldID(env, cls, "c", "[B");
    if (fid != NULL) {
        jbyteArray c_array = (jbyteArray)(*env)->GetObjectField(env, java_cipher, fid);
        if (c_array != NULL) {
            jsize c_len = (*env)->GetArrayLength(env, c_array);
            /* Update L field if not already set */
            if (native_cipher->L == 0) {
                native_cipher->L = c_len;
            }
            /* Note: C is not copied here - flexible array member.
             * If actual cipher data needed, caller must allocate larger struct and copy */
        }
    }

    return true;
}

bool java_to_native_ECCPublicKey(JNIEnv *env, jobject java_key, ECCrefPublicKey *native_key) {
    if (java_key == NULL || native_key == NULL) {
        return false;
    }

    memset(native_key, 0, sizeof(ECCrefPublicKey));

    jclass cls = (*env)->GetObjectClass(env, java_key);
    if (cls == NULL) return false;

    jfieldID fid;

    /* bits */
    fid = (*env)->GetFieldID(env, cls, "bits", "I");
    if (fid == NULL) return false;
    native_key->bits = (*env)->GetIntField(env, java_key, fid);

    /* x */
    fid = (*env)->GetFieldID(env, cls, "x", "[B");
    if (fid == NULL) return false;
    jbyteArray x_array = (jbyteArray)(*env)->GetObjectField(env, java_key, fid);
    if (x_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, x_array);
        if (len > ECCref_MAX_LEN) len = ECCref_MAX_LEN;
        (*env)->GetByteArrayRegion(env, x_array, 0, len, (jbyte*)native_key->x);
    }

    /* y */
    fid = (*env)->GetFieldID(env, cls, "y", "[B");
    if (fid == NULL) return false;
    jbyteArray y_array = (jbyteArray)(*env)->GetObjectField(env, java_key, fid);
    if (y_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, y_array);
        if (len > ECCref_MAX_LEN) len = ECCref_MAX_LEN;
        (*env)->GetByteArrayRegion(env, y_array, 0, len, (jbyte*)native_key->y);
    }

    return true;
}

bool java_to_native_ECCSignature(JNIEnv *env, jobject java_sig, ECCSignature *native_sig) {
    if (java_sig == NULL || native_sig == NULL) {
        return false;
    }

    memset(native_sig, 0, sizeof(ECCSignature));

    jclass cls = (*env)->GetObjectClass(env, java_sig);
    if (cls == NULL) return false;

    jfieldID fid;

    /* r */
    fid = (*env)->GetFieldID(env, cls, "r", "[B");
    if (fid == NULL) return false;
    jbyteArray r_array = (jbyteArray)(*env)->GetObjectField(env, java_sig, fid);
    if (r_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, r_array);
        if (len > ECCref_MAX_LEN) len = ECCref_MAX_LEN;
        (*env)->GetByteArrayRegion(env, r_array, 0, len, (jbyte*)native_sig->r);
    }

    /* s */
    fid = (*env)->GetFieldID(env, cls, "s", "[B");
    if (fid == NULL) return false;
    jbyteArray s_array = (jbyteArray)(*env)->GetObjectField(env, java_sig, fid);
    if (s_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, s_array);
        if (len > ECCref_MAX_LEN) len = ECCref_MAX_LEN;
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

bool java_byte_array_to_native(JNIEnv *env, jbyteArray java_array, BYTE *native_buffer, ULONG buffer_size) {
    if (java_array == NULL || native_buffer == NULL) {
        return false;
    }

    jsize len = (*env)->GetArrayLength(env, java_array);
    if ((ULONG)len > buffer_size) {
        len = buffer_size;
    }

    (*env)->GetByteArrayRegion(env, java_array, 0, len, (jbyte*)native_buffer);
    return true;
}

jbyteArray native_to_java_byte_array(JNIEnv *env, const BYTE *native_data, ULONG data_len) {
    if (native_data == NULL || data_len == 0) {
        return NULL;
    }

    jbyteArray array = (*env)->NewByteArray(env, data_len);
    if (array == NULL) {
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, array, 0, data_len, (jbyte*)native_data);
    return array;
}

jobject create_key_encryption_result(JNIEnv *env, const BYTE *encrypted_key,
                                     ULONG key_length, HANDLE key_handle) {
    if (encrypted_key == NULL || key_length == 0) {
        return NULL;
    }

    /* Find KeyEncryptionResult class */
    jclass cls = (*env)->FindClass(env, "org/openhitls/sdf4j/types/KeyEncryptionResult");
    if (cls == NULL) {
        return NULL;
    }

    /* Get constructor: KeyEncryptionResult(byte[] encryptedKey, long keyHandle) */
    jmethodID constructor = (*env)->GetMethodID(env, cls, "<init>", "([BJ)V");
    if (constructor == NULL) {
        return NULL;
    }

    /* Create byte array for encrypted key */
    jbyteArray key_array = (*env)->NewByteArray(env, key_length);
    if (key_array == NULL) {
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, key_array, 0, key_length, (jbyte*)encrypted_key);

    /* Create KeyEncryptionResult object */
    jobject obj = (*env)->NewObject(env, cls, constructor, key_array, (jlong)key_handle);
    return obj;
}

jobject native_to_java_RSAPrivateKey(JNIEnv *env, const RSArefPrivateKey *native_key) {
    if (native_key == NULL) {
        return NULL;
    }

    jclass cls = (*env)->FindClass(env, "org/openhitls/sdf4j/types/RSAPrivateKey");
    if (cls == NULL) return NULL;

    jmethodID constructor = (*env)->GetMethodID(env, cls, "<init>", "()V");
    if (constructor == NULL) return NULL;

    jobject obj = (*env)->NewObject(env, cls, constructor);
    if (obj == NULL) return NULL;

    jfieldID fid;

    /* bits */
    fid = (*env)->GetFieldID(env, cls, "bits", "I");
    if (fid != NULL) {
        (*env)->SetIntField(env, obj, fid, (jint)native_key->bits);
    }

    /* m, e, d */
    fid = (*env)->GetFieldID(env, cls, "m", "[B");
    if (fid != NULL) {
        jbyteArray m = (*env)->NewByteArray(env, RSAref_MAX_LEN);
        (*env)->SetByteArrayRegion(env, m, 0, RSAref_MAX_LEN, (const jbyte*)native_key->m);
        (*env)->SetObjectField(env, obj, fid, m);
    }

    fid = (*env)->GetFieldID(env, cls, "e", "[B");
    if (fid != NULL) {
        jbyteArray e = (*env)->NewByteArray(env, RSAref_MAX_LEN);
        (*env)->SetByteArrayRegion(env, e, 0, RSAref_MAX_LEN, (const jbyte*)native_key->e);
        (*env)->SetObjectField(env, obj, fid, e);
    }

    fid = (*env)->GetFieldID(env, cls, "d", "[B");
    if (fid != NULL) {
        jbyteArray d = (*env)->NewByteArray(env, RSAref_MAX_LEN);
        (*env)->SetByteArrayRegion(env, d, 0, RSAref_MAX_LEN, (const jbyte*)native_key->d);
        (*env)->SetObjectField(env, obj, fid, d);
    }

    /* prime[2], pexp[2], coef */
    fid = (*env)->GetFieldID(env, cls, "prime", "[[B");
    if (fid != NULL) {
        jclass byteArrayClass = (*env)->FindClass(env, "[B");
        jobjectArray primeArray = (*env)->NewObjectArray(env, 2, byteArrayClass, NULL);
        for (int i = 0; i < 2; i++) {
            jbyteArray p = (*env)->NewByteArray(env, RSAref_MAX_PLEN);
            (*env)->SetByteArrayRegion(env, p, 0, RSAref_MAX_PLEN, (const jbyte*)native_key->prime[i]);
            (*env)->SetObjectArrayElement(env, primeArray, i, p);
        }
        (*env)->SetObjectField(env, obj, fid, primeArray);
    }

    fid = (*env)->GetFieldID(env, cls, "pexp", "[[B");
    if (fid != NULL) {
        jclass byteArrayClass = (*env)->FindClass(env, "[B");
        jobjectArray pexpArray = (*env)->NewObjectArray(env, 2, byteArrayClass, NULL);
        for (int i = 0; i < 2; i++) {
            jbyteArray p = (*env)->NewByteArray(env, RSAref_MAX_PLEN);
            (*env)->SetByteArrayRegion(env, p, 0, RSAref_MAX_PLEN, (const jbyte*)native_key->pexp[i]);
            (*env)->SetObjectArrayElement(env, pexpArray, i, p);
        }
        (*env)->SetObjectField(env, obj, fid, pexpArray);
    }

    fid = (*env)->GetFieldID(env, cls, "coef", "[B");
    if (fid != NULL) {
        jbyteArray coef = (*env)->NewByteArray(env, RSAref_MAX_PLEN);
        (*env)->SetByteArrayRegion(env, coef, 0, RSAref_MAX_PLEN, (const jbyte*)native_key->coef);
        (*env)->SetObjectField(env, obj, fid, coef);
    }

    return obj;
}

jobject native_to_java_ECCPrivateKey(JNIEnv *env, const ECCrefPrivateKey *native_key) {
    if (native_key == NULL) {
        return NULL;
    }

    jclass cls = (*env)->FindClass(env, "org/openhitls/sdf4j/types/ECCPrivateKey");
    if (cls == NULL) return NULL;

    jmethodID constructor = (*env)->GetMethodID(env, cls, "<init>", "()V");
    if (constructor == NULL) return NULL;

    jobject obj = (*env)->NewObject(env, cls, constructor);
    if (obj == NULL) return NULL;

    jfieldID fid;

    /* bits */
    fid = (*env)->GetFieldID(env, cls, "bits", "I");
    if (fid != NULL) {
        (*env)->SetIntField(env, obj, fid, (jint)native_key->bits);
    }

    /* k */
    fid = (*env)->GetFieldID(env, cls, "k", "[B");
    if (fid != NULL) {
        jbyteArray k = (*env)->NewByteArray(env, ECCref_MAX_LEN);
        (*env)->SetByteArrayRegion(env, k, 0, ECCref_MAX_LEN, (const jbyte*)native_key->K);
        (*env)->SetObjectField(env, obj, fid, k);
    }

    return obj;
}

bool java_to_native_RSAPrivateKey(JNIEnv *env, jobject java_key, RSArefPrivateKey *native_key) {
    if (java_key == NULL || native_key == NULL) {
        return false;
    }

    memset(native_key, 0, sizeof(RSArefPrivateKey));

    jclass cls = (*env)->GetObjectClass(env, java_key);
    if (cls == NULL) return false;

    jfieldID fid;

    /* bits */
    fid = (*env)->GetFieldID(env, cls, "bits", "I");
    if (fid == NULL) return false;
    native_key->bits = (*env)->GetIntField(env, java_key, fid);

    /* m, e, d */
    fid = (*env)->GetFieldID(env, cls, "m", "[B");
    if (fid == NULL) return false;
    jbyteArray m_array = (jbyteArray)(*env)->GetObjectField(env, java_key, fid);
    if (m_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, m_array);
        if (len > RSAref_MAX_LEN) len = RSAref_MAX_LEN;
        (*env)->GetByteArrayRegion(env, m_array, 0, len, (jbyte*)native_key->m);
    }

    fid = (*env)->GetFieldID(env, cls, "e", "[B");
    if (fid == NULL) return false;
    jbyteArray e_array = (jbyteArray)(*env)->GetObjectField(env, java_key, fid);
    if (e_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, e_array);
        if (len > RSAref_MAX_LEN) len = RSAref_MAX_LEN;
        (*env)->GetByteArrayRegion(env, e_array, 0, len, (jbyte*)native_key->e);
    }

    fid = (*env)->GetFieldID(env, cls, "d", "[B");
    if (fid == NULL) return false;
    jbyteArray d_array = (jbyteArray)(*env)->GetObjectField(env, java_key, fid);
    if (d_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, d_array);
        if (len > RSAref_MAX_LEN) len = RSAref_MAX_LEN;
        (*env)->GetByteArrayRegion(env, d_array, 0, len, (jbyte*)native_key->d);
    }

    /* prime[2], pexp[2], coef */
    fid = (*env)->GetFieldID(env, cls, "prime", "[[B");
    if (fid != NULL) {
        jobjectArray prime_array = (jobjectArray)(*env)->GetObjectField(env, java_key, fid);
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
    }

    fid = (*env)->GetFieldID(env, cls, "pexp", "[[B");
    if (fid != NULL) {
        jobjectArray pexp_array = (jobjectArray)(*env)->GetObjectField(env, java_key, fid);
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
    }

    fid = (*env)->GetFieldID(env, cls, "coef", "[B");
    if (fid != NULL) {
        jbyteArray coef_array = (jbyteArray)(*env)->GetObjectField(env, java_key, fid);
        if (coef_array != NULL) {
            jsize len = (*env)->GetArrayLength(env, coef_array);
            if (len > RSAref_MAX_PLEN) len = RSAref_MAX_PLEN;
            (*env)->GetByteArrayRegion(env, coef_array, 0, len, (jbyte*)native_key->coef);
        }
    }

    return true;
}

bool java_to_native_ECCPrivateKey(JNIEnv *env, jobject java_key, ECCrefPrivateKey *native_key) {
    if (java_key == NULL || native_key == NULL) {
        return false;
    }

    memset(native_key, 0, sizeof(ECCrefPrivateKey));

    jclass cls = (*env)->GetObjectClass(env, java_key);
    if (cls == NULL) return false;

    jfieldID fid;

    /* bits */
    fid = (*env)->GetFieldID(env, cls, "bits", "I");
    if (fid == NULL) return false;
    native_key->bits = (*env)->GetIntField(env, java_key, fid);

    /* k */
    fid = (*env)->GetFieldID(env, cls, "k", "[B");
    if (fid == NULL) return false;
    jbyteArray k_array = (jbyteArray)(*env)->GetObjectField(env, java_key, fid);
    if (k_array != NULL) {
        jsize len = (*env)->GetArrayLength(env, k_array);
        if (len > ECCref_MAX_LEN) len = ECCref_MAX_LEN;
        (*env)->GetByteArrayRegion(env, k_array, 0, len, (jbyte*)native_key->K);
    }

    return true;
}
