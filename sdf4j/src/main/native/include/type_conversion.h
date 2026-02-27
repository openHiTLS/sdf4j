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

#ifndef SDF4J_TYPE_CONVERSION_H
#define SDF4J_TYPE_CONVERSION_H

#include <jni.h>
#include "sdf.h"
#include <stdbool.h>
#include <string.h>

/**
 * 抛出SDF异常
 * @param env JNI环境
 * @param error_code 错误码
 * @param fmt 格式化字符串（可以为NULL，使用默认消息）
 * @param ... 可变参数
 */
void throw_sdf_exception_with_format(JNIEnv *env, int error_code, const char *fmt, ...);

/**
 * 抛出SDF异常的便利宏（自动传递函数名、文件名、行号）
 * 用法:
 *   THROW_SDF_EXCEPTION(env, error_code, "message: %s", str)
 *
 * 异常消息格式: Function: xxx, File: xxx, Line: xxx, ErrorNum: 0xXXXXXXXX, Message: xxx
 */
#define THROW_SDF_EXCEPTION(env, error_code, ...) \
    throw_sdf_exception_with_format(env, error_code, \
        "Function: %s, File: %s, Line: %d, ErrorNum: 0x%08X, Message: " __VA_ARGS__, \
        __func__, strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__, __LINE__, \
        (unsigned int)(error_code))

/* ========================================================================
 * C结构体 → Java对象转换
 * ======================================================================== */

/**
 * DEVICEINFO → DeviceInfo
 */
jobject native_to_java_DeviceInfo(JNIEnv *env, const DEVICEINFO *native_info);

/**
 * RSArefPublicKey → RSAPublicKey
 */
jobject native_to_java_RSAPublicKey(JNIEnv *env, const RSArefPublicKey *native_key);

/**
 * ECCrefPublicKey → ECCPublicKey
 */
jobject native_to_java_ECCPublicKey(JNIEnv *env, const ECCrefPublicKey *native_key);

/**
 * ECCSignature → ECCSignature
 */
jobject native_to_java_ECCSignature(JNIEnv *env, const ECCSignature *native_sig);

/**
 * ECCCipher → ECCCipher
 */
jobject native_to_java_ECCCipher(JNIEnv *env, const ECCCipher *native_cipher, ULONG cipher_len);

/**
 * RSArefPrivateKey → RSAPrivateKey
 */
jobject native_to_java_RSAPrivateKey(JNIEnv *env, const RSArefPrivateKey *native_key);

/**
 * ECCrefPrivateKey → ECCPrivateKey
 */
jobject native_to_java_ECCPrivateKey(JNIEnv *env, const ECCrefPrivateKey *native_key);

/* ========================================================================
 * Java对象 → C结构体转换
 * ======================================================================== */

/**
 * RSAPublicKey → RSArefPublicKey
 */
bool java_to_native_RSAPublicKey(JNIEnv *env, jobject java_key, RSArefPublicKey *native_key);

/**
 * ECCPublicKey → ECCrefPublicKey
 */
bool java_to_native_ECCPublicKey(JNIEnv *env, jobject java_key, ECCrefPublicKey *native_key);

/**
 * ECCCipher → ECCCipher (with dynamic memory allocation)
 * This function allocates memory for the complete ECCCipher structure including
 * the flexible array member C[]. Caller MUST free the returned pointer.
 *
 * @param env JNI环境
 * @param java_cipher Java ECCCipher对象
 * @return 动态分配的ECCCipher指针，失败返回NULL。调用者必须释放内存。
 */
ECCCipher* java_to_native_ECCCipher_alloc(JNIEnv *env, jobject java_cipher);

/**
 * RSAPrivateKey → RSArefPrivateKey
 */
bool java_to_native_RSAPrivateKey(JNIEnv *env, jobject java_key, RSArefPrivateKey *native_key);

/**
 * ECCPrivateKey → ECCrefPrivateKey
 */
bool java_to_native_ECCPrivateKey(JNIEnv *env, jobject java_key, ECCrefPrivateKey *native_key);

/**
 * ECCSignature → ECCSignature
 */
bool java_to_native_ECCSignature(JNIEnv *env, jobject java_sig, ECCSignature *native_sig);

/**
 * String → char* (需要调用者释放内存)
 */
char* java_string_to_native(JNIEnv *env, jstring java_str);

/**
 * BYTE* → byte[] (创建新的Java字节数组)
 */
jbyteArray native_to_java_byte_array(JNIEnv *env, const BYTE *native_data, ULONG data_len);

/**
 * 创建KeyEncryptionResult对象
 * Create KeyEncryptionResult object
 *
 * @param env JNI环境
 * @param encrypted_key 加密的密钥数据
 * @param key_length 密钥长度
 * @param key_handle 密钥句柄
 * @return KeyEncryptionResult对象
 */
jobject create_key_encryption_result(JNIEnv *env, const BYTE *encrypted_key,
                                     ULONG key_length, HANDLE key_handle);

/**
 * 创建ECCKeyEncryptionResult对象
 * Create ECCKeyEncryptionResult object
 *
 * @param env JNI环境
 * @param ecc_encrypted_key 加密的ECCCipher数据
 * @param key_length 密钥长度
 * @param key_handle 密钥句柄
 * @return ECCKeyEncryptionResult对象
 */
jobject create_ecc_key_encryption_result(JNIEnv *env, ECCCipher *ecc_cipher,
                                     ULONG key_length, HANDLE key_handle);

/**
 * 创建KeyAgreementResult对象
 * Create KeyAgreementResult object
 *
 * @param env JNI环境
 * @param agreement_handle 协商句柄或密钥句柄
 * @param pub_key 公钥
 * @param tmp_pub_key 临时公钥
 * @return KeyAgreementResult对象
 */
jobject native_to_java_KeyAgreementResult (JNIEnv *env, HANDLE agreement_handle,
                                    const ECCrefPublicKey *pub_key,
                                    const ECCrefPublicKey *tmp_pub_key);

#endif /* SDF4J_TYPE_CONVERSION_H */
