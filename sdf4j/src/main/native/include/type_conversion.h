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

/**
 * 抛出SDFException
 *
 * @param env JNI环境
 * @param error_code SDF错误码
 */
void throw_sdf_exception(JNIEnv *env, int error_code);

/**
 * 抛出带自定义消息的SDFException
 *
 * @param env JNI环境
 * @param error_code SDF错误码
 * @param message 错误消息
 */
void throw_sdf_exception_with_message(JNIEnv *env, int error_code, const char *message);

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

#endif /* SDF4J_TYPE_CONVERSION_H */
