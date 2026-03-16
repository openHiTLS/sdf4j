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

#ifndef SDF4J_JCE_COMMON_H
#define SDF4J_JCE_COMMON_H

#include <jni.h>
#include <stdint.h>
#include <string.h>
#include "sdf.h"
#include "sdf_err.h"
#include "dynamic_loader.h"

/* 全局设备句柄 - 在JNI_OnLoad时初始化，JNI_OnUnload时释放 */
extern HANDLE g_device_handle;
extern int g_sdf_initialized;

/* 声明会话池清理函数 */
void sdf_jce_session_cleanup(void);

/* SM2/SM3/SM4 常量 */
#define SM2_KEY_BITS        256
#define SM2_KEY_BYTES       32
#define SM2_SIGNATURE_BYTES 64
#define SM3_DIGEST_LENGTH   32
#define SM4_KEY_LENGTH      16
#define SM4_BLOCK_SIZE      16
#define SM4_GCM_TAG_LENGTH  16

/* SM4 加密模式 */
#define SM4_MODE_ECB    0
#define SM4_MODE_CBC    1
#define SM4_MODE_GCM    2
#define SM4_MODE_CCM    3

/* 密钥类型 */
typedef enum {
    KEY_TYPE_SIGN = 0,
    KEY_TYPE_ENCRYPT = 1,
    KEY_TYPE_KEK = 2
} KeyType;

/* SM3上下文 */
typedef struct {
    int initialized;
    HANDLE session_handle;  /* Session handle for this hash operation */
} SM3Context;

/* SM4上下文 */
typedef struct {
    int initialized;
    HANDLE session_handle;  /* Session handle for this crypto operation */
    HANDLE key_handle;      /* Imported key handle, destroyed with context */
} SM4Context;

/**
 * 抛出SDFJceException
 */
static inline void throw_jce_exception(JNIEnv *env, int error_code, const char *message) {
    jclass cls = (*env)->FindClass(env, "org/openhitls/sdf4j/jce/SDFJceException");
    if (cls != NULL) {
        jmethodID ctor = (*env)->GetMethodID(env, cls, "<init>", "(ILjava/lang/String;)V");
        if (ctor != NULL) {
            jstring jmsg = (*env)->NewStringUTF(env, message ? message : "Unknown error");
            jobject exc = (*env)->NewObject(env, cls, ctor, error_code, jmsg);
            if (exc != NULL) {
                (*env)->Throw(env, (jthrowable)exc);
            }
            if (jmsg != NULL) {
                (*env)->DeleteLocalRef(env, jmsg);
            }
        }
        (*env)->DeleteLocalRef(env, cls);
    }
}

/**
 * 抛出通用Java异常
 */
static inline void throw_exception(JNIEnv *env, const char *class_name, const char *message) {
    jclass cls = (*env)->FindClass(env, class_name);
    if (cls != NULL) {
        (*env)->ThrowNew(env, cls, message);
        (*env)->DeleteLocalRef(env, cls);
    }
}

/**
 * 检查SDF函数是否可用
 */
#define CHECK_FUNCTION(func, env, func_name) \
    do { \
        if (g_sdf_functions.func == NULL) { \
            throw_jce_exception(env, SDR_NOTSUPPORT, \
                "Function " func_name " not available in SDF library"); \
            return; \
        } \
    } while(0)

#define CHECK_FUNCTION_RET(func, env, func_name, ret) \
    do { \
        if (g_sdf_functions.func == NULL) { \
            throw_jce_exception(env, SDR_NOTSUPPORT, \
                "Function " func_name " not available in SDF library"); \
            return ret; \
        } \
    } while(0)

/**
 * 检查SDF是否已初始化
 */
#define CHECK_INIT(env) \
    do { \
        if (!g_sdf_initialized) { \
            throw_jce_exception(env, SDR_UNKNOWERR, \
                "SDF not initialized"); \
            return; \
        } \
    } while(0)

#define CHECK_INIT_RET(env, ret) \
    do { \
        if (!g_sdf_initialized) { \
            throw_jce_exception(env, SDR_UNKNOWERR, \
                "SDF not initialized"); \
            return ret; \
        } \
    } while(0)

#endif /* SDF4J_JCE_COMMON_H */
