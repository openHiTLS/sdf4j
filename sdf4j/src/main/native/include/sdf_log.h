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

#ifndef SDF_LOG_H
#define SDF_LOG_H

#include <stdio.h>
#include <stdarg.h>
#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 日志文件路径
 */
#define LOG_FILE "/tmp/sdf4j.log"

/**
 * 写日志函数
 * @param format 格式化字符串，类似printf
 * @param ... 可变参数
 * @return 成功返回0，失败返回-1
 */
int write_log(const char *format, ...);

/**
 * 设置Java日志回调对象（全局引用）
 * @param env JNI环境指针
 * @param logger_obj Java日志回调对象
 */
void sdf_log_set_java_logger(JNIEnv *env, jobject logger_obj);

/**
 * 启用/禁用文件日志
 * @param enable 1启用，0禁用
 */
void sdf_log_set_file_enabled(int enable);

/**
 * 启用/禁用Java回调日志
 * @param enable 1启用，0禁用
 */
void sdf_log_set_java_enabled(int enable);

/**
 * 日志宏定义
 * 在Release版本（定义了NDEBUG）时为空，不输出日志
 * 在Debug版本时调用write_log函数
 */
//#ifdef NDEBUG
    /* Release版本：禁用日志 */
 //   #define SDF_JNI_LOG(...)  ((void)0)
//#else
    /* Debug版本：启用日志 */
    #define SDF_JNI_LOG(...)  write_log(__VA_ARGS__)
//#endif

/**
 * 日志辅助宏：记录函数入口
 */
#define SDF_LOG_ENTER(func_name) \
    SDF_JNI_LOG("ENTER: %s", func_name)

/**
 * 日志辅助宏：记录函数退出及返回值
 */
#define SDF_LOG_EXIT(func_name, ret_code) \
    SDF_JNI_LOG("EXIT: %s, ret=0x%08X", func_name, (unsigned int)(ret_code))

/**
 * 日志辅助宏：记录错误
 */
#define SDF_LOG_ERROR(func_name, error_msg) \
    SDF_JNI_LOG("ERROR: %s - %s", func_name, error_msg)

/**
 * 日志辅助宏：记录十六进制数据（用于密钥、数据等）
 */
#define SDF_LOG_HEX(label, data, len) \
    do { \
        if ((data) != NULL && (len) > 0) { \
            char hex_buf[256]; \
            int bytes_to_log = ((len) < 32) ? (len) : 32; \
            for (int i = 0; i < bytes_to_log && i < 127; i++) { \
                snprintf(hex_buf + i*2, 3, "%02X", ((unsigned char*)(data))[i]); \
            } \
            hex_buf[bytes_to_log * 2] = '\0'; \
            if ((len) > 32) { \
                SDF_JNI_LOG("%s: %s... (%d bytes total)", label, hex_buf, (int)(len)); \
            } else { \
                SDF_JNI_LOG("%s: %s", label, hex_buf); \
            } \
        } \
    } while(0)

#ifdef __cplusplus
}
#endif

#endif /* SDF_LOG_H */
