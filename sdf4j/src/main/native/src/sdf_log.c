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

#include "sdf_log.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <string.h>

/* 日志模式控制 */
static int file_logging_enabled = 1;     // 默认启用文件日志
static int java_logging_enabled = 1;     // 默认启用Java回调日志

/* Java日志回调相关的全局变量 */
static JavaVM *g_jvm = NULL;              // Java虚拟机指针
static jobject g_logger_obj = NULL;       // Java日志回调对象（全局引用）
static jmethodID g_log_method_id = NULL;  // Java日志方法ID
static pthread_mutex_t g_logger_mutex = PTHREAD_MUTEX_INITIALIZER;  // 互斥锁

/**
 * 设置Java日志回调对象（全局引用）
 * @param env JNI环境指针
 * @param logger_obj Java日志回调对象
 */
void sdf_log_set_java_logger(JNIEnv *env, jobject logger_obj) {
    pthread_mutex_lock(&g_logger_mutex);

    // 释放旧的全局引用
    if (g_logger_obj != NULL && g_jvm != NULL) {
        (*env)->DeleteGlobalRef(env, g_logger_obj);
        g_logger_obj = NULL;
        g_log_method_id = NULL;
    }

    if (logger_obj != NULL) {
        // 创建全局引用
        g_logger_obj = (*env)->NewGlobalRef(env, logger_obj);

        // 获取JavaVM指针
        if (g_jvm == NULL) {
            (*env)->GetJavaVM(env, &g_jvm);
        }

        // 获取log方法ID
        jclass logger_class = (*env)->GetObjectClass(env, logger_obj);
        if (logger_class != NULL) {
            g_log_method_id = (*env)->GetMethodID(env, logger_class, "log", "(Ljava/lang/String;)V");
            (*env)->DeleteLocalRef(env, logger_class);
        }
    }

    pthread_mutex_unlock(&g_logger_mutex);
}

/**
 * 启用/禁用文件日志
 * @param enable 1启用，0禁用
 */
void sdf_log_set_file_enabled(int enable) {
    file_logging_enabled = enable;
}

/**
 * 启用/禁用Java回调日志
 * @param enable 1启用，0禁用
 */
void sdf_log_set_java_enabled(int enable) {
    java_logging_enabled = enable;
}

/**
 * 调用Java日志回调
 * @param log_message 完整的日志消息
 */
static void call_java_logger(const char *log_message) {
    if (!java_logging_enabled || g_logger_obj == NULL || g_log_method_id == NULL || g_jvm == NULL) {
        return;
    }

    pthread_mutex_lock(&g_logger_mutex);

    JNIEnv *env = NULL;
    int need_detach = 0;

    // 获取JNI环境
    int status = (*g_jvm)->GetEnv(g_jvm, (void **)&env, JNI_VERSION_1_6);
    if (status == JNI_EDETACHED) {
        // 当前线程未附加到JVM，需要附加
        if ((*g_jvm)->AttachCurrentThread(g_jvm, (void **)&env, NULL) == JNI_OK) {
            need_detach = 1;
        } else {
            pthread_mutex_unlock(&g_logger_mutex);
            return;
        }
    } else if (status != JNI_OK) {
        pthread_mutex_unlock(&g_logger_mutex);
        return;
    }

    // 创建Java字符串
    jstring j_log_message = (*env)->NewStringUTF(env, log_message);
    if (j_log_message != NULL) {
        // 调用Java回调方法
        (*env)->CallVoidMethod(env, g_logger_obj, g_log_method_id, j_log_message);

        // 检查是否有异常发生
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);  // 清除异常，避免影响后续操作
        }

        (*env)->DeleteLocalRef(env, j_log_message);
    }

    // 如果需要，从JVM分离当前线程
    if (need_detach) {
        (*g_jvm)->DetachCurrentThread(g_jvm);
    }

    pthread_mutex_unlock(&g_logger_mutex);
}

/**
 * 写日志函数（双模式：文件 + Java回调）
 * @param format 格式化字符串，类似printf
 * @param ... 可变参数
 * @return 成功返回0，失败返回-1
 */
int write_log(const char *format, ...) {
    time_t now;
    struct tm *timeinfo;
    char time_str[64];
    va_list args;
    pid_t pid;
    pthread_t tid;
    char log_buffer[4096];  // 日志缓冲区
    int header_len;
    int ret = 0;

    // 获取当前时间
    time(&now);
    timeinfo = localtime(&now);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);

    // 获取进程ID和线程ID
    pid = getpid();
    tid = pthread_self();

    // 构建日志头部（时间戳、进程ID、线程ID）
    header_len = snprintf(log_buffer, sizeof(log_buffer),
                         "[%s] [PID:%d TID:%lu] ",
                         time_str, pid, (unsigned long)tid);

    // 构建日志内容
    va_start(args, format);
    vsnprintf(log_buffer + header_len, sizeof(log_buffer) - header_len, format, args);
    va_end(args);

    // 模式1：文件日志
    if (file_logging_enabled) {
        FILE *fp = fopen(LOG_FILE, "a");
        if (fp != NULL) {
            fprintf(fp, "%s\n", log_buffer);
            fflush(fp);
            fclose(fp);
        } else {
            ret = -1;
        }
    }

    // 模式2：Java回调日志
    if (java_logging_enabled) {
        call_java_logger(log_buffer);
    }

    return ret;
}
