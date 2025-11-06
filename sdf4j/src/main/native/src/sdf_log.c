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

/**
 * 写日志函数
 * @param format 格式化字符串，类似printf
 * @param ... 可变参数
 * @return 成功返回0，失败返回-1
 */
int write_log(const char *format, ...) {
    FILE *fp = NULL;
    time_t now;
    struct tm *timeinfo;
    char time_str[64];
    va_list args;
    pid_t pid;
    pthread_t tid;

    // 以追加模式打开文件，如果不存在则创建
    fp = fopen(LOG_FILE, "a");
    if (fp == NULL) {
        // 如果无法打开日志文件，静默失败（避免影响正常功能）
        return -1;
    }

    // 获取当前时间
    time(&now);
    timeinfo = localtime(&now);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);

    // 获取进程ID和线程ID
    pid = getpid();
    tid = pthread_self();

    // 写入时间戳、进程ID和线程ID
    fprintf(fp, "[%s] [PID:%d TID:%lu] ", time_str, pid, (unsigned long)tid);

    // 写入日志内容
    va_start(args, format);
    vfprintf(fp, format, args);
    va_end(args);

    // 添加换行符
    fprintf(fp, "\n");

    // 刷新缓冲区确保日志立即写入
    fflush(fp);

    // 关闭文件
    fclose(fp);

    return 0;
}
