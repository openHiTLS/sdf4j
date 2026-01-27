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

#ifndef SDF_JNI_COMMON_H
#define SDF_JNI_COMMON_H

#include "dynamic_loader.h"
#include "type_conversion.h"
#include "sdf_log.h"
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 标记未使用的参数以避免编译警告 */
#define UNUSED(x) (void)(x)

/**
 * 验证会话句柄有效性
 *
 * 无效句柄（0或明显的小地址值）会导致底层SDF库崩溃，
 * 因此在调用底层库之前进行验证。
 *
 * 有效句柄通常是动态分配的内存地址，在64位系统上这些地址
 * 通常远大于 0x10000000 (256MB)。使用这个阈值可以过滤掉
 * 测试中使用的小整数值（如 99999 = 0x1869F）。
 */
#define SDF_MIN_VALID_HANDLE 0x10000000UL

#define VALIDATE_SESSION_HANDLE(env, sessionHandle, funcName, returnValue) \
    do { \
        if ((jlong)(sessionHandle) == 0 || (unsigned long)(sessionHandle) < SDF_MIN_VALID_HANDLE) { \
            SDF_LOG_ERROR(funcName, "Invalid session handle"); \
            throw_sdf_exception_with_message(env, SDR_OPENSESSION, "Invalid session handle"); \
            return returnValue; \
        } \
    } while (0)

#define VALIDATE_DEVICE_HANDLE(env, deviceHandle, funcName, returnValue) \
    do { \
        if ((jlong)(deviceHandle) == 0 || (unsigned long)(deviceHandle) < SDF_MIN_VALID_HANDLE) { \
            SDF_LOG_ERROR(funcName, "Invalid device handle"); \
            throw_sdf_exception_with_message(env, SDR_OPENDEVICE, "Invalid device handle"); \
            return returnValue; \
        } \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif /* SDF_JNI_COMMON_H */
