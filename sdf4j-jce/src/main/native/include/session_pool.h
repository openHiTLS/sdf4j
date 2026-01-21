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

#ifndef SDF4J_JCE_SESSION_POOL_H
#define SDF4J_JCE_SESSION_POOL_H

#include "sdf.h"
#include <pthread.h>

#define MAX_POOL_SIZE 64
#define DEFAULT_POOL_SIZE 16

/**
 * 会话池结构
 */
typedef struct {
    HANDLE deviceHandle;
    HANDLE sessions[MAX_POOL_SIZE];
    int available[MAX_POOL_SIZE];
    int poolSize;
    int initialized;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} SDFSessionPool;

/**
 * 初始化会话池
 *
 * @param poolSize 会话池大小（最大MAX_POOL_SIZE）
 * @return SDR_OK成功，否则返回SDF错误码
 */
int session_pool_init(int poolSize);

/**
 * 获取一个会话（带超时的阻塞等待，默认30秒）
 *
 * @return 会话句柄，超时或失败返回NULL
 */
HANDLE session_pool_acquire(void);

/**
 * 获取一个会话（带自定义超时的阻塞等待）
 *
 * @param timeout_sec 超时时间（秒）
 * @return 会话句柄，超时或失败返回NULL
 */
HANDLE session_pool_acquire_timeout(int timeout_sec);

/**
 * 尝试获取一个会话（非阻塞）
 *
 * @return 会话句柄，无可用会话返回NULL
 */
HANDLE session_pool_try_acquire(void);

/**
 * 释放会话回池
 *
 * @param session 会话句柄
 */
void session_pool_release(HANDLE session);

/**
 * 销毁会话池
 */
void session_pool_destroy(void);

/**
 * 检查会话池是否已初始化
 *
 * @return 1已初始化，0未初始化
 */
int session_pool_is_initialized(void);

/**
 * 获取会话池统计信息
 *
 * @param total 输出：总会话数
 * @param avail 输出：可用会话数
 */
void session_pool_get_stats(int *total, int *avail);

/**
 * 获取设备句柄
 *
 * @return 设备句柄
 */
HANDLE session_pool_get_device(void);

#endif /* SDF4J_JCE_SESSION_POOL_H */
