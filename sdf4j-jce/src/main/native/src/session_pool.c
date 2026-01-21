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

#include "session_pool.h"
#include "dynamic_loader.h"
#include "sdf_log.h"
#include "sdf_err.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

/* Default timeout for session acquisition: 30 seconds */
#define DEFAULT_ACQUIRE_TIMEOUT_SEC 30

static SDFSessionPool g_pool = {0};

int session_pool_init(int poolSize) {
    SDF_LOG_ENTER("session_pool_init");

    if (g_pool.initialized) {
        SDF_JNI_LOG("session_pool_init: Already initialized");
        return SDR_OK;
    }

    /* 检查SDF库是否已加载 */
    if (!sdf_is_loaded()) {
        SDF_LOG_ERROR("session_pool_init", "SDF library not loaded");
        return SDR_OPENDEVICE;
    }

    /* 检查必需函数 */
    if (g_sdf_functions.SDF_OpenDevice == NULL ||
        g_sdf_functions.SDF_CloseDevice == NULL ||
        g_sdf_functions.SDF_OpenSession == NULL ||
        g_sdf_functions.SDF_CloseSession == NULL) {
        SDF_LOG_ERROR("session_pool_init", "Required SDF functions not available");
        return SDR_NOTSUPPORT;
    }

    /* 初始化互斥锁和条件变量 */
    if (pthread_mutex_init(&g_pool.mutex, NULL) != 0) {
        SDF_LOG_ERROR("session_pool_init", "Failed to init mutex");
        return SDR_UNKNOWERR;
    }

    if (pthread_cond_init(&g_pool.cond, NULL) != 0) {
        pthread_mutex_destroy(&g_pool.mutex);
        SDF_LOG_ERROR("session_pool_init", "Failed to init condition variable");
        return SDR_UNKNOWERR;
    }

    /* 打开设备 */
    LONG ret = g_sdf_functions.SDF_OpenDevice(&g_pool.deviceHandle);
    if (ret != SDR_OK) {
        SDF_LOG_ERROR("session_pool_init", "SDF_OpenDevice failed");
        pthread_mutex_destroy(&g_pool.mutex);
        pthread_cond_destroy(&g_pool.cond);
        return (int)ret;
    }

    SDF_JNI_LOG("session_pool_init: Device opened, handle=0x%lX",
                (unsigned long)g_pool.deviceHandle);

    /* 确定池大小 */
    g_pool.poolSize = (poolSize > MAX_POOL_SIZE) ? MAX_POOL_SIZE :
                      (poolSize <= 0) ? DEFAULT_POOL_SIZE : poolSize;

    /* 预创建会话 */
    for (int i = 0; i < g_pool.poolSize; i++) {
        ret = g_sdf_functions.SDF_OpenSession(g_pool.deviceHandle, &g_pool.sessions[i]);
        if (ret != SDR_OK) {
            SDF_JNI_LOG("ERROR: session_pool_init - SDF_OpenSession failed for session %d", i);
            /* 回滚已创建的会话 */
            for (int j = 0; j < i; j++) {
                g_sdf_functions.SDF_CloseSession(g_pool.sessions[j]);
            }
            g_sdf_functions.SDF_CloseDevice(g_pool.deviceHandle);
            g_pool.deviceHandle = NULL;
            pthread_mutex_destroy(&g_pool.mutex);
            pthread_cond_destroy(&g_pool.cond);
            return (int)ret;
        }
        g_pool.available[i] = 1;
        SDF_JNI_LOG("session_pool_init: Session %d opened, handle=0x%lX",
                    i, (unsigned long)g_pool.sessions[i]);
    }

    g_pool.initialized = 1;
    SDF_JNI_LOG("session_pool_init: Pool initialized with %d sessions", g_pool.poolSize);

    return SDR_OK;
}

HANDLE session_pool_acquire_timeout(int timeout_sec) {
    if (!g_pool.initialized) {
        SDF_LOG_ERROR("session_pool_acquire", "Pool not initialized");
        return NULL;
    }

    pthread_mutex_lock(&g_pool.mutex);

    /* Calculate absolute timeout */
    struct timespec abstime;
    clock_gettime(CLOCK_REALTIME, &abstime);
    abstime.tv_sec += timeout_sec;

    /* Wait for available session with timeout */
    while (1) {
        for (int i = 0; i < g_pool.poolSize; i++) {
            if (g_pool.available[i]) {
                g_pool.available[i] = 0;
                HANDLE session = g_pool.sessions[i];
                pthread_mutex_unlock(&g_pool.mutex);
                SDF_JNI_LOG("session_pool_acquire: Acquired session %d, handle=0x%lX",
                            i, (unsigned long)session);
                return session;
            }
        }
        /* No available session, wait with timeout */
        SDF_JNI_LOG("session_pool_acquire: No available session, waiting (timeout=%ds)...", timeout_sec);
        int rc = pthread_cond_timedwait(&g_pool.cond, &g_pool.mutex, &abstime);
        if (rc == ETIMEDOUT) {
            SDF_LOG_ERROR("session_pool_acquire", "Timeout waiting for session");
            pthread_mutex_unlock(&g_pool.mutex);
            return NULL;
        }
    }
}

HANDLE session_pool_acquire(void) {
    return session_pool_acquire_timeout(DEFAULT_ACQUIRE_TIMEOUT_SEC);
}

HANDLE session_pool_try_acquire(void) {
    if (!g_pool.initialized) {
        return NULL;
    }

    pthread_mutex_lock(&g_pool.mutex);

    for (int i = 0; i < g_pool.poolSize; i++) {
        if (g_pool.available[i]) {
            g_pool.available[i] = 0;
            HANDLE session = g_pool.sessions[i];
            pthread_mutex_unlock(&g_pool.mutex);
            return session;
        }
    }

    pthread_mutex_unlock(&g_pool.mutex);
    return NULL;
}

void session_pool_release(HANDLE session) {
    if (!g_pool.initialized || session == NULL) {
        return;
    }

    pthread_mutex_lock(&g_pool.mutex);

    for (int i = 0; i < g_pool.poolSize; i++) {
        if (g_pool.sessions[i] == session) {
            g_pool.available[i] = 1;
            SDF_JNI_LOG("session_pool_release: Released session %d, handle=0x%lX",
                        i, (unsigned long)session);
            pthread_cond_signal(&g_pool.cond);
            break;
        }
    }

    pthread_mutex_unlock(&g_pool.mutex);
}

void session_pool_destroy(void) {
    SDF_LOG_ENTER("session_pool_destroy");

    if (!g_pool.initialized) {
        return;
    }

    pthread_mutex_lock(&g_pool.mutex);

    /* 关闭所有会话 */
    for (int i = 0; i < g_pool.poolSize; i++) {
        if (g_pool.sessions[i] != NULL) {
            SDF_JNI_LOG("session_pool_destroy: Closing session %d", i);
            g_sdf_functions.SDF_CloseSession(g_pool.sessions[i]);
            g_pool.sessions[i] = NULL;
        }
        g_pool.available[i] = 0;
    }

    /* 关闭设备 */
    if (g_pool.deviceHandle != NULL) {
        SDF_JNI_LOG("session_pool_destroy: Closing device");
        g_sdf_functions.SDF_CloseDevice(g_pool.deviceHandle);
        g_pool.deviceHandle = NULL;
    }

    g_pool.initialized = 0;
    g_pool.poolSize = 0;

    pthread_mutex_unlock(&g_pool.mutex);

    pthread_mutex_destroy(&g_pool.mutex);
    pthread_cond_destroy(&g_pool.cond);

    SDF_JNI_LOG("session_pool_destroy: Pool destroyed");
}

int session_pool_is_initialized(void) {
    return g_pool.initialized;
}

void session_pool_get_stats(int *total, int *avail) {
    if (!g_pool.initialized) {
        if (total) *total = 0;
        if (avail) *avail = 0;
        return;
    }

    pthread_mutex_lock(&g_pool.mutex);

    if (total) *total = g_pool.poolSize;

    if (avail) {
        *avail = 0;
        for (int i = 0; i < g_pool.poolSize; i++) {
            if (g_pool.available[i]) (*avail)++;
        }
    }

    pthread_mutex_unlock(&g_pool.mutex);
}

HANDLE session_pool_get_device(void) {
    return g_pool.initialized ? g_pool.deviceHandle : NULL;
}
