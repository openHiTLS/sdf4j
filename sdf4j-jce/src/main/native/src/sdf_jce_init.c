/*
 * Copyright (c) 2025 OpenHitls
 * SDF4J is licensed under Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include "jce_common.h"
#include "dynamic_loader.h"

/* 全局设备句柄 */
HANDLE g_device_handle = NULL;
int g_sdf_initialized = 0;

static pthread_mutex_t g_init_mutex = PTHREAD_MUTEX_INITIALIZER;

/* 前向声明 */
void sdf_jce_cleanup(void);

/**
 * 初始化SDF - 打开设备
 * 如果已经初始化过且句柄有效，直接返回成功
 * 如果句柄无效，会先清理然后重新初始化
 */
int sdf_jce_initialize(const char *library_path) {
    pthread_mutex_lock(&g_init_mutex);
    if (g_sdf_initialized) {
        /* 检查句柄是否有效（简单检查：不为NULL）*/
        if (g_device_handle != NULL) {
            pthread_mutex_unlock(&g_init_mutex);
            return SDR_OK;  // 已初始化且句柄有效
        }
        /* 句柄无效，先清理（不加锁，因为已持有锁） */
        g_sdf_initialized = 0;
        if (g_device_handle != NULL && g_sdf_functions.SDF_CloseDevice != NULL) {
            g_sdf_functions.SDF_CloseDevice(g_device_handle);
            g_device_handle = NULL;
        }
        sdf_unload_library();
    }

    /* 加载SDF库 */
    if (!sdf_load_library(library_path)) {
        pthread_mutex_unlock(&g_init_mutex);
        return SDR_OPENDEVICE;
    }

    /* 打开设备 */
    int ret = g_sdf_functions.SDF_OpenDevice(&g_device_handle);
    if (ret != SDR_OK) {
        sdf_unload_library();
        pthread_mutex_unlock(&g_init_mutex);
        return ret;
    }

    g_sdf_initialized = 1;
    pthread_mutex_unlock(&g_init_mutex);
    return SDR_OK;
}

/**
 * 清理SDF资源 - 关闭设备和卸载库
 * Note: Sessions are managed by Java layer and must be closed via closeSession()
 */
void sdf_jce_cleanup(void) {
    pthread_mutex_lock(&g_init_mutex);
    if (!g_sdf_initialized) {
        pthread_mutex_unlock(&g_init_mutex);
        return;
    }

    /* 关闭设备 */
    if (g_device_handle != NULL && g_sdf_functions.SDF_CloseDevice != NULL) {
        g_sdf_functions.SDF_CloseDevice(g_device_handle);
        g_device_handle = NULL;
    }

    /* 卸载SDF库 */
    sdf_unload_library();

    g_sdf_initialized = 0;
    pthread_mutex_unlock(&g_init_mutex);
}
