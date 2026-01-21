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

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include "jce_common.h"
#include "session_pool.h"
#include "auth_manager.h"
#include "dynamic_loader.h"
#include "sdf_log.h"

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    init
 * Signature: (Ljava/lang/String;I)V
 */
JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_jce_native_1_SDFJceNative_init(
    JNIEnv *env, jclass cls, jstring libraryPath, jint poolSize)
{
    (void)cls;
    SDF_LOG_ENTER("SDFJceNative_init");

    if (libraryPath == NULL) {
        throw_exception(env, "java/lang/NullPointerException", "libraryPath is null");
        return;
    }

    /* 获取库路径 */
    const char *path = (*env)->GetStringUTFChars(env, libraryPath, NULL);
    if (path == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to get library path string");
        return;
    }

    SDF_JNI_LOG("SDFJceNative_init: Loading library from %s", path);

    /* 加载SDF库 */
    if (!sdf_load_library(path)) {
        const char *error = sdf_get_load_error();
        (*env)->ReleaseStringUTFChars(env, libraryPath, path);
        throw_jce_exception(env, SDR_OPENDEVICE, error ? error : "Failed to load SDF library");
        return;
    }

    (*env)->ReleaseStringUTFChars(env, libraryPath, path);

    /* 初始化权限管理器 */
    int ret = auth_manager_init(poolSize > 0 ? poolSize : DEFAULT_POOL_SIZE);
    if (ret != SDR_OK) {
        sdf_unload_library();
        throw_jce_exception(env, ret, "Failed to initialize auth manager");
        return;
    }

    /* 初始化会话池 */
    ret = session_pool_init(poolSize);
    if (ret != SDR_OK) {
        auth_manager_destroy();
        sdf_unload_library();
        throw_jce_exception(env, ret, "Failed to initialize session pool");
        return;
    }

    SDF_JNI_LOG("SDFJceNative_init: Initialization completed successfully");
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    shutdown
 * Signature: ()V
 */
JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_jce_native_1_SDFJceNative_shutdown(
    JNIEnv *env, jclass cls)
{
    (void)env;
    (void)cls;
    SDF_LOG_ENTER("SDFJceNative_shutdown");

    /* 销毁会话池 */
    session_pool_destroy();

    /* 销毁权限管理器 */
    auth_manager_destroy();

    /* 卸载SDF库 */
    sdf_unload_library();

    SDF_JNI_LOG("SDFJceNative_shutdown: Shutdown completed");
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    isInitialized
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL
Java_org_openhitls_sdf4j_jce_native_1_SDFJceNative_isInitialized(
    JNIEnv *env, jclass cls)
{
    (void)env;
    (void)cls;
    return sdf_is_loaded() && session_pool_is_initialized() ? JNI_TRUE : JNI_FALSE;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    getPoolStats
 * Signature: ()[I
 */
JNIEXPORT jintArray JNICALL
Java_org_openhitls_sdf4j_jce_native_1_SDFJceNative_getPoolStats(
    JNIEnv *env, jclass cls)
{
    (void)cls;

    int total = 0, avail = 0;
    session_pool_get_stats(&total, &avail);

    jintArray result = (*env)->NewIntArray(env, 2);
    if (result != NULL) {
        jint stats[2] = {total, avail};
        (*env)->SetIntArrayRegion(env, result, 0, 2, stats);
    }
    return result;
}
