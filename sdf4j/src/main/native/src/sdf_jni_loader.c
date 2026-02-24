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

#include "sdf_jni_common.h"
#include "dynamic_loader.h"

/* ========================================================================
 * NativeLibraryLoader JNI 实现
 * ======================================================================== */

JNIEXPORT jboolean JNICALL
JNI_NativeLibraryLoader_loadSDFLibrary(JNIEnv *env, jclass cls, jstring library_path) {
    UNUSED(cls);

    // Java层应该保证传递非null的库路径或库名
    if (library_path == NULL) {
        THROW_SDF_EXCEPTION(env, 0x01000006, "Library path is null"); /* SDR_INARGERR */
        return JNI_FALSE;
    }

    const char *path = (*env)->GetStringUTFChars(env, library_path, NULL);
    if (path == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Failed to get library path string"); /* SDR_NOBUFFER */
        return JNI_FALSE;
    }

    // 加载SDF库
    // path 可能是完整路径（如 /opt/sdf/lib/libswsds.so）
    // 或者只是库文件名（如 libswsds.so），让系统在标准路径中查找
    bool result = sdf_load_library(path);

    (*env)->ReleaseStringUTFChars(env, library_path, path);

    if (!result) {
        // 获取详细错误信息并抛出异常
        const char *error = sdf_get_load_error();
        throw_sdf_exception_with_format(env, SDR_OPENDEVICE, "%s", error ? error : "Failed to load SDF library");
        return JNI_FALSE;
    }
    return JNI_TRUE;
}
