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

/* ========================================================================
 * NativeLibraryLoader JNI 实现
 * ======================================================================== */

JNIEXPORT jboolean JNICALL
Java_org_openhitls_sdf4j_internal_NativeLibraryLoader_nativeLoadSDFLibrary
  (JNIEnv *env, jclass cls, jstring library_path) {
    UNUSED(cls);

    // Java层应该保证传递非null的库路径或库名
    if (library_path == NULL) {
        return JNI_FALSE;
    }

    const char *path = (*env)->GetStringUTFChars(env, library_path, NULL);
    if (path == NULL) {
        return JNI_FALSE;
    }

    // 加载SDF库
    // path 可能是完整路径（如 /opt/sdf/lib/libswsds.so）
    // 或者只是库文件名（如 libswsds.so），让系统在标准路径中查找
    bool result = sdf_load_library(path);

    (*env)->ReleaseStringUTFChars(env, library_path, path);

    return result ? JNI_TRUE : JNI_FALSE;
}
