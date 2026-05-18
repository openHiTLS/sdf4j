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
#include "sdf_jce_functions.h"
#include "dynamic_loader.h"

/* 保存库路径用于初始化 */
static char *g_library_path = NULL;

/* SDF库路径环境变量名 */
#define SDF_LIBRARY_PATH_ENV "SDF_LIBRARY_PATH"

/* NativeLoader 方法注册表 */
static const JNINativeMethod native_loader_methods[] = {
    {"setLibraryPath", "(Ljava/lang/String;)V", (void*)Sdf4j_Jce_NativeLoader_SetLibraryPath},
    {"initialize", "()Z", (void*)Sdf4j_Jce_NativeLoader_Initialize},
    {"cleanup", "()V", (void*)Sdf4j_Jce_NativeLoader_Cleanup},
};

/* SDFJceNative 方法注册表 */
static const JNINativeMethod sdf_jce_methods[] = {
    /* ==================== Session Management ==================== */
    {"openSession", "()J", (void*)Sdf4j_jce_SDFJceNative_openSession},
    {"closeSession", "(J)V", (void*)Sdf4j_jce_SDFJceNative_closeSession},

    /* ==================== SM3 Hash ==================== */
    {"sm3Digest", "(J[B)[B", (void*)JNI_SDFJceNative_sm3Digest},
    {"sm3Init", "(J)J", (void*)JNI_SDFJceNative_sm3Init},
    {"sm3Update", "(J[BII)V", (void*)JNI_SDFJceNative_sm3Update},
    {"sm3Final", "(J)[B", (void*)JNI_SDFJceNative_sm3Final},
    {"sm3Free", "(J)V", (void*)JNI_SDFJceNative_sm3Free},

    /* ==================== SM4 Symmetric Encryption ==================== */
    {"sm4AuthEnc", "(JI[B[B[B[B)[B", (void*)JNI_SDFJceNative_sm4AuthEnc},
    {"sm4AuthDec", "(JI[B[B[B[B[B)[B", (void*)JNI_SDFJceNative_sm4AuthDec},
    {"sm4AuthEncWithKeyHandle", "(JJI[B[B[B)[B", (void*)JNI_SDFJceNative_sm4AuthEncWithKeyHandle},
    {"sm4AuthDecWithKeyHandle", "(JJI[B[B[B[B)[B", (void*)JNI_SDFJceNative_sm4AuthDecWithKeyHandle},
    {"sm4EncryptInit", "(JI[B[B)J", (void*)JNI_SDFJceNative_sm4EncryptInit},
    {"sm4EncryptUpdate", "(J[BII)[B", (void*)JNI_SDFJceNative_sm4EncryptUpdate},
    {"sm4EncryptFinal", "(J)[B", (void*)JNI_SDFJceNative_sm4EncryptFinal},
    {"sm4DecryptInit", "(JI[B[B)J", (void*)JNI_SDFJceNative_sm4DecryptInit},
    {"sm4DecryptUpdate", "(J[BII)[B", (void*)JNI_SDFJceNative_sm4DecryptUpdate},
    {"sm4DecryptFinal", "(J)[B", (void*)JNI_SDFJceNative_sm4DecryptFinal},
    {"sm4Free", "(J)V", (void*)JNI_SDFJceNative_sm4Free},

    /* ==================== SM2 Asymmetric ==================== */
    {"sm2GenerateKeyPair", "(J)[B", (void*)JNI_SDFJceNative_sm2GenerateKeyPair},
    {"sm2Sign", "(J[B[B)[B", (void*)JNI_SDFJceNative_sm2Sign},
    {"sm2Verify", "(J[B[B[B[B)Z", (void*)JNI_SDFJceNative_sm2Verify},
    {"sm2Encrypt", "(J[B[B[B)[B", (void*)JNI_SDFJceNative_sm2Encrypt},
    {"sm2Decrypt", "(J[B[B)[B", (void*)JNI_SDFJceNative_sm2Decrypt},

    /* ==================== MAC ==================== */
    {"sm4Mac", "(J[B[B[B)[B", (void*)JNI_SDFJceNative_sm4Mac},
    {"hmacSm3", "(J[B[B)[B", (void*)JNI_SDFJceNative_hmacSm3},

    /* ==================== Random ==================== */
    {"generateRandom", "(JI)[B", (void*)JNI_SDFJceNative_generateRandom},

    /* ==================== Key Management ==================== */
    {"generateSm4Key", "(J)[B", (void*)JNI_SDFJceNative_generateSm4Key},

    /* ==================== SM2 Internal Operations ==================== */
    {"sm2InternalSign", "(JI[B)[B", (void*)JNI_SDFJceNative_sm2InternalSign},
    {"sm2InternalVerify", "(JI[B[B)Z", (void*)JNI_SDFJceNative_sm2InternalVerify},
    {"sm2InternalEncrypt", "(JI[B)[B", (void*)JNI_SDFJceNative_sm2InternalEncrypt},
    {"sm2InternalDecrypt", "(JII[B)[B", (void*)JNI_SDFJceNative_sm2InternalDecrypt},
    {"exportSignPublicKeyECC", "(JI)[B", (void*)JNI_SDFJceNative_exportSignPublicKeyECC},
    {"exportEncPublicKeyECC", "(JI)[B", (void*)JNI_SDFJceNative_exportEncPublicKeyECC},

    /* ==================== Access Right Management ==================== */
    {"getPrivateKeyAccessRight", "(JI[B)V", (void*)JNI_SDFJceNative_getPrivateKeyAccessRight},
    {"releasePrivateKeyAccessRight", "(JI)V", (void*)JNI_SDFJceNative_releasePrivateKeyAccessRight},
    {"getKEKAccessRight", "(JI[B)V", (void*)JNI_SDFJceNative_getKEKAccessRight},
    {"releaseKEKAccessRight", "(JI)V", (void*)JNI_SDFJceNative_releaseKEKAccessRight},

    /* ==================== SM4 Internal (KEK) Operations ==================== */
    {"sm4GenerateKeyWithKEK", "(JIII)[B", (void*)JNI_SDFJceNative_sm4GenerateKeyWithKEK},
    {"sm4ImportKeyWithKEK", "(JII[B)J", (void*)JNI_SDFJceNative_sm4ImportKeyWithKEK},
    {"sm4EncryptInitWithKeyHandle", "(JJI[B)J", (void*)JNI_SDFJceNative_sm4EncryptInitWithKeyHandle},
    {"sm4DecryptInitWithKeyHandle", "(JJI[B)J", (void*)JNI_SDFJceNative_sm4DecryptInitWithKeyHandle},
    {"destroyKey", "(JJ)V", (void*)JNI_SDFJceNative_destroyKey},
};

/* 注册标志 */
static volatile int g_registered = 0;

/* 内部注册函数 */
static int do_register(JNIEnv *env) {
    if (g_registered) {
        return 1;
    }

    /* 注册 NativeLoader 的方法 */
    jclass loaderClazz = (*env)->FindClass(env, "org/openhitls/sdf4j/jce/NativeLoader");
    if (loaderClazz == NULL) {
        return 0;
    }

    jint loaderMethodCount = sizeof(native_loader_methods) / sizeof(native_loader_methods[0]);
    if ((*env)->RegisterNatives(env, loaderClazz, native_loader_methods, loaderMethodCount) < 0) {
        (*env)->DeleteLocalRef(env, loaderClazz);
        return 0;
    }
    (*env)->DeleteLocalRef(env, loaderClazz);

    /* 注册 SDFJceNative 的方法 */
    jclass jceClazz = (*env)->FindClass(env, "org/openhitls/sdf4j/jce/SDFJceNative");
    if (jceClazz == NULL) {
        return 0;
    }

    jint jceMethodCount = sizeof(sdf_jce_methods) / sizeof(sdf_jce_methods[0]);
    if ((*env)->RegisterNatives(env, jceClazz, sdf_jce_methods, jceMethodCount) < 0) {
        (*env)->DeleteLocalRef(env, jceClazz);
        return 0;
    }
    (*env)->DeleteLocalRef(env, jceClazz);

    g_registered = 1;
    return 1;
}

/**
 * JNI_OnLoad - JVM 加载库时调用
 *
 * 注册native方法，SDF初始化由Java层通过setLibraryPath/initialize触发
 */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;

    JNIEnv *env;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_8) != JNI_OK) {
        return JNI_ERR;
    }

    /* 尝试注册native方法 */
    if (!do_register(env)) {
        return JNI_ERR;
    }

    return JNI_VERSION_1_8;
}

/**
 * Sdf4j_Jce_NativeLoader_SetLibraryPath
 * 设置SDF库路径（不立即初始化）
 */
JNIEXPORT void JNICALL Sdf4j_Jce_NativeLoader_SetLibraryPath(JNIEnv *env, jclass cls, jstring path) {
    (void)cls;

    if (path == NULL) {
        return;
    }

    /* 释放旧路径 */
    if (g_library_path != NULL) {
        free(g_library_path);
        g_library_path = NULL;
    }

    /* 获取并保存新路径 */
    const char *path_str = (*env)->GetStringUTFChars(env, path, NULL);
    if (path_str != NULL) {
        g_library_path = strdup(path_str);
        (*env)->ReleaseStringUTFChars(env, path, path_str);
    }
}

/**
 * Sdf4j_Jce_NativeLoader_Initialize
 * 使用已设置的库路径初始化SDF
 * 如果没有设置路径，则尝试从环境变量读取
 *
 * @return JNI_TRUE 初始化成功，JNI_FALSE 初始化失败
 */
JNIEXPORT jboolean JNICALL Sdf4j_Jce_NativeLoader_Initialize(JNIEnv *env, jclass cls) {
    (void)cls;

    /* 如果已初始化，直接返回成功 */
    if (g_sdf_initialized) {
        return JNI_TRUE;
    }

    const char *library_path = g_library_path;

    /* 如果没有通过setLibraryPath设置，尝试环境变量 */
    if (library_path == NULL) {
        library_path = getenv(SDF_LIBRARY_PATH_ENV);
    }

    /* 如果有路径，进行初始化 */
    if (library_path != NULL && library_path[0] != '\0') {
        /* 保存路径（如果是来自环境变量） */
        if (g_library_path == NULL) {
            g_library_path = strdup(library_path);
            if (g_library_path == NULL) {
                throw_exception(env, "java/lang/OutOfMemoryError", "Failed to allocate library path");
                return JNI_FALSE;
            }
        }
    }

    /* 调用初始化（library_path 为 NULL 时会触发默认路径搜索） */
    int ret = sdf_jce_initialize(g_library_path);
    if (ret != SDR_OK) {
        const char* load_error = sdf_get_load_error();
        char err_msg[1024];
        snprintf(err_msg, sizeof(err_msg), "Failed to initialize SDF: %s. "
            "Set SDF_LIBRARY_PATH or SDF_LIBRARY_NAME to specify the SDF library.",
            load_error ? load_error : "Unknown error");
        throw_jce_exception(env, ret, err_msg);
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

/**
 * Sdf4j_Jce_NativeLoader_Cleanup
 * 清理SDF资源（关闭会话、设备、卸载库）
 * 用于在测试之间重置状态
 */
JNIEXPORT void JNICALL Sdf4j_Jce_NativeLoader_Cleanup(JNIEnv *env, jclass cls) {
    (void)env;
    (void)cls;
    sdf_jce_cleanup();
}

/**
 * JNI_OnUnload - JVM 卸载库时调用
 */
JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved) {
    (void)reserved;

    JNIEnv *env;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_8) != JNI_OK) {
        return;
    }

    /* 清理SDF资源 */
    sdf_jce_cleanup();

    /* 释放库路径字符串 */
    if (g_library_path != NULL) {
        free(g_library_path);
        g_library_path = NULL;
    }

    /* 注销 NativeLoader 类 */
    jclass loaderClazz = (*env)->FindClass(env, "org/openhitls/sdf4j/jce/NativeLoader");
    if (loaderClazz != NULL) {
        (*env)->UnregisterNatives(env, loaderClazz);
        (*env)->DeleteLocalRef(env, loaderClazz);
    }

    /* 注销 SDFSession 类 */
    jclass sessionClazz = (*env)->FindClass(env, "org/openhitls/sdf4j/jce/SDFSession");
    if (sessionClazz != NULL) {
        (*env)->UnregisterNatives(env, sessionClazz);
        (*env)->DeleteLocalRef(env, sessionClazz);
    }

    /* 注销 SDFJceNative 类 */
    jclass jceClazz = (*env)->FindClass(env, "org/openhitls/sdf4j/jce/SDFJceNative");
    if (jceClazz != NULL) {
        (*env)->UnregisterNatives(env, jceClazz);
        (*env)->DeleteLocalRef(env, jceClazz);
    }
    g_registered = 0;
}
