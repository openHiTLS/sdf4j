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
 * 设备管理函数 JNI 实现
 * ======================================================================== */

JNIEXPORT jlong JNICALL JNI_SDF_OpenDevice(JNIEnv *env, jobject obj) {
    UNUSED(obj);

    HANDLE hDevice;
    LONG ret = g_sdf_functions.SDF_OpenDevice(&hDevice);
    if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to open device");
        return 0;
    }

    return (jlong)hDevice;
}

JNIEXPORT jlong JNICALL JNI_SDF_OpenDeviceWithConf(JNIEnv *env, jobject obj, jstring configFile) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_OpenDeviceWithConf == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return 0;
    }

    /* 转换配置文件路径 */
    const char *configPath = NULL;
    if (configFile != NULL) {
        configPath = (*env)->GetStringUTFChars(env, configFile, NULL);
        if (configPath == NULL) {
            THROW_SDF_EXCEPTION(env, SDR_INARGERR, "Failed to get config file path");
            return 0;
        }
    }

    HANDLE hDevice = NULL;
    LONG ret = g_sdf_functions.SDF_OpenDeviceWithConf(&hDevice, configPath);

    /* 释放字符串 */
    if (configPath != NULL) {
        (*env)->ReleaseStringUTFChars(env, configFile, configPath);
    }

    if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to open device with config");
        return 0;
    }
    return (jlong)hDevice;
}

JNIEXPORT void JNICALL JNI_SDF_CloseDevice(JNIEnv *env, jobject obj, jlong deviceHandle) {
    UNUSED(obj);

    VALIDATE_DEVICE_HANDLE(env, deviceHandle, "SDF_CloseDevice", );

    LONG ret = g_sdf_functions.SDF_CloseDevice((HANDLE)deviceHandle);
    if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to close device");
    }
}

JNIEXPORT jlong JNICALL JNI_SDF_OpenSession(JNIEnv *env, jobject obj, jlong deviceHandle) {
    UNUSED(obj);

    VALIDATE_DEVICE_HANDLE(env, deviceHandle, "SDF_OpenSession", 0);

    HANDLE hSession;
    LONG ret = g_sdf_functions.SDF_OpenSession((HANDLE)deviceHandle, &hSession);
    if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to open session");
        return 0;
    }

    return (jlong)hSession;
}

JNIEXPORT void JNICALL JNI_SDF_CloseSession(JNIEnv *env, jobject obj, jlong sessionHandle) {
    UNUSED(obj);

    VALIDATE_SESSION_HANDLE(env, sessionHandle, "SDF_CloseSession", );

    LONG ret = g_sdf_functions.SDF_CloseSession((HANDLE)sessionHandle);
    if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to close session");
    }
}

JNIEXPORT jobject JNICALL JNI_SDF_GetDeviceInfo(JNIEnv *env, jobject obj, jlong sessionHandle) {
    UNUSED(obj);

    VALIDATE_SESSION_HANDLE(env, sessionHandle, "SDF_GetDeviceInfo", NULL);

    if (g_sdf_functions.SDF_GetDeviceInfo == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return NULL;
    }

    DEVICEINFO deviceInfo;
    memset(&deviceInfo, 0, sizeof(deviceInfo));

    LONG ret = g_sdf_functions.SDF_GetDeviceInfo((HANDLE)sessionHandle, &deviceInfo);

    if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to get device info");
        return NULL;
    }

    return native_to_java_DeviceInfo(env, &deviceInfo);
}

JNIEXPORT jbyteArray JNICALL JNI_SDF_GenerateRandom(JNIEnv *env, jobject obj, jlong sessionHandle, jint length) {
    UNUSED(obj);

    VALIDATE_SESSION_HANDLE(env, sessionHandle, "SDF_GenerateRandom", NULL);

    if (g_sdf_functions.SDF_GenerateRandom == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return NULL;
    }
    if (length <= 0) {
        THROW_SDF_EXCEPTION(env, 0x0100001D, "Invalid random length"); /* SDR_INARGERR */
        return NULL;
    }
    jbyteArray result = (*env)->NewByteArray(env, length);
    if (result == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Failed to allocate random array"); /* SDR_NOBUFFER */
        return NULL;
    }

    jbyte *random = (*env)->GetPrimitiveArrayCritical(env, result, NULL);
    if (random == NULL) {
        (*env)->DeleteLocalRef(env, result);
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Failed to get random array buffer"); /* SDR_NOBUFFER */
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_GenerateRandom((HANDLE)sessionHandle, length, (BYTE*)random);
    (*env)->ReleasePrimitiveArrayCritical(env, result, random, 0);

    if (ret != SDR_OK) {
        (*env)->DeleteLocalRef(env, result);
        THROW_SDF_EXCEPTION(env, ret, "Failed to generate random");
        return NULL;
    }
    return result;
}

JNIEXPORT void JNICALL JNI_SDF_GetPrivateKeyAccessRight(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint keyIndex, jstring password) {
    UNUSED(obj);

    VALIDATE_SESSION_HANDLE(env, sessionHandle, "SDF_GetPrivateKeyAccessRight", );

    if (g_sdf_functions.SDF_GetPrivateKeyAccessRight == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return;
    }

    char *pwd = java_string_to_native(env, password);
    if (pwd == NULL && password != NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001D, "Invalid password"); /* SDR_INARGERR */
        return;
    }

    ULONG pwd_len = pwd ? strlen(pwd) : 0;

    LONG ret = g_sdf_functions.SDF_GetPrivateKeyAccessRight((HANDLE)sessionHandle,
        keyIndex, (LPSTR)pwd, pwd_len);

    if (pwd != NULL) {
        /* 清除密码内存 */
        memset(pwd, 0, pwd_len);
        free(pwd);
    }

    if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to get private key access right");
    }
}

JNIEXPORT void JNICALL JNI_SDF_ReleasePrivateKeyAccessRight(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint keyIndex) {
    UNUSED(obj);

    VALIDATE_SESSION_HANDLE(env, sessionHandle, "SDF_ReleasePrivateKeyAccessRight", );

    if (g_sdf_functions.SDF_ReleasePrivateKeyAccessRight == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return;
    }

    LONG ret = g_sdf_functions.SDF_ReleasePrivateKeyAccessRight((HANDLE)sessionHandle, keyIndex);

    if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to release private key access right");
    }
}

JNIEXPORT void JNICALL JNI_SDF_GetKEKAccessRight(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint keyIndex, jstring password) {
    UNUSED(obj);
    VALIDATE_SESSION_HANDLE(env, sessionHandle, "SDF_GetKEKAccessRight", );

    if (g_sdf_functions.SDF_GetKEKAccessRight == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return;
    }

    char *pwd = java_string_to_native(env, password);
    if (pwd == NULL && password != NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001D, "Invalid password"); /* SDR_INARGERR */
        return;
    }

    ULONG pwd_len = pwd ? strlen(pwd) : 0;
    LONG ret = g_sdf_functions.SDF_GetKEKAccessRight((HANDLE)sessionHandle,
                                                      keyIndex, (LPSTR)pwd, pwd_len);

    if (pwd != NULL) {
        /* 清除密码内存 */
        memset(pwd, 0, pwd_len);
        free(pwd);
    }

    if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to get KEK access right");
    }
}

JNIEXPORT void JNICALL JNI_SDF_ReleaseKEKAccessRight(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint keyIndex) {
    UNUSED(obj);

    VALIDATE_SESSION_HANDLE(env, sessionHandle, "SDF_ReleaseKEKAccessRight", );

    if (g_sdf_functions.SDF_ReleaseKEKAccessRight == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return;
    }

    LONG ret = g_sdf_functions.SDF_ReleaseKEKAccessRight((HANDLE)sessionHandle, keyIndex);
    if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to release KEK access right");
    }
}

