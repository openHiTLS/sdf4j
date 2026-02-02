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

    SDF_LOG_ENTER("SDF_OpenDevice");

    HANDLE hDevice;
    LONG ret = g_sdf_functions.SDF_OpenDevice(&hDevice);

    SDF_LOG_EXIT("SDF_OpenDevice", ret);
    SDF_JNI_LOG("SDF_OpenDevice: hDevice=0x%lX", (unsigned long)hDevice);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return 0;
    }

    return (jlong)hDevice;
}

JNIEXPORT jlong JNICALL JNI_SDF_OpenDeviceWithConf(JNIEnv *env, jobject obj, jstring configFile) {
    UNUSED(obj);

    SDF_LOG_ENTER("SDF_OpenDeviceWithConf");

    if (g_sdf_functions.SDF_OpenDeviceWithConf == NULL) {
        SDF_LOG_ERROR("SDF_OpenDeviceWithConf", "Function not supported");
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return 0;
    }

    /* 转换配置文件路径 */
    const char *configPath = NULL;
    if (configFile != NULL) {
        configPath = (*env)->GetStringUTFChars(env, configFile, NULL);
        if (configPath == NULL) {
            SDF_LOG_ERROR("SDF_OpenDeviceWithConf", "Failed to get config file path");
            throw_sdf_exception(env, SDR_INARGERR);
            return 0;
        }
    }

    SDF_JNI_LOG("SDF_OpenDeviceWithConf: configFile=%s", configPath ? configPath : "(null)");

    HANDLE hDevice = NULL;
    LONG ret = g_sdf_functions.SDF_OpenDeviceWithConf(&hDevice, configPath);

    /* 释放字符串 */
    if (configPath != NULL) {
        (*env)->ReleaseStringUTFChars(env, configFile, configPath);
    }

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return 0;
    }
    SDF_LOG_EXIT("SDF_OpenDeviceWithConf", ret);
    SDF_JNI_LOG("SDF_OpenDeviceWithConf: hDevice=0x%lX", (unsigned long)hDevice);
    return (jlong)hDevice;
}

JNIEXPORT void JNICALL JNI_SDF_CloseDevice(JNIEnv *env, jobject obj, jlong deviceHandle) {
    UNUSED(obj);

    SDF_LOG_ENTER("SDF_CloseDevice");
    SDF_JNI_LOG("SDF_CloseDevice: hDevice=0x%lX", (unsigned long)deviceHandle);

    VALIDATE_DEVICE_HANDLE(env, deviceHandle, "SDF_CloseDevice", );

    LONG ret = g_sdf_functions.SDF_CloseDevice((HANDLE)deviceHandle);

    SDF_LOG_EXIT("SDF_CloseDevice", ret);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

JNIEXPORT jlong JNICALL JNI_SDF_OpenSession(JNIEnv *env, jobject obj, jlong deviceHandle) {
    UNUSED(obj);

    SDF_LOG_ENTER("SDF_OpenSession");
    SDF_JNI_LOG("SDF_OpenSession: hDevice=0x%lX", (unsigned long)deviceHandle);

    VALIDATE_DEVICE_HANDLE(env, deviceHandle, "SDF_OpenSession", 0);

    HANDLE hSession;
    LONG ret = g_sdf_functions.SDF_OpenSession((HANDLE)deviceHandle, &hSession);

    SDF_LOG_EXIT("SDF_OpenSession", ret);
    SDF_JNI_LOG("SDF_OpenSession: hSession=0x%lX", (unsigned long)hSession);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return 0;
    }

    return (jlong)hSession;
}

JNIEXPORT void JNICALL JNI_SDF_CloseSession(JNIEnv *env, jobject obj, jlong sessionHandle) {
    UNUSED(obj);

    SDF_LOG_ENTER("SDF_CloseSession");
    SDF_JNI_LOG("SDF_CloseSession: hSession=0x%lX", (unsigned long)sessionHandle);

    VALIDATE_SESSION_HANDLE(env, sessionHandle, "SDF_CloseSession", );

    LONG ret = g_sdf_functions.SDF_CloseSession((HANDLE)sessionHandle);

    SDF_LOG_EXIT("SDF_CloseSession", ret);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

JNIEXPORT jobject JNICALL JNI_SDF_GetDeviceInfo(JNIEnv *env, jobject obj, jlong sessionHandle) {
    UNUSED(obj);

    VALIDATE_SESSION_HANDLE(env, sessionHandle, "SDF_GetDeviceInfo", NULL);

    if (g_sdf_functions.SDF_GetDeviceInfo == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    DEVICEINFO deviceInfo;
    memset(&deviceInfo, 0, sizeof(deviceInfo));

    LONG ret = g_sdf_functions.SDF_GetDeviceInfo((HANDLE)sessionHandle, &deviceInfo);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return NULL;
    }

    return native_to_java_DeviceInfo(env, &deviceInfo);
}

JNIEXPORT jbyteArray JNICALL JNI_SDF_GenerateRandom(JNIEnv *env, jobject obj, jlong sessionHandle, jint length) {
    UNUSED(obj);

    SDF_LOG_ENTER("SDF_GenerateRandom");
    SDF_JNI_LOG("SDF_GenerateRandom: hSession=0x%lX, length=%d",
                (unsigned long)sessionHandle, (int)length);

    VALIDATE_SESSION_HANDLE(env, sessionHandle, "SDF_GenerateRandom", NULL);

    if (g_sdf_functions.SDF_GenerateRandom == NULL) {
        SDF_LOG_ERROR("SDF_GenerateRandom", "Function not supported");
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (length <= 0 || length > 1024 * 1024) {  /* 限制最大1MB */
        SDF_LOG_ERROR("SDF_GenerateRandom", "Invalid length parameter");
        throw_sdf_exception(env, 0x0100001D);  /* SDR_INARGERR */
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, length);
    if (result == NULL) {
        SDF_LOG_ERROR("SDF_GenerateRandom", "NewByteArray failed");
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    jbyte *random = (*env)->GetPrimitiveArrayCritical(env, result, NULL);
    if (random == NULL) {
        (*env)->DeleteLocalRef(env, result);
        SDF_LOG_ERROR("SDF_GenerateRandom", "GetPrimitiveArrayCritical failed");
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_GenerateRandom((HANDLE)sessionHandle, length, (BYTE*)random);
    (*env)->ReleasePrimitiveArrayCritical(env, result, random, 0);

    if (ret != SDR_OK) {
        (*env)->DeleteLocalRef(env, result);
        throw_sdf_exception(env, ret);
        return NULL;
    }
    SDF_LOG_EXIT("SDF_GenerateRandom", ret);
    return result;
}

JNIEXPORT void JNICALL JNI_SDF_GetPrivateKeyAccessRight(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint keyIndex, jstring password) {
    UNUSED(obj);

    SDF_LOG_ENTER("SDF_GetPrivateKeyAccessRight");
    SDF_JNI_LOG("SDF_GetPrivateKeyAccessRight: hSession=0x%lX, keyIndex=%d",
                (unsigned long)sessionHandle, (int)keyIndex);

    VALIDATE_SESSION_HANDLE(env, sessionHandle, "SDF_GetPrivateKeyAccessRight", );

    if (g_sdf_functions.SDF_GetPrivateKeyAccessRight == NULL) {
        SDF_LOG_ERROR("SDF_GetPrivateKeyAccessRight", "Function not supported");
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    char *pwd = java_string_to_native(env, password);
    if (pwd == NULL && password != NULL) {
        SDF_LOG_ERROR("SDF_GetPrivateKeyAccessRight", "Failed to convert password string");
        throw_sdf_exception(env, 0x0100001D);  /* SDR_INARGERR */
        return;
    }

    ULONG pwd_len = pwd ? strlen(pwd) : 0;

    LONG ret = g_sdf_functions.SDF_GetPrivateKeyAccessRight((HANDLE)sessionHandle,
        keyIndex, (LPSTR)pwd, pwd_len);

    SDF_LOG_EXIT("SDF_GetPrivateKeyAccessRight", ret);

    if (pwd != NULL) {
        /* 清除密码内存 */
        memset(pwd, 0, pwd_len);
        free(pwd);
    }

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

JNIEXPORT void JNICALL JNI_SDF_ReleasePrivateKeyAccessRight(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint keyIndex) {
    UNUSED(obj);

    VALIDATE_SESSION_HANDLE(env, sessionHandle, "SDF_ReleasePrivateKeyAccessRight", );

    if (g_sdf_functions.SDF_ReleasePrivateKeyAccessRight == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    LONG ret = g_sdf_functions.SDF_ReleasePrivateKeyAccessRight((HANDLE)sessionHandle, keyIndex);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

JNIEXPORT void JNICALL JNI_SDF_GetKEKAccessRight(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint keyIndex, jstring password) {
    UNUSED(obj);

    SDF_LOG_ENTER("SDF_GetKEKAccessRight");
    SDF_JNI_LOG("SDF_GetKEKAccessRight: hSession=0x%lX, keyIndex=%d",
                (unsigned long)sessionHandle, (int)keyIndex);

    VALIDATE_SESSION_HANDLE(env, sessionHandle, "SDF_GetKEKAccessRight", );

    if (g_sdf_functions.SDF_GetKEKAccessRight == NULL) {
        SDF_LOG_ERROR("SDF_GetKEKAccessRight", "Function not supported");
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    char *pwd = java_string_to_native(env, password);
    if (pwd == NULL && password != NULL) {
        SDF_LOG_ERROR("SDF_GetKEKAccessRight", "Failed to convert password string");
        throw_sdf_exception(env, 0x0100001D);  /* SDR_INARGERR */
        return;
    }

    ULONG pwd_len = pwd ? strlen(pwd) : 0;
    LONG ret = g_sdf_functions.SDF_GetKEKAccessRight((HANDLE)sessionHandle,
                                                      keyIndex, (LPSTR)pwd, pwd_len);

    SDF_LOG_EXIT("SDF_GetKEKAccessRight", ret);

    if (pwd != NULL) {
        /* 清除密码内存 */
        memset(pwd, 0, pwd_len);
        free(pwd);
    }

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

JNIEXPORT void JNICALL JNI_SDF_ReleaseKEKAccessRight(JNIEnv *env, jobject obj, jlong sessionHandle,
    jint keyIndex) {
    UNUSED(obj);

    SDF_LOG_ENTER("SDF_ReleaseKEKAccessRight");
    SDF_JNI_LOG("SDF_ReleaseKEKAccessRight: hSession=0x%lX, keyIndex=%d",
                (unsigned long)sessionHandle, (int)keyIndex);

    VALIDATE_SESSION_HANDLE(env, sessionHandle, "SDF_ReleaseKEKAccessRight", );

    if (g_sdf_functions.SDF_ReleaseKEKAccessRight == NULL) {
        SDF_LOG_ERROR("SDF_ReleaseKEKAccessRight", "Function not supported");
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    LONG ret = g_sdf_functions.SDF_ReleaseKEKAccessRight((HANDLE)sessionHandle, keyIndex);

    SDF_LOG_EXIT("SDF_ReleaseKEKAccessRight", ret);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

