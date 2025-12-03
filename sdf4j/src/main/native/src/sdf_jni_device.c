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

JNIEXPORT jlong JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1OpenDevice
  (JNIEnv *env, jobject obj) {
    UNUSED(obj);

    SDF_LOG_ENTER("SDF_OpenDevice");

    if (!sdf_is_loaded()) {
        SDF_LOG_ERROR("SDF_OpenDevice", "SDF library not loaded");
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return 0;
    }

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

JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1CloseDevice
  (JNIEnv *env, jobject obj, jlong deviceHandle) {
    UNUSED(obj);

    SDF_LOG_ENTER("SDF_CloseDevice");
    SDF_JNI_LOG("SDF_CloseDevice: hDevice=0x%lX", (unsigned long)deviceHandle);

    if (!sdf_is_loaded()) {
        SDF_LOG_ERROR("SDF_CloseDevice", "SDF library not loaded");
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    VALIDATE_DEVICE_HANDLE(env, deviceHandle, "SDF_CloseDevice", );

    LONG ret = g_sdf_functions.SDF_CloseDevice((HANDLE)deviceHandle);

    SDF_LOG_EXIT("SDF_CloseDevice", ret);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

JNIEXPORT jlong JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1OpenSession
  (JNIEnv *env, jobject obj, jlong deviceHandle) {
    UNUSED(obj);

    SDF_LOG_ENTER("SDF_OpenSession");
    SDF_JNI_LOG("SDF_OpenSession: hDevice=0x%lX", (unsigned long)deviceHandle);

    if (!sdf_is_loaded()) {
        SDF_LOG_ERROR("SDF_OpenSession", "SDF library not loaded");
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return 0;
    }

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

JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1CloseSession
  (JNIEnv *env, jobject obj, jlong sessionHandle) {
    UNUSED(obj);

    SDF_LOG_ENTER("SDF_CloseSession");
    SDF_JNI_LOG("SDF_CloseSession: hSession=0x%lX", (unsigned long)sessionHandle);

    if (!sdf_is_loaded()) {
        SDF_LOG_ERROR("SDF_CloseSession", "SDF library not loaded");
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    VALIDATE_SESSION_HANDLE(env, sessionHandle, "SDF_CloseSession", );

    LONG ret = g_sdf_functions.SDF_CloseSession((HANDLE)sessionHandle);

    SDF_LOG_EXIT("SDF_CloseSession", ret);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

JNIEXPORT jobject JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1GetDeviceInfo
  (JNIEnv *env, jobject obj, jlong sessionHandle) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

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

JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1GenerateRandom
  (JNIEnv *env, jobject obj, jlong sessionHandle, jint length) {
    UNUSED(obj);

    SDF_LOG_ENTER("SDF_GenerateRandom");
    SDF_JNI_LOG("SDF_GenerateRandom: hSession=0x%lX, length=%d",
                (unsigned long)sessionHandle, (int)length);

    if (!sdf_is_loaded()) {
        SDF_LOG_ERROR("SDF_GenerateRandom", "SDF library not loaded");
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    VALIDATE_SESSION_HANDLE(env, sessionHandle, "SDF_GenerateRandom", NULL);

    if (g_sdf_functions.SDF_GenerateRandom == NULL) {
        SDF_LOG_ERROR("SDF_GenerateRandom", "Function not supported");
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (length <= 0 || length > 102400) {  /* 限制最大100KB */
        SDF_LOG_ERROR("SDF_GenerateRandom", "Invalid length parameter");
        throw_sdf_exception(env, 0x0100001D);  /* SDR_INARGERR */
        return NULL;
    }

    BYTE *random = (BYTE*)malloc(length);
    if (random == NULL) {
        SDF_LOG_ERROR("SDF_GenerateRandom", "Memory allocation failed");
        throw_sdf_exception_with_message(env, 0x0100001C, "Out of memory");  /* SDR_NOBUFFER */
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_GenerateRandom((HANDLE)sessionHandle, length, random);

    SDF_LOG_EXIT("SDF_GenerateRandom", ret);
    if (ret == SDR_OK) {
        SDF_LOG_HEX("SDF_GenerateRandom output", random, length);
    }

    if (ret != SDR_OK) {
        free(random);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, random, length);
    free(random);
    return result;
}

JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1GetPrivateKeyAccessRight
  (JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex, jstring password) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    VALIDATE_SESSION_HANDLE(env, sessionHandle, "SDF_GetPrivateKeyAccessRight", );

    if (g_sdf_functions.SDF_GetPrivateKeyAccessRight == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    char *pwd = java_string_to_native(env, password);
    if (pwd == NULL && password != NULL) {
        throw_sdf_exception(env, 0x0100001D);  /* SDR_INARGERR */
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
        throw_sdf_exception(env, ret);
    }
}

JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ReleasePrivateKeyAccessRight
  (JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

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

