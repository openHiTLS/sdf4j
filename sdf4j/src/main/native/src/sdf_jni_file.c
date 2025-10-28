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
 * File Operation Functions
 * ======================================================================== */


/**
 * 6.7.1 创建文件
 * Pattern: String parameter, void return
 */
JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1CreateFile
(JNIEnv *env, jobject obj, jlong sessionHandle, jstring fileName, jint fileSize) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_CreateFile == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    if (fileName == NULL) {
        throw_sdf_exception_with_message(env, 0x01000001, "File name is null");
        return;
    }

    /* 转换文件名 */
    char *file_name = java_string_to_native(env, fileName);
    if (file_name == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return;
    }

    LONG ret = g_sdf_functions.SDF_CreateFile(
        (HANDLE)sessionHandle,
        (LPSTR)file_name,
        (ULONG)fileSize
    );

    free(file_name);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/**
 * 6.7.2 读取文件
 * Pattern: String + offset + length parameters, byte array return
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ReadFile
(JNIEnv *env, jobject obj, jlong sessionHandle, jstring fileName, jint offset, jint length) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_ReadFile == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (fileName == NULL) {
        throw_sdf_exception_with_message(env, 0x01000001, "File name is null");
        return NULL;
    }

    /* 转换文件名 */
    char *file_name = java_string_to_native(env, fileName);
    if (file_name == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    /* 分配读取缓冲区 */
    BYTE *buffer = (BYTE*)malloc(length);
    if (buffer == NULL) {
        free(file_name);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    ULONG read_len = 0;

    LONG ret = g_sdf_functions.SDF_ReadFile(
        (HANDLE)sessionHandle,
        (LPSTR)file_name,
        (ULONG)offset,
        (ULONG)length,
        buffer,
        &read_len
    );

    free(file_name);

    if (ret != SDR_OK) {
        free(buffer);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, buffer, read_len);
    free(buffer);

    return result;
}

/**
 * 6.7.3 写文件
 * SDF_WriteFile
 */
JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1WriteFile
(JNIEnv *env, jobject obj, jlong sessionHandle, jstring fileName, jint offset, jbyteArray data) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_WriteFile == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    if (fileName == NULL || data == NULL) {
        throw_sdf_exception_with_message(env, 0x01000006, "File name or data is null");
        return;
    }

    /* Convert file name */
    char *file_name = java_string_to_native(env, fileName);
    if (file_name == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return;
    }

    /* Get data buffer */
    jsize data_len = (*env)->GetArrayLength(env, data);
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        free(file_name);
        throw_sdf_exception(env, 0x0100001C);
        return;
    }
    (*env)->GetByteArrayRegion(env, data, 0, data_len, (jbyte*)data_buf);

    LONG ret = g_sdf_functions.SDF_WriteFile(
        (HANDLE)sessionHandle,
        (LPSTR)file_name,
        (ULONG)strlen(file_name),
        (ULONG)offset,
        (ULONG)data_len,
        data_buf
    );

    free(file_name);
    free(data_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/**
 * 6.7.4 删除文件
 * SDF_DeleteFile
 */
JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1DeleteFile
(JNIEnv *env, jobject obj, jlong sessionHandle, jstring fileName) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_DeleteFile == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    if (fileName == NULL) {
        throw_sdf_exception_with_message(env, 0x01000006, "File name is null");
        return;
    }

    /* Convert file name */
    char *file_name = java_string_to_native(env, fileName);
    if (file_name == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return;
    }

    LONG ret = g_sdf_functions.SDF_DeleteFile(
        (HANDLE)sessionHandle,
        (LPSTR)file_name,
        (ULONG)strlen(file_name)
    );

    free(file_name);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

