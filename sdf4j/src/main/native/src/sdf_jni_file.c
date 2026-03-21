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
 * 6.7.2 创建文件
 * SDF_CreateFile(hSessionHandle, pucFileName, uiNameLen, uiFileSize)
 */
JNIEXPORT void JNICALL JNI_SDF_CreateFile(JNIEnv *env, jobject obj, jlong sessionHandle, jstring fileName,
    jint fileSize) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_CreateFile == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return;
    }

    if (fileName == NULL) {
        THROW_SDF_EXCEPTION(env, 0x01000001, "File name is null");
        return;
    }

    /* 转换文件名 */
    char *file_name = java_string_to_native(env, fileName);
    if (file_name == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");
        return;
    }
    ULONG name_len = (ULONG)strlen(file_name);

    LONG ret = g_sdf_functions.SDF_CreateFile(
        (HANDLE)sessionHandle,
        (BYTE*)file_name,
        name_len,
        (ULONG)fileSize
    );

    free(file_name);

    if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform file create operation");
    }
}

/**
 * 6.7.3 读取文件
 * SDF_ReadFile(hSessionHandle, pucFileName, uiNameLen, uiOffset, puiFileLength, pucBuffer)
 * uiOffset: 读取文件的偏移值
 * puiFileLength: 输入时为要读取的长度，输出时为实际读取的长度
 */
JNIEXPORT jbyteArray JNICALL JNI_SDF_ReadFile(JNIEnv *env, jobject obj, jlong sessionHandle, jstring fileName,
    jint offset, jint length) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_ReadFile == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return NULL;
    }

    if (fileName == NULL) {
        THROW_SDF_EXCEPTION(env, 0x01000001, "File name is null");
        return NULL;
    }

    /* 转换文件名 */
    char *file_name = java_string_to_native(env, fileName);
    if (file_name == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");
        return NULL;
    }
    ULONG name_len = (ULONG)strlen(file_name);

    /* 分配读取缓冲区 */
    BYTE *buffer = (BYTE*)malloc(length);
    if (buffer == NULL) {
        free(file_name);
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");
        return NULL;
    }

    /* puiFileLength 输入时为要读取的长度 */
    ULONG file_len = (ULONG)length;

    LONG ret = g_sdf_functions.SDF_ReadFile(
        (HANDLE)sessionHandle,
        (BYTE*)file_name,
        name_len,
        (ULONG)offset,
        &file_len,
        buffer
    );

    free(file_name);

    if (ret != SDR_OK) {
        free(buffer);
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform file read operation");
        return NULL;
    }

    /* file_len 输出时为实际读取的长度 */
    jbyteArray result = native_to_java_byte_array(env, buffer, file_len);
    free(buffer);

    return result;
}

/**
 * 6.7.4 写文件
 * SDF_WriteFile(hSessionHandle, pucFileName, uiNameLen, uiOffset, uiFileLength, pucBuffer)
 */
JNIEXPORT void JNICALL JNI_SDF_WriteFile(JNIEnv *env, jobject obj, jlong sessionHandle, jstring fileName, jint offset,
    jbyteArray data) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_WriteFile == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return;
    }

    if (fileName == NULL || data == NULL) {
        THROW_SDF_EXCEPTION(env, 0x01000006, "File name or data is null");
        return;
    }

    /* Convert file name */
    char *file_name = java_string_to_native(env, fileName);
    if (file_name == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");
        return;
    }
    ULONG name_len = (ULONG)strlen(file_name);

    /* Get data buffer */
    jsize data_len = (*env)->GetArrayLength(env, data);
    jbyte *data_buf = (*env)->GetByteArrayElements(env, data, NULL);
    if (data_buf == NULL) {
        free(file_name);
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");
        return;
    }

    LONG ret = g_sdf_functions.SDF_WriteFile(
        (HANDLE)sessionHandle,
        (BYTE*)file_name,
        name_len,
        (ULONG)offset,
        (ULONG)data_len,
        (BYTE*)data_buf
    );

    free(file_name);
    (*env)->ReleaseByteArrayElements(env, data, data_buf, JNI_ABORT);

    if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform file write operation");
    }
}

/**
 * 6.7.5 删除文件
 * SDF_DeleteFile(hSessionHandle, pucFileName, uiNameLen)
 */
JNIEXPORT void JNICALL JNI_SDF_DeleteFile(JNIEnv *env, jobject obj, jlong sessionHandle, jstring fileName) {
    UNUSED(obj);

    if (g_sdf_functions.SDF_DeleteFile == NULL) {
        THROW_SDF_EXCEPTION(env, SDR_NOTSUPPORT, "Function not supported");
        return;
    }

    if (fileName == NULL) {
        THROW_SDF_EXCEPTION(env, 0x01000006, "File name is null");
        return;
    }

    /* Convert file name */
    char *file_name = java_string_to_native(env, fileName);
    if (file_name == NULL) {
        THROW_SDF_EXCEPTION(env, 0x0100001C, "Memory allocation failed");
        return;
    }
    ULONG name_len = (ULONG)strlen(file_name);

    LONG ret = g_sdf_functions.SDF_DeleteFile(
        (HANDLE)sessionHandle,
        (BYTE*)file_name,
        name_len
    );

    free(file_name);

    if (ret != SDR_OK) {
        THROW_SDF_EXCEPTION(env, ret, "Failed to perform file delete operation");
    }
}

