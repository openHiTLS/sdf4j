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

#include "org_openhitls_sdf4j_SDF.h"
#include "org_openhitls_sdf4j_internal_NativeLibraryLoader.h"
#include "dynamic_loader.h"
#include "type_conversion.h"
#include <stdlib.h>
#include <string.h>

/* 标记未使用的参数以避免编译警告 */
#define UNUSED(x) (void)(x)

/* SDR_NOTSUPPORT 已在 sdf_err.h 中定义，无需重复定义 */

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

/* ========================================================================
 * 设备管理函数 JNI 实现
 * ======================================================================== */

JNIEXPORT jlong JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1OpenDevice
  (JNIEnv *env, jobject obj) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return 0;
    }

    HANDLE hDevice;
    LONG ret = g_sdf_functions.SDF_OpenDevice(&hDevice);

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

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    LONG ret = g_sdf_functions.SDF_CloseDevice((HANDLE)deviceHandle);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

JNIEXPORT jlong JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1OpenSession
  (JNIEnv *env, jobject obj, jlong deviceHandle) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return 0;
    }

    HANDLE hSession;
    LONG ret = g_sdf_functions.SDF_OpenSession((HANDLE)deviceHandle, &hSession);

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

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    LONG ret = g_sdf_functions.SDF_CloseSession((HANDLE)sessionHandle);

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

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_GenerateRandom == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (length <= 0 || length > 102400) {  /* 限制最大100KB */
        throw_sdf_exception(env, 0x0100001D);  /* SDR_INARGERR */
        return NULL;
    }

    BYTE *random = (BYTE*)malloc(length);
    if (random == NULL) {
        throw_sdf_exception_with_message(env, 0x0100001C, "Out of memory");  /* SDR_NOBUFFER */
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_GenerateRandom((HANDLE)sessionHandle, length, random);

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

    if (g_sdf_functions.SDF_ReleasePrivateKeyAccessRight == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    LONG ret = g_sdf_functions.SDF_ReleasePrivateKeyAccessRight((HANDLE)sessionHandle, keyIndex);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/* ========================================================================
 * 密钥管理函数 JNI 实现
 * ======================================================================== */

JNIEXPORT jobject JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ExportSignPublicKey_1RSA
  (JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_ExportSignPublicKey_RSA == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    RSArefPublicKey publicKey;
    memset(&publicKey, 0, sizeof(publicKey));

    LONG ret = g_sdf_functions.SDF_ExportSignPublicKey_RSA((HANDLE)sessionHandle,
                                                           keyIndex, &publicKey);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return NULL;
    }

    return native_to_java_RSAPublicKey(env, &publicKey);
}

JNIEXPORT jobject JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ExportEncPublicKey_1RSA
  (JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_ExportEncPublicKey_RSA == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    RSArefPublicKey publicKey;
    memset(&publicKey, 0, sizeof(publicKey));

    LONG ret = g_sdf_functions.SDF_ExportEncPublicKey_RSA((HANDLE)sessionHandle,
                                                          keyIndex, &publicKey);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return NULL;
    }

    return native_to_java_RSAPublicKey(env, &publicKey);
}

JNIEXPORT jobject JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ExportSignPublicKey_1ECC
  (JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_ExportSignPublicKey_ECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    ECCrefPublicKey publicKey;
    memset(&publicKey, 0, sizeof(publicKey));

    LONG ret = g_sdf_functions.SDF_ExportSignPublicKey_ECC((HANDLE)sessionHandle,
                                                           keyIndex, &publicKey);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return NULL;
    }

    return native_to_java_ECCPublicKey(env, &publicKey);
}

JNIEXPORT jobject JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ExportEncPublicKey_1ECC
  (JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_ExportEncPublicKey_ECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    ECCrefPublicKey publicKey;
    memset(&publicKey, 0, sizeof(publicKey));

    LONG ret = g_sdf_functions.SDF_ExportEncPublicKey_ECC((HANDLE)sessionHandle,
                                                          keyIndex, &publicKey);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return NULL;
    }

    return native_to_java_ECCPublicKey(env, &publicKey);
}

JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1DestroyKey
  (JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_DestroyKey == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    LONG ret = g_sdf_functions.SDF_DestroyKey((HANDLE)sessionHandle, (HANDLE)keyHandle);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/* ========================================================================
 * 非对称算法函数 JNI 实现
 * ======================================================================== */

JNIEXPORT jobject JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1InternalSign_1ECC
  (JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex, jbyteArray data) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_InternalSign_ECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (data == NULL) {
        throw_sdf_exception(env, 0x0100001D);  /* SDR_INARGERR */
        return NULL;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);  /* SDR_NOBUFFER */
        return NULL;
    }

    (*env)->GetByteArrayRegion(env, data, 0, data_len, (jbyte*)data_buf);

    ECCSignature signature;
    memset(&signature, 0, sizeof(signature));

    LONG ret = g_sdf_functions.SDF_InternalSign_ECC((HANDLE)sessionHandle, keyIndex,
                                                     data_buf, data_len, &signature);

    free(data_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return NULL;
    }

    return native_to_java_ECCSignature(env, &signature);
}

JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1InternalVerify_1ECC
  (JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex, jbyteArray data, jobject signature) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_InternalVerify_ECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    if (data == NULL || signature == NULL) {
        throw_sdf_exception(env, 0x0100001D);  /* SDR_INARGERR */
        return;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);  /* SDR_NOBUFFER */
        return;
    }

    (*env)->GetByteArrayRegion(env, data, 0, data_len, (jbyte*)data_buf);

    ECCSignature native_sig;
    if (!java_to_native_ECCSignature(env, signature, &native_sig)) {
        free(data_buf);
        throw_sdf_exception(env, 0x0100001D);  /* SDR_INARGERR */
        return;
    }

    LONG ret = g_sdf_functions.SDF_InternalVerify_ECC((HANDLE)sessionHandle, keyIndex,
                                                       data_buf, data_len, &native_sig);

    free(data_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ExternalVerify_1ECC
  (JNIEnv *env, jobject obj, jlong sessionHandle, jint algID, jobject publicKey,
   jbyteArray data, jobject signature) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_ExternalVerify_ECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    if (publicKey == NULL || data == NULL || signature == NULL) {
        throw_sdf_exception(env, 0x0100001D);  /* SDR_INARGERR */
        return;
    }

    ECCrefPublicKey native_key;
    if (!java_to_native_ECCPublicKey(env, publicKey, &native_key)) {
        throw_sdf_exception(env, 0x0100001D);
        return;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return;
    }

    (*env)->GetByteArrayRegion(env, data, 0, data_len, (jbyte*)data_buf);

    ECCSignature native_sig;
    if (!java_to_native_ECCSignature(env, signature, &native_sig)) {
        free(data_buf);
        throw_sdf_exception(env, 0x0100001D);
        return;
    }

    LONG ret = g_sdf_functions.SDF_ExternalVerify_ECC((HANDLE)sessionHandle, algID,
                                                       &native_key, data_buf, data_len,
                                                       &native_sig);

    free(data_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

JNIEXPORT jobject JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ExternalEncrypt_1ECC
  (JNIEnv *env, jobject obj, jlong sessionHandle, jint algID, jobject publicKey, jbyteArray data) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_ExternalEncrypt_ECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (publicKey == NULL || data == NULL) {
        throw_sdf_exception(env, 0x0100001D);
        return NULL;
    }

    ECCrefPublicKey native_key;
    if (!java_to_native_ECCPublicKey(env, publicKey, &native_key)) {
        throw_sdf_exception(env, 0x0100001D);
        return NULL;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    (*env)->GetByteArrayRegion(env, data, 0, data_len, (jbyte*)data_buf);

    /* 分配ECCCipher结构 + 密文空间 */
    ECCCipher *cipher = (ECCCipher*)malloc(sizeof(ECCCipher) + data_len);
    if (cipher == NULL) {
        free(data_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    memset(cipher, 0, sizeof(ECCCipher) + data_len);

    LONG ret = g_sdf_functions.SDF_ExternalEncrypt_ECC((HANDLE)sessionHandle, algID,
                                                        &native_key, data_buf, data_len,
                                                        cipher);

    free(data_buf);

    if (ret != SDR_OK) {
        free(cipher);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jobject result = native_to_java_ECCCipher(env, cipher, cipher->L);
    free(cipher);
    return result;
}

// ========================================================================
// 6.5 对称算法运算类函数 (Symmetric Algorithm Functions)
// ========================================================================

JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1Encrypt
  (JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle, jint algID, jbyteArray iv, jbyteArray data) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_Encrypt == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (data == NULL) {
        throw_sdf_exception(env, 0x0100001D);
        return NULL;
    }

    /* 获取输入数据 */
    jsize data_len = (*env)->GetArrayLength(env, data);
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, data, 0, data_len, (jbyte*)data_buf);

    /* 获取IV（可选）*/
    BYTE *iv_buf = NULL;
    if (iv != NULL) {
        jsize iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (BYTE*)malloc(iv_len);
        if (iv_buf == NULL) {
            free(data_buf);
            throw_sdf_exception(env, 0x0100001C);
            return NULL;
        }
        (*env)->GetByteArrayRegion(env, iv, 0, iv_len, (jbyte*)iv_buf);
    }

    /* 分配输出缓冲区（预留足够空间用于填充）*/
    ULONG enc_data_len = data_len + 16;  /* 预留填充空间 */
    BYTE *enc_data_buf = (BYTE*)malloc(enc_data_len);
    if (enc_data_buf == NULL) {
        free(data_buf);
        if (iv_buf) free(iv_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_Encrypt((HANDLE)sessionHandle, (HANDLE)keyHandle,
                                            algID, iv_buf, data_buf, data_len,
                                            enc_data_buf, &enc_data_len);

    free(data_buf);
    if (iv_buf) free(iv_buf);

    if (ret != SDR_OK) {
        free(enc_data_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, enc_data_buf, enc_data_len);
    free(enc_data_buf);
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1Decrypt
  (JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle, jint algID, jbyteArray iv, jbyteArray encData) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_Decrypt == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (encData == NULL) {
        throw_sdf_exception(env, 0x0100001D);
        return NULL;
    }

    /* 获取加密数据 */
    jsize enc_data_len = (*env)->GetArrayLength(env, encData);
    BYTE *enc_data_buf = (BYTE*)malloc(enc_data_len);
    if (enc_data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, encData, 0, enc_data_len, (jbyte*)enc_data_buf);

    /* 获取IV（可选）*/
    BYTE *iv_buf = NULL;
    if (iv != NULL) {
        jsize iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (BYTE*)malloc(iv_len);
        if (iv_buf == NULL) {
            free(enc_data_buf);
            throw_sdf_exception(env, 0x0100001C);
            return NULL;
        }
        (*env)->GetByteArrayRegion(env, iv, 0, iv_len, (jbyte*)iv_buf);
    }

    /* 分配输出缓冲区 */
    ULONG data_len = enc_data_len;
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        free(enc_data_buf);
        if (iv_buf) free(iv_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_Decrypt((HANDLE)sessionHandle, (HANDLE)keyHandle,
                                            algID, iv_buf, enc_data_buf, enc_data_len,
                                            data_buf, &data_len);

    free(enc_data_buf);
    if (iv_buf) free(iv_buf);

    if (ret != SDR_OK) {
        free(data_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, data_buf, data_len);
    free(data_buf);
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1CalculateMAC
  (JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle, jint algID, jbyteArray iv, jbyteArray data) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_CalculateMAC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (data == NULL) {
        throw_sdf_exception(env, 0x0100001D);
        return NULL;
    }

    /* 获取输入数据 */
    jsize data_len = (*env)->GetArrayLength(env, data);
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, data, 0, data_len, (jbyte*)data_buf);

    /* 获取IV（可选）*/
    BYTE *iv_buf = NULL;
    if (iv != NULL) {
        jsize iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (BYTE*)malloc(iv_len);
        if (iv_buf == NULL) {
            free(data_buf);
            throw_sdf_exception(env, 0x0100001C);
            return NULL;
        }
        (*env)->GetByteArrayRegion(env, iv, 0, iv_len, (jbyte*)iv_buf);
    }

    /* 分配MAC缓冲区 */
    ULONG mac_len = 16;  /* SM4-CBC-MAC 通常为16字节 */
    BYTE *mac_buf = (BYTE*)malloc(mac_len);
    if (mac_buf == NULL) {
        free(data_buf);
        if (iv_buf) free(iv_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_CalculateMAC((HANDLE)sessionHandle, (HANDLE)keyHandle,
                                                 algID, iv_buf, data_buf, data_len,
                                                 mac_buf, &mac_len);

    free(data_buf);
    if (iv_buf) free(iv_buf);

    if (ret != SDR_OK) {
        free(mac_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, mac_buf, mac_len);
    free(mac_buf);
    return result;
}

/**
 * 6.5.5 单包可鉴别加密
 * SDF_AuthEnc
 * Returns byte[][] containing [encrypted data, auth tag]
 */
JNIEXPORT jobjectArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1AuthEnc
(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle, jint algID,
 jbyteArray iv, jbyteArray aad, jbyteArray data) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_AuthEnc == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (data == NULL) {
        throw_sdf_exception_with_message(env, 0x01000006, "Data is null");
        return NULL;
    }

    /* Convert IV */
    BYTE *iv_buf = NULL;
    jsize iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (BYTE*)malloc(iv_len);
        if (iv_buf == NULL) {
            throw_sdf_exception(env, 0x0100001C);
            return NULL;
        }
        (*env)->GetByteArrayRegion(env, iv, 0, iv_len, (jbyte*)iv_buf);
    }

    /* Convert AAD */
    BYTE *aad_buf = NULL;
    jsize aad_len = 0;
    if (aad != NULL) {
        aad_len = (*env)->GetArrayLength(env, aad);
        aad_buf = (BYTE*)malloc(aad_len);
        if (aad_buf == NULL) {
            if (iv_buf != NULL) free(iv_buf);
            throw_sdf_exception(env, 0x0100001C);
            return NULL;
        }
        (*env)->GetByteArrayRegion(env, aad, 0, aad_len, (jbyte*)aad_buf);
    }

    /* Convert data */
    jsize data_len = (*env)->GetArrayLength(env, data);
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        if (iv_buf != NULL) free(iv_buf);
        if (aad_buf != NULL) free(aad_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, data, 0, data_len, (jbyte*)data_buf);

    /* Allocate output buffers */
    ULONG enc_len = data_len + 32;  /* Data + possible padding */
    BYTE *enc_buf = (BYTE*)malloc(enc_len);
    if (enc_buf == NULL) {
        if (iv_buf != NULL) free(iv_buf);
        if (aad_buf != NULL) free(aad_buf);
        free(data_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    ULONG tag_len = 32;  /* Max tag size */
    BYTE *tag_buf = (BYTE*)malloc(tag_len);
    if (tag_buf == NULL) {
        if (iv_buf != NULL) free(iv_buf);
        if (aad_buf != NULL) free(aad_buf);
        free(data_buf);
        free(enc_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_AuthEnc(
        (HANDLE)sessionHandle,
        (HANDLE)keyHandle,
        (ULONG)algID,
        iv_buf,
        (ULONG)iv_len,
        aad_buf,
        (ULONG)aad_len,
        data_buf,
        (ULONG)data_len,
        enc_buf,
        &enc_len,
        tag_buf,
        &tag_len
    );

    if (iv_buf != NULL) free(iv_buf);
    if (aad_buf != NULL) free(aad_buf);
    free(data_buf);

    if (ret != SDR_OK) {
        free(enc_buf);
        free(tag_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    /* Create 2D array to return [encrypted data, auth tag] */
    jclass byteArrayClass = (*env)->FindClass(env, "[B");
    if (byteArrayClass == NULL) {
        free(enc_buf);
        free(tag_buf);
        return NULL;
    }

    jobjectArray result = (*env)->NewObjectArray(env, 2, byteArrayClass, NULL);
    if (result == NULL) {
        free(enc_buf);
        free(tag_buf);
        return NULL;
    }

    /* Set [0] = encrypted data */
    jbyteArray encData = native_to_java_byte_array(env, enc_buf, enc_len);
    if (encData != NULL) {
        (*env)->SetObjectArrayElement(env, result, 0, encData);
    }

    /* Set [1] = auth tag */
    jbyteArray authTag = native_to_java_byte_array(env, tag_buf, tag_len);
    if (authTag != NULL) {
        (*env)->SetObjectArrayElement(env, result, 1, authTag);
    }

    free(enc_buf);
    free(tag_buf);

    return result;
}

/**
 * 6.5.6 单包可鉴别解密
 * SDF_AuthDec
 * Returns decrypted plaintext data
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1AuthDec
(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle, jint algID,
 jbyteArray iv, jbyteArray aad, jbyteArray authTag, jbyteArray encData) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_AuthDec == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (encData == NULL || authTag == NULL) {
        throw_sdf_exception_with_message(env, 0x01000006, "Encrypted data or auth tag is null");
        return NULL;
    }

    /* Convert IV */
    BYTE *iv_buf = NULL;
    jsize iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (BYTE*)malloc(iv_len);
        if (iv_buf == NULL) {
            throw_sdf_exception(env, 0x0100001C);
            return NULL;
        }
        (*env)->GetByteArrayRegion(env, iv, 0, iv_len, (jbyte*)iv_buf);
    }

    /* Convert AAD */
    BYTE *aad_buf = NULL;
    jsize aad_len = 0;
    if (aad != NULL) {
        aad_len = (*env)->GetArrayLength(env, aad);
        aad_buf = (BYTE*)malloc(aad_len);
        if (aad_buf == NULL) {
            if (iv_buf != NULL) free(iv_buf);
            throw_sdf_exception(env, 0x0100001C);
            return NULL;
        }
        (*env)->GetByteArrayRegion(env, aad, 0, aad_len, (jbyte*)aad_buf);
    }

    /* Convert auth tag */
    jsize tag_len = (*env)->GetArrayLength(env, authTag);
    BYTE *tag_buf = (BYTE*)malloc(tag_len);
    if (tag_buf == NULL) {
        if (iv_buf != NULL) free(iv_buf);
        if (aad_buf != NULL) free(aad_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, authTag, 0, tag_len, (jbyte*)tag_buf);

    /* Convert encrypted data */
    jsize enc_len = (*env)->GetArrayLength(env, encData);
    BYTE *enc_buf = (BYTE*)malloc(enc_len);
    if (enc_buf == NULL) {
        if (iv_buf != NULL) free(iv_buf);
        if (aad_buf != NULL) free(aad_buf);
        free(tag_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, encData, 0, enc_len, (jbyte*)enc_buf);

    /* Allocate output buffer for plaintext */
    ULONG plaintext_len = enc_len;
    BYTE *plaintext_buf = (BYTE*)malloc(plaintext_len);
    if (plaintext_buf == NULL) {
        if (iv_buf != NULL) free(iv_buf);
        if (aad_buf != NULL) free(aad_buf);
        free(tag_buf);
        free(enc_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_AuthDec(
        (HANDLE)sessionHandle,
        (HANDLE)keyHandle,
        (ULONG)algID,
        iv_buf,
        (ULONG)iv_len,
        aad_buf,
        (ULONG)aad_len,
        tag_buf,
        (ULONG)tag_len,
        enc_buf,
        (ULONG)enc_len,
        plaintext_buf,
        &plaintext_len
    );

    if (iv_buf != NULL) free(iv_buf);
    if (aad_buf != NULL) free(aad_buf);
    free(tag_buf);
    free(enc_buf);

    if (ret != SDR_OK) {
        free(plaintext_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, plaintext_buf, plaintext_len);
    free(plaintext_buf);

    return result;
}

// ========================================================================
// 6.6 杂凑运算类函数 (Hash Operation Functions)
// ========================================================================

JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1HashInit
  (JNIEnv *env, jobject obj, jlong sessionHandle, jint algID, jobject publicKey, jbyteArray id) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_HashInit == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    /* 转换ECC公钥（可选，用于SM3 Z值计算）*/
    ECCrefPublicKey *native_key_ptr = NULL;
    ECCrefPublicKey native_key;
    if (publicKey != NULL) {
        if (!java_to_native_ECCPublicKey(env, publicKey, &native_key)) {
            throw_sdf_exception(env, 0x0100001D);
            return;
        }
        native_key_ptr = &native_key;
    }

    /* 获取用户ID（可选，用于SM3）*/
    BYTE *id_buf = NULL;
    ULONG id_len = 0;
    if (id != NULL) {
        id_len = (*env)->GetArrayLength(env, id);
        id_buf = (BYTE*)malloc(id_len);
        if (id_buf == NULL) {
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
        (*env)->GetByteArrayRegion(env, id, 0, id_len, (jbyte*)id_buf);
    }

    LONG ret = g_sdf_functions.SDF_HashInit((HANDLE)sessionHandle, algID,
                                             native_key_ptr, id_buf, id_len);

    if (id_buf) free(id_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1HashUpdate
  (JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray data) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_HashUpdate == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    if (data == NULL) {
        throw_sdf_exception(env, 0x0100001D);
        return;
    }

    /* 获取输入数据 */
    jsize data_len = (*env)->GetArrayLength(env, data);
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return;
    }
    (*env)->GetByteArrayRegion(env, data, 0, data_len, (jbyte*)data_buf);

    LONG ret = g_sdf_functions.SDF_HashUpdate((HANDLE)sessionHandle, data_buf, data_len);

    free(data_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1HashFinal
  (JNIEnv *env, jobject obj, jlong sessionHandle) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_HashFinal == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* 分配哈希值缓冲区（SM3为32字节，SHA256也是32字节）*/
    ULONG hash_len = 64;  /* 预留足够空间 */
    BYTE *hash_buf = (BYTE*)malloc(hash_len);
    if (hash_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_HashFinal((HANDLE)sessionHandle, hash_buf, &hash_len);

    if (ret != SDR_OK) {
        free(hash_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, hash_buf, hash_len);
    free(hash_buf);
    return result;
}

/* ========================================================================
 * 新增接口实现 - Pattern 1: KeyEncryptionResult 返回
 * ======================================================================== */

/**
 * 6.3.5 使用内部RSA加密公钥生成会话密钥
 * Pattern: KeyEncryptionResult return (encrypted key + handle)
 */
JNIEXPORT jobject JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1GenerateKeyWithIPK_1RSA
(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex, jint keyBits) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_GenerateKeyWithIPK_RSA == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* 分配密钥缓冲区 */
    ULONG key_len = (keyBits + 7) / 8;  /* RSA密钥长度，按位转字节 */
    BYTE *key_buf = (BYTE*)malloc(key_len);
    if (key_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    HANDLE key_handle = 0;

    LONG ret = g_sdf_functions.SDF_GenerateKeyWithIPK_RSA(
        (HANDLE)sessionHandle,
        (ULONG)keyIndex,
        (ULONG)keyBits,
        key_buf,
        &key_len,
        &key_handle
    );

    if (ret != SDR_OK) {
        free(key_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    /* 创建 KeyEncryptionResult 对象 */
    jobject result = create_key_encryption_result(env, key_buf, key_len, key_handle);
    free(key_buf);

    return result;
}

/**
 * 6.3.6 使用外部RSA公钥生成会话密钥
 * Pattern: KeyEncryptionResult return (encrypted key + handle)
 */
JNIEXPORT jobject JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1GenerateKeyWithEPK_1RSA
(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyBits, jobject publicKey) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_GenerateKeyWithEPK_RSA == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* 转换Java RSAPublicKey到C结构 */
    RSArefPublicKey rsa_pub_key;
    if (!java_to_native_RSAPublicKey(env, publicKey, &rsa_pub_key)) {
        return NULL;  /* Exception already thrown */
    }

    /* 分配密钥缓冲区 */
    ULONG key_len = (keyBits + 7) / 8;
    BYTE *key_buf = (BYTE*)malloc(key_len);
    if (key_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    HANDLE key_handle = 0;

    LONG ret = g_sdf_functions.SDF_GenerateKeyWithEPK_RSA(
        (HANDLE)sessionHandle,
        (ULONG)keyBits,
        &rsa_pub_key,
        key_buf,
        &key_len,
        &key_handle
    );

    if (ret != SDR_OK) {
        free(key_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    /* 创建 KeyEncryptionResult 对象 */
    jobject result = create_key_encryption_result(env, key_buf, key_len, key_handle);
    free(key_buf);

    return result;
}

/**
 * 6.3.7 导入会话密钥并用内部RSA私钥解密
 * Pattern: Returns key handle (long)
 */
JNIEXPORT jlong JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ImportKeyWithISK_1RSA
(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex, jbyteArray encryptedKey) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return 0;
    }

    if (g_sdf_functions.SDF_ImportKeyWithISK_RSA == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return 0;
    }

    /* 转换加密密钥数据 */
    jsize key_len = (*env)->GetArrayLength(env, encryptedKey);
    BYTE *key_buf = (BYTE*)malloc(key_len);
    if (key_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return 0;
    }

    (*env)->GetByteArrayRegion(env, encryptedKey, 0, key_len, (jbyte*)key_buf);

    HANDLE key_handle = 0;

    LONG ret = g_sdf_functions.SDF_ImportKeyWithISK_RSA(
        (HANDLE)sessionHandle,
        (ULONG)keyIndex,
        key_buf,
        (ULONG)key_len,
        &key_handle
    );

    free(key_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return 0;
    }

    return (jlong)key_handle;
}

/**
 * 6.3.9 使用内部ECC公钥生成会话密钥
 * Pattern: KeyEncryptionResult return (ECCCipher + handle)
 */
JNIEXPORT jobject JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1GenerateKeyWithIPK_1ECC
(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex, jint keyBits) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_GenerateKeyWithIPK_ECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* 分配ECCCipher结构 */
    ECCCipher ecc_cipher;
    memset(&ecc_cipher, 0, sizeof(ECCCipher));

    HANDLE key_handle = 0;

    LONG ret = g_sdf_functions.SDF_GenerateKeyWithIPK_ECC(
        (HANDLE)sessionHandle,
        (ULONG)keyIndex,
        (ULONG)keyBits,
        &ecc_cipher,
        &key_handle
    );

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return NULL;
    }


    /* 创建KeyEncryptionResult，其中encryptedKey是ECCCipher的序列化 */
    /* 序列化ECCCipher: x(32) + y(32) + M(32) + C(cipher_len) */
    ULONG cipher_data_len = 32 + 32 + 32 + ecc_cipher.L;
    BYTE *cipher_data = (BYTE*)malloc(cipher_data_len);
    if (cipher_data == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    memcpy(cipher_data, ecc_cipher.x, 32);
    memcpy(cipher_data + 32, ecc_cipher.y, 32);
    memcpy(cipher_data + 64, ecc_cipher.M, 32);
    memcpy(cipher_data + 96, &ecc_cipher.C, ecc_cipher.L);

    jobject result = create_key_encryption_result(env, cipher_data, cipher_data_len, key_handle);
    free(cipher_data);

    return result;
}

/**
 * 6.3.10 使用外部ECC公钥生成会话密钥
 * Pattern: KeyEncryptionResult return (ECCCipher + handle)
 */
JNIEXPORT jobject JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1GenerateKeyWithEPK_1ECC
(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyBits, jint algID, jobject publicKey) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_GenerateKeyWithEPK_ECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* 转换Java ECCPublicKey到C结构 */
    ECCrefPublicKey ecc_pub_key;
    if (!java_to_native_ECCPublicKey(env, publicKey, &ecc_pub_key)) {
        return NULL;  /* Exception already thrown */
    }

    /* 分配ECCCipher结构 */
    ECCCipher ecc_cipher;
    memset(&ecc_cipher, 0, sizeof(ECCCipher));

    HANDLE key_handle = 0;

    LONG ret = g_sdf_functions.SDF_GenerateKeyWithEPK_ECC(
        (HANDLE)sessionHandle,
        (ULONG)keyBits,
        (ULONG)algID,
        &ecc_pub_key,
        &ecc_cipher,
        &key_handle
    );

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return NULL;
    }

    /* 序列化ECCCipher */
    ULONG cipher_data_len = 32 + 32 + 32 + ecc_cipher.L;
    BYTE *cipher_data = (BYTE*)malloc(cipher_data_len);
    if (cipher_data == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    memcpy(cipher_data, ecc_cipher.x, 32);
    memcpy(cipher_data + 32, ecc_cipher.y, 32);
    memcpy(cipher_data + 64, ecc_cipher.M, 32);
    memcpy(cipher_data + 96, &ecc_cipher.C, ecc_cipher.L);

    jobject result = create_key_encryption_result(env, cipher_data, cipher_data_len, key_handle);
    free(cipher_data);

    return result;
}

/**
 * 6.3.11 导入会话密钥并用内部ECC私钥解密
 * Pattern: Returns key handle (long)
 */
JNIEXPORT jlong JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ImportKeyWithISK_1ECC
(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex, jobject cipher) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return 0;
    }

    if (g_sdf_functions.SDF_ImportKeyWithISK_ECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return 0;
    }

    /* 转换Java ECCCipher到C结构 */
    ECCCipher ecc_cipher;
    if (!java_to_native_ECCCipher(env, cipher, &ecc_cipher)) {
        return 0;  /* Exception already thrown */
    }

    HANDLE key_handle = 0;

    LONG ret = g_sdf_functions.SDF_ImportKeyWithISK_ECC(
        (HANDLE)sessionHandle,
        (ULONG)keyIndex,
        &ecc_cipher,
        &key_handle
    );

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return 0;
    }

    return (jlong)key_handle;
}

/**
 * 6.3.12 生成密钥协商参数并输出
 * Pattern: Returns agreement handle (long)
 * Note: Java API signature differs from C - sponsorTmpPublicKey is output parameter in C, input in Java
 */
JNIEXPORT jlong JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1GenerateAgreementDataWithECC
(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex, jint keyBits,
 jbyteArray sponsorID, jobject sponsorPublicKey, jobject sponsorTmpPublicKey) {
    UNUSED(obj);
    UNUSED(sponsorTmpPublicKey);  /* Output parameter, handled by device */

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return 0;
    }

    if (g_sdf_functions.SDF_GenerateAgreementDataWithECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return 0;
    }

    /* 转换sponsorID */
    jsize sponsor_id_len = (*env)->GetArrayLength(env, sponsorID);
    BYTE *sponsor_id_buf = (BYTE*)malloc(sponsor_id_len);
    if (sponsor_id_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return 0;
    }
    (*env)->GetByteArrayRegion(env, sponsorID, 0, sponsor_id_len, (jbyte*)sponsor_id_buf);

    /* 转换sponsorPublicKey */
    ECCrefPublicKey sponsor_pub_key;
    if (!java_to_native_ECCPublicKey(env, sponsorPublicKey, &sponsor_pub_key)) {
        free(sponsor_id_buf);
        return 0;
    }

    /* 临时公钥由设备生成 */
    ECCrefPublicKey sponsor_tmp_pub_key;
    memset(&sponsor_tmp_pub_key, 0, sizeof(ECCrefPublicKey));

    HANDLE agreement_handle = 0;

    LONG ret = g_sdf_functions.SDF_GenerateAgreementDataWithECC(
        (HANDLE)sessionHandle,
        (ULONG)keyIndex,
        (ULONG)keyBits,
        sponsor_id_buf,
        (ULONG)sponsor_id_len,
        &sponsor_pub_key,
        &sponsor_tmp_pub_key,
        &agreement_handle
    );

    free(sponsor_id_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return 0;
    }

    return (jlong)agreement_handle;
}

/**
 * 6.3.13 计算会话密钥
 * Pattern: Returns key handle (long)
 */
JNIEXPORT jlong JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1GenerateKeyWithECC
(JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray responseID,
 jobject responsePublicKey, jobject responseTmpPublicKey, jlong agreementHandle) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return 0;
    }

    if (g_sdf_functions.SDF_GenerateKeyWithECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return 0;
    }

    /* 转换responseID */
    jsize response_id_len = (*env)->GetArrayLength(env, responseID);
    BYTE *response_id_buf = (BYTE*)malloc(response_id_len);
    if (response_id_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return 0;
    }
    (*env)->GetByteArrayRegion(env, responseID, 0, response_id_len, (jbyte*)response_id_buf);

    /* 转换responsePublicKey */
    ECCrefPublicKey response_pub_key;
    if (!java_to_native_ECCPublicKey(env, responsePublicKey, &response_pub_key)) {
        free(response_id_buf);
        return 0;
    }

    /* 转换responseTmpPublicKey */
    ECCrefPublicKey response_tmp_pub_key;
    if (!java_to_native_ECCPublicKey(env, responseTmpPublicKey, &response_tmp_pub_key)) {
        free(response_id_buf);
        return 0;
    }

    HANDLE key_handle = 0;

    LONG ret = g_sdf_functions.SDF_GenerateKeyWithECC(
        (HANDLE)sessionHandle,
        response_id_buf,
        (ULONG)response_id_len,
        &response_pub_key,
        &response_tmp_pub_key,
        (HANDLE)agreementHandle,
        &key_handle
    );

    free(response_id_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return 0;
    }

    return (jlong)key_handle;
}

/**
 * 6.3.14 产生协商数据并计算会话密钥
 * Pattern: Returns key handle (long)
 */
JNIEXPORT jlong JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1GenerateAgreementDataAndKeyWithECC
(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex, jint keyBits,
 jbyteArray responseID, jbyteArray sponsorID,
 jobject sponsorPublicKey, jobject sponsorTmpPublicKey,
 jobject responsePublicKey, jobject responseTmpPublicKey) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return 0;
    }

    if (g_sdf_functions.SDF_GenerateAgreementDataAndKeyWithECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return 0;
    }

    /* 转换responseID */
    jsize response_id_len = (*env)->GetArrayLength(env, responseID);
    BYTE *response_id_buf = (BYTE*)malloc(response_id_len);
    if (response_id_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return 0;
    }
    (*env)->GetByteArrayRegion(env, responseID, 0, response_id_len, (jbyte*)response_id_buf);

    /* 转换sponsorID */
    jsize sponsor_id_len = (*env)->GetArrayLength(env, sponsorID);
    BYTE *sponsor_id_buf = (BYTE*)malloc(sponsor_id_len);
    if (sponsor_id_buf == NULL) {
        free(response_id_buf);
        throw_sdf_exception(env, 0x0100001C);
        return 0;
    }
    (*env)->GetByteArrayRegion(env, sponsorID, 0, sponsor_id_len, (jbyte*)sponsor_id_buf);

    /* 转换所有ECC公钥 */
    ECCrefPublicKey sponsor_pub_key, sponsor_tmp_pub_key, response_pub_key, response_tmp_pub_key;

    if (!java_to_native_ECCPublicKey(env, sponsorPublicKey, &sponsor_pub_key)) {
        free(response_id_buf);
        free(sponsor_id_buf);
        return 0;
    }
    if (!java_to_native_ECCPublicKey(env, sponsorTmpPublicKey, &sponsor_tmp_pub_key)) {
        free(response_id_buf);
        free(sponsor_id_buf);
        return 0;
    }
    if (!java_to_native_ECCPublicKey(env, responsePublicKey, &response_pub_key)) {
        free(response_id_buf);
        free(sponsor_id_buf);
        return 0;
    }
    if (!java_to_native_ECCPublicKey(env, responseTmpPublicKey, &response_tmp_pub_key)) {
        free(response_id_buf);
        free(sponsor_id_buf);
        return 0;
    }

    HANDLE key_handle = 0;

    LONG ret = g_sdf_functions.SDF_GenerateAgreementDataAndKeyWithECC(
        (HANDLE)sessionHandle,
        (ULONG)keyIndex,
        (ULONG)keyBits,
        response_id_buf,
        (ULONG)response_id_len,
        sponsor_id_buf,
        (ULONG)sponsor_id_len,
        &sponsor_pub_key,
        &sponsor_tmp_pub_key,
        &response_pub_key,
        &response_tmp_pub_key,
        &key_handle
    );

    free(response_id_buf);
    free(sponsor_id_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return 0;
    }

    return (jlong)key_handle;
}

/**
 * 6.3.15 生成会话密钥并用密钥加密密钥加密输出
 * Pattern: KeyEncryptionResult return (encrypted key + handle)
 */
JNIEXPORT jobject JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1GenerateKeyWithKEK
(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyBits, jint algID, jint kekIndex) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_GenerateKeyWithKEK == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* 分配密钥缓冲区 */
    ULONG key_len = (keyBits + 7) / 8;
    /* KEK加密可能需要padding，分配更大空间 */
    ULONG buffer_size = key_len + 16;
    BYTE *key_buf = (BYTE*)malloc(buffer_size);
    if (key_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    key_len = buffer_size;  /* 设置为缓冲区大小 */
    HANDLE key_handle = 0;

    LONG ret = g_sdf_functions.SDF_GenerateKeyWithKEK(
        (HANDLE)sessionHandle,
        (ULONG)keyBits,
        (ULONG)algID,
        (ULONG)kekIndex,
        key_buf,
        &key_len,
        &key_handle
    );

    if (ret != SDR_OK) {
        free(key_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    /* 创建 KeyEncryptionResult 对象 */
    jobject result = create_key_encryption_result(env, key_buf, key_len, key_handle);
    free(key_buf);

    return result;
}

/**
 * 6.3.16 导入会话密钥并用密钥加密密钥解密
 * Pattern: Returns key handle (long)
 */
JNIEXPORT jlong JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ImportKeyWithKEK
(JNIEnv *env, jobject obj, jlong sessionHandle, jint algID, jint kekIndex, jbyteArray encryptedKey) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return 0;
    }

    if (g_sdf_functions.SDF_ImportKeyWithKEK == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return 0;
    }

    /* 转换加密密钥数据 */
    jsize key_len = (*env)->GetArrayLength(env, encryptedKey);
    BYTE *key_buf = (BYTE*)malloc(key_len);
    if (key_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return 0;
    }

    (*env)->GetByteArrayRegion(env, encryptedKey, 0, key_len, (jbyte*)key_buf);

    HANDLE key_handle = 0;

    LONG ret = g_sdf_functions.SDF_ImportKeyWithKEK(
        (HANDLE)sessionHandle,
        (ULONG)algID,
        (ULONG)kekIndex,
        key_buf,
        (ULONG)key_len,
        &key_handle
    );

    free(key_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return 0;
    }

    return (jlong)key_handle;
}

/* ========================================================================
 * 新增接口实现 - Pattern 2: Init/Update/Final 序列
 * ======================================================================== */

/**
 * 6.5.7 多包对称加密初始化
 * Pattern: Void function with IV parameter (可选)
 */
JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1EncryptInit
(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle, jint algID, jbyteArray iv) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_EncryptInit == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    /* 转换IV参数（可能为NULL，ECB模式不需要IV）*/
    BYTE *iv_buf = NULL;
    jsize iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (BYTE*)malloc(iv_len);
        if (iv_buf == NULL) {
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
        (*env)->GetByteArrayRegion(env, iv, 0, iv_len, (jbyte*)iv_buf);
    }

    LONG ret = g_sdf_functions.SDF_EncryptInit(
        (HANDLE)sessionHandle,
        (HANDLE)keyHandle,
        (ULONG)algID,
        iv_buf,
        (ULONG)iv_len
    );

    if (iv_buf != NULL) {
        free(iv_buf);
    }

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/**
 * 6.5.8 多包对称加密更新
 * Pattern: Byte array I/O with dynamic output length
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1EncryptUpdate
(JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray data) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_EncryptUpdate == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (data == NULL) {
        throw_sdf_exception_with_message(env, 0x01000001, "Data is null");
        return NULL;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, data, 0, data_len, (jbyte*)data_buf);

    /* 密文长度可能大于明文（填充），分配足够空间 */
    ULONG enc_len = data_len + 32;  /* 预留填充空间 */
    BYTE *enc_buf = (BYTE*)malloc(enc_len);
    if (enc_buf == NULL) {
        free(data_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_EncryptUpdate(
        (HANDLE)sessionHandle,
        data_buf,
        (ULONG)data_len,
        enc_buf,
        &enc_len
    );

    free(data_buf);

    if (ret != SDR_OK) {
        free(enc_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, enc_buf, enc_len);
    free(enc_buf);

    return result;
}

/**
 * 6.5.9 多包对称加密结束
 * Pattern: Final function with output buffer
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1EncryptFinal
(JNIEnv *env, jobject obj, jlong sessionHandle) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_EncryptFinal == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* 分配最终块缓冲区（最多一个块大小 + 填充）*/
    ULONG enc_len = 64;  /* 预留足够空间 */
    BYTE *enc_buf = (BYTE*)malloc(enc_len);
    if (enc_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_EncryptFinal(
        (HANDLE)sessionHandle,
        enc_buf,
        &enc_len
    );

    if (ret != SDR_OK) {
        free(enc_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, enc_buf, enc_len);
    free(enc_buf);

    return result;
}

/* ========================================================================
 * 新增接口实现 - Pattern 3: Void函数（简单初始化）
 * ======================================================================== */

/**
 * 6.6.5 HMAC初始化
 * Pattern: Simple void function
 */
JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1HMACInit
(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle, jint algID) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_HMACInit == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    LONG ret = g_sdf_functions.SDF_HMACInit(
        (HANDLE)sessionHandle,
        (HANDLE)keyHandle,
        (ULONG)algID
    );

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/* ========================================================================
 * 新增接口实现 - Pattern 4: 字节数组返回
 * ======================================================================== */

/**
 * 6.4.5 外部RSA公钥运算
 * Pattern: Byte array return with RSA key input
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ExternalPublicKeyOperation_1RSA
(JNIEnv *env, jobject obj, jlong sessionHandle, jobject publicKey, jbyteArray dataInput) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_ExternalPublicKeyOperation_RSA == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (publicKey == NULL || dataInput == NULL) {
        throw_sdf_exception_with_message(env, 0x01000001, "Public key or data is null");
        return NULL;
    }

    /* 转换公钥 */
    RSArefPublicKey native_key;
    memset(&native_key, 0, sizeof(RSArefPublicKey));

    jclass key_class = (*env)->GetObjectClass(env, publicKey);
    
    /* 获取bits字段 */
    jfieldID bits_fid = (*env)->GetFieldID(env, key_class, "bits", "I");
    if (bits_fid == NULL) {
        throw_sdf_exception_with_message(env, 0x01000001, "Cannot get bits field");
        return NULL;
    }
    native_key.bits = (*env)->GetIntField(env, publicKey, bits_fid);

    /* 获取m字段 */
    jfieldID m_fid = (*env)->GetFieldID(env, key_class, "m", "[B");
    if (m_fid != NULL) {
        jbyteArray m_array = (jbyteArray)(*env)->GetObjectField(env, publicKey, m_fid);
        if (m_array != NULL) {
            jsize m_len = (*env)->GetArrayLength(env, m_array);
            if (m_len > RSAref_MAX_LEN) m_len = RSAref_MAX_LEN;
            (*env)->GetByteArrayRegion(env, m_array, 0, m_len, (jbyte*)native_key.m);
        }
    }

    /* 获取e字段 */
    jfieldID e_fid = (*env)->GetFieldID(env, key_class, "e", "[B");
    if (e_fid != NULL) {
        jbyteArray e_array = (jbyteArray)(*env)->GetObjectField(env, publicKey, e_fid);
        if (e_array != NULL) {
            jsize e_len = (*env)->GetArrayLength(env, e_array);
            if (e_len > RSAref_MAX_LEN) e_len = RSAref_MAX_LEN;
            (*env)->GetByteArrayRegion(env, e_array, 0, e_len, (jbyte*)native_key.e);
        }
    }

    /* 转换输入数据 */
    jsize input_len = (*env)->GetArrayLength(env, dataInput);
    BYTE *input_buf = (BYTE*)malloc(input_len);
    if (input_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, dataInput, 0, input_len, (jbyte*)input_buf);

    /* 分配输出缓冲区（RSA输出长度等于模长）*/
    ULONG output_len = (native_key.bits + 7) / 8;
    BYTE *output_buf = (BYTE*)malloc(output_len);
    if (output_buf == NULL) {
        free(input_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_ExternalPublicKeyOperation_RSA(
        (HANDLE)sessionHandle,
        &native_key,
        input_buf,
        (ULONG)input_len,
        output_buf,
        &output_len
    );

    free(input_buf);

    if (ret != SDR_OK) {
        free(output_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, output_buf, output_len);
    free(output_buf);

    return result;
}

/**
 * 6.4.3 内部公钥RSA运算
 * SDF_InternalPublicKeyOperation_RSA
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1InternalPublicKeyOperation_1RSA
(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex, jbyteArray dataInput) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_InternalPublicKeyOperation_RSA == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (dataInput == NULL) {
        throw_sdf_exception_with_message(env, 0x01000006, "Data input is null");
        return NULL;
    }

    /* Get input data */
    jsize input_len = (*env)->GetArrayLength(env, dataInput);
    BYTE *input_buf = (BYTE*)malloc(input_len);
    if (input_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, dataInput, 0, input_len, (jbyte*)input_buf);

    /* Allocate output buffer (RSA output is same size as key) */
    ULONG output_len = 512;  /* Max RSA key size in bytes (4096 bits) */
    BYTE *output_buf = (BYTE*)malloc(output_len);
    if (output_buf == NULL) {
        free(input_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_InternalPublicKeyOperation_RSA(
        (HANDLE)sessionHandle,
        (ULONG)keyIndex,
        input_buf,
        (ULONG)input_len,
        output_buf,
        &output_len
    );

    free(input_buf);

    if (ret != SDR_OK) {
        free(output_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, output_buf, output_len);
    free(output_buf);

    return result;
}

/**
 * 6.4.4 内部私钥RSA运算
 * SDF_InternalPrivateKeyOperation_RSA
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1InternalPrivateKeyOperation_1RSA
(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyIndex, jbyteArray dataInput) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_InternalPrivateKeyOperation_RSA == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (dataInput == NULL) {
        throw_sdf_exception_with_message(env, 0x01000006, "Data input is null");
        return NULL;
    }

    /* Get input data */
    jsize input_len = (*env)->GetArrayLength(env, dataInput);
    BYTE *input_buf = (BYTE*)malloc(input_len);
    if (input_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, dataInput, 0, input_len, (jbyte*)input_buf);

    /* Allocate output buffer (RSA output is same size as key) */
    ULONG output_len = 512;  /* Max RSA key size in bytes (4096 bits) */
    BYTE *output_buf = (BYTE*)malloc(output_len);
    if (output_buf == NULL) {
        free(input_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_InternalPrivateKeyOperation_RSA(
        (HANDLE)sessionHandle,
        (ULONG)keyIndex,
        input_buf,
        (ULONG)input_len,
        output_buf,
        &output_len
    );

    free(input_buf);

    if (ret != SDR_OK) {
        free(output_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, output_buf, output_len);
    free(output_buf);

    return result;
}

/* ========================================================================
 * 新增接口实现 - Pattern 5: 文件操作
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

/* ========================================================================
 * Pattern 2 Extension: Decrypt Init/Update/Final 序列
 * ======================================================================== */

/**
 * 6.5.10 多包对称解密初始化
 */
JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1DecryptInit
(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle, jint algID, jbyteArray iv) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_DecryptInit == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    BYTE *iv_buf = NULL;
    jsize iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (BYTE*)malloc(iv_len);
        if (iv_buf == NULL) {
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
        (*env)->GetByteArrayRegion(env, iv, 0, iv_len, (jbyte*)iv_buf);
    }

    LONG ret = g_sdf_functions.SDF_DecryptInit(
        (HANDLE)sessionHandle,
        (HANDLE)keyHandle,
        (ULONG)algID,
        iv_buf,
        (ULONG)iv_len
    );

    if (iv_buf != NULL) {
        free(iv_buf);
    }

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/**
 * 6.5.11 多包对称解密更新
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1DecryptUpdate
(JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray encData) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_DecryptUpdate == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (encData == NULL) {
        throw_sdf_exception_with_message(env, 0x01000001, "Encrypted data is null");
        return NULL;
    }

    jsize enc_len = (*env)->GetArrayLength(env, encData);
    BYTE *enc_buf = (BYTE*)malloc(enc_len);
    if (enc_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, encData, 0, enc_len, (jbyte*)enc_buf);

    ULONG data_len = enc_len + 32;
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        free(enc_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_DecryptUpdate(
        (HANDLE)sessionHandle,
        enc_buf,
        (ULONG)enc_len,
        data_buf,
        &data_len
    );

    free(enc_buf);

    if (ret != SDR_OK) {
        free(data_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, data_buf, data_len);
    free(data_buf);

    return result;
}

/**
 * 6.5.12 多包对称解密结束
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1DecryptFinal
(JNIEnv *env, jobject obj, jlong sessionHandle) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_DecryptFinal == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    ULONG data_len = 64;
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_DecryptFinal(
        (HANDLE)sessionHandle,
        data_buf,
        &data_len
    );

    if (ret != SDR_OK) {
        free(data_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, data_buf, data_len);
    free(data_buf);

    return result;
}

/* ========================================================================
 * Pattern 2 Extension: MAC Init/Update/Final 序列
 * ======================================================================== */

/**
 * 6.5.13 多包MAC计算初始化
 */
JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1CalculateMACInit
(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle, jint algID, jbyteArray iv) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_CalculateMACInit == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    BYTE *iv_buf = NULL;
    jsize iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (BYTE*)malloc(iv_len);
        if (iv_buf == NULL) {
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
        (*env)->GetByteArrayRegion(env, iv, 0, iv_len, (jbyte*)iv_buf);
    }

    LONG ret = g_sdf_functions.SDF_CalculateMACInit(
        (HANDLE)sessionHandle,
        (HANDLE)keyHandle,
        (ULONG)algID,
        iv_buf,
        (ULONG)iv_len
    );

    if (iv_buf != NULL) {
        free(iv_buf);
    }

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/**
 * 6.5.14 多包MAC计算更新
 */
JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1CalculateMACUpdate
(JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray data) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_CalculateMACUpdate == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    if (data == NULL) {
        throw_sdf_exception_with_message(env, 0x01000001, "Data is null");
        return;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return;
    }
    (*env)->GetByteArrayRegion(env, data, 0, data_len, (jbyte*)data_buf);

    LONG ret = g_sdf_functions.SDF_CalculateMACUpdate(
        (HANDLE)sessionHandle,
        data_buf,
        (ULONG)data_len
    );

    free(data_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/**
 * 6.5.15 多包MAC计算结束
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1CalculateMACFinal
(JNIEnv *env, jobject obj, jlong sessionHandle) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_CalculateMACFinal == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    ULONG mac_len = 32;
    BYTE *mac_buf = (BYTE*)malloc(mac_len);
    if (mac_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_CalculateMACFinal(
        (HANDLE)sessionHandle,
        mac_buf,
        &mac_len
    );

    if (ret != SDR_OK) {
        free(mac_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, mac_buf, mac_len);
    free(mac_buf);

    return result;
}

/* ========================================================================
 * Pattern 3 Extension: HMAC Update/Final
 * ======================================================================== */

/**
 * 6.6.6 HMAC更新
 */
JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1HMACUpdate
(JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray data) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_HMACUpdate == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    if (data == NULL) {
        throw_sdf_exception_with_message(env, 0x01000001, "Data is null");
        return;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return;
    }
    (*env)->GetByteArrayRegion(env, data, 0, data_len, (jbyte*)data_buf);

    LONG ret = g_sdf_functions.SDF_HMACUpdate(
        (HANDLE)sessionHandle,
        data_buf,
        (ULONG)data_len
    );

    free(data_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/**
 * 6.6.7 HMAC结束
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1HMACFinal
(JNIEnv *env, jobject obj, jlong sessionHandle) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_HMACFinal == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    ULONG hmac_len = 64;
    BYTE *hmac_buf = (BYTE*)malloc(hmac_len);
    if (hmac_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_HMACFinal(
        (HANDLE)sessionHandle,
        hmac_buf,
        &hmac_len
    );

    if (ret != SDR_OK) {
        free(hmac_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, hmac_buf, hmac_len);
    free(hmac_buf);

    return result;
}

/* ========================================
 * 6.5.5 认证加密 Authenticated Encryption
 * ======================================== */

/**
 * 认证加密初始化
 * SDF_AuthEncInit
 * Java signature: (long sessionHandle, long keyHandle, int algID, byte[] iv, byte[] aad, int dataLength)
 */
JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1AuthEncInit
(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle, jint algID, jbyteArray iv, jbyteArray aad, jint dataLength) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_AuthEncInit == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    /* Convert IV */
    BYTE *iv_buf = NULL;
    jsize iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (BYTE*)malloc(iv_len);
        if (iv_buf == NULL) {
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
        (*env)->GetByteArrayRegion(env, iv, 0, iv_len, (jbyte*)iv_buf);
    }

    /* Convert AAD (Additional Authenticated Data) */
    BYTE *aad_buf = NULL;
    jsize aad_len = 0;
    if (aad != NULL) {
        aad_len = (*env)->GetArrayLength(env, aad);
        aad_buf = (BYTE*)malloc(aad_len);
        if (aad_buf == NULL) {
            if (iv_buf != NULL) free(iv_buf);
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
        (*env)->GetByteArrayRegion(env, aad, 0, aad_len, (jbyte*)aad_buf);
    }

    LONG ret = g_sdf_functions.SDF_AuthEncInit(
        (HANDLE)sessionHandle,
        (HANDLE)keyHandle,
        (ULONG)algID,
        iv_buf,
        (ULONG)iv_len,
        aad_buf,
        (ULONG)aad_len,
        (ULONG)dataLength
    );

    if (iv_buf != NULL) free(iv_buf);
    if (aad_buf != NULL) free(aad_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/**
 * 认证加密更新
 * SDF_AuthEncUpdate
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1AuthEncUpdate
(JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray data) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_AuthEncUpdate == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (data == NULL) {
        throw_sdf_exception_with_message(env, 0x01000006, "Data is null");
        return NULL;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, data, 0, data_len, (jbyte*)data_buf);

    /* Allocate output buffer (worst case: same size as input + block size) */
    ULONG output_len = data_len + 32;
    BYTE *output_buf = (BYTE*)malloc(output_len);
    if (output_buf == NULL) {
        free(data_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_AuthEncUpdate(
        (HANDLE)sessionHandle,
        data_buf,
        (ULONG)data_len,
        output_buf,
        &output_len
    );

    free(data_buf);

    if (ret != SDR_OK) {
        free(output_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, output_buf, output_len);
    free(output_buf);

    return result;
}

/**
 * 认证加密结束
 * SDF_AuthEncFinal
 * Java signature: (long sessionHandle) -> byte[][]
 * Returns: [0] = final encrypted data, [1] = authentication tag
 */
JNIEXPORT jobjectArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1AuthEncFinal
(JNIEnv *env, jobject obj, jlong sessionHandle) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_AuthEncFinal == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* Allocate output buffer for final encrypted block */
    ULONG output_len = 256;  /* Max block size */
    BYTE *output_buf = (BYTE*)malloc(output_len);
    if (output_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    /* Allocate tag buffer */
    ULONG tag_len = 32;  /* Max tag size */
    BYTE *tag_buf = (BYTE*)malloc(tag_len);
    if (tag_buf == NULL) {
        free(output_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_AuthEncFinal(
        (HANDLE)sessionHandle,
        output_buf,
        &output_len,
        tag_buf,
        &tag_len
    );

    if (ret != SDR_OK) {
        free(output_buf);
        free(tag_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    /* Create 2D byte array to return both outputs */
    jclass byteArrayClass = (*env)->FindClass(env, "[B");
    if (byteArrayClass == NULL) {
        free(output_buf);
        free(tag_buf);
        return NULL;
    }

    jobjectArray result = (*env)->NewObjectArray(env, 2, byteArrayClass, NULL);
    if (result == NULL) {
        free(output_buf);
        free(tag_buf);
        return NULL;
    }

    /* Set [0] = final encrypted data */
    jbyteArray encData = native_to_java_byte_array(env, output_buf, output_len);
    if (encData != NULL) {
        (*env)->SetObjectArrayElement(env, result, 0, encData);
    }

    /* Set [1] = authentication tag */
    jbyteArray authTag = native_to_java_byte_array(env, tag_buf, tag_len);
    if (authTag != NULL) {
        (*env)->SetObjectArrayElement(env, result, 1, authTag);
    }

    free(output_buf);
    free(tag_buf);

    return result;
}

/**
 * 认证解密初始化
 * SDF_AuthDecInit
 * Java signature: (long sessionHandle, long keyHandle, int algID, byte[] iv, byte[] aad, byte[] authTag, int dataLength)
 */
JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1AuthDecInit
(JNIEnv *env, jobject obj, jlong sessionHandle, jlong keyHandle, jint algID, jbyteArray iv, jbyteArray aad, jbyteArray authTag, jint dataLength) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_AuthDecInit == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    /* Convert IV */
    BYTE *iv_buf = NULL;
    jsize iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (BYTE*)malloc(iv_len);
        if (iv_buf == NULL) {
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
        (*env)->GetByteArrayRegion(env, iv, 0, iv_len, (jbyte*)iv_buf);
    }

    /* Convert AAD */
    BYTE *aad_buf = NULL;
    jsize aad_len = 0;
    if (aad != NULL) {
        aad_len = (*env)->GetArrayLength(env, aad);
        aad_buf = (BYTE*)malloc(aad_len);
        if (aad_buf == NULL) {
            if (iv_buf != NULL) free(iv_buf);
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
        (*env)->GetByteArrayRegion(env, aad, 0, aad_len, (jbyte*)aad_buf);
    }

    /* Convert auth tag */
    BYTE *tag_buf = NULL;
    jsize tag_len = 0;
    if (authTag != NULL) {
        tag_len = (*env)->GetArrayLength(env, authTag);
        tag_buf = (BYTE*)malloc(tag_len);
        if (tag_buf == NULL) {
            if (iv_buf != NULL) free(iv_buf);
            if (aad_buf != NULL) free(aad_buf);
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
        (*env)->GetByteArrayRegion(env, authTag, 0, tag_len, (jbyte*)tag_buf);
    }

    LONG ret = g_sdf_functions.SDF_AuthDecInit(
        (HANDLE)sessionHandle,
        (HANDLE)keyHandle,
        (ULONG)algID,
        iv_buf,
        (ULONG)iv_len,
        aad_buf,
        (ULONG)aad_len,
        tag_buf,
        (ULONG)tag_len,
        (ULONG)dataLength
    );

    if (iv_buf != NULL) free(iv_buf);
    if (aad_buf != NULL) free(aad_buf);
    if (tag_buf != NULL) free(tag_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/**
 * 认证解密更新
 * SDF_AuthDecUpdate
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1AuthDecUpdate
(JNIEnv *env, jobject obj, jlong sessionHandle, jbyteArray data) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_AuthDecUpdate == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    if (data == NULL) {
        throw_sdf_exception_with_message(env, 0x01000006, "Data is null");
        return NULL;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, data, 0, data_len, (jbyte*)data_buf);

    /* Allocate output buffer */
    ULONG output_len = data_len + 32;
    BYTE *output_buf = (BYTE*)malloc(output_len);
    if (output_buf == NULL) {
        free(data_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_AuthDecUpdate(
        (HANDLE)sessionHandle,
        data_buf,
        (ULONG)data_len,
        output_buf,
        &output_len
    );

    free(data_buf);

    if (ret != SDR_OK) {
        free(output_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, output_buf, output_len);
    free(output_buf);

    return result;
}

/**
 * 认证解密结束
 * SDF_AuthDecFinal
 * Java signature: (long sessionHandle) -> byte[]
 * Note: auth tag was already passed in AuthDecInit
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1AuthDecFinal
(JNIEnv *env, jobject obj, jlong sessionHandle) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_AuthDecFinal == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* Allocate output buffer for final block */
    ULONG output_len = 256;
    BYTE *output_buf = (BYTE*)malloc(output_len);
    if (output_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_AuthDecFinal(
        (HANDLE)sessionHandle,
        output_buf,
        &output_len
    );

    if (ret != SDR_OK) {
        free(output_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, output_buf, output_len);
    free(output_buf);

    return result;
}

/* ========================================================================
 * Category 6.8 验证调试类函数 (Verification and Debug Functions)
 * ======================================================================== */

/**
 * 6.8.2 产生RSA非对称密钥对并输出
 * Pattern: Returns Object[] {RSAPublicKey, RSAPrivateKey}
 */
JNIEXPORT jobjectArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1GenerateKeyPair_1RSA
(JNIEnv *env, jobject obj, jlong sessionHandle, jint keyBits) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_GenerateKeyPair_RSA == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    RSArefPublicKey pub_key;
    RSArefPrivateKey priv_key;
    memset(&pub_key, 0, sizeof(RSArefPublicKey));
    memset(&priv_key, 0, sizeof(RSArefPrivateKey));

    LONG ret = g_sdf_functions.SDF_GenerateKeyPair_RSA(
        (HANDLE)sessionHandle,
        (ULONG)keyBits,
        &pub_key,
        &priv_key
    );

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return NULL;
    }

    /* Convert to Java objects */
    jobject java_pub = native_to_java_RSAPublicKey(env, &pub_key);
    jobject java_priv = native_to_java_RSAPrivateKey(env, &priv_key);

    if (java_pub == NULL || java_priv == NULL) {
        return NULL;  /* Exception already thrown */
    }

    /* Create Object array */
    jclass objClass = (*env)->FindClass(env, "java/lang/Object");
    jobjectArray result = (*env)->NewObjectArray(env, 2, objClass, NULL);
    (*env)->SetObjectArrayElement(env, result, 0, java_pub);
    (*env)->SetObjectArrayElement(env, result, 1, java_priv);

    return result;
}

/**
 * 6.8.3 产生ECC非对称密钥对并输出
 * Pattern: Returns Object[] {ECCPublicKey, ECCPrivateKey}
 */
JNIEXPORT jobjectArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1GenerateKeyPair_1ECC
(JNIEnv *env, jobject obj, jlong sessionHandle, jint algID, jint keyBits) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_GenerateKeyPair_ECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    ECCrefPublicKey pub_key;
    ECCrefPrivateKey priv_key;
    memset(&pub_key, 0, sizeof(ECCrefPublicKey));
    memset(&priv_key, 0, sizeof(ECCrefPrivateKey));

    LONG ret = g_sdf_functions.SDF_GenerateKeyPair_ECC(
        (HANDLE)sessionHandle,
        (ULONG)algID,
        (ULONG)keyBits,
        &pub_key,
        &priv_key
    );

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return NULL;
    }

    /* Convert to Java objects */
    jobject java_pub = native_to_java_ECCPublicKey(env, &pub_key);
    jobject java_priv = native_to_java_ECCPrivateKey(env, &priv_key);

    if (java_pub == NULL || java_priv == NULL) {
        return NULL;  /* Exception already thrown */
    }

    /* Create Object array */
    jclass objClass = (*env)->FindClass(env, "java/lang/Object");
    jobjectArray result = (*env)->NewObjectArray(env, 2, objClass, NULL);
    (*env)->SetObjectArrayElement(env, result, 0, java_pub);
    (*env)->SetObjectArrayElement(env, result, 1, java_priv);

    return result;
}

/**
 * 6.8.4 外部私钥RSA运算
 * Pattern: Returns byte[] output data
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ExternalPrivateKeyOperation_1RSA
(JNIEnv *env, jobject obj, jlong sessionHandle, jobject privateKey, jbyteArray dataInput) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_ExternalPrivateKeyOperation_RSA == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* Convert private key */
    RSArefPrivateKey priv_key;
    if (!java_to_native_RSAPrivateKey(env, privateKey, &priv_key)) {
        return NULL;
    }

    /* Convert input data */
    jsize input_len = (*env)->GetArrayLength(env, dataInput);
    BYTE *input_buf = (BYTE*)malloc(input_len);
    if (input_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, dataInput, 0, input_len, (jbyte*)input_buf);

    /* Allocate output buffer */
    ULONG output_len = 512;  /* Max RSA key size */
    BYTE *output_buf = (BYTE*)malloc(output_len);
    if (output_buf == NULL) {
        free(input_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_ExternalPrivateKeyOperation_RSA(
        (HANDLE)sessionHandle,
        &priv_key,
        input_buf,
        (ULONG)input_len,
        output_buf,
        &output_len
    );

    free(input_buf);

    if (ret != SDR_OK) {
        free(output_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, output_buf, output_len);
    free(output_buf);

    return result;
}

/**
 * 6.8.5 外部私钥ECC签名
 * Pattern: Returns ECCSignature
 */
JNIEXPORT jobject JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ExternalSign_1ECC
(JNIEnv *env, jobject obj, jlong sessionHandle, jint algID, jobject privateKey, jbyteArray data) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_ExternalSign_ECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* Convert private key */
    ECCrefPrivateKey priv_key;
    if (!java_to_native_ECCPrivateKey(env, privateKey, &priv_key)) {
        return NULL;
    }

    /* Convert data */
    jsize data_len = (*env)->GetArrayLength(env, data);
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, data, 0, data_len, (jbyte*)data_buf);

    ECCSignature signature;
    memset(&signature, 0, sizeof(ECCSignature));

    LONG ret = g_sdf_functions.SDF_ExternalSign_ECC(
        (HANDLE)sessionHandle,
        (ULONG)algID,
        &priv_key,
        data_buf,
        (ULONG)data_len,
        &signature
    );

    free(data_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
        return NULL;
    }

    return native_to_java_ECCSignature(env, &signature);
}

/**
 * 6.8.6 外部私钥ECC解密
 * Pattern: Returns byte[] plaintext
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ExternalDecrypt_1ECC
(JNIEnv *env, jobject obj, jlong sessionHandle, jint algID, jobject privateKey, jobject cipher) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_ExternalDecrypt_ECC == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* Convert private key */
    ECCrefPrivateKey priv_key;
    if (!java_to_native_ECCPrivateKey(env, privateKey, &priv_key)) {
        return NULL;
    }

    /* Convert cipher */
    ECCCipher ecc_cipher;
    if (!java_to_native_ECCCipher(env, cipher, &ecc_cipher)) {
        return NULL;
    }

    /* Allocate output buffer */
    ULONG plaintext_len = 256;  /* Reasonable max */
    BYTE *plaintext_buf = (BYTE*)malloc(plaintext_len);
    if (plaintext_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_ExternalDecrypt_ECC(
        (HANDLE)sessionHandle,
        (ULONG)algID,
        &priv_key,
        &ecc_cipher,
        plaintext_buf,
        &plaintext_len
    );

    if (ret != SDR_OK) {
        free(plaintext_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, plaintext_buf, plaintext_len);
    free(plaintext_buf);

    return result;
}

/**
 * 6.8.9 外部密钥单包对称加密
 * Pattern: Returns byte[] encrypted data
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ExternalKeyEncrypt
(JNIEnv *env, jobject obj, jlong sessionHandle, jint algID, jbyteArray key, jbyteArray iv, jbyteArray data) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_ExternalKeyEncrypt == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* Convert key */
    jsize key_len = (*env)->GetArrayLength(env, key);
    BYTE *key_buf = (BYTE*)malloc(key_len);
    if (key_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, key, 0, key_len, (jbyte*)key_buf);

    /* Convert IV (may be NULL) */
    BYTE *iv_buf = NULL;
    ULONG iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (BYTE*)malloc(iv_len);
        if (iv_buf == NULL) {
            free(key_buf);
            throw_sdf_exception(env, 0x0100001C);
            return NULL;
        }
        (*env)->GetByteArrayRegion(env, iv, 0, iv_len, (jbyte*)iv_buf);
    }

    /* Convert data */
    jsize data_len = (*env)->GetArrayLength(env, data);
    BYTE *data_buf = (BYTE*)malloc(data_len);
    if (data_buf == NULL) {
        free(key_buf);
        if (iv_buf) free(iv_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, data, 0, data_len, (jbyte*)data_buf);

    /* Allocate encrypted buffer (may need padding) */
    ULONG enc_len = data_len + 32;
    BYTE *enc_buf = (BYTE*)malloc(enc_len);
    if (enc_buf == NULL) {
        free(key_buf);
        if (iv_buf) free(iv_buf);
        free(data_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_ExternalKeyEncrypt(
        (HANDLE)sessionHandle,
        (ULONG)algID,
        key_buf,
        (ULONG)key_len,
        iv_buf,
        iv_len,
        data_buf,
        (ULONG)data_len,
        enc_buf,
        &enc_len
    );

    free(key_buf);
    if (iv_buf) free(iv_buf);
    free(data_buf);

    if (ret != SDR_OK) {
        free(enc_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, enc_buf, enc_len);
    free(enc_buf);

    return result;
}

/**
 * 6.8.10 外部密钥单包对称解密
 * Pattern: Returns byte[] decrypted data
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ExternalKeyDecrypt
(JNIEnv *env, jobject obj, jlong sessionHandle, jint algID, jbyteArray key, jbyteArray iv, jbyteArray encData) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return NULL;
    }

    if (g_sdf_functions.SDF_ExternalKeyDecrypt == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return NULL;
    }

    /* Convert key */
    jsize key_len = (*env)->GetArrayLength(env, key);
    BYTE *key_buf = (BYTE*)malloc(key_len);
    if (key_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, key, 0, key_len, (jbyte*)key_buf);

    /* Convert IV (may be NULL) */
    BYTE *iv_buf = NULL;
    ULONG iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (BYTE*)malloc(iv_len);
        if (iv_buf == NULL) {
            free(key_buf);
            throw_sdf_exception(env, 0x0100001C);
            return NULL;
        }
        (*env)->GetByteArrayRegion(env, iv, 0, iv_len, (jbyte*)iv_buf);
    }

    /* Convert encrypted data */
    jsize enc_len = (*env)->GetArrayLength(env, encData);
    BYTE *enc_buf = (BYTE*)malloc(enc_len);
    if (enc_buf == NULL) {
        free(key_buf);
        if (iv_buf) free(iv_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, encData, 0, enc_len, (jbyte*)enc_buf);

    /* Allocate plaintext buffer */
    ULONG plaintext_len = enc_len;
    BYTE *plaintext_buf = (BYTE*)malloc(plaintext_len);
    if (plaintext_buf == NULL) {
        free(key_buf);
        if (iv_buf) free(iv_buf);
        free(enc_buf);
        throw_sdf_exception(env, 0x0100001C);
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_ExternalKeyDecrypt(
        (HANDLE)sessionHandle,
        (ULONG)algID,
        key_buf,
        (ULONG)key_len,
        iv_buf,
        iv_len,
        enc_buf,
        (ULONG)enc_len,
        plaintext_buf,
        &plaintext_len
    );

    free(key_buf);
    if (iv_buf) free(iv_buf);
    free(enc_buf);

    if (ret != SDR_OK) {
        free(plaintext_buf);
        throw_sdf_exception(env, ret);
        return NULL;
    }

    jbyteArray result = native_to_java_byte_array(env, plaintext_buf, plaintext_len);
    free(plaintext_buf);

    return result;
}

/**
 * 6.8.11 外部密钥多包对称加密初始化
 * Pattern: Void function
 */
JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ExternalKeyEncryptInit
(JNIEnv *env, jobject obj, jlong sessionHandle, jint algID, jbyteArray key, jbyteArray iv) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_ExternalKeyEncryptInit == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    /* Convert key */
    jsize key_len = (*env)->GetArrayLength(env, key);
    BYTE *key_buf = (BYTE*)malloc(key_len);
    if (key_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return;
    }
    (*env)->GetByteArrayRegion(env, key, 0, key_len, (jbyte*)key_buf);

    /* Convert IV (may be NULL) */
    BYTE *iv_buf = NULL;
    ULONG iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (BYTE*)malloc(iv_len);
        if (iv_buf == NULL) {
            free(key_buf);
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
        (*env)->GetByteArrayRegion(env, iv, 0, iv_len, (jbyte*)iv_buf);
    }

    LONG ret = g_sdf_functions.SDF_ExternalKeyEncryptInit(
        (HANDLE)sessionHandle,
        (ULONG)algID,
        key_buf,
        (ULONG)key_len,
        iv_buf,
        iv_len
    );

    free(key_buf);
    if (iv_buf) free(iv_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/**
 * 6.8.12 外部密钥多包对称解密初始化
 * Pattern: Void function
 */
JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ExternalKeyDecryptInit
(JNIEnv *env, jobject obj, jlong sessionHandle, jint algID, jbyteArray key, jbyteArray iv) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_ExternalKeyDecryptInit == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    /* Convert key */
    jsize key_len = (*env)->GetArrayLength(env, key);
    BYTE *key_buf = (BYTE*)malloc(key_len);
    if (key_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return;
    }
    (*env)->GetByteArrayRegion(env, key, 0, key_len, (jbyte*)key_buf);

    /* Convert IV (may be NULL) */
    BYTE *iv_buf = NULL;
    ULONG iv_len = 0;
    if (iv != NULL) {
        iv_len = (*env)->GetArrayLength(env, iv);
        iv_buf = (BYTE*)malloc(iv_len);
        if (iv_buf == NULL) {
            free(key_buf);
            throw_sdf_exception(env, 0x0100001C);
            return;
        }
        (*env)->GetByteArrayRegion(env, iv, 0, iv_len, (jbyte*)iv_buf);
    }

    LONG ret = g_sdf_functions.SDF_ExternalKeyDecryptInit(
        (HANDLE)sessionHandle,
        (ULONG)algID,
        key_buf,
        (ULONG)key_len,
        iv_buf,
        iv_len
    );

    free(key_buf);
    if (iv_buf) free(iv_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}

/**
 * 6.8.13 带外部密钥的杂凑运算初始化
 * Pattern: Void function
 */
JNIEXPORT void JNICALL
Java_org_openhitls_sdf4j_SDF_SDF_1ExternalKeyHMACInit
(JNIEnv *env, jobject obj, jlong sessionHandle, jint algID, jbyteArray key) {
    UNUSED(obj);

    if (!sdf_is_loaded()) {
        throw_sdf_exception_with_message(env, 0x01000003, "SDF library not loaded");
        return;
    }

    if (g_sdf_functions.SDF_ExternalKeyHMACInit == NULL) {
        throw_sdf_exception(env, SDR_NOTSUPPORT);
        return;
    }

    /* Convert key */
    jsize key_len = (*env)->GetArrayLength(env, key);
    BYTE *key_buf = (BYTE*)malloc(key_len);
    if (key_buf == NULL) {
        throw_sdf_exception(env, 0x0100001C);
        return;
    }
    (*env)->GetByteArrayRegion(env, key, 0, key_len, (jbyte*)key_buf);

    LONG ret = g_sdf_functions.SDF_ExternalKeyHMACInit(
        (HANDLE)sessionHandle,
        (ULONG)algID,
        key_buf,
        (ULONG)key_len
    );

    free(key_buf);

    if (ret != SDR_OK) {
        throw_sdf_exception(env, ret);
    }
}
