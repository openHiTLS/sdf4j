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

#include "dynamic_loader.h"
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

/* 全局变量 */
static void *g_sdf_handle = NULL;
static char g_load_error[256] = {0};

/* 全局SDF函数表 */
SDFFunctionTable g_sdf_functions = {0};

/**
 * 加载单个函数符号
 *
 * @param handle 库句柄
 * @param func_ptr 函数指针存储位置
 * @param func_name 函数名称
 * @param required 是否为必需函数
 * @return 成功返回true，失败时：必需函数返回false，可选函数返回true
 */
static bool load_function(void *handle, void **func_ptr, const char *func_name, bool required) {
    *func_ptr = dlsym(handle, func_name);
    if (*func_ptr == NULL) {
        if (required) {
            /* 必需函数加载失败，返回错误 */
            const char *error = dlerror();
            if (error == NULL) {
                error = "unknown error";
            }
            snprintf(g_load_error, sizeof(g_load_error),
                    "Failed to load required function '%s': %s", func_name, error);
            return false;
        } else {
            /* 可选函数加载失败，忽略并清空错误 */
            dlerror();
            return true;
        }
    }
    return true;
}

/**
 * 加载所有SDF函数
 *
 * 核心函数（必需）：OpenDevice, CloseDevice, OpenSession, CloseSession
 * 其他函数均为可选，不同SDF实现可能只提供部分功能
 */
static bool load_all_functions(void *handle) {
    /* ========================================
     * 核心设备管理函数（必需）
     * ======================================== */
    if (!load_function(handle, (void**)&g_sdf_functions.SDF_OpenDevice,
                      "SDF_OpenDevice", true))
        return false;
    load_function(handle, (void**)&g_sdf_functions.SDF_OpenDeviceWithConf,
                 "SDF_OpenDeviceWithConf", false);
    if (!load_function(handle, (void**)&g_sdf_functions.SDF_CloseDevice,
                      "SDF_CloseDevice", true))
        return false;
    if (!load_function(handle, (void**)&g_sdf_functions.SDF_OpenSession,
                      "SDF_OpenSession", true))
        return false;
    if (!load_function(handle, (void**)&g_sdf_functions.SDF_CloseSession,
                      "SDF_CloseSession", true))
        return false;

    /* ========================================
     * 可选设备管理函数
     * ======================================== */
    load_function(handle, (void**)&g_sdf_functions.SDF_GetDeviceInfo,
                 "SDF_GetDeviceInfo", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_GenerateRandom,
                 "SDF_GenerateRandom", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_GetPrivateKeyAccessRight,
                 "SDF_GetPrivateKeyAccessRight", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_ReleasePrivateKeyAccessRight,
                 "SDF_ReleasePrivateKeyAccessRight", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_GetKEKAccessRight,
                 "SDF_GetKEKAccessRight", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_ReleaseKEKAccessRight,
                 "SDF_ReleaseKEKAccessRight", false);

    /* ========================================
     * 可选密钥管理函数
     * ======================================== */
    load_function(handle, (void**)&g_sdf_functions.SDF_ExportSignPublicKey_RSA,
                 "SDF_ExportSignPublicKey_RSA", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_ExportEncPublicKey_RSA,
                 "SDF_ExportEncPublicKey_RSA", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_ExportSignPublicKey_ECC,
                 "SDF_ExportSignPublicKey_ECC", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_ExportEncPublicKey_ECC,
                 "SDF_ExportEncPublicKey_ECC", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_GenerateKeyWithIPK_RSA,
                 "SDF_GenerateKeyWithIPK_RSA", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_GenerateKeyWithEPK_RSA,
                 "SDF_GenerateKeyWithEPK_RSA", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_ImportKeyWithISK_RSA,
                 "SDF_ImportKeyWithISK_RSA", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_GenerateKeyWithIPK_ECC,
                 "SDF_GenerateKeyWithIPK_ECC", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_GenerateKeyWithEPK_ECC,
                 "SDF_GenerateKeyWithEPK_ECC", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_ImportKeyWithISK_ECC,
                 "SDF_ImportKeyWithISK_ECC", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_GenerateAgreementDataWithECC,
                 "SDF_GenerateAgreementDataWithECC", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_GenerateKeyWithECC,
                 "SDF_GenerateKeyWithECC", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_GenerateAgreementDataAndKeyWithECC,
                 "SDF_GenerateAgreementDataAndKeyWithECC", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_GenerateKeyWithKEK,
                 "SDF_GenerateKeyWithKEK", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_ImportKeyWithKEK,
                 "SDF_ImportKeyWithKEK", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_ImportKey,
                 "SDF_ImportKey", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_DestroyKey,
                 "SDF_DestroyKey", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_ExchangeDigitEnvelopeBaseOnECC,
                 "SDF_ExchangeDigitEnvelopeBaseOnECC", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_ExchangeDigitEnvelopeBaseOnRSA,
                 "SDF_ExchangeDigitEnvelopeBaseOnRSA", false);

    /* ========================================
     * 可选非对称算法函数
     * ======================================== */
    load_function(handle, (void**)&g_sdf_functions.SDF_ExternalPublicKeyOperation_RSA,
                 "SDF_ExternalPublicKeyOperation_RSA", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_InternalPublicKeyOperation_RSA,
                 "SDF_InternalPublicKeyOperation_RSA", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_InternalPrivateKeyOperation_RSA,
                 "SDF_InternalPrivateKeyOperation_RSA", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_InternalSign_ECC,
                 "SDF_InternalSign_ECC", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_InternalVerify_ECC,
                 "SDF_InternalVerify_ECC", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_ExternalVerify_ECC,
                 "SDF_ExternalVerify_ECC", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_ExternalEncrypt_ECC,
                 "SDF_ExternalEncrypt_ECC", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_InternalEncrypt_ECC,
                 "SDF_InternalEncrypt_ECC", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_InternalDecrypt_ECC,
                 "SDF_InternalDecrypt_ECC", false);

    /* ========================================
     * 可选对称算法函数
     * ======================================== */
    load_function(handle, (void**)&g_sdf_functions.SDF_Encrypt,
                 "SDF_Encrypt", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_Decrypt,
                 "SDF_Decrypt", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_CalculateMAC,
                 "SDF_CalculateMAC", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_AuthEnc,
                 "SDF_AuthEnc", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_AuthDec,
                 "SDF_AuthDec", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_EncryptInit,
                 "SDF_EncryptInit", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_EncryptUpdate,
                 "SDF_EncryptUpdate", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_EncryptFinal,
                 "SDF_EncryptFinal", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_DecryptInit,
                 "SDF_DecryptInit", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_DecryptUpdate,
                 "SDF_DecryptUpdate", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_DecryptFinal,
                 "SDF_DecryptFinal", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_CalculateMACInit,
                 "SDF_CalculateMACInit", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_CalculateMACUpdate,
                 "SDF_CalculateMACUpdate", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_CalculateMACFinal,
                 "SDF_CalculateMACFinal", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_AuthEncInit,
                 "SDF_AuthEncInit", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_AuthEncUpdate,
                 "SDF_AuthEncUpdate", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_AuthEncFinal,
                 "SDF_AuthEncFinal", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_AuthDecInit,
                 "SDF_AuthDecInit", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_AuthDecUpdate,
                 "SDF_AuthDecUpdate", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_AuthDecFinal,
                 "SDF_AuthDecFinal", false);

    /* ========================================
     * 可选杂凑算法函数
     * ======================================== */
    load_function(handle, (void**)&g_sdf_functions.SDF_HashInit,
                 "SDF_HashInit", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_HashUpdate,
                 "SDF_HashUpdate", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_HashFinal,
                 "SDF_HashFinal", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_HMACInit,
                 "SDF_HMACInit", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_HMACUpdate,
                 "SDF_HMACUpdate", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_HMACFinal,
                 "SDF_HMACFinal", false);

    /* ========================================
     * 可选文件操作函数
     * ======================================== */
    load_function(handle, (void**)&g_sdf_functions.SDF_CreateFile,
                 "SDF_CreateFile", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_ReadFile,
                 "SDF_ReadFile", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_WriteFile,
                 "SDF_WriteFile", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_DeleteFile,
                 "SDF_DeleteFile", false);

    /* ========================================
     * 可选验证调试函数
     * ======================================== */
    load_function(handle, (void**)&g_sdf_functions.SDF_GenerateKeyPair_RSA,
                 "SDF_GenerateKeyPair_RSA", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_GenerateKeyPair_ECC,
                 "SDF_GenerateKeyPair_ECC", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_ExternalPrivateKeyOperation_RSA,
                 "SDF_ExternalPrivateKeyOperation_RSA", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_ExternalSign_ECC,
                 "SDF_ExternalSign_ECC", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_ExternalDecrypt_ECC,
                 "SDF_ExternalDecrypt_ECC", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_ExternalKeyEncrypt,
                 "SDF_ExternalKeyEncrypt", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_ExternalKeyDecrypt,
                 "SDF_ExternalKeyDecrypt", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_ExternalKeyEncryptInit,
                 "SDF_ExternalKeyEncryptInit", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_ExternalKeyDecryptInit,
                 "SDF_ExternalKeyDecryptInit", false);
    load_function(handle, (void**)&g_sdf_functions.SDF_ExternalKeyHMACInit,
                 "SDF_ExternalKeyHMACInit", false);

    return true;
}

bool sdf_load_library(const char *library_path) {

    if (library_path == NULL) {
        snprintf(g_load_error, sizeof(g_load_error), "Library path is NULL");
        return false;
    }

    /* 如果已经加载，先卸载 */
    if (g_sdf_handle != NULL) {
        sdf_unload_library();
    }

    /* 清空错误缓冲 */
    dlerror();

    /* 打开库文件 */
    g_sdf_handle = dlopen(library_path, RTLD_LAZY | RTLD_LOCAL);
    if (g_sdf_handle == NULL) {
        const char *error = dlerror();
        snprintf(g_load_error, sizeof(g_load_error),
                "Failed to load library '%s': %s", library_path, error);
        return false;
    }

    /* 加载所有函数 */
    if (!load_all_functions(g_sdf_handle)) {
        dlclose(g_sdf_handle);
        g_sdf_handle = NULL;
        memset(&g_sdf_functions, 0, sizeof(g_sdf_functions));
        return false;
    }

    snprintf(g_load_error, sizeof(g_load_error), "Library loaded successfully");
    return true;
}

void sdf_unload_library(void) {

    if (g_sdf_handle != NULL) {
        dlclose(g_sdf_handle);
        g_sdf_handle = NULL;
    }
    memset(&g_sdf_functions, 0, sizeof(g_sdf_functions));

}

const char* sdf_get_load_error(void) {
    return g_load_error;
}
