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
 #include "sdf_jni_functions.h"
 #include "jni_cache.h"
 #include <string.h>
 #include <stdio.h>
 
 /* JNI 方法注册表 - SDF 类 */
 static JNINativeMethod sdf_methods[] = {
    /* 6.2 设备管理类函数 */
    {"SDF_OpenDeviceNative", "()J", (void*)JNI_SDF_OpenDevice},
    {"SDF_OpenDeviceWithConf", "(Ljava/lang/String;)J", (void*)JNI_SDF_OpenDeviceWithConf},
    {"SDF_CloseDeviceNative", "(J)V", (void*)JNI_SDF_CloseDevice},
    {"SDF_OpenSessionNative", "(J)J", (void*)JNI_SDF_OpenSession},
    {"SDF_CloseSessionNative", "(J)V", (void*)JNI_SDF_CloseSession},
     {"SDF_GetDeviceInfo", "(J)Lorg/openhitls/sdf4j/types/DeviceInfo;", (void*)JNI_SDF_GetDeviceInfo},
     {"SDF_GenerateRandom", "(JI)[B", (void*)JNI_SDF_GenerateRandom},
     {"SDF_GetPrivateKeyAccessRight", "(JILjava/lang/String;)V", (void*)JNI_SDF_GetPrivateKeyAccessRight},
     {"SDF_ReleasePrivateKeyAccessRight", "(JI)V", (void*)JNI_SDF_ReleasePrivateKeyAccessRight},
     {"SDF_GetKEKAccessRight", "(JILjava/lang/String;)V", (void*)JNI_SDF_GetKEKAccessRight},
     {"SDF_ReleaseKEKAccessRight", "(JI)V", (void*)JNI_SDF_ReleaseKEKAccessRight},
 
     /* 6.3 密钥管理类函数 */
     {"SDF_ExportSignPublicKey_RSA", "(JI)Lorg/openhitls/sdf4j/types/RSAPublicKey;", (void*)JNI_SDF_ExportSignPublicKey_RSA},
     {"SDF_ExportEncPublicKey_RSA", "(JI)Lorg/openhitls/sdf4j/types/RSAPublicKey;", (void*)JNI_SDF_ExportEncPublicKey_RSA},
     {"SDF_ExportSignPublicKey_ECC", "(JI)Lorg/openhitls/sdf4j/types/ECCPublicKey;", (void*)JNI_SDF_ExportSignPublicKey_ECC},
     {"SDF_ExportEncPublicKey_ECC", "(JI)Lorg/openhitls/sdf4j/types/ECCPublicKey;", (void*)JNI_SDF_ExportEncPublicKey_ECC},
     {"SDF_GenerateKeyWithIPK_RSA_Native", "(JII)Lorg/openhitls/sdf4j/types/KeyEncryptionResult;", (void*)JNI_SDF_GenerateKeyWithIPK_RSA},
     {"SDF_GenerateKeyWithEPK_RSA_Native", "(JILorg/openhitls/sdf4j/types/RSAPublicKey;)Lorg/openhitls/sdf4j/types/KeyEncryptionResult;", (void*)JNI_SDF_GenerateKeyWithEPK_RSA},
     {"SDF_ImportKeyWithISK_RSA", "(JI[B)J", (void*)JNI_SDF_ImportKeyWithISK_RSA},
     {"SDF_GenerateKeyWithIPK_ECC_Native", "(JII)Lorg/openhitls/sdf4j/types/ECCKeyEncryptionResult;", (void*)JNI_SDF_GenerateKeyWithIPK_ECC},
     {"SDF_GenerateKeyWithEPK_ECC_Native", "(JIILorg/openhitls/sdf4j/types/ECCPublicKey;)Lorg/openhitls/sdf4j/types/ECCKeyEncryptionResult;", (void*)JNI_SDF_GenerateKeyWithEPK_ECC},
     {"SDF_ImportKeyWithISK_ECC", "(JILorg/openhitls/sdf4j/types/ECCCipher;)J", (void*)JNI_SDF_ImportKeyWithISK_ECC},
     {"SDF_GenerateAgreementDataWithECC", "(JII[BLorg/openhitls/sdf4j/types/ECCPublicKey;Lorg/openhitls/sdf4j/types/ECCPublicKey;)J", (void*)JNI_SDF_GenerateAgreementDataWithECC},
     {"SDF_GenerateKeyWithECC", "(J[BLorg/openhitls/sdf4j/types/ECCPublicKey;Lorg/openhitls/sdf4j/types/ECCPublicKey;J)J", (void*)JNI_SDF_GenerateKeyWithECC},
     {"SDF_GenerateAgreementDataAndKeyWithECC", "(JII[B[BLorg/openhitls/sdf4j/types/ECCPublicKey;Lorg/openhitls/sdf4j/types/ECCPublicKey;Lorg/openhitls/sdf4j/types/ECCPublicKey;Lorg/openhitls/sdf4j/types/ECCPublicKey;)J", (void*)JNI_SDF_GenerateAgreementDataAndKeyWithECC},
     {"SDF_GenerateKeyWithKEK_Native", "(JIII)Lorg/openhitls/sdf4j/types/KeyEncryptionResult;", (void*)JNI_SDF_GenerateKeyWithKEK},
     {"SDF_ImportKeyWithKEK", "(JII[B)J", (void*)JNI_SDF_ImportKeyWithKEK},
     {"SDF_DestroyKey_Native", "(JJ)V", (void*)JNI_SDF_DestroyKey},
     {"SDF_ImportKey", "(J[B)J", (void*)JNI_SDF_ImportKey},
     {"SDF_ExchangeDigitEnvelopeBaseOnECC", "(JIILorg/openhitls/sdf4j/types/ECCPublicKey;Lorg/openhitls/sdf4j/types/ECCCipher;)Lorg/openhitls/sdf4j/types/ECCCipher;", (void*)JNI_SDF_ExchangeDigitEnvelopeBaseOnECC},
     {"SDF_ExchangeDigitEnvelopeBaseOnRSA", "(JILorg/openhitls/sdf4j/types/RSAPublicKey;[B)[B", (void*)JNI_SDF_ExchangeDigitEnvelopeBaseOnRSA},

     /* 6.4 非对称算法类函数 */
     {"SDF_ExternalPublicKeyOperation_RSA", "(JLorg/openhitls/sdf4j/types/RSAPublicKey;[B)[B", (void*)JNI_SDF_ExternalPublicKeyOperation_RSA},
     {"SDF_InternalPublicKeyOperation_RSA", "(JI[B)[B", (void*)JNI_SDF_InternalPublicKeyOperation_RSA},
     {"SDF_InternalPrivateKeyOperation_RSA", "(JI[B)[B", (void*)JNI_SDF_InternalPrivateKeyOperation_RSA},
     {"SDF_InternalSign_ECC", "(JI[B)Lorg/openhitls/sdf4j/types/ECCSignature;", (void*)JNI_SDF_InternalSign_ECC},
     {"SDF_InternalVerify_ECC", "(JI[BLorg/openhitls/sdf4j/types/ECCSignature;)V", (void*)JNI_SDF_InternalVerify_ECC},
     {"SDF_ExternalVerify_ECC", "(JILorg/openhitls/sdf4j/types/ECCPublicKey;[BLorg/openhitls/sdf4j/types/ECCSignature;)V", (void*)JNI_SDF_ExternalVerify_ECC},
     {"SDF_ExternalEncrypt_ECC", "(JILorg/openhitls/sdf4j/types/ECCPublicKey;[B)Lorg/openhitls/sdf4j/types/ECCCipher;", (void*)JNI_SDF_ExternalEncrypt_ECC},
     {"SDF_InternalEncrypt_ECC", "(JI[B)Lorg/openhitls/sdf4j/types/ECCCipher;", (void*)JNI_SDF_InternalEncrypt_ECC},
     {"SDF_InternalDecrypt_ECC", "(JIILorg/openhitls/sdf4j/types/ECCCipher;)[B", (void*)JNI_SDF_InternalDecrypt_ECC},
 
     /* 6.5 对称算法类函数 */
     {"SDF_Encrypt", "(JJI[B[B)[B", (void*)JNI_SDF_Encrypt},
     {"SDF_Decrypt", "(JJI[B[B)[B", (void*)JNI_SDF_Decrypt},
     {"SDF_CalculateMAC", "(JJI[B[B)[B", (void*)JNI_SDF_CalculateMAC},
     {"SDF_AuthEnc", "(JJI[B[B[B)[[B", (void*)JNI_SDF_AuthEnc},
     {"SDF_AuthDec", "(JJI[B[B[B[B)[B", (void*)JNI_SDF_AuthDec},
     {"SDF_EncryptInit", "(JJI[B)V", (void*)JNI_SDF_EncryptInit},
     {"SDF_EncryptUpdate", "(J[B)[B", (void*)JNI_SDF_EncryptUpdate},
     {"SDF_EncryptFinal", "(J)[B", (void*)JNI_SDF_EncryptFinal},
     {"SDF_DecryptInit", "(JJI[B)V", (void*)JNI_SDF_DecryptInit},
     {"SDF_DecryptUpdate", "(J[B)[B", (void*)JNI_SDF_DecryptUpdate},
     {"SDF_DecryptFinal", "(J)[B", (void*)JNI_SDF_DecryptFinal},
     {"SDF_CalculateMACInit", "(JJI[B)V", (void*)JNI_SDF_CalculateMACInit},
     {"SDF_CalculateMACUpdate", "(J[B)V", (void*)JNI_SDF_CalculateMACUpdate},
     {"SDF_CalculateMACFinal", "(J)[B", (void*)JNI_SDF_CalculateMACFinal},
     {"SDF_AuthEncInit", "(JJI[B[BI)V", (void*)JNI_SDF_AuthEncInit},
     {"SDF_AuthEncUpdate", "(J[B)[B", (void*)JNI_SDF_AuthEncUpdate},
     {"SDF_AuthEncFinal", "(J[B)[[B", (void*)JNI_SDF_AuthEncFinal},
     {"SDF_AuthDecInit", "(JJI[B[B[BI)V", (void*)JNI_SDF_AuthDecInit},
     {"SDF_AuthDecUpdate", "(J[B)[B", (void*)JNI_SDF_AuthDecUpdate},
     {"SDF_AuthDecFinal", "(J)[B", (void*)JNI_SDF_AuthDecFinal},
 
     /* 6.6 杂凑算法类函数 */
     {"SDF_HashInit", "(JILorg/openhitls/sdf4j/types/ECCPublicKey;[B)V", (void*)JNI_SDF_HashInit},
     {"SDF_HashUpdate", "(J[B)V", (void*)JNI_SDF_HashUpdate},
     {"SDF_HashFinal", "(J)[B", (void*)JNI_SDF_HashFinal},
     {"SDF_HMACInit", "(JJI)V", (void*)JNI_SDF_HMACInit},
     {"SDF_HMACUpdate", "(J[B)V", (void*)JNI_SDF_HMACUpdate},
     {"SDF_HMACFinal", "(J)[B", (void*)JNI_SDF_HMACFinal},
 
     /* 6.7 文件操作类函数 */
     {"SDF_CreateFile", "(JLjava/lang/String;I)V", (void*)JNI_SDF_CreateFile},
     {"SDF_ReadFile", "(JLjava/lang/String;II)[B", (void*)JNI_SDF_ReadFile},
     {"SDF_WriteFile", "(JLjava/lang/String;I[B)V", (void*)JNI_SDF_WriteFile},
     {"SDF_DeleteFile", "(JLjava/lang/String;)V", (void*)JNI_SDF_DeleteFile},
 
     /* 6.8 验证调试类函数 */
     {"SDF_GenerateKeyPair_RSA", "(JI)[Ljava/lang/Object;", (void*)JNI_SDF_GenerateKeyPair_RSA},
     {"SDF_GenerateKeyPair_ECC", "(JII)[Ljava/lang/Object;", (void*)JNI_SDF_GenerateKeyPair_ECC},
     {"SDF_ExternalPrivateKeyOperation_RSA", "(JLorg/openhitls/sdf4j/types/RSAPrivateKey;[B)[B", (void*)JNI_SDF_ExternalPrivateKeyOperation_RSA},
     {"SDF_ExternalSign_ECC", "(JILorg/openhitls/sdf4j/types/ECCPrivateKey;[B)Lorg/openhitls/sdf4j/types/ECCSignature;", (void*)JNI_SDF_ExternalSign_ECC},
     {"SDF_ExternalDecrypt_ECC", "(JILorg/openhitls/sdf4j/types/ECCPrivateKey;Lorg/openhitls/sdf4j/types/ECCCipher;)[B", (void*)JNI_SDF_ExternalDecrypt_ECC},
     {"SDF_ExternalKeyEncrypt", "(JI[B[B[B)[B", (void*)JNI_SDF_ExternalKeyEncrypt},
     {"SDF_ExternalKeyDecrypt", "(JI[B[B[B)[B", (void*)JNI_SDF_ExternalKeyDecrypt},
     {"SDF_ExternalKeyEncryptInit", "(JI[B[B)V", (void*)JNI_SDF_ExternalKeyEncryptInit},
     {"SDF_ExternalKeyDecryptInit", "(JI[B[B)V", (void*)JNI_SDF_ExternalKeyDecryptInit},
     {"SDF_ExternalKeyHMACInit", "(JI[B)V", (void*)JNI_SDF_ExternalKeyHMACInit},
 };

/* JNI 方法注册表 - NativeLibraryLoader 类 */
static JNINativeMethod loader_methods[] = {
   {"nativeLoadSDFLibrary", "(Ljava/lang/String;)Z", (void*)JNI_NativeLibraryLoader_loadSDFLibrary},
};

/**
  * JNI_OnLoad - JVM 加载库时调用
  *
  * 这个函数在 System.loadLibrary() 时被 JVM 自动调用，
  * 用于初始化JNI缓存并动态注册所有 native 方法。
  */
 JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
     UNUSED(reserved);

     JNIEnv *env;
     if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_8) != JNI_OK) {
         return JNI_ERR;
     }

     /* 初始化 JNI 缓存 */
     if (jni_cache_init(env) != JNI_TRUE) {
         return JNI_ERR;
     }

     /* 注册 SDF 类的 native 方法 */
     jclass sdfClass = (*env)->FindClass(env, "org/openhitls/sdf4j/SDF");
     if (sdfClass == NULL) {
         jni_cache_cleanup(env);
         return JNI_ERR;
     }

     int sdfMethodCount = sizeof(sdf_methods) / sizeof(sdf_methods[0]);
     if ((*env)->RegisterNatives(env, sdfClass, sdf_methods, sdfMethodCount) < 0) {
         if ((*env)->ExceptionCheck(env)) {
             (*env)->ExceptionDescribe(env);
             (*env)->ExceptionClear(env);
         }
         (*env)->DeleteLocalRef(env, sdfClass);
         jni_cache_cleanup(env);
         return JNI_ERR;
     }
     (*env)->DeleteLocalRef(env, sdfClass);

     /* 注册 NativeLibraryLoader 类的 native 方法 */
     jclass loaderClass = (*env)->FindClass(env, "org/openhitls/sdf4j/internal/NativeLibraryLoader");
     if (loaderClass == NULL) {
        jni_cache_cleanup(env);
        return JNI_ERR;
     }
    int loaderMethodCount = sizeof(loader_methods) / sizeof(loader_methods[0]);
    if ((*env)->RegisterNatives(env, loaderClass, loader_methods, loaderMethodCount) < 0) {
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, loaderClass);
        jni_cache_cleanup(env);
        return JNI_ERR;
    }
    (*env)->DeleteLocalRef(env, loaderClass);
     return JNI_VERSION_1_8;
 }
 
 /**
  * JNI_OnUnload - JVM 卸载库时调用
  *
  * 这个函数在库被卸载时被 JVM 自动调用，
  * 用于注销 native 方法并清理JNI缓存资源。
  */
 JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved) {
     UNUSED(reserved);

     JNIEnv *env;
     if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_8) != JNI_OK) {
         return;
     }

     /* 注销 SDF 类的 native 方法 */
     jclass sdfClass = (*env)->FindClass(env, "org/openhitls/sdf4j/SDF");
     if (sdfClass != NULL) {
         (*env)->UnregisterNatives(env, sdfClass);
         (*env)->DeleteLocalRef(env, sdfClass);
     }

     /* 注销 NativeLibraryLoader 类的 native 方法 */
     jclass loaderClass = (*env)->FindClass(env, "org/openhitls/sdf4j/internal/NativeLibraryLoader");
     if (loaderClass != NULL) {
         (*env)->UnregisterNatives(env, loaderClass);
         (*env)->DeleteLocalRef(env, loaderClass);
     }

     /* 清理 JNI 缓存 */
     jni_cache_cleanup(env);
 }
 