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

#ifndef SDF4J_JCE_FUNCTIONS_H
#define SDF4J_JCE_FUNCTIONS_H

#include <jni.h>

int sdf_jce_initialize(const char *library_path);
void sdf_jce_cleanup(void);

/* ==================== Session Management ==================== */

JNIEXPORT jlong JNICALL Sdf4j_jce_SDFJceNative_openSession(JNIEnv *env, jclass cls);

JNIEXPORT void JNICALL Sdf4j_jce_SDFJceNative_closeSession(JNIEnv *env, jclass cls, jlong sessionHandle);

/* ==================== NativeLoader ==================== */

JNIEXPORT void JNICALL Sdf4j_Jce_NativeLoader_SetLibraryPath(JNIEnv *env, jclass cls, jstring path);

JNIEXPORT jboolean JNICALL Sdf4j_Jce_NativeLoader_Initialize(JNIEnv *env, jclass cls);

JNIEXPORT void JNICALL Sdf4j_Jce_NativeLoader_Cleanup(JNIEnv *env, jclass cls);

/* ==================== SM3 Hash ==================== */

JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm3Digest(JNIEnv *env,
    jclass cls, jlong sessionHandle, jbyteArray data);

JNIEXPORT jlong JNICALL JNI_SDFJceNative_sm3Init(JNIEnv *env,
    jclass cls, jlong sessionHandle);

JNIEXPORT void JNICALL JNI_SDFJceNative_sm3Update(JNIEnv *env,
    jclass cls, jlong ctx, jbyteArray data, jint offset, jint len);

JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm3Final(JNIEnv *env,
    jclass cls, jlong ctx);

JNIEXPORT void JNICALL JNI_SDFJceNative_sm3Free(JNIEnv *env,
    jclass cls, jlong ctx);

/* ==================== SM4 Symmetric Encryption ==================== */
JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm4AuthEnc(JNIEnv *env,
    jclass cls, jlong sessionHandle, jint mode, jbyteArray key, jbyteArray iv,
    jbyteArray aad, jbyteArray data);

JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm4AuthDec(JNIEnv *env,
    jclass cls, jlong sessionHandle, jint mode, jbyteArray key, jbyteArray iv,
    jbyteArray aad, jbyteArray tag, jbyteArray ciphertext);

JNIEXPORT jlong JNICALL JNI_SDFJceNative_sm4EncryptInit(JNIEnv *env,
    jclass cls, jlong sessionHandle, jint mode, jbyteArray key, jbyteArray iv);

JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm4EncryptUpdate(JNIEnv *env,
    jclass cls, jlong ctx, jbyteArray data, jint offset, jint len);

JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm4EncryptFinal(JNIEnv *env,
    jclass cls, jlong ctx);

JNIEXPORT jlong JNICALL JNI_SDFJceNative_sm4DecryptInit(JNIEnv *env,
    jclass cls, jlong sessionHandle, jint mode, jbyteArray key, jbyteArray iv);

JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm4DecryptUpdate(JNIEnv *env,
    jclass cls, jlong ctx, jbyteArray data, jint offset, jint len);

JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm4DecryptFinal(JNIEnv *env,
    jclass cls, jlong ctx);

JNIEXPORT void JNICALL JNI_SDFJceNative_sm4Free(JNIEnv *env,
    jclass cls, jlong ctx);

/* ==================== SM2 Asymmetric ==================== */

JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm2GenerateKeyPair(JNIEnv *env,
    jclass cls, jlong sessionHandle);

JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm2Sign(JNIEnv *env,
    jclass cls, jlong sessionHandle, jbyteArray privateKey, jbyteArray data);

JNIEXPORT jboolean JNICALL JNI_SDFJceNative_sm2Verify(JNIEnv *env,
    jclass cls, jlong sessionHandle, jbyteArray publicKeyX, jbyteArray publicKeyY,
    jbyteArray data, jbyteArray signature);

JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm2Encrypt(JNIEnv *env,
    jclass cls, jlong sessionHandle, jbyteArray publicKeyX, jbyteArray publicKeyY, jbyteArray plaintext);

JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm2Decrypt(JNIEnv *env,
    jclass cls, jlong sessionHandle, jbyteArray privateKey, jbyteArray ciphertext);

/* ==================== MAC ==================== */

JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_sm4Mac(JNIEnv *env,
    jclass cls, jlong sessionHandle, jbyteArray key, jbyteArray iv, jbyteArray data);

JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_hmacSm3(JNIEnv *env,
    jclass cls, jlong sessionHandle, jbyteArray key, jbyteArray data);

/* ==================== Random ==================== */

JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_generateRandom(JNIEnv *env,
    jclass cls, jlong sessionHandle, jint length);

/* ==================== Key Management ==================== */

JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_generateSm4Key(JNIEnv *env,
    jclass cls, jlong sessionHandle);

#endif /* SDF4J_JCE_FUNCTIONS_H */
