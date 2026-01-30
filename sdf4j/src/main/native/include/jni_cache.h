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

#ifndef SDF4J_JNI_CACHE_H
#define SDF4J_JNI_CACHE_H

#include <jni.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * JNI ID Cache Structure
 * All JNI class, method, and field IDs are cached here for performance.
 * These are initialized once in JNI_OnLoad and used throughout the library.
 * ======================================================================== */

/* SDFException cache */
typedef struct {
    jclass cls;                     /* org/openhitls/sdf4j/SDFException */
    jmethodID ctor_int;             /* <init>(I)V */
    jmethodID ctor_int_string;      /* <init>(ILjava/lang/String;)V */
} SDFExceptionCache;

/* DeviceInfo cache */
typedef struct {
    jclass cls;                     /* org/openhitls/sdf4j/types/DeviceInfo */
    jmethodID ctor;                 /* <init>()V */
    jfieldID issuerName;            /* Ljava/lang/String; */
    jfieldID deviceName;            /* Ljava/lang/String; */
    jfieldID deviceSerial;          /* Ljava/lang/String; */
    jfieldID deviceVersion;         /* J */
    jfieldID standardVersion;       /* J */
    jfieldID asymAlgAbility;        /* [J */
    jfieldID symAlgAbility;         /* J */
    jfieldID hashAlgAbility;        /* J */
    jfieldID bufferSize;            /* J */
} DeviceInfoCache;

/* RSAPublicKey cache */
typedef struct {
    jclass cls;                     /* org/openhitls/sdf4j/types/RSAPublicKey */
    jmethodID ctor;                 /* <init>()V */
    jfieldID bits;                  /* I */
    jfieldID m;                     /* [B */
    jfieldID e;                     /* [B */
} RSAPublicKeyCache;

/* RSAPrivateKey cache */
typedef struct {
    jclass cls;                     /* org/openhitls/sdf4j/types/RSAPrivateKey */
    jmethodID ctor;                 /* <init>()V */
    jfieldID bits;                  /* I */
    jfieldID m;                     /* [B */
    jfieldID e;                     /* [B */
    jfieldID d;                     /* [B */
    jfieldID prime;                 /* [[B */
    jfieldID pexp;                  /* [[B */
    jfieldID coef;                  /* [B */
} RSAPrivateKeyCache;

/* ECCPublicKey cache */
typedef struct {
    jclass cls;                     /* org/openhitls/sdf4j/types/ECCPublicKey */
    jmethodID ctor;                 /* <init>()V */
    jfieldID bits;                  /* I */
    jfieldID x;                     /* [B */
    jfieldID y;                     /* [B */
} ECCPublicKeyCache;

/* ECCPrivateKey cache */
typedef struct {
    jclass cls;                     /* org/openhitls/sdf4j/types/ECCPrivateKey */
    jmethodID ctor;                 /* <init>()V */
    jfieldID bits;                  /* I */
    jfieldID k;                     /* [B */
} ECCPrivateKeyCache;

/* ECCSignature cache */
typedef struct {
    jclass cls;                     /* org/openhitls/sdf4j/types/ECCSignature */
    jmethodID ctor;                 /* <init>()V */
    jfieldID r;                     /* [B */
    jfieldID s;                     /* [B */
} ECCSignatureCache;

/* ECCCipher cache */
typedef struct {
    jclass cls;                     /* org/openhitls/sdf4j/types/ECCCipher */
    jmethodID ctor;                 /* <init>()V */
    jfieldID x;                     /* [B */
    jfieldID y;                     /* [B */
    jfieldID m;                     /* [B */
    jfieldID l;                     /* J */
    jfieldID c;                     /* [B */
} ECCCipherCache;

/* KeyEncryptionResult cache */
typedef struct {
    jclass cls;                     /* org/openhitls/sdf4j/types/KeyEncryptionResult */
    jmethodID ctor;                 /* <init>([BJ)V */
} KeyEncryptionResultCache;

/* ECCKeyEncryptionResult cache */
typedef struct {
    jclass cls;                     /* org/openhitls/sdf4j/types/ECCKeyEncryptionResult */
    jmethodID ctor;                 /* <init>([BJ)V */
} ECCKeyEncryptionResultCache;

/* Common Java classes cache */
typedef struct {
    jclass objectClass;             /* java/lang/Object */
    jclass byteArrayClass;          /* [B */
} CommonClassCache;

/* Master cache structure containing all cached JNI IDs */
typedef struct {
    bool initialized;
    SDFExceptionCache sdfException;
    DeviceInfoCache deviceInfo;
    RSAPublicKeyCache rsaPublicKey;
    RSAPrivateKeyCache rsaPrivateKey;
    ECCPublicKeyCache eccPublicKey;
    ECCPrivateKeyCache eccPrivateKey;
    ECCSignatureCache eccSignature;
    ECCCipherCache eccCipher;
    KeyEncryptionResultCache keyEncryptionResult;
    ECCKeyEncryptionResultCache eccKeyEncryptionResult;
    CommonClassCache common;
} JNICache;

/* Global JNI cache - extern declaration */
extern JNICache g_jni_cache;

/* ========================================================================
 * Cache Management Functions
 * ======================================================================== */

/**
 * Initialize the JNI cache. Called from JNI_OnLoad.
 *
 * @param env JNI environment
 * @return JNI_TRUE on success, JNI_FALSE on failure
 */
jint jni_cache_init(JNIEnv *env);

/**
 * Cleanup the JNI cache. Called from JNI_OnUnload.
 *
 * @param env JNI environment
 */
void jni_cache_cleanup(JNIEnv *env);

/**
 * Check if the JNI cache is initialized.
 *
 * @return true if initialized, false otherwise
 */
bool jni_cache_is_initialized(void);

#ifdef __cplusplus
}
#endif

#endif /* SDF4J_JNI_CACHE_H */
