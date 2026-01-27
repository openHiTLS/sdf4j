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

#include "jni_cache.h"
#include <string.h>

/* Global JNI cache instance */
JNICache g_jni_cache = {0};

/* Helper macro to find class and create global reference */
#define CACHE_CLASS(env, cache_field, class_name) do { \
    jclass local = (*env)->FindClass(env, class_name); \
    if (local == NULL) { \
        return JNI_FALSE; \
    } \
    cache_field = (*env)->NewGlobalRef(env, local); \
    (*env)->DeleteLocalRef(env, local); \
    if (cache_field == NULL) { \
        return JNI_FALSE; \
    } \
} while(0)

/* Helper macro to get method ID */
#define CACHE_METHOD(env, cache_field, cls, name, sig) do { \
    cache_field = (*env)->GetMethodID(env, cls, name, sig); \
    if (cache_field == NULL) { \
        return JNI_FALSE; \
    } \
} while(0)

/* Helper macro to get field ID */
#define CACHE_FIELD(env, cache_field, cls, name, sig) do { \
    cache_field = (*env)->GetFieldID(env, cls, name, sig); \
    if (cache_field == NULL) { \
        return JNI_FALSE; \
    } \
} while(0)

/* Initialize SDFException cache */
static jint init_sdf_exception_cache(JNIEnv *env) {
    CACHE_CLASS(env, g_jni_cache.sdfException.cls, "org/openhitls/sdf4j/SDFException");
    CACHE_METHOD(env, g_jni_cache.sdfException.ctor_int,
                 g_jni_cache.sdfException.cls, "<init>", "(I)V");
    CACHE_METHOD(env, g_jni_cache.sdfException.ctor_int_string,
                 g_jni_cache.sdfException.cls, "<init>", "(ILjava/lang/String;)V");
    return JNI_TRUE;
}

/* Initialize DeviceInfo cache */
static jint init_device_info_cache(JNIEnv *env) {
    CACHE_CLASS(env, g_jni_cache.deviceInfo.cls, "org/openhitls/sdf4j/types/DeviceInfo");
    CACHE_METHOD(env, g_jni_cache.deviceInfo.ctor,
                 g_jni_cache.deviceInfo.cls, "<init>", "()V");
    CACHE_FIELD(env, g_jni_cache.deviceInfo.issuerName,
                g_jni_cache.deviceInfo.cls, "issuerName", "Ljava/lang/String;");
    CACHE_FIELD(env, g_jni_cache.deviceInfo.deviceName,
                g_jni_cache.deviceInfo.cls, "deviceName", "Ljava/lang/String;");
    CACHE_FIELD(env, g_jni_cache.deviceInfo.deviceSerial,
                g_jni_cache.deviceInfo.cls, "deviceSerial", "Ljava/lang/String;");
    CACHE_FIELD(env, g_jni_cache.deviceInfo.deviceVersion,
                g_jni_cache.deviceInfo.cls, "deviceVersion", "J");
    CACHE_FIELD(env, g_jni_cache.deviceInfo.standardVersion,
                g_jni_cache.deviceInfo.cls, "standardVersion", "J");
    CACHE_FIELD(env, g_jni_cache.deviceInfo.asymAlgAbility,
                g_jni_cache.deviceInfo.cls, "asymAlgAbility", "[J");
    CACHE_FIELD(env, g_jni_cache.deviceInfo.symAlgAbility,
                g_jni_cache.deviceInfo.cls, "symAlgAbility", "J");
    CACHE_FIELD(env, g_jni_cache.deviceInfo.hashAlgAbility,
                g_jni_cache.deviceInfo.cls, "hashAlgAbility", "J");
    CACHE_FIELD(env, g_jni_cache.deviceInfo.bufferSize,
                g_jni_cache.deviceInfo.cls, "bufferSize", "J");
    return JNI_TRUE;
}

/* Initialize RSAPublicKey cache */
static jint init_rsa_public_key_cache(JNIEnv *env) {
    CACHE_CLASS(env, g_jni_cache.rsaPublicKey.cls, "org/openhitls/sdf4j/types/RSAPublicKey");
    CACHE_METHOD(env, g_jni_cache.rsaPublicKey.ctor,
                 g_jni_cache.rsaPublicKey.cls, "<init>", "()V");
    CACHE_FIELD(env, g_jni_cache.rsaPublicKey.bits,
                g_jni_cache.rsaPublicKey.cls, "bits", "I");
    CACHE_FIELD(env, g_jni_cache.rsaPublicKey.m,
                g_jni_cache.rsaPublicKey.cls, "m", "[B");
    CACHE_FIELD(env, g_jni_cache.rsaPublicKey.e,
                g_jni_cache.rsaPublicKey.cls, "e", "[B");
    return JNI_TRUE;
}

/* Initialize RSAPrivateKey cache */
static jint init_rsa_private_key_cache(JNIEnv *env) {
    CACHE_CLASS(env, g_jni_cache.rsaPrivateKey.cls, "org/openhitls/sdf4j/types/RSAPrivateKey");
    CACHE_METHOD(env, g_jni_cache.rsaPrivateKey.ctor,
                 g_jni_cache.rsaPrivateKey.cls, "<init>", "()V");
    CACHE_FIELD(env, g_jni_cache.rsaPrivateKey.bits,
                g_jni_cache.rsaPrivateKey.cls, "bits", "I");
    CACHE_FIELD(env, g_jni_cache.rsaPrivateKey.m,
                g_jni_cache.rsaPrivateKey.cls, "m", "[B");
    CACHE_FIELD(env, g_jni_cache.rsaPrivateKey.e,
                g_jni_cache.rsaPrivateKey.cls, "e", "[B");
    CACHE_FIELD(env, g_jni_cache.rsaPrivateKey.d,
                g_jni_cache.rsaPrivateKey.cls, "d", "[B");
    CACHE_FIELD(env, g_jni_cache.rsaPrivateKey.prime,
                g_jni_cache.rsaPrivateKey.cls, "prime", "[[B");
    CACHE_FIELD(env, g_jni_cache.rsaPrivateKey.pexp,
                g_jni_cache.rsaPrivateKey.cls, "pexp", "[[B");
    CACHE_FIELD(env, g_jni_cache.rsaPrivateKey.coef,
                g_jni_cache.rsaPrivateKey.cls, "coef", "[B");
    return JNI_TRUE;
}

/* Initialize ECCPublicKey cache */
static jint init_ecc_public_key_cache(JNIEnv *env) {
    CACHE_CLASS(env, g_jni_cache.eccPublicKey.cls, "org/openhitls/sdf4j/types/ECCPublicKey");
    CACHE_METHOD(env, g_jni_cache.eccPublicKey.ctor,
                 g_jni_cache.eccPublicKey.cls, "<init>", "()V");
    CACHE_FIELD(env, g_jni_cache.eccPublicKey.bits,
                g_jni_cache.eccPublicKey.cls, "bits", "I");
    CACHE_FIELD(env, g_jni_cache.eccPublicKey.x,
                g_jni_cache.eccPublicKey.cls, "x", "[B");
    CACHE_FIELD(env, g_jni_cache.eccPublicKey.y,
                g_jni_cache.eccPublicKey.cls, "y", "[B");
    return JNI_TRUE;
}

/* Initialize ECCPrivateKey cache */
static jint init_ecc_private_key_cache(JNIEnv *env) {
    CACHE_CLASS(env, g_jni_cache.eccPrivateKey.cls, "org/openhitls/sdf4j/types/ECCPrivateKey");
    CACHE_METHOD(env, g_jni_cache.eccPrivateKey.ctor,
                 g_jni_cache.eccPrivateKey.cls, "<init>", "()V");
    CACHE_FIELD(env, g_jni_cache.eccPrivateKey.bits,
                g_jni_cache.eccPrivateKey.cls, "bits", "I");
    CACHE_FIELD(env, g_jni_cache.eccPrivateKey.k,
                g_jni_cache.eccPrivateKey.cls, "k", "[B");
    return JNI_TRUE;
}

/* Initialize ECCSignature cache */
static jint init_ecc_signature_cache(JNIEnv *env) {
    CACHE_CLASS(env, g_jni_cache.eccSignature.cls, "org/openhitls/sdf4j/types/ECCSignature");
    CACHE_METHOD(env, g_jni_cache.eccSignature.ctor,
                 g_jni_cache.eccSignature.cls, "<init>", "()V");
    CACHE_FIELD(env, g_jni_cache.eccSignature.r,
                g_jni_cache.eccSignature.cls, "r", "[B");
    CACHE_FIELD(env, g_jni_cache.eccSignature.s,
                g_jni_cache.eccSignature.cls, "s", "[B");
    return JNI_TRUE;
}

/* Initialize ECCCipher cache */
static jint init_ecc_cipher_cache(JNIEnv *env) {
    CACHE_CLASS(env, g_jni_cache.eccCipher.cls, "org/openhitls/sdf4j/types/ECCCipher");
    CACHE_METHOD(env, g_jni_cache.eccCipher.ctor,
                 g_jni_cache.eccCipher.cls, "<init>", "()V");
    CACHE_FIELD(env, g_jni_cache.eccCipher.x,
                g_jni_cache.eccCipher.cls, "x", "[B");
    CACHE_FIELD(env, g_jni_cache.eccCipher.y,
                g_jni_cache.eccCipher.cls, "y", "[B");
    CACHE_FIELD(env, g_jni_cache.eccCipher.m,
                g_jni_cache.eccCipher.cls, "m", "[B");
    CACHE_FIELD(env, g_jni_cache.eccCipher.l,
                g_jni_cache.eccCipher.cls, "l", "J");
    CACHE_FIELD(env, g_jni_cache.eccCipher.c,
                g_jni_cache.eccCipher.cls, "c", "[B");
    return JNI_TRUE;
}

/* Initialize KeyEncryptionResult cache */
static jint init_key_encryption_result_cache(JNIEnv *env) {
    CACHE_CLASS(env, g_jni_cache.keyEncryptionResult.cls,
                "org/openhitls/sdf4j/types/KeyEncryptionResult");
    CACHE_METHOD(env, g_jni_cache.keyEncryptionResult.ctor,
                 g_jni_cache.keyEncryptionResult.cls, "<init>", "([BJ)V");
    return JNI_TRUE;
}

/* Initialize common class cache */
static jint init_common_class_cache(JNIEnv *env) {
    CACHE_CLASS(env, g_jni_cache.common.objectClass, "java/lang/Object");
    CACHE_CLASS(env, g_jni_cache.common.byteArrayClass, "[B");
    return JNI_TRUE;
}

/* Helper to delete global ref if not NULL */
static void delete_global_ref_safe(JNIEnv *env, jclass *ref) {
    if (*ref != NULL) {
        (*env)->DeleteGlobalRef(env, *ref);
        *ref = NULL;
    }
}

jint jni_cache_init(JNIEnv *env) {
    if (g_jni_cache.initialized) {
        return JNI_TRUE;
    }

    memset(&g_jni_cache, 0, sizeof(JNICache));

    /* Initialize all caches */
    if (init_sdf_exception_cache(env) != JNI_TRUE) {
        jni_cache_cleanup(env);
        return JNI_FALSE;
    }

    if (init_device_info_cache(env) != JNI_TRUE) {
        jni_cache_cleanup(env);
        return JNI_FALSE;
    }

    if (init_rsa_public_key_cache(env) != JNI_TRUE) {
        jni_cache_cleanup(env);
        return JNI_FALSE;
    }

    if (init_rsa_private_key_cache(env) != JNI_TRUE) {
        jni_cache_cleanup(env);
        return JNI_FALSE;
    }

    if (init_ecc_public_key_cache(env) != JNI_TRUE) {
        jni_cache_cleanup(env);
        return JNI_FALSE;
    }

    if (init_ecc_private_key_cache(env) != JNI_TRUE) {
        jni_cache_cleanup(env);
        return JNI_FALSE;
    }

    if (init_ecc_signature_cache(env) != JNI_TRUE) {
        jni_cache_cleanup(env);
        return JNI_FALSE;
    }

    if (init_ecc_cipher_cache(env) != JNI_TRUE) {
        jni_cache_cleanup(env);
        return JNI_FALSE;
    }

    if (init_key_encryption_result_cache(env) != JNI_TRUE) {
        jni_cache_cleanup(env);
        return JNI_FALSE;
    }

    if (init_common_class_cache(env) != JNI_TRUE) {
        jni_cache_cleanup(env);
        return JNI_FALSE;
    }

    g_jni_cache.initialized = true;
    return JNI_TRUE;
}

void jni_cache_cleanup(JNIEnv *env) {
    /* Delete all global references */
    delete_global_ref_safe(env, &g_jni_cache.sdfException.cls);
    delete_global_ref_safe(env, &g_jni_cache.deviceInfo.cls);
    delete_global_ref_safe(env, &g_jni_cache.rsaPublicKey.cls);
    delete_global_ref_safe(env, &g_jni_cache.rsaPrivateKey.cls);
    delete_global_ref_safe(env, &g_jni_cache.eccPublicKey.cls);
    delete_global_ref_safe(env, &g_jni_cache.eccPrivateKey.cls);
    delete_global_ref_safe(env, &g_jni_cache.eccSignature.cls);
    delete_global_ref_safe(env, &g_jni_cache.eccCipher.cls);
    delete_global_ref_safe(env, &g_jni_cache.keyEncryptionResult.cls);
    delete_global_ref_safe(env, &g_jni_cache.common.objectClass);
    delete_global_ref_safe(env, &g_jni_cache.common.byteArrayClass);

    g_jni_cache.initialized = false;
}

bool jni_cache_is_initialized(void) {
    return g_jni_cache.initialized;
}
