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

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include "jce_common.h"
#include "session_pool.h"
#include "dynamic_loader.h"
#include "sdf_log.h"

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    exportPublicKey
 * Signature: (II)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_jce_native_1_SDFJceNative_exportPublicKey(
    JNIEnv *env, jclass cls, jint keyIndex, jint keyType)
{
    (void)cls;

    CHECK_INITIALIZED_RET(env, NULL);

    HANDLE session = session_pool_acquire();
    if (session == NULL) {
        throw_jce_exception(env, SDR_OPENSESSION, "Failed to acquire session");
        return NULL;
    }

    ECCrefPublicKey pubKey;
    memset(&pubKey, 0, sizeof(pubKey));
    LONG ret;

    if (keyType == KEY_TYPE_SIGN) {
        CHECK_FUNCTION_RET(SDF_ExportSignPublicKey_ECC, env, "SDF_ExportSignPublicKey_ECC", NULL);
        ret = g_sdf_functions.SDF_ExportSignPublicKey_ECC(session, (ULONG)keyIndex, &pubKey);
    } else {
        CHECK_FUNCTION_RET(SDF_ExportEncPublicKey_ECC, env, "SDF_ExportEncPublicKey_ECC", NULL);
        ret = g_sdf_functions.SDF_ExportEncPublicKey_ECC(session, (ULONG)keyIndex, &pubKey);
    }

    session_pool_release(session);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "Export public key failed");
        return NULL;
    }

    /* 返回 X(32) || Y(32) = 64 bytes */
    jbyteArray result = (*env)->NewByteArray(env, 64);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, 32,
                                   (jbyte *)(pubKey.x + ECCref_MAX_LEN - SM2_KEY_BYTES));
        (*env)->SetByteArrayRegion(env, result, 32, 32,
                                   (jbyte *)(pubKey.y + ECCref_MAX_LEN - SM2_KEY_BYTES));
    }

    return result;
}

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    generateSm4Key
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_jce_native_1_SDFJceNative_generateSm4Key(
    JNIEnv *env, jclass cls)
{
    (void)cls;

    CHECK_INITIALIZED_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_GenerateRandom, env, "SDF_GenerateRandom", NULL);

    HANDLE session = session_pool_acquire();
    if (session == NULL) {
        throw_jce_exception(env, SDR_OPENSESSION, "Failed to acquire session");
        return NULL;
    }

    BYTE key[SM4_KEY_LENGTH];
    LONG ret = g_sdf_functions.SDF_GenerateRandom(session, SM4_KEY_LENGTH, key);

    session_pool_release(session);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "Generate SM4 key failed");
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, SM4_KEY_LENGTH);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, SM4_KEY_LENGTH, (jbyte *)key);
    }

    /* 清除敏感数据 */
    memset(key, 0, SM4_KEY_LENGTH);

    return result;
}
