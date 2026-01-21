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
#include <stdlib.h>
#include "jce_common.h"
#include "session_pool.h"
#include "dynamic_loader.h"
#include "sdf_log.h"

#define MAX_RANDOM_LENGTH (1024 * 1024)  /* 1MB */

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    generateRandom
 * Signature: (I)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_org_openhitls_sdf4j_jce_native_1_SDFJceNative_generateRandom(
    JNIEnv *env, jclass cls, jint length)
{
    (void)cls;

    CHECK_INITIALIZED_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_GenerateRandom, env, "SDF_GenerateRandom", NULL);

    if (length <= 0 || length > MAX_RANDOM_LENGTH) {
        throw_exception(env, "java/lang/IllegalArgumentException",
                       "Length must be between 1 and 1048576");
        return NULL;
    }

    HANDLE session = session_pool_acquire();
    if (session == NULL) {
        throw_jce_exception(env, SDR_OPENSESSION, "Failed to acquire session");
        return NULL;
    }

    BYTE *random = (BYTE *)malloc((size_t)length);
    if (random == NULL) {
        session_pool_release(session);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to allocate buffer");
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_GenerateRandom(session, (ULONG)length, random);

    session_pool_release(session);

    if (ret != SDR_OK) {
        free(random);
        throw_jce_exception(env, (int)ret, "Generate random failed");
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, length);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(env, result, 0, length, (jbyte *)random);
    }

    free(random);
    return result;
}
