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
#include "dynamic_loader.h"

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    generateRandom
 * Signature: (I)[B
 */
JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_generateRandom(JNIEnv *env, jclass cls, jlong sessionHandle, jint length)
{
    (void)cls;
    CHECK_INIT_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_GenerateRandom, env, "SDF_GenerateRandom", NULL);

    if (length <= 0) {
        throw_exception(env, "java/lang/IllegalArgumentException",
                       "Length must be greater than 0");
        return NULL;
    }

    BYTE *random = (BYTE *)malloc((size_t)length);
    if (random == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to allocate buffer");
        return NULL;
    }

    LONG ret = g_sdf_functions.SDF_GenerateRandom((HANDLE)sessionHandle, (ULONG)length, random);

    if (ret != SDR_OK) {
        free(random);
        throw_jce_exception(env, (int)ret, "Generate random failed");
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, length);
    if (result == NULL) {
        free(random);
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to create byte array");
        return NULL;
    }
    /* length > 0 is guaranteed by earlier check */
    (*env)->SetByteArrayRegion(env, result, 0, length, (jbyte *)random);

    free(random);
    return result;
}
