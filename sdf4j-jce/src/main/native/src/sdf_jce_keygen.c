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
#include "dynamic_loader.h"

/*
 * Class:     org_openhitls_sdf4j_jce_native_SDFJceNative
 * Method:    generateSm4Key
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL JNI_SDFJceNative_generateSm4Key(JNIEnv *env, jclass cls, jlong sessionHandle)
{
    (void)cls;
    CHECK_INIT_RET(env, NULL);
    CHECK_FUNCTION_RET(SDF_GenerateRandom, env, "SDF_GenerateRandom", NULL);

    BYTE key[SM4_KEY_LENGTH];
    LONG ret = g_sdf_functions.SDF_GenerateRandom((HANDLE)sessionHandle, SM4_KEY_LENGTH, key);

    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "Generate SM4 key failed");
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, SM4_KEY_LENGTH);
    if (result == NULL) {
        throw_exception(env, "java/lang/OutOfMemoryError", "Failed to create byte array");
        memset(key, 0, SM4_KEY_LENGTH);
        return NULL;
    }
    /* SM4_KEY_LENGTH > 0 is guaranteed */
    (*env)->SetByteArrayRegion(env, result, 0, SM4_KEY_LENGTH, (jbyte *)key);

    /* 清除敏感数据 */
    memset(key, 0, SM4_KEY_LENGTH);

    return result;
}
