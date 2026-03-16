/*
 * Copyright (c) 2025 OpenHitls
 * SDF4J is licensed under Mulan PSL v2.
 * You can obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include "jce_common.h"
#include "dynamic_loader.h"

/*
 * Class:     org_openhitls_sdf4j_jce_SDFJceNative
 * Method:    openSession
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Sdf4j_jce_SDFJceNative_openSession(JNIEnv *env, jclass cls) {
    (void)cls;
    CHECK_INIT_RET(env, 0);
    CHECK_FUNCTION_RET(SDF_OpenSession, env, "SDF_OpenSession", 0);

    if (g_device_handle == NULL) {
        throw_jce_exception(env, SDR_UNKNOWERR, "Device not opened");
        return 0;
    }

    /* Open session */
    HANDLE session_handle = NULL;
    LONG ret = g_sdf_functions.SDF_OpenSession(g_device_handle, &session_handle);
    if (ret != SDR_OK) {
        throw_jce_exception(env, (int)ret, "Failed to open SDF session");
        return 0;
    }

    return (jlong)(uintptr_t)session_handle;
}

/*
 * Class:     org_openhitls_sdf4j_jce_SDFJceNative
 * Method:    closeSession
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Sdf4j_jce_SDFJceNative_closeSession(JNIEnv *env, jclass cls, jlong sessionHandle) {
    (void)cls;
    if (sessionHandle == 0) {
        return;
    }

    CHECK_FUNCTION(SDF_CloseSession, env, "SDF_CloseSession");

    HANDLE handle = (HANDLE)(uintptr_t)sessionHandle;
    if (g_sdf_functions.SDF_CloseSession != NULL) {
        g_sdf_functions.SDF_CloseSession(handle);
    }
}
