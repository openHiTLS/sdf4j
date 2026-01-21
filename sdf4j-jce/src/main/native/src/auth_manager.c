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

#include "auth_manager.h"
#include "dynamic_loader.h"
#include "sdf_log.h"
#include "sdf_err.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    SessionAuthState *states;
    int stateCount;
    int initialized;
    pthread_mutex_t mutex;
} AuthManager;

static AuthManager g_auth_mgr = {0};

int auth_manager_init(int sessionCount) {
    SDF_LOG_ENTER("auth_manager_init");

    if (g_auth_mgr.initialized) {
        return SDR_OK;
    }

    if (sessionCount <= 0 || sessionCount > MAX_SESSIONS) {
        sessionCount = MAX_SESSIONS;
    }

    if (pthread_mutex_init(&g_auth_mgr.mutex, NULL) != 0) {
        SDF_LOG_ERROR("auth_manager_init", "Failed to init mutex");
        return SDR_UNKNOWERR;
    }

    g_auth_mgr.states = (SessionAuthState *)calloc((size_t)sessionCount, sizeof(SessionAuthState));
    if (g_auth_mgr.states == NULL) {
        pthread_mutex_destroy(&g_auth_mgr.mutex);
        SDF_LOG_ERROR("auth_manager_init", "Failed to allocate memory");
        return SDR_NOBUFFER;
    }

    g_auth_mgr.stateCount = sessionCount;
    g_auth_mgr.initialized = 1;

    SDF_JNI_LOG("auth_manager_init: Initialized with %d session slots", sessionCount);

    return SDR_OK;
}

void auth_manager_destroy(void) {
    SDF_LOG_ENTER("auth_manager_destroy");

    if (!g_auth_mgr.initialized) {
        return;
    }

    pthread_mutex_lock(&g_auth_mgr.mutex);

    /* 释放所有会话的权限 */
    for (int i = 0; i < g_auth_mgr.stateCount; i++) {
        SessionAuthState *state = &g_auth_mgr.states[i];
        if (state->session != NULL) {
            /* 释放私钥权限 */
            for (int j = 0; j < MAX_KEY_INDEX; j++) {
                if (state->privateKeyAuthed[j] &&
                    g_sdf_functions.SDF_ReleasePrivateKeyAccessRight != NULL) {
                    g_sdf_functions.SDF_ReleasePrivateKeyAccessRight(state->session, (ULONG)j);
                }
                if (state->kekAuthed[j] &&
                    g_sdf_functions.SDF_ReleaseKEKAccessRight != NULL) {
                    g_sdf_functions.SDF_ReleaseKEKAccessRight(state->session, (ULONG)j);
                }
            }
        }
    }

    free(g_auth_mgr.states);
    g_auth_mgr.states = NULL;
    g_auth_mgr.stateCount = 0;
    g_auth_mgr.initialized = 0;

    pthread_mutex_unlock(&g_auth_mgr.mutex);
    pthread_mutex_destroy(&g_auth_mgr.mutex);

    SDF_JNI_LOG("auth_manager_destroy: Destroyed");
}

static SessionAuthState *find_or_create_state(HANDLE session) {
    /* 查找现有状态 */
    for (int i = 0; i < g_auth_mgr.stateCount; i++) {
        if (g_auth_mgr.states[i].session == session) {
            return &g_auth_mgr.states[i];
        }
    }

    /* 找一个空槽位 */
    for (int i = 0; i < g_auth_mgr.stateCount; i++) {
        if (g_auth_mgr.states[i].session == NULL) {
            g_auth_mgr.states[i].session = session;
            return &g_auth_mgr.states[i];
        }
    }

    return NULL;
}

int auth_manager_get_private_key_access(HANDLE session, int keyIndex,
                                         const char *pin, int pinLen) {
    if (!g_auth_mgr.initialized) {
        return SDR_UNKNOWERR;
    }

    if (keyIndex < 0 || keyIndex >= MAX_KEY_INDEX) {
        return SDR_INARGERR;
    }

    if (g_sdf_functions.SDF_GetPrivateKeyAccessRight == NULL) {
        /* 如果函数不可用，假定不需要权限 */
        return SDR_OK;
    }

    pthread_mutex_lock(&g_auth_mgr.mutex);

    SessionAuthState *state = find_or_create_state(session);
    if (state == NULL) {
        pthread_mutex_unlock(&g_auth_mgr.mutex);
        return SDR_NOBUFFER;
    }

    /* 已有权限 */
    if (state->privateKeyAuthed[keyIndex]) {
        pthread_mutex_unlock(&g_auth_mgr.mutex);
        SDF_JNI_LOG("auth_manager_get_private_key_access: Already authed for key %d", keyIndex);
        return SDR_OK;
    }

    pthread_mutex_unlock(&g_auth_mgr.mutex);

    /* 获取权限 */
    SDF_JNI_LOG("auth_manager_get_private_key_access: Getting access for key %d", keyIndex);
    LONG ret = g_sdf_functions.SDF_GetPrivateKeyAccessRight(
        session, (ULONG)keyIndex, (LPSTR)pin, (ULONG)pinLen);

    if (ret == SDR_OK) {
        pthread_mutex_lock(&g_auth_mgr.mutex);
        /* Re-lookup state to handle TOCTOU - state pointer may have changed */
        state = find_or_create_state(session);
        if (state != NULL) {
            state->privateKeyAuthed[keyIndex] = 1;
        }
        pthread_mutex_unlock(&g_auth_mgr.mutex);
        SDF_JNI_LOG("auth_manager_get_private_key_access: Access granted for key %d", keyIndex);
    } else {
        SDF_JNI_LOG("ERROR: auth_manager_get_private_key_access - Failed for key %d, ret=%ld", keyIndex, ret);
    }

    return (int)ret;
}

int auth_manager_release_private_key_access(HANDLE session, int keyIndex) {
    if (!g_auth_mgr.initialized) {
        return SDR_OK;
    }

    if (keyIndex < 0 || keyIndex >= MAX_KEY_INDEX) {
        return SDR_INARGERR;
    }

    if (g_sdf_functions.SDF_ReleasePrivateKeyAccessRight == NULL) {
        return SDR_OK;
    }

    pthread_mutex_lock(&g_auth_mgr.mutex);

    SessionAuthState *state = find_or_create_state(session);
    if (state == NULL || !state->privateKeyAuthed[keyIndex]) {
        pthread_mutex_unlock(&g_auth_mgr.mutex);
        return SDR_OK;
    }

    pthread_mutex_unlock(&g_auth_mgr.mutex);

    LONG ret = g_sdf_functions.SDF_ReleasePrivateKeyAccessRight(session, (ULONG)keyIndex);

    if (ret == SDR_OK) {
        pthread_mutex_lock(&g_auth_mgr.mutex);
        /* Re-lookup state to handle TOCTOU */
        state = find_or_create_state(session);
        if (state != NULL) {
            state->privateKeyAuthed[keyIndex] = 0;
        }
        pthread_mutex_unlock(&g_auth_mgr.mutex);
    }

    return (int)ret;
}

int auth_manager_get_kek_access(HANDLE session, int keyIndex,
                                 const char *pin, int pinLen) {
    if (!g_auth_mgr.initialized) {
        return SDR_UNKNOWERR;
    }

    if (keyIndex < 0 || keyIndex >= MAX_KEY_INDEX) {
        return SDR_INARGERR;
    }

    if (g_sdf_functions.SDF_GetKEKAccessRight == NULL) {
        return SDR_OK;
    }

    pthread_mutex_lock(&g_auth_mgr.mutex);

    SessionAuthState *state = find_or_create_state(session);
    if (state == NULL) {
        pthread_mutex_unlock(&g_auth_mgr.mutex);
        return SDR_NOBUFFER;
    }

    if (state->kekAuthed[keyIndex]) {
        pthread_mutex_unlock(&g_auth_mgr.mutex);
        return SDR_OK;
    }

    pthread_mutex_unlock(&g_auth_mgr.mutex);

    LONG ret = g_sdf_functions.SDF_GetKEKAccessRight(
        session, (ULONG)keyIndex, (LPSTR)pin, (ULONG)pinLen);

    if (ret == SDR_OK) {
        pthread_mutex_lock(&g_auth_mgr.mutex);
        /* Re-lookup state to handle TOCTOU */
        state = find_or_create_state(session);
        if (state != NULL) {
            state->kekAuthed[keyIndex] = 1;
        }
        pthread_mutex_unlock(&g_auth_mgr.mutex);
    }

    return (int)ret;
}

int auth_manager_release_kek_access(HANDLE session, int keyIndex) {
    if (!g_auth_mgr.initialized) {
        return SDR_OK;
    }

    if (keyIndex < 0 || keyIndex >= MAX_KEY_INDEX) {
        return SDR_INARGERR;
    }

    if (g_sdf_functions.SDF_ReleaseKEKAccessRight == NULL) {
        return SDR_OK;
    }

    pthread_mutex_lock(&g_auth_mgr.mutex);

    SessionAuthState *state = find_or_create_state(session);
    if (state == NULL || !state->kekAuthed[keyIndex]) {
        pthread_mutex_unlock(&g_auth_mgr.mutex);
        return SDR_OK;
    }

    pthread_mutex_unlock(&g_auth_mgr.mutex);

    LONG ret = g_sdf_functions.SDF_ReleaseKEKAccessRight(session, (ULONG)keyIndex);

    if (ret == SDR_OK) {
        pthread_mutex_lock(&g_auth_mgr.mutex);
        /* Re-lookup state to handle TOCTOU */
        state = find_or_create_state(session);
        if (state != NULL) {
            state->kekAuthed[keyIndex] = 0;
        }
        pthread_mutex_unlock(&g_auth_mgr.mutex);
    }

    return (int)ret;
}

int auth_manager_has_private_key_access(HANDLE session, int keyIndex) {
    if (!g_auth_mgr.initialized || keyIndex < 0 || keyIndex >= MAX_KEY_INDEX) {
        return 0;
    }

    pthread_mutex_lock(&g_auth_mgr.mutex);

    for (int i = 0; i < g_auth_mgr.stateCount; i++) {
        if (g_auth_mgr.states[i].session == session) {
            int result = g_auth_mgr.states[i].privateKeyAuthed[keyIndex];
            pthread_mutex_unlock(&g_auth_mgr.mutex);
            return result;
        }
    }

    pthread_mutex_unlock(&g_auth_mgr.mutex);
    return 0;
}

int auth_manager_has_kek_access(HANDLE session, int keyIndex) {
    if (!g_auth_mgr.initialized || keyIndex < 0 || keyIndex >= MAX_KEY_INDEX) {
        return 0;
    }

    pthread_mutex_lock(&g_auth_mgr.mutex);

    for (int i = 0; i < g_auth_mgr.stateCount; i++) {
        if (g_auth_mgr.states[i].session == session) {
            int result = g_auth_mgr.states[i].kekAuthed[keyIndex];
            pthread_mutex_unlock(&g_auth_mgr.mutex);
            return result;
        }
    }

    pthread_mutex_unlock(&g_auth_mgr.mutex);
    return 0;
}

void auth_manager_release_all(HANDLE session) {
    if (!g_auth_mgr.initialized || session == NULL) {
        return;
    }

    pthread_mutex_lock(&g_auth_mgr.mutex);

    for (int i = 0; i < g_auth_mgr.stateCount; i++) {
        if (g_auth_mgr.states[i].session == session) {
            SessionAuthState *state = &g_auth_mgr.states[i];

            for (int j = 0; j < MAX_KEY_INDEX; j++) {
                if (state->privateKeyAuthed[j] &&
                    g_sdf_functions.SDF_ReleasePrivateKeyAccessRight != NULL) {
                    g_sdf_functions.SDF_ReleasePrivateKeyAccessRight(session, (ULONG)j);
                }
                if (state->kekAuthed[j] &&
                    g_sdf_functions.SDF_ReleaseKEKAccessRight != NULL) {
                    g_sdf_functions.SDF_ReleaseKEKAccessRight(session, (ULONG)j);
                }
            }

            memset(state, 0, sizeof(SessionAuthState));
            break;
        }
    }

    pthread_mutex_unlock(&g_auth_mgr.mutex);
}
