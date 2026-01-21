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

#ifndef SDF4J_JCE_AUTH_MANAGER_H
#define SDF4J_JCE_AUTH_MANAGER_H

#include "sdf.h"
#include "jce_common.h"
#include <pthread.h>

#define MAX_KEY_INDEX 32
#define MAX_SESSIONS  64

/**
 * 会话权限状态
 */
typedef struct {
    HANDLE session;
    int privateKeyAuthed[MAX_KEY_INDEX];
    int kekAuthed[MAX_KEY_INDEX];
} SessionAuthState;

/**
 * 初始化权限管理器
 *
 * @param sessionCount 最大会话数
 * @return SDR_OK成功
 */
int auth_manager_init(int sessionCount);

/**
 * 销毁权限管理器
 */
void auth_manager_destroy(void);

/**
 * 获取私钥访问权限
 * 如果已有权限则直接返回成功
 *
 * @param session 会话句柄
 * @param keyIndex 密钥索引
 * @param pin PIN码
 * @param pinLen PIN长度
 * @return SDR_OK成功
 */
int auth_manager_get_private_key_access(HANDLE session, int keyIndex,
                                         const char *pin, int pinLen);

/**
 * 释放私钥访问权限
 *
 * @param session 会话句柄
 * @param keyIndex 密钥索引
 * @return SDR_OK成功
 */
int auth_manager_release_private_key_access(HANDLE session, int keyIndex);

/**
 * 获取KEK访问权限
 *
 * @param session 会话句柄
 * @param keyIndex KEK索引
 * @param pin PIN码
 * @param pinLen PIN长度
 * @return SDR_OK成功
 */
int auth_manager_get_kek_access(HANDLE session, int keyIndex,
                                 const char *pin, int pinLen);

/**
 * 释放KEK访问权限
 *
 * @param session 会话句柄
 * @param keyIndex KEK索引
 * @return SDR_OK成功
 */
int auth_manager_release_kek_access(HANDLE session, int keyIndex);

/**
 * 检查是否已有私钥访问权限
 *
 * @param session 会话句柄
 * @param keyIndex 密钥索引
 * @return 1有权限，0无权限
 */
int auth_manager_has_private_key_access(HANDLE session, int keyIndex);

/**
 * 检查是否已有KEK访问权限
 *
 * @param session 会话句柄
 * @param keyIndex KEK索引
 * @return 1有权限，0无权限
 */
int auth_manager_has_kek_access(HANDLE session, int keyIndex);

/**
 * 释放会话的所有权限
 *
 * @param session 会话句柄
 */
void auth_manager_release_all(HANDLE session);

#endif /* SDF4J_JCE_AUTH_MANAGER_H */
