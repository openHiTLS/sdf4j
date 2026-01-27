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

#include "sdf_log.h"

/**
 * 设置Native日志回调对象
 * Class:     org_openhitls_sdf4j_SDF
 * Method:    setNativeLogger
 * Signature: (Lorg/openhitls/sdf4j/SDFLogger;)V
 */
JNIEXPORT void JNICALL Java_org_openhitls_sdf4j_SDF_setNativeLogger
  (JNIEnv *env, jclass cls, jobject logger) {
    (void)cls;  // 未使用的参数
    sdf_log_set_java_logger(env, logger);
    SDF_JNI_LOG("Java logger callback has been set");
}

/**
 * 启用/禁用文件日志
 * Class:     org_openhitls_sdf4j_SDF
 * Method:    setFileLoggingEnabled
 * Signature: (Z)V
 */
JNIEXPORT void JNICALL Java_org_openhitls_sdf4j_SDF_setFileLoggingEnabled
  (JNIEnv *env, jclass cls, jboolean enable) {
    (void)env;  // 未使用的参数
    (void)cls;  // 未使用的参数
    sdf_log_set_file_enabled(enable ? 1 : 0);
    SDF_JNI_LOG("File logging has been %s", enable ? "enabled" : "disabled");
}

/**
 * 启用/禁用Java回调日志
 * Class:     org_openhitls_sdf4j_SDF
 * Method:    setJavaLoggingEnabled
 * Signature: (Z)V
 */
JNIEXPORT void JNICALL Java_org_openhitls_sdf4j_SDF_setJavaLoggingEnabled
  (JNIEnv *env, jclass cls, jboolean enable) {
    (void)env;  // 未使用的参数
    (void)cls;  // 未使用的参数
    sdf_log_set_java_enabled(enable ? 1 : 0);
    SDF_JNI_LOG("Java callback logging has been %s", enable ? "enabled" : "disabled");
}
