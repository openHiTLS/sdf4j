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

package org.openhitls.sdf4j;

/**
 * SDF日志回调接口
 * SDF Logger Callback Interface
 *
 * <p>该接口用于接收来自Native层的日志消息
 * <p>This interface is used to receive log messages from the native layer
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
public interface SDFLogger {

    /**
     * 日志回调方法
     * Log callback method
     *
     * @param message 日志消息（已包含时间戳、进程ID和线程ID）
     *                Log message (already includes timestamp, PID and TID)
     */
    void log(String message);
}
