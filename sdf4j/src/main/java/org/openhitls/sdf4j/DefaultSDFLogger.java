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
 * SDF默认日志实现
 * Default SDF Logger Implementation
 *
 * <p>该实现将日志输出到标准输出（System.out）
 * <p>This implementation outputs logs to standard output (System.out)
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
public class DefaultSDFLogger implements SDFLogger {

    /**
     * 是否启用日志输出
     */
    private boolean enabled = true;

    /**
     * 创建默认日志实现（默认启用）
     */
    public DefaultSDFLogger() {
        this(true);
    }

    /**
     * 创建默认日志实现
     *
     * @param enabled 是否启用日志输出
     */
    public DefaultSDFLogger(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * 设置是否启用日志输出
     *
     * @param enabled 是否启用
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * 检查是否启用日志输出
     *
     * @return 是否启用
     */
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public void log(String message) {
        if (enabled) {
            System.out.println(message);
        }
    }
}
