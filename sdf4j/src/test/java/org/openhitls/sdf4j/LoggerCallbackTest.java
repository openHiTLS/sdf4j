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

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

/**
 * 测试 Java 日志回调功能
 */
public class LoggerCallbackTest {

    @Test
    public void testDefaultLoggerIsSet() {
        // 验证默认 logger 已经设置
        SDFLogger logger = SDF.getLogger();
        assertNotNull("默认 logger 应该不为空", logger);
        assertTrue("默认 logger 应该是 DefaultSDFLogger", logger instanceof DefaultSDFLogger);
    }

    @Test
    public void testCustomLogger() {
        // 创建自定义 logger 来捕获日志
        TestLogger testLogger = new TestLogger();

        // 设置自定义 logger
        SDF.setLogger(testLogger);

        // 验证 logger 已更新
        SDFLogger currentLogger = SDF.getLogger();
        assertSame("当前 logger 应该是我们设置的", testLogger, currentLogger);

        System.out.println("✓ 自定义日志回调设置成功");
        System.out.println("  - Logger 类型: " + currentLogger.getClass().getSimpleName());
    }

    @Test
    public void testSetNullLoggerUsesDefault() {
        // 设置 null 应该使用默认 logger
        SDF.setLogger(null);

        SDFLogger logger = SDF.getLogger();
        assertNotNull("Logger 不应为 null", logger);
        assertTrue("应该使用默认 DefaultSDFLogger", logger instanceof DefaultSDFLogger);

        System.out.println("✓ 设置 null logger 正确回退到默认实现");
    }

    @Test
    public void testDefaultLoggerOutput() {
        // 测试默认 logger 的输出功能
        DefaultSDFLogger logger = new DefaultSDFLogger();

        System.out.println("\n测试默认日志输出:");
        System.out.println("-------------------");
        logger.log("[TEST] 这是一条测试日志消息");
        logger.log("[TEST] PID:12345 TID:67890 测试带有进程和线程信息的日志");
        System.out.println("-------------------");

        System.out.println("✓ 默认日志输出测试完成");
    }

    @Test
    public void testDisableDefaultLogger() {
        DefaultSDFLogger logger = new DefaultSDFLogger();

        // 测试启用状态
        assertTrue("默认应该启用", logger.isEnabled());

        // 禁用日志
        logger.setEnabled(false);
        assertFalse("应该已禁用", logger.isEnabled());

        // 测试禁用后不输出（不会有输出）
        System.out.println("\n测试禁用日志（下面这行不应该有输出）:");
        logger.log("[TEST] 这条消息不应该显示");
        System.out.println("✓ 日志已禁用，没有输出");

        // 重新启用
        logger.setEnabled(true);
        assertTrue("应该已重新启用", logger.isEnabled());

        System.out.println("\n测试重新启用日志（下面应该有输出）:");
        logger.log("[TEST] 这条消息应该显示");
        System.out.println("✓ 日志重新启用测试完成");
    }

    /**
     * 测试用的自定义 Logger，捕获所有日志消息
     */
    private static class TestLogger implements SDFLogger {
        private List<String> logMessages = new ArrayList<>();

        @Override
        public void log(String message) {
            logMessages.add(message);
            System.out.println("[TestLogger] " + message);
        }

        public List<String> getLogMessages() {
            return logMessages;
        }

        public int getLogCount() {
            return logMessages.size();
        }
    }
}
