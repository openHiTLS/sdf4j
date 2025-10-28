/*
 * Copyright (c) 2025 OpenHitls
 * SDF4J is licensed under Mulan PSL v2.
 */

package org.openhitls.sdf4j.examples;

import org.junit.Before;
import org.junit.Test;
import org.openhitls.sdf4j.SDF;
import org.openhitls.sdf4j.SDFLogger;
import org.openhitls.sdf4j.SDFException;
import org.openhitls.sdf4j.types.DeviceInfo;

import java.util.ArrayList;
import java.util.List;

/**
 * 测试 Native 日志回调功能
 */
public class NativeLoggerTest {

    private static class CaptureLogger implements SDFLogger {
        private final List<String> logs = new ArrayList<>();

        @Override
        public void log(String message) {
            logs.add(message);
            // 同时打印到控制台，加上明显的标记
            System.out.println("🔔 [NATIVE-LOG-CALLBACK] " + message);
        }

        public List<String> getLogs() {
            return logs;
        }

        public void clear() {
            logs.clear();
        }
    }

    @Before
    public void setUp() {
        System.out.println("\n========================================");
        System.out.println("Native 日志回调测试");
        System.out.println("========================================\n");
    }

    @Test
    public void testNativeLoggerCallback() throws SDFException {
        // 创建自定义 logger 来捕获 native 日志
        CaptureLogger captureLogger = new CaptureLogger();

        System.out.println("步骤 1: 设置自定义日志回调...");
        SDF.setLogger(captureLogger);
        SDF.setFileLoggingEnabled(false);  // 禁用文件日志
        SDF.setJavaLoggingEnabled(true);   // 启用 Java 回调日志
        System.out.println("✓ 自定义 logger 已设置\n");

        captureLogger.clear();

        System.out.println("步骤 2: 执行 SDF 操作，触发 native 日志...");
        SDF sdf = new SDF();
        long deviceHandle = 0;
        long sessionHandle = 0;

        try {
            // 打开设备
            System.out.println("  → 调用 SDF_OpenDevice()");
            deviceHandle = sdf.SDF_OpenDevice();
            System.out.println("  ← 返回设备句柄: " + deviceHandle + "\n");

            // 打开会话
            System.out.println("  → 调用 SDF_OpenSession()");
            sessionHandle = sdf.SDF_OpenSession(deviceHandle);
            System.out.println("  ← 返回会话句柄: " + sessionHandle + "\n");

            // 获取设备信息
            System.out.println("  → 调用 SDF_GetDeviceInfo()");
            DeviceInfo info = sdf.SDF_GetDeviceInfo(sessionHandle);
            System.out.println("  ← 设备信息: " + info.getDeviceName() + "\n");

            // 尝试生成随机数
            System.out.println("  → 调用 SDF_GenerateRandom()");
            try {
                byte[] random = sdf.SDF_GenerateRandom(sessionHandle, 16);
                System.out.println("  ← 随机数长度: " + random.length + " bytes\n");
            } catch (SDFException e) {
                System.out.println("  ← 随机数生成未实现（预期的）\n");
            }

        } finally {
            // 关闭资源
            if (sessionHandle != 0) {
                System.out.println("  → 调用 SDF_CloseSession()");
                sdf.SDF_CloseSession(sessionHandle);
                System.out.println("  ← 会话已关闭\n");
            }
            if (deviceHandle != 0) {
                System.out.println("  → 调用 SDF_CloseDevice()");
                sdf.SDF_CloseDevice(deviceHandle);
                System.out.println("  ← 设备已关闭\n");
            }
        }

        System.out.println("========================================");
        System.out.println("步骤 3: 分析捕获的 native 日志");
        System.out.println("========================================");
        System.out.println("共捕获 " + captureLogger.getLogs().size() + " 条 native 日志\n");

        if (captureLogger.getLogs().isEmpty()) {
            System.out.println("⚠️  警告: 没有捕获到 native 日志！");
            System.out.println("   可能的原因:");
            System.out.println("   1. Native 日志被禁用");
            System.out.println("   2. Java 回调未正确设置");
            System.out.println("   3. Native 代码中没有调用日志函数");
        } else {
            System.out.println("✅ 成功捕获到 native 日志！");
            System.out.println("\n详细日志列表:");
            System.out.println("----------------------------------------");
            int count = 1;
            for (String log : captureLogger.getLogs()) {
                System.out.printf("[%2d] %s\n", count++, log);
            }
            System.out.println("----------------------------------------");
        }

        System.out.println("\n========================================");
        System.out.println("测试完成！");
        System.out.println("========================================\n");
    }
}
