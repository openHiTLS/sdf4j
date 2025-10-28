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

package org.openhitls.sdf4j.examples;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.openhitls.sdf4j.*;
import org.openhitls.sdf4j.constants.ErrorCode;
import org.openhitls.sdf4j.types.*;

import static org.junit.Assert.*;

/**
 * SDF4J 基础示例测试
 * 演示设备打开、会话管理和基本操作
 */
public class BasicExampleTest {

    private SDF sdf;
    private long deviceHandle;
    private long sessionHandle;

    @Before
    public void setUp() throws SDFException {
        System.out.println("========================================");
        System.out.println("SDF4J 基础示例");
        System.out.println("========================================\n");

        // 启用 native 日志输出
        SDF.setLogger(message -> System.out.println("🔔 [NATIVE] " + message));
        SDF.setFileLoggingEnabled(false);   // 禁用文件日志
        SDF.setJavaLoggingEnabled(true);    // 启用 Java 回调日志

        sdf = new SDF();
        deviceHandle = 0;
        sessionHandle = 0;
    }

    @After
    public void tearDown() {
        // 关闭会话和设备
        try {
            if (sessionHandle != 0) {
                System.out.println("\n关闭会话...");
                sdf.SDF_CloseSession(sessionHandle);
            }
            if (deviceHandle != 0) {
                System.out.println("关闭设备...");
                sdf.SDF_CloseDevice(deviceHandle);
            }
            System.out.println("✓ 资源清理完成");
        } catch (SDFException e) {
            System.err.println("关闭资源失败: " + e.getMessage());
        }
    }

    @Test
    public void testDeviceAndSessionManagement() throws SDFException {
        // 1. 打开设备
        System.out.println("1. 打开设备...");
        deviceHandle = sdf.SDF_OpenDevice();
        System.out.println("   设备句柄: " + deviceHandle);
        System.out.println("   ✓ 设备打开成功\n");
        assertTrue("设备句柄应该非零", deviceHandle != 0);

        // 2. 打开会话
        System.out.println("2. 打开会话...");
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);
        System.out.println("   会话句柄: " + sessionHandle);
        System.out.println("   ✓ 会话打开成功\n");
        assertTrue("会话句柄应该非零", sessionHandle != 0);
    }

    @Test
    public void testGetDeviceInfo() throws SDFException {
        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        // 3. 获取设备信息
        System.out.println("3. 获取设备信息...");
        DeviceInfo info = sdf.SDF_GetDeviceInfo(sessionHandle);
        assertNotNull("设备信息不应为空", info);

        System.out.println("   厂商名称: " + info.getIssuerName());
        System.out.println("   设备型号: " + info.getDeviceName());
        System.out.println("   设备序列号: " + info.getDeviceSerial());
        System.out.println("   设备版本: 0x" + Long.toHexString(info.getDeviceVersion()));
        System.out.println("   标准版本: 0x" + Long.toHexString(info.getStandardVersion()));
        System.out.println("   缓冲区大小: " + info.getBufferSize() + " bytes");
        System.out.println("   ✓ 设备信息获取成功\n");

        assertNotNull("厂商名称不应为空", info.getIssuerName());
        assertNotNull("设备型号不应为空", info.getDeviceName());
    }

    @Test
    public void testGenerateRandom() throws SDFException {
        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 4. 生成随机数
            System.out.println("4. 生成随机数...");
            byte[] random16 = sdf.SDF_GenerateRandom(sessionHandle, 16);
            System.out.println("   16字节随机数: " + bytesToHex(random16));
            assertNotNull("16字节随机数不应为空", random16);
            assertEquals("随机数长度应为16字节", 16, random16.length);

            byte[] random32 = sdf.SDF_GenerateRandom(sessionHandle, 32);
            System.out.println("   32字节随机数: " + bytesToHex(random32));
            assertNotNull("32字节随机数不应为空", random32);
            assertEquals("随机数长度应为32字节", 32, random32.length);
            System.out.println("   ✓ 随机数生成成功\n");
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("   ⚠ 随机数生成功能未实现（这是正常的）");
            } else {
                throw e;
            }
        }
    }

    @Test
    public void testMultipleSessions() throws SDFException {
        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        // 5. 测试多会话
        System.out.println("5. 测试多会话...");
        long session2 = sdf.SDF_OpenSession(deviceHandle);
        System.out.println("   第二个会话句柄: " + session2);
        assertTrue("第二个会话句柄应该非零", session2 != 0);
        assertNotEquals("两个会话句柄应该不同", sessionHandle, session2);

        try {
            // 在第二个会话中生成随机数
            byte[] random = sdf.SDF_GenerateRandom(session2, 16);
            System.out.println("   第二个会话中的随机数: " + bytesToHex(random));
            assertNotNull("随机数不应为空", random);
            assertEquals("随机数长度应为16字节", 16, random.length);
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("   ⚠ 随机数生成功能未实现（这是正常的）");
            } else {
                throw e;
            }
        }

        // 关闭第二个会话
        sdf.SDF_CloseSession(session2);
        System.out.println("   ✓ 多会话测试成功\n");

        System.out.println("========================================");
        System.out.println("所有操作完成！");
        System.out.println("========================================");
    }

    /**
     * 字节数组转十六进制字符串
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
