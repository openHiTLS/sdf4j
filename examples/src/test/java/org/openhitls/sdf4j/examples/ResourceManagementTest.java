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

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openhitls.sdf4j.*;
import org.openhitls.sdf4j.constants.AlgorithmID;
import org.openhitls.sdf4j.constants.ErrorCode;
import org.openhitls.sdf4j.types.*;

import static org.junit.Assert.*;

/**
 * SDF4J 资源管理测试
 * Resource Management Test
 *
 * <p>包含以下测试场景：
 * <p>Test scenarios include:
 * <ul>
 *   <li>手动关闭</li>
 *   <li>自动清理</li>
 *   <li>异常情况下的自动清理</li>
 *   <li>多个设备/会话</li>
 *   <li>测试 KeyHandle 自动释放</li>
 * </ul>
 */
public class ResourceManagementTest {

    @BeforeClass
    public static void setUpClass() {
        System.out.println("========================================");
        System.out.println("SDF4J 资源管理测试");
        System.out.println("Resource Management Test");
        System.out.println("========================================\n");
    }

    @Before
    public void setUp() {
        SDF.setLogger(message -> System.out.println("[LOG] " + message));
        SDF.setFileLoggingEnabled(false);
        SDF.setJavaLoggingEnabled(false);
    }

    /**
     * 手动关闭
     */
    @Test
    public void testManualClose() throws SDFException {
        System.out.println("--- 手动关闭 ---");
        SDF sdf1 = new SDF();
        long deviceHandle = sdf1.SDF_OpenDevice();
        assertNotEquals("设备句柄有效", 0, deviceHandle);
        System.out.println("打开设备成功: handle=0x" + Long.toHexString(deviceHandle));

        long sessionHandle = sdf1.SDF_OpenSession(deviceHandle);
        assertNotEquals("会话句柄有效", 0, sessionHandle);
        System.out.println("打开会话成功: handle=0x" + Long.toHexString(sessionHandle));

        // 获取设备信息
        DeviceInfo info = sdf1.SDF_GetDeviceInfo(sessionHandle);
        assertNotNull("设备信息应该不为空", info);
        System.out.println("获取设备信息: " + info.getIssuerName());

        // 产生随机数
        byte[] random = sdf1.SDF_GenerateRandom(sessionHandle, 16);
        assertNotNull("随机数应该不为空", random);
        assertEquals("随机数长度应该正确", 16, random.length);
        System.out.println("产生随机数: " + bytesToHex(random));

        // 手动关闭
        sdf1.SDF_CloseSession(sessionHandle);
        System.out.println("手动关闭会话成功");

        sdf1.SDF_CloseDevice(deviceHandle);
        System.out.println("手动关闭设备成功\n");
    }

    /**
     * 自动清理
     */
    @Test
    public void testAutoCleanup() throws SDFException {
        SDF sdf2 = new SDF();
        System.out.println("--- 自动清理 ---");
        long deviceHandle = sdf2.SDF_OpenDevice();
        assertNotEquals("设备句柄有效", 0, deviceHandle);
        System.out.println("打开设备成功: handle=0x" + Long.toHexString(deviceHandle));

        long sessionHandle = sdf2.SDF_OpenSession(deviceHandle);
        assertNotEquals("会话句柄有效", 0, sessionHandle);
        System.out.println("打开会话成功: handle=0x" + Long.toHexString(sessionHandle));

        // 获取设备信息
        DeviceInfo info = sdf2.SDF_GetDeviceInfo(sessionHandle);
        assertNotNull("设备信息应该不为空", info);
        System.out.println("获取设备信息: " + info.getIssuerName());
        // 直接关闭会话，保证session也能被关闭
        sdf2.SDF_CloseDevice(deviceHandle);
    }

    /**
     * 异常情况下的自动清理
     */
    @Test
    public void testExceptionHandling() throws SDFException {
        System.out.println("--- 异常情况下的自动清理 ---");
        SDF sdf3 = new SDF();
        long deviceHandle = sdf3.SDF_OpenDevice();
        try {
            // 打开设备
            assertNotEquals("设备句柄有效", 0, deviceHandle);
            System.out.println("打开设备成功: handle=0x" + Long.toHexString(deviceHandle));

            long sessionHandle = sdf3.SDF_OpenSession(deviceHandle);
            assertNotEquals("会话句柄有效", 0, sessionHandle);
            System.out.println("打开会话成功: handle=0x" + Long.toHexString(sessionHandle));

            // 获取设备信息
            DeviceInfo info = sdf3.SDF_GetDeviceInfo(sessionHandle);
            assertNotNull("设备信息应该不为空", info);

            // 模拟异常情况
            throw new RuntimeException("模拟异常");
        } catch (RuntimeException e) {
            System.out.println("捕获异常: " + e.getMessage());
           // 直接关闭设备，保证session也能被关闭
            sdf3.SDF_CloseDevice(deviceHandle);
            System.out.println("自动关闭设备成功\n");
        }
    }

    /**
     * 多个设备/会话
     */
    @Test
    public void testNestedUsage() throws SDFException {
        SDF sdf5 = new SDF();
        System.out.println("--- 嵌套资源释放 ---");

        // 外层设备
        System.out.println("打开设备");
        long deviceHandle = sdf5.SDF_OpenDevice();
        assertNotEquals("设备句柄有效", 0, deviceHandle);

        // 内层会话 1
        System.out.println("  打开会话 1");
        long sessionHandle1 = sdf5.SDF_OpenSession(deviceHandle);
        assertNotEquals("会话句柄有效", 0, sessionHandle1);
        DeviceInfo info1 = sdf5.SDF_GetDeviceInfo(sessionHandle1);
        System.out.println("  设备信息: " + info1.getIssuerName());

        // 内层会话 2
        System.out.println("  打开会话 2");
        long sessionHandle2 = sdf5.SDF_OpenSession(deviceHandle);
        assertNotEquals("会话句柄有效", 0, sessionHandle2);
        byte[] random = sdf5.SDF_GenerateRandom(sessionHandle2, 8);
        System.out.println("  随机数: " + bytesToHex(random));
        sdf5.SDF_CloseSession(sessionHandle1);
        System.out.println("  会话 1 已手动关闭");
        // session1 关闭，session2 自动关闭
        sdf5.SDF_CloseDevice(deviceHandle);
        System.out.println("设备 已手动关闭\n");
    }

    /**
     * 测试 KeyEncryptionResult 自动释放
     * 创建密钥句柄后不手动调用 destroy，验证自动释放功能
     */
    @Test
    public void testKeyHandleAutoCleanup() throws SDFException {
        SDF sdf6 = new SDF();
        System.out.println("--- KeyHandle 自动释放测试 ---");

        long deviceHandle = sdf6.SDF_OpenDevice();
        long sessionHandle = sdf6.SDF_OpenSession(deviceHandle);

        try {
            // 创建密钥句柄（不手动调用 destroy）
            System.out.println("创建密钥句柄，不手动调用 destroy");
            KeyEncryptionResult result = sdf6.SDF_GenerateKeyWithIPK_ECC(sessionHandle, 1, 128);
            assertNotNull("密钥生成结果不应为空", result);
            assertTrue("密钥句柄应大于 0", result.getKeyHandle() > 0);
            assertNotNull("加密密钥不应为空", result.getEncryptedKey());
            
            long keyHandle = result.getKeyHandle();
            System.out.println("密钥句柄创建成功: keyHandle=0x" + Long.toHexString(keyHandle).toUpperCase());
            System.out.println("加密密钥长度: " + result.getEncryptedKey().length + " bytes");
            // 使用密钥进行加密操作
            byte[] testData = new byte[16];
            byte[] encrypted = sdf6.SDF_Encrypt(sessionHandle, keyHandle, 
                    AlgorithmID.SGD_SM4_ECB, null, testData);
            assertNotNull("加密结果不应为空", encrypted);
            System.out.println("使用密钥加密成功");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] " + e.getMessage() + "\n");
                return;
            }
            throw e;
        }
        // 直接关闭设备，保证session和key也能被关闭释放
        sdf6.SDF_CloseDevice(deviceHandle);
    }

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}

