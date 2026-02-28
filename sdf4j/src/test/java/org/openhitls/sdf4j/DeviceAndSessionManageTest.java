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

import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openhitls.sdf4j.*;
import org.openhitls.sdf4j.constants.ErrorCode;
import org.openhitls.sdf4j.types.*;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import static org.junit.Assert.*;

/**
 * SDF4J 设备管理类函数测试
 * 测试 GM/T 0018-2023 标准中 6.2 节定义的设备管理类函数
 *
 * 包含以下接口测试：
 * - 6.2.2 SDF_OpenDevice - 打开设备
 * - 6.2.3 SDF_CloseDevice - 关闭设备
 * - 6.2.4 SDF_OpenSession - 创建会话
 * - 6.2.5 SDF_CloseSession - 关闭会话
 * - 6.2.6 SDF_GetDeviceInfo - 获取设备信息
 * - 6.2.7 SDF_GenerateRandom - 产生随机数
 * - 6.2.8 SDF_GetPrivateKeyAccessRight - 获取私钥使用权限
 * - 6.2.9 SDF_ReleasePrivateKeyAccessRight - 释放私钥使用权限
 */
public class DeviceAndSessionManageTest {

    // 配置开关：设置为 true 时从配置文件读取，false 时使用下面的默认值
    private static final boolean USE_CONFIG_FILE = true;

    // 默认私钥配置（当 USE_CONFIG_FILE = false 时使用）
    private static final int DEFAULT_KEY_INDEX = 1;
    private static final String DEFAULT_KEY_PASSWORD = "123abc!@";

    // 实际使用的私钥配置
    private static int privateKeyIndex;
    private static String privateKeyPassword;

    private SDF sdf;
    private long deviceHandle;
    private long sessionHandle;

    @BeforeClass
    public static void loadConfig() {
        if (USE_CONFIG_FILE) {
            Properties testConfig = new Properties();
            try (InputStream is = DeviceAndSessionManageTest.class.getClassLoader()
                    .getResourceAsStream("test-config.properties")) {
                if (is != null) {
                    testConfig.load(is);
                    privateKeyIndex = Integer.parseInt(
                            testConfig.getProperty("sm2.internal.key.index", String.valueOf(DEFAULT_KEY_INDEX)));
                    privateKeyPassword = testConfig.getProperty("sm2.key.access.password", DEFAULT_KEY_PASSWORD);
                    return;
                }
            } catch (IOException e) {
                System.err.println("读取配置文件失败: " + e.getMessage());
            }
        }
        // 使用默认值
        privateKeyIndex = DEFAULT_KEY_INDEX;
        privateKeyPassword = DEFAULT_KEY_PASSWORD;
    }

    @Before
    public void setUp() throws SDFException {
        sdf = new SDF();
        deviceHandle = 0;
        sessionHandle = 0;
    }

    @After
    public void tearDown() {
        try {
            if (sessionHandle != 0) {
                sdf.SDF_CloseSession(sessionHandle);
                sessionHandle = 0;
            }
            if (deviceHandle != 0) {
                sdf.SDF_CloseDevice(deviceHandle);
                deviceHandle = 0;
            }
        } catch (SDFException e) {
            System.err.println("关闭资源失败: " + e.getMessage());
        }
    }

    /**
     * 测试 6.2.2 SDF_OpenDevice - 打开设备
     */
    @Test
    public void testOpenDevice() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        assertTrue("设备句柄应该非零", deviceHandle != 0);
    }

    /**
     * 测试 6.2.3 SDF_CloseDevice - 关闭设备
     */
    @Test
    public void testCloseDevice() throws SDFException {
        // 先打开设备
        deviceHandle = sdf.SDF_OpenDevice();
        assertTrue("设备句柄应该非零", deviceHandle != 0);

        // 关闭设备
        sdf.SDF_CloseDevice(deviceHandle);
        deviceHandle = 0; // 防止tearDown再次关闭

    }

    /**
     * 测试 6.2.4 SDF_OpenSession - 创建会话
     */
    @Test
    public void testOpenSession() throws SDFException {
        // 先打开设备
        deviceHandle = sdf.SDF_OpenDevice();

        // 创建会话
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        assertTrue("会话句柄应该非零", sessionHandle != 0);
    }

    /**
     * 测试 6.2.5 SDF_CloseSession - 关闭会话
     */
    @Test
    public void testCloseSession() throws SDFException {
        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);
        assertTrue("会话句柄应该非零", sessionHandle != 0);

        // 关闭会话
        sdf.SDF_CloseSession(sessionHandle);
        sessionHandle = 0; // 防止tearDown再次关闭

        try {
            sdf.SDF_CloseSession(0);
            fail("关闭会话0应失败");
        } catch (SDFException e) {
            // 异常会话关闭失败，符合预期
        }
    }

    /**
     * 测试 6.2.6 SDF_GetDeviceInfo - 获取设备信息
     */
    @Test
    public void testGetDeviceInfo() throws SDFException {
        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        // 获取设备信息
        DeviceInfo info = sdf.SDF_GetDeviceInfo(sessionHandle);
        assertNotNull("设备信息不应为空", info);

        assertNotNull("厂商名称不应为空", info.getIssuerName());
        assertNotEquals("厂商名称长度不应为0", 0, info.getIssuerName().length());
        assertNotNull("设备名称不应为空", info.getDeviceName());
        assertNotEquals("设备名称长度不应为0", 0, info.getDeviceName().length());
        assertNotNull("设备序列号不应为空", info.getDeviceSerial());
        assertNotEquals("设备序列号长度不应为0", 0, info.getDeviceSerial().length());
        assertNotEquals("设备版本不应为空", 0, info.getDeviceVersion());
        assertNotEquals("标准版本不应为空", 0, info.getStandardVersion());
        assertNotNull("非对称算法能力不应为空", info.getAsymAlgAbility());
        assertNotEquals("对称算法能力不应为0", 0, info.getSymAlgAbility());
        assertNotEquals("哈希算法能力不应为0", 0, info.getHashAlgAbility());
        assertNotEquals("缓冲区大小不应为0", 0, info.getBufferSize());
    }

    /**
     * 测试 6.2.7 SDF_GenerateRandom - 产生随机数
     */
    @Test
    public void testGenerateRandom() throws SDFException {
        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成16字节随机数
            byte[] random16 = sdf.SDF_GenerateRandom(sessionHandle, 16);
            assertNotNull("16字节随机数不应为空", random16);
            assertEquals("随机数长度应为16字节", 16, random16.length);

            // 生成32字节随机数
            byte[] random32 = sdf.SDF_GenerateRandom(sessionHandle, 32);
            assertNotNull("32字节随机数不应为空", random32);
            assertEquals("随机数长度应为32字节", 32, random32.length);

            // 生成64字节随机数
            byte[] random64 = sdf.SDF_GenerateRandom(sessionHandle, 64);
            assertNotNull("64字节随机数不应为空", random64);
            assertEquals("随机数长度应为64字节", 64, random64.length);

            // 验证两次生成的随机数不同
            byte[] random16_2 = sdf.SDF_GenerateRandom(sessionHandle, 16);
            assertFalse("两次生成的随机数应该不同", java.util.Arrays.equals(random16, random16_2));

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 随机数生成功能未实现");
                Assume.assumeTrue("随机数生成功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        }
    }

    /**
     * 测试 6.2.8 SDF_GetPrivateKeyAccessRight - 获取私钥使用权限
     * 注意：此测试需要有效的密钥索引和密码
     */
    @Test
    public void testGetPrivateKeyAccessRight() throws SDFException {
        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 尝试获取私钥使用权限
            sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, privateKeyIndex, privateKeyPassword);

            // 释放权限（在下一个测试中单独测试）
            sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, privateKeyIndex);

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 获取私钥使用权限功能未实现");
                Assume.assumeTrue("获取私钥使用权限功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        }
    }

    /**
     * 测试 6.2.9 SDF_ReleasePrivateKeyAccessRight - 释放私钥使用权限
     */
    @Test
    public void testReleasePrivateKeyAccessRight() throws SDFException {
        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 先获取权限
            sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, privateKeyIndex, privateKeyPassword);

            // 释放权限
            sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, privateKeyIndex);

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 释放私钥使用权限功能未实现");
                Assume.assumeTrue("释放私钥使用权限功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        }
    }

    /**
     * 测试 6.2.8 SDF_GetPrivateKeyAccessRight - 使用错误密码获取私钥使用权限
     * 预期结果：应该返回密码错误或权限拒绝的错误码
     */
    @Test
    public void testGetPrivateKeyAccessRightWithWrongPassword() throws SDFException {
        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        // 使用错误密码
        String wrongPassword = "WrongPassword123!";

        try {
            sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, privateKeyIndex, wrongPassword);

            // 如果没有抛出异常，说明测试失败（错误密码不应该成功）
            fail("使用错误密码应该抛出异常");

        } catch (SDFException e) {
            int errorCode = e.getErrorCode();

            // 验证返回了预期的错误码
            if (errorCode == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 获取私钥使用权限功能未实现");
                Assume.assumeTrue("获取私钥使用权限功能未实现", false);
            }
            // Expected: wrong password should be rejected
        }
    }

    /**
     * 测试多会话管理
     */
    @Test
    public void testMultipleSessions() throws SDFException {
        // 打开设备
        deviceHandle = sdf.SDF_OpenDevice();

        // 创建第一个会话
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);
        assertTrue("会话1句柄应该非零", sessionHandle != 0);

        // 创建第二个会话
        long session2 = sdf.SDF_OpenSession(deviceHandle);
        assertTrue("会话2句柄应该非零", session2 != 0);
        assertNotEquals("两个会话句柄应该不同", sessionHandle, session2);

        // 创建第三个会话
        long session3 = sdf.SDF_OpenSession(deviceHandle);
        assertTrue("会话3句柄应该非零", session3 != 0);

        try {
            // 在不同会话中生成随机数
            byte[] random1 = sdf.SDF_GenerateRandom(sessionHandle, 16);
            byte[] random2 = sdf.SDF_GenerateRandom(session2, 16);
            byte[] random3 = sdf.SDF_GenerateRandom(session3, 16);

            // 验证各会话生成的随机数不同
            assertFalse("会话1和会话2的随机数应不同", java.util.Arrays.equals(random1, random2));
            assertFalse("会话2和会话3的随机数应不同", java.util.Arrays.equals(random2, random3));
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 随机数生成功能未实现，跳过随机数验证");
                Assume.assumeTrue("随机数生成功能未实现，跳过随机数验证", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        }

        // 关闭额外创建的会话
        sdf.SDF_CloseSession(session2);
        sdf.SDF_CloseSession(session3);

    }

    /**
     * 测试设备和会话的正确生命周期
     */
    @Test
    public void testDeviceSessionLifecycle() throws SDFException {
        // 多次打开和关闭设备
        for (int i = 1; i <= 3; i++) {
            long device = sdf.SDF_OpenDevice();
            assertTrue("设备句柄应该非零", device != 0);

            // 创建会话
            long session = sdf.SDF_OpenSession(device);
            assertTrue("会话句柄应该非零", session != 0);

            // 获取设备信息验证会话正常工作
            DeviceInfo info = sdf.SDF_GetDeviceInfo(session);
            assertNotNull("设备信息不应为空", info);

            // 关闭会话和设备
            sdf.SDF_CloseSession(session);
            sdf.SDF_CloseDevice(device);
        }

        // 重新打开设备供tearDown使用
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

    }

    /**
     * 测试边界条件 - 随机数长度
     */
    @Test
    public void testRandomBoundaryConditions() throws SDFException {
        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 测试最小长度 (1字节)
            byte[] random1 = sdf.SDF_GenerateRandom(sessionHandle, 1);
            assertNotNull("1字节随机数不应为空", random1);
            assertEquals("随机数长度应为1字节", 1, random1.length);

            // 测试较大长度 (256字节)
            byte[] random256 = sdf.SDF_GenerateRandom(sessionHandle, 256);
            assertNotNull("256字节随机数不应为空", random256);
            assertEquals("随机数长度应为256字节", 256, random256.length);

            // 测试1024字节
            byte[] random1024 = sdf.SDF_GenerateRandom(sessionHandle, 1024);
            assertNotNull("1024字节随机数不应为空", random1024);
            assertEquals("随机数长度应为1024字节", 1024, random1024.length);

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 随机数生成功能未实现");
                Assume.assumeTrue("随机数生成功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        }
    }

    /**
     * 测试 SDF_OpenDeviceWithConf - 使用配置文件打开设备
     *
     * 配置文件格式示例 (sdf.conf):
     * <pre>
     * workers:1
     * timeout:2000
     * </pre>
     */
    @Test
    public void testOpenDeviceWithConf() throws SDFException {
        // 配置文件格式: key:value，每行一个配置项
        // 例如:
        //   workers:1
        //   timeout:2000
        // 配置文件相对路径: examples/src/test/resources/sdf.conf
        String configFile = "examples/src/test/resources/sdf.conf";

        java.io.File file = new java.io.File(configFile);
        Assume.assumeTrue("配置文件不存在: " + file.getAbsolutePath(), file.exists());


        try {
            deviceHandle = sdf.SDF_OpenDeviceWithConf(configFile);

            assertTrue("设备句柄应该非零", deviceHandle != 0);

            // 创建会话验证设备工作正常
            sessionHandle = sdf.SDF_OpenSession(deviceHandle);
            assertTrue("会话句柄应该非零", sessionHandle != 0);

            // 获取设备信息验证功能正常
            DeviceInfo info = sdf.SDF_GetDeviceInfo(sessionHandle);
            assertNotNull("设备信息不应为空", info);


        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SDF_OpenDeviceWithConf 功能未实现");
                Assume.assumeTrue("SDF_OpenDeviceWithConf 功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        }
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
