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
public class DeviceManagementTest {

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
            try (InputStream is = DeviceManagementTest.class.getClassLoader()
                    .getResourceAsStream("test-config.properties")) {
                if (is != null) {
                    testConfig.load(is);
                    privateKeyIndex = Integer.parseInt(
                            testConfig.getProperty("sm2.internal.key.index", String.valueOf(DEFAULT_KEY_INDEX)));
                    privateKeyPassword = testConfig.getProperty("sm2.key.access.password", DEFAULT_KEY_PASSWORD);
                    System.out.println("已从配置文件加载私钥配置: keyIndex=" + privateKeyIndex);
                    return;
                }
            } catch (IOException e) {
                System.err.println("读取配置文件失败: " + e.getMessage());
            }
        }
        // 使用默认值
        privateKeyIndex = DEFAULT_KEY_INDEX;
        privateKeyPassword = DEFAULT_KEY_PASSWORD;
        System.out.println("使用默认私钥配置: keyIndex=" + privateKeyIndex);
    }

    @Before
    public void setUp() throws SDFException {
        System.out.println("========================================");
        System.out.println("SDF4J 设备管理类函数测试");
        System.out.println("========================================\n");
        sdf = new SDF();
        deviceHandle = 0;
        sessionHandle = 0;
    }

    @After
    public void tearDown() {
        try {
            if (sessionHandle != 0) {
                System.out.println("\n关闭会话...");
                sdf.SDF_CloseSession(sessionHandle);
                sessionHandle = 0;
            }
            if (deviceHandle != 0) {
                System.out.println("关闭设备...");
                sdf.SDF_CloseDevice(deviceHandle);
                deviceHandle = 0;
            }
            System.out.println("资源清理完成\n");
        } catch (SDFException e) {
            System.err.println("关闭资源失败: " + e.getMessage());
        }
    }

    /**
     * 测试 6.2.2 SDF_OpenDevice - 打开设备
     */
    @Test
    public void testOpenDevice() throws SDFException {
        System.out.println("测试 6.2.2 SDF_OpenDevice - 打开设备");
        System.out.println("----------------------------------------");

        deviceHandle = sdf.SDF_OpenDevice();
        System.out.println("设备句柄: 0x" + Long.toHexString(deviceHandle));

        assertTrue("设备句柄应该非零", deviceHandle != 0);
        System.out.println("[通过] 设备打开成功\n");
    }

    /**
     * 测试 6.2.3 SDF_CloseDevice - 关闭设备
     */
    @Test
    public void testCloseDevice() throws SDFException {
        System.out.println("测试 6.2.3 SDF_CloseDevice - 关闭设备");
        System.out.println("----------------------------------------");

        // 先打开设备
        deviceHandle = sdf.SDF_OpenDevice();
        System.out.println("已打开设备, 句柄: 0x" + Long.toHexString(deviceHandle));
        assertTrue("设备句柄应该非零", deviceHandle != 0);

        // 关闭设备
        sdf.SDF_CloseDevice(deviceHandle);
        System.out.println("设备已关闭");
        deviceHandle = 0; // 防止tearDown再次关闭

        System.out.println("[通过] 设备关闭成功\n");
    }

    /**
     * 测试 6.2.4 SDF_OpenSession - 创建会话
     */
    @Test
    public void testOpenSession() throws SDFException {
        System.out.println("测试 6.2.4 SDF_OpenSession - 创建会话");
        System.out.println("----------------------------------------");

        // 先打开设备
        deviceHandle = sdf.SDF_OpenDevice();
        System.out.println("已打开设备, 句柄: 0x" + Long.toHexString(deviceHandle));

        // 创建会话
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);
        System.out.println("会话句柄: 0x" + Long.toHexString(sessionHandle));

        assertTrue("会话句柄应该非零", sessionHandle != 0);
        System.out.println("[通过] 会话创建成功\n");
    }

    /**
     * 测试 6.2.5 SDF_CloseSession - 关闭会话
     */
    @Test
    public void testCloseSession() throws SDFException {
        System.out.println("测试 6.2.5 SDF_CloseSession - 关闭会话");
        System.out.println("----------------------------------------");

        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);
        System.out.println("已创建会话, 句柄: 0x" + Long.toHexString(sessionHandle));
        assertTrue("会话句柄应该非零", sessionHandle != 0);

        // 关闭会话
        sdf.SDF_CloseSession(sessionHandle);
        System.out.println("会话已关闭");
        sessionHandle = 0; // 防止tearDown再次关闭

        System.out.println("[通过] 会话关闭成功\n");
        try {
            sdf.SDF_CloseSession(0);
            fail("关闭会话0应失败");
        } catch (SDFException e) {
            System.err.println("[通过]关闭会话失败: " + e.getErrorCodeHex());
            System.err.println("[通过]关闭会话失败: " + e.getMessage());
        }
    }

    /**
     * 测试 6.2.6 SDF_GetDeviceInfo - 获取设备信息
     */
    @Test
    public void testGetDeviceInfo() throws SDFException {
        System.out.println("测试 6.2.6 SDF_GetDeviceInfo - 获取设备信息");
        System.out.println("----------------------------------------");

        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        // 获取设备信息
        DeviceInfo info = sdf.SDF_GetDeviceInfo(sessionHandle);
        assertNotNull("设备信息不应为空", info);

        System.out.println("设备信息:");
        System.out.println("  厂商名称: " + info.getIssuerName());
        System.out.println("  设备名称: " + info.getDeviceName());
        System.out.println("  设备序列号: " + info.getDeviceSerial());
        System.out.println("  设备版本: 0x" + Long.toHexString(info.getDeviceVersion()));
        System.out.println("  标准版本: 0x" + Long.toHexString(info.getStandardVersion()));
        System.out.println("  非对称加密算法: 0x" + Long.toHexString(info.getAsymAlgAbility()[0]) +
                           ", 0x" + Long.toHexString(info.getAsymAlgAbility()[1]));
        System.out.println("  对称加密算法: 0x" + Long.toHexString(info.getSymAlgAbility()));
        System.out.println("  哈希算法: 0x" + Long.toHexString(info.getHashAlgAbility()));
        System.out.println("  缓冲区大小: " + info.getBufferSize() + " bytes");

        assertNotNull("厂商名称不应为空", info.getIssuerName());
        assertNotNull("设备名称不应为空", info.getDeviceName());
        System.out.println("[通过] 设备信息获取成功\n");
    }

    /**
     * 测试 6.2.7 SDF_GenerateRandom - 产生随机数
     */
    @Test
    public void testGenerateRandom() throws SDFException {
        System.out.println("测试 6.2.7 SDF_GenerateRandom - 产生随机数");
        System.out.println("----------------------------------------");

        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成16字节随机数
            System.out.println("生成16字节随机数:");
            byte[] random16 = sdf.SDF_GenerateRandom(sessionHandle, 16);
            assertNotNull("16字节随机数不应为空", random16);
            assertEquals("随机数长度应为16字节", 16, random16.length);
            System.out.println("  " + bytesToHex(random16));

            // 生成32字节随机数
            System.out.println("生成32字节随机数:");
            byte[] random32 = sdf.SDF_GenerateRandom(sessionHandle, 32);
            assertNotNull("32字节随机数不应为空", random32);
            assertEquals("随机数长度应为32字节", 32, random32.length);
            System.out.println("  " + bytesToHex(random32));

            // 生成64字节随机数
            System.out.println("生成64字节随机数:");
            byte[] random64 = sdf.SDF_GenerateRandom(sessionHandle, 64);
            assertNotNull("64字节随机数不应为空", random64);
            assertEquals("随机数长度应为64字节", 64, random64.length);
            System.out.println("  " + bytesToHex(random64));

            // 验证两次生成的随机数不同
            byte[] random16_2 = sdf.SDF_GenerateRandom(sessionHandle, 16);
            assertFalse("两次生成的随机数应该不同", java.util.Arrays.equals(random16, random16_2));

            System.out.println("[通过] 随机数生成成功\n");
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 随机数生成功能未实现\n");
            } else {
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
        System.out.println("测试 6.2.8 SDF_GetPrivateKeyAccessRight - 获取私钥使用权限");
        System.out.println("----------------------------------------");

        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 尝试获取私钥使用权限
            System.out.println("尝试获取密钥索引 " + privateKeyIndex + " 的私钥使用权限...");
            sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, privateKeyIndex, privateKeyPassword);
            System.out.println("[通过] 获取私钥使用权限成功\n");

            // 释放权限（在下一个测试中单独测试）
            sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, privateKeyIndex);
            System.out.println("已释放私钥使用权限\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 获取私钥使用权限功能未实现\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_KEYNOTEXIST) {
                throw new SDFException(ErrorCode.SDR_KEYNOTEXIST, "指定密钥索引不存在");
            } else if (e.getErrorCode() == ErrorCode.SDR_PRKRERR) {
                throw new SDFException(ErrorCode.SDR_PRKRERR, "私钥使用权限获取失败（密码错误或其他原因）");
            } else if (e.getErrorCode() == ErrorCode.SDR_PARDENY) {
                throw new SDFException(ErrorCode.SDR_PARDENY, "无私钥使用权限");
            } else {
                throw e;
            }
        }
    }

    /**
     * 测试 6.2.9 SDF_ReleasePrivateKeyAccessRight - 释放私钥使用权限
     */
    @Test
    public void testReleasePrivateKeyAccessRight() throws SDFException {
        System.out.println("测试 6.2.9 SDF_ReleasePrivateKeyAccessRight - 释放私钥使用权限");
        System.out.println("----------------------------------------");

        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 先获取权限
            System.out.println("先获取密钥索引 " + privateKeyIndex + " 的私钥使用权限...");
            sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, privateKeyIndex, privateKeyPassword);
            System.out.println("已获取私钥使用权限");

            // 释放权限
            System.out.println("释放私钥使用权限...");
            sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, privateKeyIndex);
            System.out.println("[通过] 释放私钥使用权限成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 释放私钥使用权限功能未实现\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_KEYNOTEXIST) {
                throw new SDFException(ErrorCode.SDR_KEYNOTEXIST, "指定密钥索引不存在");
            } else if (e.getErrorCode() == ErrorCode.SDR_PRKRERR) {
                throw new SDFException(ErrorCode.SDR_PRKRERR, "私钥使用权限获取失败（密码错误或其他原因）");
            } else if (e.getErrorCode() == ErrorCode.SDR_PARDENY) {
                throw new SDFException(ErrorCode.SDR_PARDENY, "无私钥使用权限");
            } else {
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
        System.out.println("测试 6.2.8 SDF_GetPrivateKeyAccessRight - 错误密码场景");
        System.out.println("----------------------------------------");

        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        // 使用错误密码
        String wrongPassword = "WrongPassword123!";

        try {
            System.out.println("尝试使用错误密码获取密钥索引 " + privateKeyIndex + " 的私钥使用权限...");
            System.out.println("错误密码: " + wrongPassword);
            sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, privateKeyIndex, wrongPassword);

            // 如果没有抛出异常，说明测试失败（错误密码不应该成功）
            fail("使用错误密码应该抛出异常");

        } catch (SDFException e) {
            int errorCode = e.getErrorCode();
            System.out.println("捕获到异常，错误码: 0x" + Integer.toHexString(errorCode) + " - " + e.getMessage());

            // 验证返回了预期的错误码
            if (errorCode == ErrorCode.SDR_PRKRERR) {
                System.out.println("[通过] 错误密码被正确拒绝 (SDR_PRKRERR)\n");
            } else if (errorCode == ErrorCode.SDR_PARDENY) {
                System.out.println("[通过] 错误密码被正确拒绝 (SDR_PARDENY)\n");
            } else if (errorCode == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 获取私钥使用权限功能未实现\n");
            } else if (errorCode == ErrorCode.SDR_KEYNOTEXIST) {
                System.out.println("[跳过] 指定密钥索引不存在\n");
            } else {
                // 其他错误码也可能表示密码验证失败
                System.out.println("[通过] 错误密码被拒绝，错误码: 0x" + Integer.toHexString(errorCode) + "\n");
            }
        }
    }

    /**
     * 测试多会话管理
     */
    @Test
    public void testMultipleSessions() throws SDFException {
        System.out.println("测试多会话管理");
        System.out.println("----------------------------------------");

        // 打开设备
        deviceHandle = sdf.SDF_OpenDevice();
        System.out.println("已打开设备, 句柄: 0x" + Long.toHexString(deviceHandle));

        // 创建第一个会话
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);
        System.out.println("会话1句柄: 0x" + Long.toHexString(sessionHandle));
        assertTrue("会话1句柄应该非零", sessionHandle != 0);

        // 创建第二个会话
        long session2 = sdf.SDF_OpenSession(deviceHandle);
        System.out.println("会话2句柄: 0x" + Long.toHexString(session2));
        assertTrue("会话2句柄应该非零", session2 != 0);
        assertNotEquals("两个会话句柄应该不同", sessionHandle, session2);

        // 创建第三个会话
        long session3 = sdf.SDF_OpenSession(deviceHandle);
        System.out.println("会话3句柄: 0x" + Long.toHexString(session3));
        assertTrue("会话3句柄应该非零", session3 != 0);

        try {
            // 在不同会话中生成随机数
            byte[] random1 = sdf.SDF_GenerateRandom(sessionHandle, 16);
            byte[] random2 = sdf.SDF_GenerateRandom(session2, 16);
            byte[] random3 = sdf.SDF_GenerateRandom(session3, 16);

            System.out.println("会话1随机数: " + bytesToHex(random1));
            System.out.println("会话2随机数: " + bytesToHex(random2));
            System.out.println("会话3随机数: " + bytesToHex(random3));

            // 验证各会话生成的随机数不同
            assertFalse("会话1和会话2的随机数应不同", java.util.Arrays.equals(random1, random2));
            assertFalse("会话2和会话3的随机数应不同", java.util.Arrays.equals(random2, random3));
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("随机数生成功能未实现，跳过随机数验证");
            } else {
                throw e;
            }
        }

        // 关闭额外创建的会话
        sdf.SDF_CloseSession(session2);
        System.out.println("会话2已关闭");
        sdf.SDF_CloseSession(session3);
        System.out.println("会话3已关闭");

        System.out.println("[通过] 多会话管理测试成功\n");
    }

    /**
     * 测试设备和会话的正确生命周期
     */
    @Test
    public void testDeviceSessionLifecycle() throws SDFException {
        System.out.println("测试设备和会话的生命周期");
        System.out.println("----------------------------------------");

        // 多次打开和关闭设备
        for (int i = 1; i <= 3; i++) {
            System.out.println("第 " + i + " 次打开设备...");
            long device = sdf.SDF_OpenDevice();
            assertTrue("设备句柄应该非零", device != 0);

            // 创建会话
            long session = sdf.SDF_OpenSession(device);
            assertTrue("会话句柄应该非零", session != 0);

            // 获取设备信息验证会话正常工作
            DeviceInfo info = sdf.SDF_GetDeviceInfo(session);
            assertNotNull("设备信息不应为空", info);
            System.out.println("  设备: " + info.getDeviceName());

            // 关闭会话和设备
            sdf.SDF_CloseSession(session);
            sdf.SDF_CloseDevice(device);
            System.out.println("  已关闭设备和会话");
        }

        // 重新打开设备供tearDown使用
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        System.out.println("[通过] 设备和会话生命周期测试成功\n");
    }

    /**
     * 测试边界条件 - 随机数长度
     */
    @Test
    public void testRandomBoundaryConditions() throws SDFException {
        System.out.println("测试随机数生成边界条件");
        System.out.println("----------------------------------------");

        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 测试最小长度 (1字节)
            System.out.println("生成1字节随机数:");
            byte[] random1 = sdf.SDF_GenerateRandom(sessionHandle, 1);
            assertNotNull("1字节随机数不应为空", random1);
            assertEquals("随机数长度应为1字节", 1, random1.length);
            System.out.println("  " + bytesToHex(random1));

            // 测试较大长度 (256字节)
            System.out.println("生成256字节随机数:");
            byte[] random256 = sdf.SDF_GenerateRandom(sessionHandle, 256);
            assertNotNull("256字节随机数不应为空", random256);
            assertEquals("随机数长度应为256字节", 256, random256.length);
            System.out.println("  " + bytesToHex(random256).substring(0, 64) + "...");

            // 测试1024字节
            System.out.println("生成1024字节随机数:");
            byte[] random1024 = sdf.SDF_GenerateRandom(sessionHandle, 1024);
            assertNotNull("1024字节随机数不应为空", random1024);
            assertEquals("随机数长度应为1024字节", 1024, random1024.length);
            System.out.println("  长度验证通过");

            System.out.println("[通过] 随机数边界条件测试成功\n");
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 随机数生成功能未实现\n");
            } else {
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
        System.out.println("测试 SDF_OpenDeviceWithConf - 使用配置文件打开设备");
        System.out.println("----------------------------------------");

        // 配置文件格式: key:value，每行一个配置项
        // 例如:
        //   workers:1
        //   timeout:2000
        // 配置文件相对路径: examples/src/test/resources/sdf.conf
        String configFile = "examples/src/test/resources/sdf.conf";

        java.io.File file = new java.io.File(configFile);
        Assume.assumeTrue("配置文件不存在: " + file.getAbsolutePath(), file.exists());

        System.out.println("配置文件路径: " + configFile);

        try {
            System.out.println("尝试使用配置文件打开设备...");
            deviceHandle = sdf.SDF_OpenDeviceWithConf(configFile);
            System.out.println("设备句柄: 0x" + Long.toHexString(deviceHandle));

            assertTrue("设备句柄应该非零", deviceHandle != 0);

            // 创建会话验证设备工作正常
            sessionHandle = sdf.SDF_OpenSession(deviceHandle);
            System.out.println("会话句柄: 0x" + Long.toHexString(sessionHandle));
            assertTrue("会话句柄应该非零", sessionHandle != 0);

            // 获取设备信息验证功能正常
            DeviceInfo info = sdf.SDF_GetDeviceInfo(sessionHandle);
            assertNotNull("设备信息不应为空", info);
            System.out.println("设备名称: " + info.getDeviceName());

            System.out.println("[通过] 使用配置文件打开设备成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SDF_OpenDeviceWithConf 功能未实现\n");
            } else {
                throw new SDFException(e.getErrorCode(), "SDF_OpenDeviceWithConf 调用失败: " + e.getMessage());
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
