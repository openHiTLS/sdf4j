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
import org.junit.BeforeClass;
import org.junit.Test;
import org.openhitls.sdf4j.*;
import org.openhitls.sdf4j.constants.AlgorithmID;
import org.openhitls.sdf4j.constants.ErrorCode;
import org.openhitls.sdf4j.types.ECCPublicKey;
import org.openhitls.sdf4j.types.KeyEncryptionResult;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

import static org.junit.Assert.*;

/**
 * SDF4J 杂凑运算类函数测试
 * 测试 GM/T 0018-2023 标准中 6.6 节定义的杂凑运算类函数
 *
 * 包含以下接口测试：
 * - 6.6.2 SDF_HMACInit - 带密钥的杂凑运算初始化
 * - 6.6.3 SDF_HMACUpdate - 带密钥的多包杂凑运算
 * - 6.6.4 SDF_HMACFinal - 带密钥的杂凑运算结束
 * - 6.6.5 SDF_HashInit - 杂凑运算初始化
 * - 6.6.6 SDF_HashUpdate - 多包杂凑运算
 * - 6.6.7 SDF_HashFinal - 杂凑运算结束
 * - 6.8.13 SDF_ExternalKeyHMACInit - 带外部密钥的杂凑运算初始化
 */
public class HashOperationTest {

    // 配置开关：设置为 true 时从配置文件读取，false 时使用下面的默认值
    private static final boolean USE_CONFIG_FILE = true;

    // 默认配置
    private static final int DEFAULT_KEY_INDEX = 1;
    private static final String DEFAULT_KEY_PASSWORD = "123abc!@";
    private static final String DEFAULT_USER_ID = "1234567812345678";

    // 实际使用的配置
    private static int keyIndex;
    private static String keyPassword;
    private static String userId;

    private SDF sdf;
    private long deviceHandle;
    private long sessionHandle;

    @BeforeClass
    public static void loadConfig() {
        if (USE_CONFIG_FILE) {
            Properties testConfig = new Properties();
            try (InputStream is = HashOperationTest.class.getClassLoader()
                    .getResourceAsStream("test-config.properties")) {
                if (is != null) {
                    testConfig.load(is);
                    keyIndex = Integer.parseInt(
                            testConfig.getProperty("sm2.internal.key.index", String.valueOf(DEFAULT_KEY_INDEX)));
                    keyPassword = testConfig.getProperty("sm2.key.access.password", DEFAULT_KEY_PASSWORD);
                    userId = testConfig.getProperty("sm2.default.user.id", DEFAULT_USER_ID);
                    System.out.println("已从配置文件加载测试配置: keyIndex=" + keyIndex);
                    return;
                }
            } catch (IOException e) {
                System.err.println("读取配置文件失败: " + e.getMessage());
            }
        }
        // 使用默认值
        keyIndex = DEFAULT_KEY_INDEX;
        keyPassword = DEFAULT_KEY_PASSWORD;
        userId = DEFAULT_USER_ID;
        System.out.println("使用默认测试配置: keyIndex=" + keyIndex);
    }

    @Before
    public void setUp() throws SDFException {
        System.out.println("========================================");
        System.out.println("SDF4J 杂凑运算类函数测试");
        System.out.println("========================================\n");

        // 启用 native 日志输出
        SDF.setLogger(message -> System.out.println("[NATIVE] " + message));
        SDF.setFileLoggingEnabled(false);
        SDF.setJavaLoggingEnabled(false);

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
     * 测试 6.6.5-6.6.7 SDF_HashInit/Update/Final - 基础 SM3 杂凑运算
     */
    @Test
    public void testBasicSM3Hash() throws SDFException {
        System.out.println("测试 6.6.5-6.6.7 SDF_HashInit/Update/Final - 基础 SM3 杂凑运算");
        System.out.println("----------------------------------------");

        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            String message = "Hello, SM3! 你好，国密SM3！";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);

            System.out.println("原始消息: " + message);
            System.out.println("消息长度: " + data.length + " bytes");

            // 初始化 SM3 哈希
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            System.out.println("SM3 哈希已初始化");

            // 更新数据
            sdf.SDF_HashUpdate(sessionHandle, data);
            System.out.println("数据已更新");

            // 获取最终哈希值
            byte[] hashValue = sdf.SDF_HashFinal(sessionHandle);
            assertNotNull("哈希值不应为空", hashValue);
            assertEquals("SM3 哈希值应为32字节", 32, hashValue.length);

            System.out.println("SM3 哈希值: " + bytesToHex(hashValue));
            System.out.println("长度: " + hashValue.length + " bytes (" + (hashValue.length * 8) + " bits)");
            System.out.println("[通过] 基础 SM3 杂凑运算成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SM3 杂凑功能未实现\n");
            } else {
                throw e;
            }
        }
    }

    /**
     * 测试 6.6.5-6.6.7 SDF_HashInit/Update/Final - 流式 SM3 杂凑（多次 Update）
     */
    @Test
    public void testStreamingSM3Hash() throws SDFException {
        System.out.println("测试 6.6.5-6.6.7 SDF_HashInit/Update/Final - 流式 SM3 杂凑");
        System.out.println("----------------------------------------");

        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 分块数据
            String[] chunks = {
                    "第一块数据 / Chunk 1 data. ",
                    "第二块数据 / Chunk 2 data. ",
                    "第三块数据 / Chunk 3 data. ",
                    "最后一块数据 / Final chunk data."
            };

            System.out.println("分块处理数据:");

            // 初始化 SM3 哈希
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);

            // 分多次更新数据
            for (int i = 0; i < chunks.length; i++) {
                byte[] chunkData = chunks[i].getBytes(StandardCharsets.UTF_8);
                sdf.SDF_HashUpdate(sessionHandle, chunkData);
                System.out.println("  第 " + (i + 1) + " 块已更新 (" + chunkData.length + " bytes)");
            }

            // 获取最终哈希值
            byte[] hashValue = sdf.SDF_HashFinal(sessionHandle);
            assertNotNull("哈希值不应为空", hashValue);
            System.out.println("流式 SM3 哈希值: " + bytesToHex(hashValue));

            // 验证：计算整体数据的哈希值应该相同
            System.out.println("\n验证流式哈希与一次性哈希结果一致:");
            String fullMessage = String.join("", chunks);
            byte[] fullData = fullMessage.getBytes(StandardCharsets.UTF_8);

            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, fullData);
            byte[] hashValue2 = sdf.SDF_HashFinal(sessionHandle);

            assertArrayEquals("流式哈希与一次性哈希结果应相同", hashValue, hashValue2);
            System.out.println("整体哈希值: " + bytesToHex(hashValue2));
            System.out.println("[通过] 流式 SM3 杂凑运算成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SM3 杂凑功能未实现\n");
            } else {
                throw e;
            }
        }
    }

    /**
     * 测试 6.6.5 SDF_HashInit - 带用户 ID 和公钥的 SM3（SM2 签名场景）
     */
    @Test
    public void testSM3WithUserIDAndPublicKey() throws SDFException {
        System.out.println("测试 6.6.5 SDF_HashInit - 带用户 ID 和公钥的 SM3");
        System.out.println("----------------------------------------");

        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 尝试获取 SM2 签名公钥
            ECCPublicKey publicKey = null;
            try {
                publicKey = sdf.SDF_ExportSignPublicKey_ECC(sessionHandle, keyIndex);
                System.out.println("已导出 SM2 签名公钥, 密钥索引: " + keyIndex);
                System.out.println("密钥长度: " + publicKey.getBits() + " bits");
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT ||
                    e.getErrorCode() == ErrorCode.SDR_KEYNOTEXIST) {
                    System.out.println("[跳过] 无法导出 SM2 公钥: " + e.getMessage() + "\n");
                    return;
                }
                throw e;
            }

            // SM2 默认用户 ID
            byte[] userIdBytes = userId.getBytes(StandardCharsets.UTF_8);
            System.out.println("用户 ID: " + userId);
            System.out.println("用户 ID 长度: " + userIdBytes.length + " bytes");

            // 待签名的消息
            String message = "SM2 签名测试消息 / SM2 signature test message";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);
            System.out.println("待签名消息: " + message);

            // 使用 SM3 计算哈希（带用户 ID 和公钥）
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, publicKey, userIdBytes);
            System.out.println("SM3 哈希已初始化（带用户 ID 和公钥）");

            sdf.SDF_HashUpdate(sessionHandle, data);
            System.out.println("消息数据已更新");

            byte[] hashValue = sdf.SDF_HashFinal(sessionHandle);
            assertNotNull("哈希值不应为空", hashValue);
            assertEquals("SM3 哈希值应为32字节", 32, hashValue.length);

            System.out.println("SM2 签名用的 SM3 哈希值: " + bytesToHex(hashValue));
            System.out.println("[通过] 带用户 ID 和公钥的 SM3 杂凑运算成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 带参数的 SM3 杂凑功能未实现\n");
            } else {
                throw e;
            }
        }
    }

    /**
     * 测试 6.8.13 + 6.6.3-6.6.4 SDF_ExternalKeyHMACInit/HMACUpdate/HMACFinal - 外部密钥 HMAC
     */
    @Test
    public void testExternalKeyHMAC() throws SDFException {
        System.out.println("测试 6.8.13 + 6.6.3-6.6.4 SDF_ExternalKeyHMACInit/HMACUpdate/HMACFinal");
        System.out.println("----------------------------------------");

        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成一个随机密钥用于 HMAC
            int hmacKeyLength = 32; // 256 bits
            byte[] hmacKey = sdf.SDF_GenerateRandom(sessionHandle, hmacKeyLength);
            System.out.println("生成随机 HMAC 密钥: " + bytesToHex(hmacKey));
            System.out.println("密钥长度: " + hmacKeyLength + " bytes (" + (hmacKeyLength * 8) + " bits)");

            String message = "这是需要认证的消息 / This is the message to authenticate";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);
            System.out.println("消息: " + message);

            // 使用外部密钥初始化 SM3-HMAC
            sdf.SDF_ExternalKeyHMACInit(sessionHandle, AlgorithmID.SGD_SM3, hmacKey);
            System.out.println("SM3-HMAC 已初始化");

            // 更新数据
            sdf.SDF_HMACUpdate(sessionHandle, data);
            System.out.println("数据已更新");

            // 获取 HMAC 值
            byte[] hmacValue = sdf.SDF_HMACFinal(sessionHandle);
            assertNotNull("HMAC 值不应为空", hmacValue);
            System.out.println("SM3-HMAC 值: " + bytesToHex(hmacValue));
            System.out.println("长度: " + hmacValue.length + " bytes");

            // 验证：使用相同的密钥重新计算应该得到相同的 HMAC
            System.out.println("\n验证重复计算 HMAC 结果一致:");
            sdf.SDF_ExternalKeyHMACInit(sessionHandle, AlgorithmID.SGD_SM3, hmacKey);
            sdf.SDF_HMACUpdate(sessionHandle, data);
            byte[] hmacValue2 = sdf.SDF_HMACFinal(sessionHandle);

            assertArrayEquals("两次 HMAC 计算结果应相同", hmacValue, hmacValue2);
            System.out.println("重新计算: " + bytesToHex(hmacValue2));
            System.out.println("[通过] 外部密钥 HMAC 运算成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SM3-HMAC 功能未实现\n");
            } else {
                throw e;
            }
        }
    }

    /**
     * 测试 HMAC 篡改检测
     */
    @Test
    public void testHMACTamperDetection() throws SDFException {
        System.out.println("测试 HMAC 篡改检测");
        System.out.println("----------------------------------------");

        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成 HMAC 密钥
            byte[] hmacKey = sdf.SDF_GenerateRandom(sessionHandle, 32);

            String originalMessage = "原始消息内容";
            byte[] originalData = originalMessage.getBytes(StandardCharsets.UTF_8);

            // 计算原始消息的 HMAC
            sdf.SDF_ExternalKeyHMACInit(sessionHandle, AlgorithmID.SGD_SM3, hmacKey);
            sdf.SDF_HMACUpdate(sessionHandle, originalData);
            byte[] originalHMAC = sdf.SDF_HMACFinal(sessionHandle);

            System.out.println("原始消息: " + originalMessage);
            System.out.println("原始 HMAC: " + bytesToHex(originalHMAC));

            // 篡改消息后计算 HMAC
            String tamperedMessage = "篡改后的消息内容";
            byte[] tamperedData = tamperedMessage.getBytes(StandardCharsets.UTF_8);

            sdf.SDF_ExternalKeyHMACInit(sessionHandle, AlgorithmID.SGD_SM3, hmacKey);
            sdf.SDF_HMACUpdate(sessionHandle, tamperedData);
            byte[] tamperedHMAC = sdf.SDF_HMACFinal(sessionHandle);

            System.out.println("篡改消息: " + tamperedMessage);
            System.out.println("篡改后 HMAC: " + bytesToHex(tamperedHMAC));

            // 验证篡改检测
            assertFalse("篡改后的 HMAC 应该与原始不同", java.util.Arrays.equals(originalHMAC, tamperedHMAC));
            System.out.println("[通过] 成功检测到消息篡改\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SM3-HMAC 功能未实现\n");
            } else {
                throw e;
            }
        }
    }

    /**
     * 测试 HMAC 密钥错误检测
     */
    @Test
    public void testHMACWrongKey() throws SDFException {
        System.out.println("测试 HMAC 密钥错误检测");
        System.out.println("----------------------------------------");

        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成两个不同的 HMAC 密钥
            byte[] correctKey = sdf.SDF_GenerateRandom(sessionHandle, 32);
            byte[] wrongKey = sdf.SDF_GenerateRandom(sessionHandle, 32);

            String message = "测试消息";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);

            // 使用正确密钥计算 HMAC
            sdf.SDF_ExternalKeyHMACInit(sessionHandle, AlgorithmID.SGD_SM3, correctKey);
            sdf.SDF_HMACUpdate(sessionHandle, data);
            byte[] correctHMAC = sdf.SDF_HMACFinal(sessionHandle);

            System.out.println("消息: " + message);
            System.out.println("正确密钥 HMAC: " + bytesToHex(correctHMAC));

            // 使用错误密钥计算 HMAC
            sdf.SDF_ExternalKeyHMACInit(sessionHandle, AlgorithmID.SGD_SM3, wrongKey);
            sdf.SDF_HMACUpdate(sessionHandle, data);
            byte[] wrongHMAC = sdf.SDF_HMACFinal(sessionHandle);

            System.out.println("错误密钥 HMAC: " + bytesToHex(wrongHMAC));

            // 验证密钥错误检测
            assertFalse("错误密钥的 HMAC 应该与正确密钥不同", java.util.Arrays.equals(correctHMAC, wrongHMAC));
            System.out.println("[通过] 成功检测到密钥错误\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SM3-HMAC 功能未实现\n");
            } else {
                throw e;
            }
        }
    }

    /**
     * 测试大数据哈希
     */
    @Test
    public void testLargeDataHash() throws SDFException {
        System.out.println("测试大数据哈希");
        System.out.println("----------------------------------------");

        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成 1MB 随机数据
            int dataSize = 1024 * 1024; // 1MB
            byte[] largeData = sdf.SDF_GenerateRandom(sessionHandle, dataSize);

            System.out.println("数据大小: " + dataSize + " bytes (1 MB)");

            long startTime = System.currentTimeMillis();
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, largeData);
            byte[] hashValue = sdf.SDF_HashFinal(sessionHandle);
            long endTime = System.currentTimeMillis();

            assertNotNull("哈希值不应为空", hashValue);
            assertEquals("SM3 哈希值应为32字节", 32, hashValue.length);

            System.out.println("SM3 哈希值: " + bytesToHex(hashValue));
            System.out.println("耗时: " + (endTime - startTime) + " ms");
            System.out.println("[通过] 大数据哈希运算成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SM3 杂凑功能未实现\n");
            } else {
                throw e;
            }
        }
    }

    /**
     * 测试哈希一致性（相同数据产生相同哈希）
     */
    @Test
    public void testHashConsistency() throws SDFException {
        System.out.println("测试哈希一致性");
        System.out.println("----------------------------------------");

        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            String message = "测试哈希一致性的消息";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);

            // 第一次计算
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data);
            byte[] hash1 = sdf.SDF_HashFinal(sessionHandle);

            // 第二次计算
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data);
            byte[] hash2 = sdf.SDF_HashFinal(sessionHandle);

            // 第三次计算
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data);
            byte[] hash3 = sdf.SDF_HashFinal(sessionHandle);

            assertArrayEquals("第一次和第二次哈希结果应相同", hash1, hash2);
            assertArrayEquals("第二次和第三次哈希结果应相同", hash2, hash3);

            System.out.println("消息: " + message);
            System.out.println("第一次哈希: " + bytesToHex(hash1));
            System.out.println("第二次哈希: " + bytesToHex(hash2));
            System.out.println("第三次哈希: " + bytesToHex(hash3));
            System.out.println("[通过] 哈希一致性验证成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SM3 杂凑功能未实现\n");
            } else {
                throw e;
            }
        }
    }

    /**
     * 测试不同数据产生不同哈希（抗碰撞性）
     */
    @Test
    public void testHashCollisionResistance() throws SDFException {
        System.out.println("测试哈希抗碰撞性");
        System.out.println("----------------------------------------");

        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            String message1 = "消息A";
            String message2 = "消息B";
            String message3 = "消息A "; // 仅多一个空格

            byte[] data1 = message1.getBytes(StandardCharsets.UTF_8);
            byte[] data2 = message2.getBytes(StandardCharsets.UTF_8);
            byte[] data3 = message3.getBytes(StandardCharsets.UTF_8);

            // 计算三个不同消息的哈希
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data1);
            byte[] hash1 = sdf.SDF_HashFinal(sessionHandle);

            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data2);
            byte[] hash2 = sdf.SDF_HashFinal(sessionHandle);

            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data3);
            byte[] hash3 = sdf.SDF_HashFinal(sessionHandle);

            assertFalse("不同消息的哈希应不同", java.util.Arrays.equals(hash1, hash2));
            assertFalse("仅差一个空格的消息哈希也应不同", java.util.Arrays.equals(hash1, hash3));

            System.out.println("消息1: \"" + message1 + "\" -> " + bytesToHex(hash1));
            System.out.println("消息2: \"" + message2 + "\" -> " + bytesToHex(hash2));
            System.out.println("消息3: \"" + message3 + "\" -> " + bytesToHex(hash3));
            System.out.println("[通过] 哈希抗碰撞性验证成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SM3 杂凑功能未实现\n");
            } else {
                throw e;
            }
        }
    }

    /**
     * 测试 6.6.2-6.6.4 SDF_HMACInit/HMACUpdate/HMACFinal - 内部密钥 HMAC
     * 使用 HSM 内部生成的会话密钥进行 HMAC 运算
     */
    @Test
    public void testInternalKeyHMAC() throws SDFException {
        System.out.println("测试 6.6.2-6.6.4 SDF_HMACInit/HMACUpdate/HMACFinal - 内部密钥 HMAC");
        System.out.println("----------------------------------------");

        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long keyHandle = 0;
        boolean accessRightObtained = false;
        try {
            // 获取私钥访问权限（使用内部 ECC 密钥前必须先获取权限）
            System.out.println("获取私钥访问权限，密钥索引: " + keyIndex);
            try {
                sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, keyIndex, keyPassword);
                accessRightObtained = true;
                System.out.println("成功获取私钥访问权限");
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("获取私钥权限不需要或不支持，继续测试...");
                } else {
                    throw e;
                }
            }

            // 使用内部 ECC 密钥生成会话密钥（128 位用于 HMAC）
            System.out.println("使用内部 ECC 密钥生成会话密钥，密钥索引: " + keyIndex);
            KeyEncryptionResult keyResult = sdf.SDF_GenerateKeyWithIPK_ECC(sessionHandle, keyIndex, 128);
            keyHandle = keyResult.getKeyHandle();
            System.out.println("会话密钥生成成功，密钥句柄: " + keyHandle);
            System.out.println("加密密钥长度: " + keyResult.getEncryptedKey().length + " bytes");

            // 待认证的消息
            String message = "这是使用内部密钥进行 HMAC 认证的消息 / Internal key HMAC message";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);
            System.out.println("\n消息: " + message);
            System.out.println("消息长度: " + data.length + " bytes");

            // 使用内部密钥初始化 SM3-HMAC
            sdf.SDF_HMACInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM3);
            System.out.println("\nSM3-HMAC 已初始化（使用内部密钥）");

            // 更新数据
            sdf.SDF_HMACUpdate(sessionHandle, data);
            System.out.println("数据已更新");

            // 获取 HMAC 值
            byte[] hmacValue = sdf.SDF_HMACFinal(sessionHandle);
            assertNotNull("HMAC 值不应为空", hmacValue);
            System.out.println("SM3-HMAC 值: " + bytesToHex(hmacValue));
            System.out.println("长度: " + hmacValue.length + " bytes");

            // 验证：使用相同的密钥重新计算应该得到相同的 HMAC
            System.out.println("\n验证重复计算 HMAC 结果一致:");
            sdf.SDF_HMACInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM3);
            sdf.SDF_HMACUpdate(sessionHandle, data);
            byte[] hmacValue2 = sdf.SDF_HMACFinal(sessionHandle);

            assertArrayEquals("两次 HMAC 计算结果应相同", hmacValue, hmacValue2);
            System.out.println("重新计算: " + bytesToHex(hmacValue2));
            System.out.println("[通过] 内部密钥 HMAC 运算成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 内部密钥 SM3-HMAC 功能未实现\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_KEYNOTEXIST) {
                System.out.println("[跳过] 内部 ECC 密钥不存在，密钥索引: " + keyIndex + "\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_INARGERR) {
                System.out.println("[跳过] 输入参数错误，可能密钥索引或密钥长度不支持\n");
            } else {
                throw e;
            }
        } finally {
            // 销毁会话密钥
            if (keyHandle != 0) {
                try {
                    sdf.SDF_DestroyKey(sessionHandle, keyHandle);
                    System.out.println("会话密钥已销毁");
                } catch (SDFException e) {
                    System.err.println("销毁密钥失败: " + e.getMessage());
                }
            }
            // 释放私钥访问权限
            if (accessRightObtained) {
                try {
                    sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, keyIndex);
                    System.out.println("已释放私钥访问权限");
                } catch (SDFException e) {
                    System.err.println("释放私钥访问权限失败: " + e.getMessage());
                }
            }
        }
    }

    /**
     * 测试内部密钥 HMAC 流式处理（多次 Update）
     */
    @Test
    public void testInternalKeyHMACStreaming() throws SDFException {
        System.out.println("测试内部密钥 HMAC 流式处理");
        System.out.println("----------------------------------------");

        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long keyHandle = 0;
        boolean accessRightObtained = false;
        try {
            // 获取私钥访问权限
            System.out.println("获取私钥访问权限，密钥索引: " + keyIndex);
            try {
                sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, keyIndex, keyPassword);
                accessRightObtained = true;
                System.out.println("成功获取私钥访问权限");
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("获取私钥权限不需要或不支持，继续测试...");
                } else {
                    throw e;
                }
            }

            // 使用内部 ECC 密钥生成会话密钥
            KeyEncryptionResult keyResult = sdf.SDF_GenerateKeyWithIPK_ECC(sessionHandle, keyIndex, 128);
            keyHandle = keyResult.getKeyHandle();
            System.out.println("会话密钥生成成功，密钥句柄: " + keyHandle);

            // 分块数据
            String[] chunks = {
                    "第一块数据 / Chunk 1. ",
                    "第二块数据 / Chunk 2. ",
                    "第三块数据 / Chunk 3. ",
                    "最后一块 / Final chunk."
            };

            System.out.println("\n分块计算 HMAC:");

            // 流式计算 HMAC
            sdf.SDF_HMACInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM3);
            for (int i = 0; i < chunks.length; i++) {
                byte[] chunkData = chunks[i].getBytes(StandardCharsets.UTF_8);
                sdf.SDF_HMACUpdate(sessionHandle, chunkData);
                System.out.println("  第 " + (i + 1) + " 块已更新 (" + chunkData.length + " bytes)");
            }
            byte[] streamHMAC = sdf.SDF_HMACFinal(sessionHandle);

            System.out.println("流式 HMAC 值: " + bytesToHex(streamHMAC));

            // 验证：一次性计算整体数据的 HMAC 应该相同
            System.out.println("\n验证流式 HMAC 与一次性 HMAC 结果一致:");
            String fullMessage = String.join("", chunks);
            byte[] fullData = fullMessage.getBytes(StandardCharsets.UTF_8);

            sdf.SDF_HMACInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM3);
            sdf.SDF_HMACUpdate(sessionHandle, fullData);
            byte[] fullHMAC = sdf.SDF_HMACFinal(sessionHandle);

            assertArrayEquals("流式 HMAC 与一次性 HMAC 结果应相同", streamHMAC, fullHMAC);
            System.out.println("整体 HMAC 值: " + bytesToHex(fullHMAC));
            System.out.println("[通过] 内部密钥 HMAC 流式处理成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 内部密钥 SM3-HMAC 功能未实现\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_KEYNOTEXIST) {
                System.out.println("[跳过] 内部 ECC 密钥不存在，密钥索引: " + keyIndex + "\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_INARGERR) {
                System.out.println("[跳过] 输入参数错误，可能密钥索引或密钥长度不支持\n");
            } else {
                throw e;
            }
        } finally {
            if (keyHandle != 0) {
                try {
                    sdf.SDF_DestroyKey(sessionHandle, keyHandle);
                    System.out.println("会话密钥已销毁");
                } catch (SDFException e) {
                    System.err.println("销毁密钥失败: " + e.getMessage());
                }
            }
            // 释放私钥访问权限
            if (accessRightObtained) {
                try {
                    sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, keyIndex);
                    System.out.println("已释放私钥访问权限");
                } catch (SDFException e) {
                    System.err.println("释放私钥访问权限失败: " + e.getMessage());
                }
            }
        }
    }

    /**
     * 测试内部密钥与外部密钥 HMAC 对比
     * 验证使用不同密钥会产生不同的 HMAC 值
     */
    @Test
    public void testInternalVsExternalKeyHMAC() throws SDFException {
        System.out.println("测试内部密钥与外部密钥 HMAC 对比");
        System.out.println("----------------------------------------");

        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long keyHandle = 0;
        boolean accessRightObtained = false;
        try {
            // 获取私钥访问权限
            System.out.println("获取私钥访问权限，密钥索引: " + keyIndex);
            try {
                sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, keyIndex, keyPassword);
                accessRightObtained = true;
                System.out.println("成功获取私钥访问权限");
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("获取私钥权限不需要或不支持，继续测试...");
                } else {
                    throw e;
                }
            }

            // 生成内部会话密钥
            KeyEncryptionResult keyResult = sdf.SDF_GenerateKeyWithIPK_ECC(sessionHandle, keyIndex, 128);
            keyHandle = keyResult.getKeyHandle();
            System.out.println("内部会话密钥生成成功，密钥句柄: " + keyHandle);

            // 生成外部随机密钥
            byte[] externalKey = sdf.SDF_GenerateRandom(sessionHandle, 32);
            System.out.println("外部随机密钥: " + bytesToHex(externalKey));

            // 待认证的消息
            String message = "对比测试消息 / Comparison test message";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);
            System.out.println("\n消息: " + message);

            // 使用内部密钥计算 HMAC
            sdf.SDF_HMACInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM3);
            sdf.SDF_HMACUpdate(sessionHandle, data);
            byte[] internalHMAC = sdf.SDF_HMACFinal(sessionHandle);
            System.out.println("\n内部密钥 HMAC: " + bytesToHex(internalHMAC));

            // 使用外部密钥计算 HMAC
            sdf.SDF_ExternalKeyHMACInit(sessionHandle, AlgorithmID.SGD_SM3, externalKey);
            sdf.SDF_HMACUpdate(sessionHandle, data);
            byte[] externalHMAC = sdf.SDF_HMACFinal(sessionHandle);
            System.out.println("外部密钥 HMAC: " + bytesToHex(externalHMAC));

            // 验证两个 HMAC 值不同（因为使用了不同的密钥）
            assertFalse("内部密钥和外部密钥的 HMAC 应该不同",
                    java.util.Arrays.equals(internalHMAC, externalHMAC));
            System.out.println("\n[通过] 内部密钥与外部密钥 HMAC 结果不同（符合预期）\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] HMAC 功能未实现\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_KEYNOTEXIST) {
                System.out.println("[跳过] 内部 ECC 密钥不存在，密钥索引: " + keyIndex + "\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_INARGERR) {
                System.out.println("[跳过] 输入参数错误，可能密钥索引或密钥长度不支持\n");
            } else {
                throw e;
            }
        } finally {
            if (keyHandle != 0) {
                try {
                    sdf.SDF_DestroyKey(sessionHandle, keyHandle);
                    System.out.println("会话密钥已销毁");
                } catch (SDFException e) {
                    System.err.println("销毁密钥失败: " + e.getMessage());
                }
            }
            // 释放私钥访问权限
            if (accessRightObtained) {
                try {
                    sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, keyIndex);
                    System.out.println("已释放私钥访问权限");
                } catch (SDFException e) {
                    System.err.println("释放私钥访问权限失败: " + e.getMessage());
                }
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
