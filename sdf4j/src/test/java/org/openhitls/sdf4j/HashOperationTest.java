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
import org.openhitls.sdf4j.constants.AlgorithmID;
import org.openhitls.sdf4j.constants.ErrorCode;
import org.openhitls.sdf4j.types.ECCPublicKey;
import org.openhitls.sdf4j.types.ECCKeyEncryptionResult;

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
     * 测试 6.6.5-6.6.7 SDF_HashInit/Update/Final - 基础 SM3 杂凑运算
     */
    @Test
    public void testBasicSM3Hash() throws SDFException {
        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            String message = "Hello, SM3! 你好，国密SM3！";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);
            // 初始化 SM3 哈希
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);

            // 更新数据
            sdf.SDF_HashUpdate(sessionHandle, data);

            // 获取最终哈希值
            byte[] hashValue = sdf.SDF_HashFinal(sessionHandle);
            assertNotNull("哈希值不应为空", hashValue);
            assertEquals("SM3 哈希值应为32字节", 32, hashValue.length);
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SM3 杂凑功能未实现");
                Assume.assumeTrue("SM3 杂凑功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        }
    }

    /**
     * 测试 6.6.5-6.6.7 SDF_HashInit/Update/Final - 流式 SM3 杂凑（多次 Update）
     */
    @Test
    public void testStreamingSM3Hash() throws SDFException {
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

            // 初始化 SM3 哈希
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);

            // 分多次更新数据
            for (int i = 0; i < chunks.length; i++) {
                byte[] chunkData = chunks[i].getBytes(StandardCharsets.UTF_8);
                sdf.SDF_HashUpdate(sessionHandle, chunkData);
            }

            // 获取最终哈希值
            byte[] hashValue = sdf.SDF_HashFinal(sessionHandle);
            assertNotNull("哈希值不应为空", hashValue);

            // 验证：计算整体数据的哈希值应该相同
            String fullMessage = String.join("", chunks);
            byte[] fullData = fullMessage.getBytes(StandardCharsets.UTF_8);

            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, fullData);
            byte[] hashValue2 = sdf.SDF_HashFinal(sessionHandle);

            assertArrayEquals("流式哈希与一次性哈希结果应相同", hashValue, hashValue2);
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SM3 杂凑功能未实现");
                Assume.assumeTrue("SM3 杂凑功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        }
    }

    /**
     * 测试 6.6.5 SDF_HashInit - 带用户 ID 和公钥的 SM3（SM2 签名场景）
     */
    @Test
    public void testSM3WithUserIDAndPublicKey() throws SDFException {
        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 尝试获取 SM2 签名公钥
            ECCPublicKey publicKey = null;
            try {
                publicKey = sdf.SDF_ExportSignPublicKey_ECC(sessionHandle, keyIndex);
                assertNotNull("publicKey不应为空", publicKey);
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] 无法导出 SM2 公钥: " + e.getMessage() + "\n");
                    return;
                }
                System.out.println(e.getMessage());
                throw e;
            }

            // SM2 默认用户 ID
            byte[] userIdBytes = userId.getBytes(StandardCharsets.UTF_8);

            // 待签名的消息
            String message = "SM2 签名测试消息 / SM2 signature test message";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);

            // 使用 SM3 计算哈希（带用户 ID 和公钥）
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, publicKey, userIdBytes);

            sdf.SDF_HashUpdate(sessionHandle, data);

            byte[] hashValue = sdf.SDF_HashFinal(sessionHandle);
            assertNotNull("哈希值不应为空", hashValue);
            assertEquals("SM3 哈希值应为32字节", 32, hashValue.length);

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 带参数的 SM3 杂凑功能未实现");
                Assume.assumeTrue("带参数的 SM3 杂凑功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        }
    }

    /**
     * 测试 6.8.13 + 6.6.3-6.6.4 SDF_ExternalKeyHMACInit/HMACUpdate/HMACFinal - 外部密钥 HMAC
     */
    @Test
    public void testExternalKeyHMAC() throws SDFException {
        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成一个随机密钥用于 HMAC
            int hmacKeyLength = 32; // 256 bits
            byte[] hmacKey = sdf.SDF_GenerateRandom(sessionHandle, hmacKeyLength);
            assertNotNull("hmacKey不应为空", hmacKey);

            String message = "这是需要认证的消息 / This is the message to authenticate";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);

            // 使用外部密钥初始化 SM3-HMAC
            sdf.SDF_ExternalKeyHMACInit(sessionHandle, AlgorithmID.SGD_SM3, hmacKey);

            // 更新数据
            sdf.SDF_HMACUpdate(sessionHandle, data);

            // 获取 HMAC 值
            byte[] hmacValue = sdf.SDF_HMACFinal(sessionHandle);
            assertNotNull("HMAC 值不应为空", hmacValue);

            // 验证：使用相同的密钥重新计算应该得到相同的 HMAC
            sdf.SDF_ExternalKeyHMACInit(sessionHandle, AlgorithmID.SGD_SM3, hmacKey);
            sdf.SDF_HMACUpdate(sessionHandle, data);
            byte[] hmacValue2 = sdf.SDF_HMACFinal(sessionHandle);

            assertArrayEquals("两次 HMAC 计算结果应相同", hmacValue, hmacValue2);

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SM3-HMAC 功能未实现");
                Assume.assumeTrue("SM3-HMAC 功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        }
    }

    /**
     * 测试 HMAC 篡改检测
     */
    @Test
    public void testHMACTamperDetection() throws SDFException {
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

            // 篡改消息后计算 HMAC
            String tamperedMessage = "篡改后的消息内容";
            byte[] tamperedData = tamperedMessage.getBytes(StandardCharsets.UTF_8);

            sdf.SDF_ExternalKeyHMACInit(sessionHandle, AlgorithmID.SGD_SM3, hmacKey);
            sdf.SDF_HMACUpdate(sessionHandle, tamperedData);
            byte[] tamperedHMAC = sdf.SDF_HMACFinal(sessionHandle);

            // 验证篡改检测
            assertFalse("篡改后的 HMAC 应该与原始不同", java.util.Arrays.equals(originalHMAC, tamperedHMAC));

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SM3-HMAC 功能未实现");
                Assume.assumeTrue("SM3-HMAC 功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        }
    }

    /**
     * 测试 HMAC 密钥错误检测
     */
    @Test
    public void testHMACWrongKey() throws SDFException {
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

            // 使用错误密钥计算 HMAC
            sdf.SDF_ExternalKeyHMACInit(sessionHandle, AlgorithmID.SGD_SM3, wrongKey);
            sdf.SDF_HMACUpdate(sessionHandle, data);
            byte[] wrongHMAC = sdf.SDF_HMACFinal(sessionHandle);

            // 验证密钥错误检测
            assertFalse("错误密钥的 HMAC 应该与正确密钥不同", java.util.Arrays.equals(correctHMAC, wrongHMAC));

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SM3-HMAC 功能未实现");
                Assume.assumeTrue("SM3-HMAC 功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        }
    }

    /**
     * 测试大数据哈希
     */
    @Test
    public void testLargeDataHash() throws SDFException {
        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成 1MB 随机数据
            int dataSize = 1024 * 1024; // 1MB
            byte[] largeData = sdf.SDF_GenerateRandom(sessionHandle, dataSize);


            long startTime = System.currentTimeMillis();
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, largeData);
            byte[] hashValue = sdf.SDF_HashFinal(sessionHandle);
            long endTime = System.currentTimeMillis();

            assertNotNull("哈希值不应为空", hashValue);
            assertEquals("SM3 哈希值应为32字节", 32, hashValue.length);

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SM3 杂凑功能未实现");
                Assume.assumeTrue("SM3 杂凑功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        }
    }

    /**
     * 测试哈希一致性（相同数据产生相同哈希）
     */
    @Test
    public void testHashConsistency() throws SDFException {
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

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SM3 杂凑功能未实现");
                Assume.assumeTrue("SM3 杂凑功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        }
    }

    /**
     * 测试不同数据产生不同哈希（抗碰撞性）
     */
    @Test
    public void testHashCollisionResistance() throws SDFException {
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
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SM3 杂凑功能未实现");
                Assume.assumeTrue("SM3 杂凑功能未实现", false);
            } else {
                System.out.println(e.getMessage());
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
        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long keyHandle = 0;
        boolean accessRightObtained = false;
        try {
            // 获取私钥访问权限（使用内部 ECC 密钥前必须先获取权限）
            try {
                sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, keyIndex, keyPassword);
                accessRightObtained = true;
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] 获取私钥权限不支持");
                    Assume.assumeTrue("获取私钥权限不支持，继续测试...", false);
                } else {
                    System.out.println(e.getMessage());
                    throw e;
                }
            }

            // 使用内部 ECC 密钥生成会话密钥（128 位用于 HMAC）
            ECCKeyEncryptionResult keyResult = sdf.SDF_GenerateKeyWithIPK_ECC(sessionHandle, keyIndex, 128);
            assertNotNull("密钥生成结果不应为空", keyResult);
            keyHandle = keyResult.getKeyHandle();

            // 待认证的消息
            String message = "这是使用内部密钥进行 HMAC 认证的消息 / Internal key HMAC message";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);

            // 使用内部密钥初始化 SM3-HMAC
            sdf.SDF_HMACInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM3);

            // 更新数据
            sdf.SDF_HMACUpdate(sessionHandle, data);

            // 获取 HMAC 值
            byte[] hmacValue = sdf.SDF_HMACFinal(sessionHandle);
            assertNotNull("HMAC 值不应为空", hmacValue);

            // 验证：使用相同的密钥重新计算应该得到相同的 HMAC
            sdf.SDF_HMACInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM3);
            sdf.SDF_HMACUpdate(sessionHandle, data);
            byte[] hmacValue2 = sdf.SDF_HMACFinal(sessionHandle);

            assertArrayEquals("两次 HMAC 计算结果应相同", hmacValue, hmacValue2);

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 内部密钥 SM3-HMAC 功能未实现");
                Assume.assumeTrue("内部密钥 SM3-HMAC 功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        } finally {
            // 销毁会话密钥
            if (keyHandle != 0) {
                try {
                    sdf.SDF_DestroyKey(sessionHandle, keyHandle);
                } catch (SDFException e) {
                    System.err.println("销毁密钥失败: " + e.getMessage());
                }
            }
            // 释放私钥访问权限
            if (accessRightObtained) {
                try {
                    sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, keyIndex);
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
        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long keyHandle = 0;
        boolean accessRightObtained = false;
        try {
            // 获取私钥访问权限
            try {
                sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, keyIndex, keyPassword);
                accessRightObtained = true;
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] 获取私钥权限不支持");
                    Assume.assumeTrue("获取私钥权限不需要或不支持，继续测试...", false);
                } else {
                    System.out.println(e.getMessage());
                    throw e;
                }
            }

            // 使用内部 ECC 密钥生成会话密钥
            ECCKeyEncryptionResult keyResult = sdf.SDF_GenerateKeyWithIPK_ECC(sessionHandle, keyIndex, 128);
            assertNotNull("密钥生成结果不应为空", keyResult);
            keyHandle = keyResult.getKeyHandle();

            // 分块数据
            String[] chunks = {
                    "第一块数据 / Chunk 1. ",
                    "第二块数据 / Chunk 2. ",
                    "第三块数据 / Chunk 3. ",
                    "最后一块 / Final chunk."
            };
            // 流式计算 HMAC
            sdf.SDF_HMACInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM3);
            for (int i = 0; i < chunks.length; i++) {
                byte[] chunkData = chunks[i].getBytes(StandardCharsets.UTF_8);
                sdf.SDF_HMACUpdate(sessionHandle, chunkData);
            }
            byte[] streamHMAC = sdf.SDF_HMACFinal(sessionHandle);

            // 验证：一次性计算整体数据的 HMAC 应该相同
            String fullMessage = String.join("", chunks);
            byte[] fullData = fullMessage.getBytes(StandardCharsets.UTF_8);

            sdf.SDF_HMACInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM3);
            sdf.SDF_HMACUpdate(sessionHandle, fullData);
            byte[] fullHMAC = sdf.SDF_HMACFinal(sessionHandle);

            assertArrayEquals("流式 HMAC 与一次性 HMAC 结果应相同", streamHMAC, fullHMAC);

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 内部密钥 SM3-HMAC 功能未实现");
                Assume.assumeTrue("内部密钥 SM3-HMAC 功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        } finally {
            if (keyHandle != 0) {
                try {
                    sdf.SDF_DestroyKey(sessionHandle, keyHandle);
                } catch (SDFException e) {
                    System.err.println("销毁密钥失败: " + e.getMessage());
                }
            }
            // 释放私钥访问权限
            if (accessRightObtained) {
                try {
                    sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, keyIndex);
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
        // 打开设备和会话
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long keyHandle = 0;
        boolean accessRightObtained = false;
        try {
            // 获取私钥访问权限
            try {
                sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, keyIndex, keyPassword);
                accessRightObtained = true;
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] 获取私钥权限不支持");
                    Assume.assumeTrue("获取私钥权限不需要或不支持，继续测试...", false);
                } else {
                    System.out.println(e.getMessage());
                    throw e;
                }
            }

            // 生成内部会话密钥
            ECCKeyEncryptionResult keyResult = sdf.SDF_GenerateKeyWithIPK_ECC(sessionHandle, keyIndex, 128);
            keyHandle = keyResult.getKeyHandle();

            // 生成外部随机密钥
            byte[] externalKey = sdf.SDF_GenerateRandom(sessionHandle, 32);

            // 待认证的消息
            String message = "对比测试消息 / Comparison test message";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);

            // 使用内部密钥计算 HMAC
            sdf.SDF_HMACInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM3);
            sdf.SDF_HMACUpdate(sessionHandle, data);
            byte[] internalHMAC = sdf.SDF_HMACFinal(sessionHandle);

            // 使用外部密钥计算 HMAC
            sdf.SDF_ExternalKeyHMACInit(sessionHandle, AlgorithmID.SGD_SM3, externalKey);
            sdf.SDF_HMACUpdate(sessionHandle, data);
            byte[] externalHMAC = sdf.SDF_HMACFinal(sessionHandle);

            // 验证两个 HMAC 值不同（因为使用了不同的密钥）
            assertFalse("内部密钥和外部密钥的 HMAC 应该不同",
                    java.util.Arrays.equals(internalHMAC, externalHMAC));

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] HMAC 功能未实现");
                Assume.assumeTrue("HMAC 功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        } finally {
            if (keyHandle != 0) {
                try {
                    sdf.SDF_DestroyKey(sessionHandle, keyHandle);
                } catch (SDFException e) {
                    System.err.println("销毁密钥失败: " + e.getMessage());
                }
            }
            // 释放私钥访问权限
            if (accessRightObtained) {
                try {
                    sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, keyIndex);
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
