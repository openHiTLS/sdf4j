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
import org.openhitls.sdf4j.SDF;
import org.openhitls.sdf4j.SDFException;
import org.openhitls.sdf4j.constants.AlgorithmID;
import org.openhitls.sdf4j.constants.ErrorCode;
import org.openhitls.sdf4j.types.ECCPublicKey;

import java.nio.charset.StandardCharsets;

/**
 * SM3 国密杂凑算法示例测试
 * SM3 Chinese Cryptographic Hash Algorithm Example Tests
 *
 * <p>本示例演示 SM3 杂凑算法的多种使用场景：
 * <ul>
 *   <li>基础 SM3 哈希计算</li>
 *   <li>流式/分块 SM3 计算（适用于大文件）</li>
 *   <li>SM2 签名场景的 SM3（带用户 ID 和公钥）</li>
 *   <li>SM3-HMAC（带密钥的消息认证码）</li>
 *   <li>部分实现支持处理</li>
 * </ul>
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
public class SM3ExampleTest {

    private static final String SEPARATOR = "================================================================================";

    private SDF sdf;
    private long deviceHandle;
    private long sessionHandle;

    @Before
    public void setUp() throws SDFException {
        System.out.println(SEPARATOR);
        System.out.println("SM3 国密杂凑算法示例 / SM3 Chinese Cryptographic Hash Algorithm Examples");
        System.out.println(SEPARATOR);

        // 启用 native 日志输出
        SDF.setLogger(message -> System.out.println("🔔 [NATIVE] " + message));
        SDF.setFileLoggingEnabled(false);   // 禁用文件日志
        SDF.setJavaLoggingEnabled(true);    // 启用 Java 回调日志

        sdf = new SDF();
        deviceHandle = 0;
        sessionHandle = 0;

        try {
            // 打开设备和会话
            System.out.println("\n打开设备和会话 / Opening device and session...");
            deviceHandle = sdf.SDF_OpenDevice();
            System.out.println("   ✓ 设备已打开 / Device opened: 0x" + Long.toHexString(deviceHandle));

            sessionHandle = sdf.SDF_OpenSession(deviceHandle);
            System.out.println("   ✓ 会话已创建 / Session opened: 0x" + Long.toHexString(sessionHandle));
        } catch (SDFException e) {
            System.err.println("⚠ 无法打开设备或会话，某些测试可能会跳过");
            System.err.println("⚠ Cannot open device or session, some tests may be skipped");
            // 不抛出异常，让测试继续，但标记为没有设备
        }
    }

    @After
    public void tearDown() {
        // 清理资源
        try {
            if (sessionHandle != 0) {
                sdf.SDF_CloseSession(sessionHandle);
                System.out.println("\n✓ 会话已关闭 / Session closed");
            }
            if (deviceHandle != 0) {
                sdf.SDF_CloseDevice(deviceHandle);
                System.out.println("✓ 设备已关闭 / Device closed");
            }
        } catch (SDFException e) {
            System.err.println("❌ 关闭资源时出错 / Error closing resources: " + e.getMessage());
        }

        System.out.println("\n" + SEPARATOR);
        System.out.println("示例运行完成 / Examples completed");
        System.out.println(SEPARATOR + "\n");
    }

    /**
     * 测试 1: 基础 SM3 哈希计算
     * Test 1: Basic SM3 Hash Calculation
     */
    @Test
    public void testBasicSM3Hash() throws SDFException {
        if (sessionHandle == 0) {
            System.out.println("⚠ 跳过测试：设备不可用 / Skipping test: device not available");
            return;
        }

        System.out.println("\n" + SEPARATOR);
        System.out.println("测试 1: 基础 SM3 哈希计算");
        System.out.println("Test 1: Basic SM3 Hash Calculation");
        System.out.println(SEPARATOR);

        try {
            String message = "Hello, SM3! 你好，国密SM3！";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);

            System.out.println("原始消息 / Original message: " + message);
            System.out.println("消息长度 / Message length: " + data.length + " bytes");

            // 初始化 SM3 哈希
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            System.out.println("✓ SM3 哈希已初始化 / SM3 hash initialized");

            // 更新数据
            sdf.SDF_HashUpdate(sessionHandle, data);
            System.out.println("✓ 数据已更新 / Data updated");

            // 获取最终哈希值
            byte[] hashValue = sdf.SDF_HashFinal(sessionHandle);
            System.out.println("✓ SM3 哈希值 / SM3 hash value:");
            System.out.println("  " + bytesToHex(hashValue));
            System.out.println("  长度 / Length: " + hashValue.length + " bytes (" + (hashValue.length * 8) + " bits)");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("⚠ 此 SDF 库不支持 SM3 哈希功能");
                System.out.println("⚠ This SDF library does not support SM3 hash function");
            } else {
                throw e;
            }
        }
    }

    /**
     * 测试 2: 流式 SM3 哈希（分多次更新）
     * Test 2: Streaming SM3 Hash (Multiple Updates)
     */
    @Test
    public void testStreamingSM3Hash() throws SDFException {
        if (sessionHandle == 0) {
            System.out.println("⚠ 跳过测试：设备不可用 / Skipping test: device not available");
            return;
        }

        System.out.println("\n" + SEPARATOR);
        System.out.println("测试 2: 流式 SM3 哈希（分多次更新）");
        System.out.println("Test 2: Streaming SM3 Hash (Multiple Updates)");
        System.out.println(SEPARATOR);

        try {
            // 模拟分块处理大文件
            String[] chunks = {
                    "第一块数据 / Chunk 1 data. ",
                    "第二块数据 / Chunk 2 data. ",
                    "第三块数据 / Chunk 3 data. ",
                    "最后一块数据 / Final chunk data."
            };

            System.out.println("分块处理数据 / Processing data in chunks:");

            // 初始化 SM3 哈希
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            System.out.println("✓ SM3 哈希已初始化 / SM3 hash initialized");

            // 分多次更新数据
            for (int i = 0; i < chunks.length; i++) {
                byte[] chunkData = chunks[i].getBytes(StandardCharsets.UTF_8);
                sdf.SDF_HashUpdate(sessionHandle, chunkData);
                System.out.println("  ✓ 第 " + (i + 1) + " 块已更新 / Chunk " + (i + 1) + " updated (" +
                        chunkData.length + " bytes)");
            }

            // 获取最终哈希值
            byte[] hashValue = sdf.SDF_HashFinal(sessionHandle);
            System.out.println("✓ 流式 SM3 哈希值 / Streaming SM3 hash value:");
            System.out.println("  " + bytesToHex(hashValue));

            // 验证：计算整体数据的哈希值应该相同
            System.out.println("\n验证 / Verification:");
            String fullMessage = String.join("", chunks);
            byte[] fullData = fullMessage.getBytes(StandardCharsets.UTF_8);

            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, fullData);
            byte[] hashValue2 = sdf.SDF_HashFinal(sessionHandle);

            boolean match = java.util.Arrays.equals(hashValue, hashValue2);
            System.out.println("  整体哈希 / Full hash: " + bytesToHex(hashValue2));
            System.out.println("  " + (match ? "✓ 哈希值匹配！/ Hash values match!" :
                    "❌ 哈希值不匹配！/ Hash values do not match!"));

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("⚠ 此 SDF 库不支持 SM3 哈希功能");
                System.out.println("⚠ This SDF library does not support SM3 hash function");
            } else {
                throw e;
            }
        }
    }

    /**
     * 测试 3: SM2 签名场景的 SM3（带用户 ID 和公钥）
     * Test 3: SM3 for SM2 Signature (with User ID and Public Key)
     */
    @Test
    public void testSM3WithUserID() throws SDFException {
        if (sessionHandle == 0) {
            System.out.println("⚠ 跳过测试：设备不可用 / Skipping test: device not available");
            return;
        }

        System.out.println("\n" + SEPARATOR);
        System.out.println("测试 3: SM2 签名场景的 SM3（带用户 ID 和公钥）");
        System.out.println("Test 3: SM3 for SM2 Signature (with User ID and Public Key)");
        System.out.println(SEPARATOR);

        try {
            // 尝试获取 SM2 签名公钥
            int keyIndex = 1;
            ECCPublicKey publicKey = null;

            try {
                publicKey = sdf.SDF_ExportSignPublicKey_ECC(sessionHandle, keyIndex);
                System.out.println("✓ 已导出 SM2 签名公钥 / Exported SM2 sign public key");
                System.out.println("  密钥长度 / Key bits: " + publicKey.getBits());
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("⚠ 此 SDF 库不支持导出 SM2 公钥");
                    System.out.println("⚠ This SDF library does not support exporting SM2 public key");
                    System.out.println("跳过此测试 / Skipping this test");
                    return;
                } else {
                    throw e;
                }
            }

            // SM2 默认用户 ID（GM/T 0009-2012 规定）
            String userIDString = "1234567812345678"; // 默认用户标识
            byte[] userID = userIDString.getBytes(StandardCharsets.UTF_8);

            System.out.println("用户 ID / User ID: " + userIDString);
            System.out.println("用户 ID 长度 / User ID length: " + userID.length + " bytes");

            // 待签名的消息
            String message = "SM2 签名测试消息 / SM2 signature test message";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);

            System.out.println("待签名消息 / Message to sign: " + message);

            // 使用 SM3 计算哈希（带用户 ID 和公钥）
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, publicKey, userID);
            System.out.println("✓ SM3 哈希已初始化（带用户 ID 和公钥）");
            System.out.println("  SM3 hash initialized with user ID and public key");

            sdf.SDF_HashUpdate(sessionHandle, data);
            System.out.println("✓ 消息数据已更新 / Message data updated");

            byte[] hashValue = sdf.SDF_HashFinal(sessionHandle);
            System.out.println("✓ SM2 签名用的 SM3 哈希值 / SM3 hash for SM2 signature:");
            System.out.println("  " + bytesToHex(hashValue));

            System.out.println("\n说明 / Note:");
            System.out.println("  此哈希值可用于 SM2 签名验签流程");
            System.out.println("  This hash value can be used in SM2 sign/verify process");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("⚠ 此 SDF 库不支持带参数的 SM3 哈希");
                System.out.println("⚠ This SDF library does not support SM3 hash with parameters");
            } else {
                throw e;
            }
        }
    }

    /**
     * 测试 4: SM3-HMAC（外部密钥）
     * Test 4: SM3-HMAC (External Key)
     */
    @Test
    public void testSM3HMAC() throws SDFException {
        if (sessionHandle == 0) {
            System.out.println("⚠ 跳过测试：设备不可用 / Skipping test: device not available");
            return;
        }

        System.out.println("\n" + SEPARATOR);
        System.out.println("测试 4: SM3-HMAC（外部密钥）");
        System.out.println("Test 4: SM3-HMAC (External Key)");
        System.out.println(SEPARATOR);

        try {
            // 生成一个随机密钥用于 HMAC
            int keyLength = 32; // 256 bits
            byte[] hmacKey = sdf.SDF_GenerateRandom(sessionHandle, keyLength);
            System.out.println("✓ 生成随机 HMAC 密钥 / Generated random HMAC key:");
            System.out.println("  " + bytesToHex(hmacKey));
            System.out.println("  密钥长度 / Key length: " + keyLength + " bytes (" + (keyLength * 8) + " bits)");

            String message = "这是需要认证的消息 / This is the message to authenticate";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);

            System.out.println("\n消息 / Message: " + message);

            // 使用外部密钥初始化 SM3-HMAC
            sdf.SDF_ExternalKeyHMACInit(sessionHandle, AlgorithmID.SGD_SM3, hmacKey);
            System.out.println("✓ SM3-HMAC 已初始化 / SM3-HMAC initialized");

            // 更新数据
            sdf.SDF_HMACUpdate(sessionHandle, data);
            System.out.println("✓ 数据已更新 / Data updated");

            // 获取 HMAC 值
            byte[] hmacValue = sdf.SDF_HMACFinal(sessionHandle);
            System.out.println("✓ SM3-HMAC 值 / SM3-HMAC value:");
            System.out.println("  " + bytesToHex(hmacValue));
            System.out.println("  长度 / Length: " + hmacValue.length + " bytes");

            // 验证：使用相同的密钥重新计算应该得到相同的 HMAC
            System.out.println("\n验证 / Verification:");
            sdf.SDF_ExternalKeyHMACInit(sessionHandle, AlgorithmID.SGD_SM3, hmacKey);
            sdf.SDF_HMACUpdate(sessionHandle, data);
            byte[] hmacValue2 = sdf.SDF_HMACFinal(sessionHandle);

            boolean match = java.util.Arrays.equals(hmacValue, hmacValue2);
            System.out.println("  重新计算 / Recalculated: " + bytesToHex(hmacValue2));
            System.out.println("  " + (match ? "✓ HMAC 值匹配！/ HMAC values match!" :
                    "❌ HMAC 值不匹配！/ HMAC values do not match!"));

            // 演示：修改消息后 HMAC 应该不同
            System.out.println("\n篡改检测演示 / Tampering detection demo:");
            String tamperedMessage = message + " (已修改 / modified)";
            byte[] tamperedData = tamperedMessage.getBytes(StandardCharsets.UTF_8);

            sdf.SDF_ExternalKeyHMACInit(sessionHandle, AlgorithmID.SGD_SM3, hmacKey);
            sdf.SDF_HMACUpdate(sessionHandle, tamperedData);
            byte[] tamperedHMAC = sdf.SDF_HMACFinal(sessionHandle);

            boolean tampered = !java.util.Arrays.equals(hmacValue, tamperedHMAC);
            System.out.println("  篡改消息 / Tampered message: " + tamperedMessage);
            System.out.println("  篡改后 HMAC / Tampered HMAC: " + bytesToHex(tamperedHMAC));
            System.out.println("  " + (tampered ? "✓ 成功检测到篡改！/ Tampering detected!" :
                    "❌ 未能检测到篡改！/ Tampering not detected!"));

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("⚠ 此 SDF 库不支持 SM3-HMAC 功能");
                System.out.println("⚠ This SDF library does not support SM3-HMAC function");
            } else {
                throw e;
            }
        }
    }

    /**
     * 测试 5: 比较不同哈希算法的输出长度
     * Test 5: Compare Hash Lengths of Different Algorithms
     */
    @Test
    public void testCompareHashLengths() throws SDFException {
        if (sessionHandle == 0) {
            System.out.println("⚠ 跳过测试：设备不可用 / Skipping test: device not available");
            return;
        }

        System.out.println("\n" + SEPARATOR);
        System.out.println("测试 5: 比较不同哈希算法的输出长度");
        System.out.println("Test 5: Compare Hash Lengths of Different Algorithms");
        System.out.println(SEPARATOR);

        String message = "测试消息 / Test message";
        byte[] data = message.getBytes(StandardCharsets.UTF_8);

        System.out.println("测试消息 / Test message: " + message);
        System.out.println("消息长度 / Message length: " + data.length + " bytes\n");

        // 要测试的哈希算法列表
        int[][] algorithms = {
                {AlgorithmID.SGD_SM3, 256},
                {AlgorithmID.SGD_SHA1, 160},
                {AlgorithmID.SGD_SHA256, 256},
                {AlgorithmID.SGD_SHA384, 384},
                {AlgorithmID.SGD_SHA512, 512}
        };

        System.out.printf("%-15s %-20s %-15s %-20s%n",
                "算法/Algorithm", "预期长度/Expected", "实际长度/Actual", "状态/Status");
        // Java 8 compatible separator line (String.repeat() is Java 11+)
        System.out.println(new String(new char[80]).replace('\0', '-'));

        for (int[] alg : algorithms) {
            int algID = alg[0];
            int expectedBits = alg[1];
            String algName = AlgorithmID.getAlgorithmName(algID);

            try {
                sdf.SDF_HashInit(sessionHandle, algID, null, null);
                sdf.SDF_HashUpdate(sessionHandle, data);
                byte[] hashValue = sdf.SDF_HashFinal(sessionHandle);

                int actualBits = hashValue.length * 8;
                String status = (actualBits == expectedBits) ? "✓ 正确" : "⚠ 长度异常";

                System.out.printf("%-15s %-20s %-15s %-20s%n",
                        algName,
                        expectedBits + " bits",
                        actualBits + " bits (" + hashValue.length + " bytes)",
                        status);

            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.printf("%-15s %-20s %-15s %-20s%n",
                            algName, expectedBits + " bits", "N/A", "不支持/Not supported");
                } else {
                    System.out.printf("%-15s %-20s %-15s %-20s%n",
                            algName, expectedBits + " bits", "Error", "错误: " + e.getErrorCodeHex());
                }
            }
        }
    }

    /**
     * 将字节数组转换为十六进制字符串
     * Convert byte array to hexadecimal string
     *
     * @param bytes 字节数组 / Byte array
     * @return 十六进制字符串 / Hexadecimal string
     */
    private static String bytesToHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
}
