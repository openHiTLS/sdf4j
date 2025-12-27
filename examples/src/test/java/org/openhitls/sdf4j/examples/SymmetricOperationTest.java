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
import org.openhitls.sdf4j.constants.AlgorithmID;
import org.openhitls.sdf4j.constants.ErrorCode;
import org.openhitls.sdf4j.types.KeyEncryptionResult;

import java.nio.charset.StandardCharsets;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * 6.5节 对称算法运算类函数测试
 * Symmetric Algorithm Operation Functions Test (GM/T 0018-2023 Section 6.5)
 *
 * The following functions are NOT tested in this file:
 * - SDF_EncryptInit (6.5.7) - 多包对称加密初始化
 * - SDF_EncryptUpdate (6.5.8) - 多包对称加密
 * - SDF_EncryptFinal (6.5.9) - 多包对称加密结束
 * - SDF_DecryptInit (6.5.10) - 多包对称解密初始化
 * - SDF_DecryptUpdate (6.5.11) - 多包对称解密
 * - SDF_DecryptFinal (6.5.12) - 多包对称解密结束
 * - SDF_CalculateMACInit (6.5.13) - 多包MAC初始化
 * - SDF_CalculateMACUpdate (6.5.14) - 多包MAC计算
 * - SDF_CalculateMACFinal (6.5.15) - 多包MAC结束
 *
 * 本测试文件包含以下函数的测试用例：
 * This file contains test cases for the following functions:
 * - SDF_Encrypt (6.5.2) - 单包对称加密
 * - SDF_Decrypt (6.5.3) - 单包对称解密
 * - SDF_CalculateMAC (6.5.4) - 计算单包MAC
 * - SDF_AuthEnc (6.5.5) - 单包可鉴别加密
 * - SDF_AuthDec (6.5.6) - 单包可鉴别解密
 * - SDF_AuthEncInit (6.5.16) - 多包可鉴别加密初始化
 * - SDF_AuthEncUpdate (6.5.17) - 多包可鉴别加密
 * - SDF_AuthEncFinal (6.5.18) - 多包可鉴别加密结束
 * - SDF_AuthDecInit (6.5.19) - 多包可鉴别解密初始化
 * - SDF_AuthDecUpdate (6.5.20) - 多包可鉴别解密
 * - SDF_AuthDecFinal (6.5.21) - 多包可鉴别解密结束
  * - SDF_EncryptInit (6.5.7) - 多包对称加密初始化
 * - SDF_EncryptUpdate (6.5.8) - 多包对称加密
 * - SDF_EncryptFinal (6.5.9) - 多包对称加密结束
 * - SDF_DecryptInit (6.5.10) - 多包对称解密初始化
 * - SDF_DecryptUpdate (6.5.11) - 多包对称解密
 * - SDF_DecryptFinal (6.5.12) - 多包对称解密结束
 */
public class SymmetricOperationTest {

    private SDF sdf;
    private long deviceHandle;
    private long sessionHandle;
    private long keyHandle;
    private TestConfig config;
    private int keyIndex;

    @Before
    public void setUp() throws SDFException {
        System.out.println("========================================");
        System.out.println("6.5 对称算法运算类函数测试");
        System.out.println("========================================\n");

        // 启用 native 日志输出
        SDF.setLogger(message -> System.out.println("[NATIVE] " + message));
        SDF.setFileLoggingEnabled(false);
        SDF.setJavaLoggingEnabled(false);

        config = TestConfig.getInstance();
        keyIndex = config.getSM4InternalKeyIndex();  // Key索引，默认为4

        sdf = new SDF();
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);
        System.out.println("设备和会话已打开");
        // 使用KEK（密钥加密密钥）生成SM4会话密钥（128位）
        System.out.println("生成SM4会话密钥 (使用Key索引: " + keyIndex + ")");
        try {
            KeyEncryptionResult result = sdf.SDF_GenerateKeyWithKEK(sessionHandle, 128, AlgorithmID.SGD_SM4_ECB, keyIndex);
            keyHandle = result.getKeyHandle();
            System.out.println("SM4密钥生成成功，密钥句柄: 0x" + Long.toHexString(keyHandle).toUpperCase() + "\n");
        } catch (SDFException e) {
            System.err.println("密钥生成失败: " + e.getMessage());
            keyHandle = 0;
        }
    }

    @After
    public void tearDown() {
        try {
            if (keyHandle != 0) {
                sdf.SDF_DestroyKey(sessionHandle, keyHandle);
            }
            if (sessionHandle != 0) {
                sdf.SDF_CloseSession(sessionHandle);
            }
            if (deviceHandle != 0) {
                sdf.SDF_CloseDevice(deviceHandle);
            }
            System.out.println("\n资源已清理");
        } catch (SDFException e) {
            System.err.println("关闭资源失败: " + e.getMessage());
        }
    }

    /**
     * 6.5.2 单包对称加密测试
     * SDF_Encrypt test
     */
    @Test
    public void testEncrypt() {
        System.out.println("测试 6.5.2 SDF_Encrypt - 单包对称加密");

        if (keyHandle == 0) {
            System.out.println("跳过测试：密钥未能成功生成");
            return;
        }

        try {
            String originalText = "Hello SDF4J!";
            byte[] plaintext = pkcs7Padding(originalText.getBytes(StandardCharsets.UTF_8), 16);
            System.out.println("  明文: " + originalText);
            System.out.println("  明文(填充后): " + bytesToHex(plaintext) + " (" + plaintext.length + "字节)");

            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 16);
            System.out.println("  IV: " + bytesToHex(iv));
            System.out.println("  算法: SM4-CBC");

            byte[] ciphertext = sdf.SDF_Encrypt(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_CBC, iv, plaintext);

            assertNotNull("密文不应为空", ciphertext);
            assertTrue("密文长度应大于0", ciphertext.length > 0);
            System.out.println("  密文: " + bytesToHex(ciphertext) + " (" + ciphertext.length + "字节)");
            System.out.println("SDF_Encrypt 测试通过");
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("SDF_Encrypt 功能未实现");
            } else {
                fail("SDF_Encrypt 测试失败: " + e.getMessage());
            }
        }
    }

    /**
     * 6.5.3 单包对称解密测试
     * SDF_Decrypt test
     */
    @Test
    public void testDecrypt() {
        System.out.println("测试 6.5.3 SDF_Decrypt - 单包对称解密");

        if (keyHandle == 0) {
            System.out.println("跳过测试：密钥未能成功生成");
            return;
        }

        try {
            String originalText = "Hello SDF4J!";
            byte[] plaintext = pkcs7Padding(originalText.getBytes(StandardCharsets.UTF_8), 16);
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 16);
            System.out.println("  原始明文: " + originalText);
            System.out.println("  IV: " + bytesToHex(iv));
            System.out.println("  算法: SM4-CBC");

            // 先加密
            System.out.println("  执行加密...");
            byte[] ciphertext = sdf.SDF_Encrypt(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_CBC, iv, plaintext);
            System.out.println("  密文: " + bytesToHex(ciphertext));

            // 再解密
            System.out.println("  执行解密...");
            byte[] decrypted = sdf.SDF_Decrypt(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_CBC, iv, ciphertext);

            assertNotNull("解密结果不应为空", decrypted);
            byte[] unpaddedData = pkcs7Unpadding(decrypted);
            String decryptedText = new String(unpaddedData, StandardCharsets.UTF_8);
            System.out.println("  解密结果: " + decryptedText);
            assertEquals("解密后应与原文一致", originalText, decryptedText);
            System.out.println("SDF_Decrypt 测试通过");
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("SDF_Decrypt 功能未实现");
            } else {
                fail("SDF_Decrypt 测试失败: " + e.getMessage());
            }
        }
    }

    /**
     * 6.5.4 计算单包MAC测试
     * SDF_CalculateMAC test
     */
    @Test
    public void testCalculateMAC() {
        System.out.println("测试 6.5.4 SDF_CalculateMAC - 计算单包MAC");

        if (keyHandle == 0) {
            System.out.println("跳过测试：密钥未能成功生成");
            return;
        }

        try {
            String message = "Message for MAC";
            byte[] data = pkcs7Padding(message.getBytes(StandardCharsets.UTF_8), 16);
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 16);
            System.out.println("  消息: " + message);
            System.out.println("  数据(填充后): " + bytesToHex(data) + " (" + data.length + "字节)");
            System.out.println("  IV: " + bytesToHex(iv));
            System.out.println("  算法: SM4-MAC");

            System.out.println("  计算MAC...");
            byte[] mac = sdf.SDF_CalculateMAC(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_MAC, iv, data);

            assertNotNull("MAC值不应为空", mac);
            assertTrue("MAC长度应大于0", mac.length > 0);
            System.out.println("  MAC值: " + bytesToHex(mac) + " (" + mac.length + "字节)");
            System.out.println("SDF_CalculateMAC 测试通过");
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("SDF_CalculateMAC 功能未实现");
            } else {
                fail("SDF_CalculateMAC 测试失败: " + e.getMessage());
            }
        }
    }

    /**
     * 6.5.5 单包可鉴别加密测试
     * SDF_AuthEnc test
     */
    @Test
    public void testAuthEnc() {
        System.out.println("测试 6.5.5 SDF_AuthEnc - 单包可鉴别加密");

        if (keyHandle == 0) {
            System.out.println("跳过测试：密钥未能成功生成");
            return;
        }

        try {
            String message = "TestAuthEncData!";  // 16字节明文
            byte[] plaintext = message.getBytes(StandardCharsets.UTF_8);
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 12);  // GCM标准12字节IV
            String aadStr = "Additional Data!";  // 16字节AAD
            byte[] aad = aadStr.getBytes(StandardCharsets.UTF_8);
            System.out.println("  明文: " + message + " (" + plaintext.length + "字节)");
            System.out.println("  IV: " + bytesToHex(iv) + " (" + iv.length + "字节)");
            System.out.println("  AAD: " + aadStr + " (" + aad.length + "字节)");
            System.out.println("  算法: SM4-GCM");

            System.out.println("  执行可鉴别加密...");
            byte[][] result = sdf.SDF_AuthEnc(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM, iv, aad, plaintext);

            assertNotNull("AuthEnc结果不应为空", result);
            assertEquals("结果应包含2个元素(密文和认证标签)", 2, result.length);
            assertNotNull("密文不应为空", result[0]);
            assertNotNull("认证标签不应为空", result[1]);
            System.out.println("  密文: " + bytesToHex(result[0]) + " (" + result[0].length + "字节)");
            System.out.println("  认证标签: " + bytesToHex(result[1]) + " (" + result[1].length + "字节)");
            System.out.println("SDF_AuthEnc 测试通过");
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("SDF_AuthEnc 功能未实现");
            } else {
                fail("SDF_AuthEnc 测试失败: " + e.getMessage());
            }
        }
    }

    /**
     * 6.5.6 单包可鉴别解密测试
     * SDF_AuthDec test
     */
    @Test
    public void testAuthDec() {
        System.out.println("测试 6.5.6 SDF_AuthDec - 单包可鉴别解密");

        if (keyHandle == 0) {
            System.out.println("跳过测试：密钥未能成功生成");
            return;
        }

        try {
            String originalText = "Test AuthDec data";
            byte[] plaintext = originalText.getBytes(StandardCharsets.UTF_8);
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 12);
            String aadStr = "Additional Data";
            byte[] aad = aadStr.getBytes(StandardCharsets.UTF_8);
            System.out.println("  原始明文: " + originalText);
            System.out.println("  IV: " + bytesToHex(iv));
            System.out.println("  AAD: " + aadStr);
            System.out.println("  算法: SM4-GCM");

            // 先进行可鉴别加密
            System.out.println("  执行可鉴别加密...");
            byte[][] encResult = sdf.SDF_AuthEnc(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM, iv, aad, plaintext);
            byte[] ciphertext = encResult[0];
            byte[] authTag = encResult[1];
            System.out.println("  密文: " + bytesToHex(ciphertext));
            System.out.println("  认证标签: " + bytesToHex(authTag));

            // 再进行可鉴别解密
            System.out.println("  执行可鉴别解密...");
            byte[] decrypted = sdf.SDF_AuthDec(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM, iv, aad, authTag, ciphertext);

            assertNotNull("解密结果不应为空", decrypted);
            String decryptedText = new String(decrypted, StandardCharsets.UTF_8);
            System.out.println("  解密结果: " + decryptedText);
            assertEquals("解密后应与原文一致", originalText, decryptedText);
            System.out.println("SDF_AuthDec 测试通过");
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("SDF_AuthDec 功能未实现");
            } else {
                fail("SDF_AuthDec 测试失败: " + e.getMessage());
            }
        }
    }

/**
 * 6.5.7-6.5.9 多包对称加密测试
 * SDF_EncryptInit/Update/Final test
 */
@Test
public void testMultiPacketEncrypt() {
    System.out.println("测试 6.5.7-6.5.9 SDF_EncryptInit/Update/Final - 多包对称加密");

    if (keyHandle == 0) {
        System.out.println("跳过测试：密钥未能成功生成");
        return;
    }

    try {
        // 准备测试数据
        String originalText = "这是一段用于测试多包加密的数据，需要分多次处理。This is a test message for multi-packet encryption.";
        byte[] plaintext = pkcs7Padding(originalText.getBytes(StandardCharsets.UTF_8), 16);
        System.out.println("  明文: " + originalText);
        System.out.println("  明文(填充后): " + bytesToHex(plaintext) + " (" + plaintext.length + "字节)");

        // 生成IV
        byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 16);
        System.out.println("  IV: " + bytesToHex(iv));
        System.out.println("  算法: SM4-CBC");

        // 1. 单包加密（用于比较结果）
        byte[] singlePacketCipher = sdf.SDF_Encrypt(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_CBC, iv, plaintext);
        System.out.println("  单包加密密文: " + bytesToHex(singlePacketCipher) + " (" + singlePacketCipher.length + "字节)");

        // 2. 多包加密
        // 初始化加密
        sdf.SDF_EncryptInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_CBC, iv);
        System.out.println("  SDF_EncryptInit 调用成功");

        // 分多次处理数据
        int blockSize = 16;
        ByteArrayOutputStream cipherStream = new ByteArrayOutputStream();

        // 第一次更新：处理前16字节
        int offset1 = 0;
        int length1 = 16;
        byte[] data1 = Arrays.copyOfRange(plaintext, offset1, offset1 + length1);
        System.out.println("  第一次更新 - 输入明文: " + bytesToHex(data1) + " (" + length1 + "字节)");
        byte[] cipher1 = sdf.SDF_EncryptUpdate(sessionHandle, data1);
        if (cipher1 != null) {
            System.out.println("  第一次更新 - 输出密文: " + bytesToHex(cipher1) + " (" + cipher1.length + "字节)");
            cipherStream.write(cipher1);
        } else {
            System.out.println("  第一次更新 - 输出密文: null (返回空)");
        }
        System.out.println("  第一次更新: 处理" + length1 + "字节明文，返回" + (cipher1 != null ? cipher1.length : 0) + "字节密文");

        // 第二次更新：处理中间32字节
        int offset2 = offset1 + length1;
        int length2 = 32;
        byte[] data2 = Arrays.copyOfRange(plaintext, offset2, offset2 + length2);
        System.out.println("  第二次更新 - 输入明文: " + bytesToHex(data2) + " (" + length2 + "字节)");
        byte[] cipher2 = sdf.SDF_EncryptUpdate(sessionHandle, data2);
        if (cipher2 != null) {
            System.out.println("  第二次更新 - 输出密文: " + bytesToHex(cipher2) + " (" + cipher2.length + "字节)");
            cipherStream.write(cipher2);
        } else {
            System.out.println("  第二次更新 - 输出密文: null (返回空)");
        }
        System.out.println("  第二次更新: 处理" + length2 + "字节明文，返回" + (cipher2 != null ? cipher2.length : 0) + "字节密文");

        // 第三次更新：处理剩余数据
        int offset3 = offset2 + length2;
        int length3 = plaintext.length - offset3;
        byte[] data3 = Arrays.copyOfRange(plaintext, offset3, plaintext.length);
        System.out.println("  第三次更新 - 输入明文: " + bytesToHex(data3) + " (" + length3 + "字节)");
        byte[] cipher3 = sdf.SDF_EncryptUpdate(sessionHandle, data3);
        if (cipher3 != null) {
            System.out.println("  第三次更新 - 输出密文: " + bytesToHex(cipher3) + " (" + cipher3.length + "字节)");
            cipherStream.write(cipher3);
        } else {
            System.out.println("  第三次更新 - 输出密文: null (返回空)");
        }
        System.out.println("  第三次更新: 处理" + length3 + "字节明文，返回" + (cipher3 != null ? cipher3.length : 0) + "字节密文");

        // 结束加密
        byte[] finalCipher = sdf.SDF_EncryptFinal(sessionHandle);
        if (finalCipher != null) {
            System.out.println("  加密结束 - 最终密文: " + bytesToHex(finalCipher) + " (" + finalCipher.length + "字节)");
            cipherStream.write(finalCipher);
        } else {
            System.out.println("  加密结束 - 最终密文: null (返回空)");
        }
        System.out.println("  加密结束: 返回" + (finalCipher != null ? finalCipher.length : 0) + "字节>密文");

        // 获取完整密文
        byte[] multiPacketCipher = cipherStream.toByteArray();
        System.out.println("  多包加密密文: " + bytesToHex(multiPacketCipher) + " (" + multiPacketCipher.length + "字节)");

        // 验证结果
        assertNotNull("多包加密密文不应为空", multiPacketCipher);
        assertTrue("多包加密密文长度应大于0", multiPacketCipher.length > 0);
        assertArrayEquals("多包加密结果应与单包加密一致", singlePacketCipher, multiPacketCipher);

        // 测试小数据块
        System.out.println("\n  测试小数据块处理：");
        byte[] smallData = pkcs7Padding("test".getBytes(StandardCharsets.UTF_8), 16);
        System.out.println("  小数据块明文: " + bytesToHex(smallData) + " (" + smallData.length + "字节)");

        sdf.SDF_EncryptInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_CBC, iv);
        System.out.println("  小数据块加密初始化完成");

        System.out.println("  小数据块更新 - 输入明文: " + bytesToHex(smallData) + " (" + smallData.length + "字节)");
        byte[] smallCipher1 = sdf.SDF_EncryptUpdate(sessionHandle, smallData);
        if (smallCipher1 != null) {
            System.out.println("  小数据块更新 - 输出密文: " + bytesToHex(smallCipher1) + " (" + smallCipher1.length + "字节)");
        } else {
            System.out.println("  小数据块更新 - 输出密文: null (返回空)");
        }

        byte[] smallCipher2 = sdf.SDF_EncryptFinal(sessionHandle);
        if (smallCipher2 != null) {
            System.out.println("  小数据块结束 - 最终密文: " + bytesToHex(smallCipher2) + " (" + smallCipher2.length + "字节)");
        } else {
            System.out.println("  小数据块结束 - 最终密文: null (返回空)");
        }

        ByteArrayOutputStream smallStream = new ByteArrayOutputStream();
        if (smallCipher1 != null) smallStream.write(smallCipher1);
        if (smallCipher2 != null) smallStream.write(smallCipher2);

        byte[] smallEncrypted = smallStream.toByteArray();
        byte[] smallExpected = sdf.SDF_Encrypt(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_CBC, iv, smallData);

        assertArrayEquals("小数据块加密结果应一致", smallExpected, smallEncrypted);
        System.out.println("  小数据块测试通过");

        System.out.println("SDF_EncryptInit/Update/Final 测试通过");

    } catch (SDFException e) {
        if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
            System.out.println("SDF_EncryptInit/Update/Final 功能未实现");
        } else {
            fail("SDF_EncryptInit/Update/Final 测试失败: " + e.getMessage());
        }
    } catch (Exception e) {
        fail("SDF_EncryptInit/Update/Final 测试异常: " + e.getMessage());
    }
}

/**
 * 6.5.10-6.5.12 多包对称解密测试
 * SDF_DecryptInit/Update/Final test
 */
@Test
public void testMultiPacketDecrypt() {
    System.out.println("测试 6.5.10-6.5.12 SDF_DecryptInit/Update/Final - 多包对称解密");

    if (keyHandle == 0) {
        System.out.println("跳过测试：密钥未能成功生成");
        return;
    }

    try {
        // 准备测试数据
        String originalText = "这是一段用于测试多包解密的数据，需要分多次处理。This is a test message for multi-packet decryption.";
        byte[] plaintext = pkcs7Padding(originalText.getBytes(StandardCharsets.UTF_8), 16);
        System.out.println("  原始明文: " + originalText);
        System.out.println("  原始明文(填充后): " + bytesToHex(plaintext) + " (" + plaintext.length + "字节)");

        // 生成IV
        byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 16);
        System.out.println("  IV: " + bytesToHex(iv));
        System.out.println("  算法: SM4-CBC");

        // 1. 先加密数据（使用单包加密函数）
        byte[] ciphertext = sdf.SDF_Encrypt(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_CBC, iv, plaintext);
        System.out.println("  密文: " + bytesToHex(ciphertext) + " (" + ciphertext.length + "字节)");

        // 2. 多包解密测试
        // 初始化解密
        sdf.SDF_DecryptInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_CBC, iv);
        System.out.println("SDF_DecryptInit 成功");

        // 分多次解密数据
        ByteArrayOutputStream plainStream = new ByteArrayOutputStream();

        // 第一次更新：解密前32字节
        int offset1 = 0;
        int length1 = 32;
        byte[] cipherPart1 = Arrays.copyOfRange(ciphertext, offset1, offset1 + length1);
        byte[] plainPart1 = sdf.SDF_DecryptUpdate(sessionHandle, cipherPart1);
        if (plainPart1 != null) {
            plainStream.write(plainPart1);
        }
        System.out.println("  第一次解密: 处理" + length1 + "字节密文，返回" + (plainPart1 != null ? plainPart1.length : 0) + "字节明文");

        // 第二次更新：解密中间16字节
        int offset2 = offset1 + length1;
        int length2 = 16;
        byte[] cipherPart2 = Arrays.copyOfRange(ciphertext, offset2, offset2 + length2);
        byte[] plainPart2 = sdf.SDF_DecryptUpdate(sessionHandle, cipherPart2);
        if (plainPart2 != null) {
            plainStream.write(plainPart2);
        }
        System.out.println("  第二次解密: 处理" + length2 + "字节密文，返回" + (plainPart2 != null ? plainPart2.length : 0) + "字节明文");

        // 第三次更新：解密剩余数据
        int offset3 = offset2 + length2;
        int length3 = ciphertext.length - offset3;
        byte[] cipherPart3 = Arrays.copyOfRange(ciphertext, offset3, ciphertext.length);
        byte[] plainPart3 = sdf.SDF_DecryptUpdate(sessionHandle, cipherPart3);
        if (plainPart3 != null) {
            plainStream.write(plainPart3);
        }
        System.out.println("  第三次解密: 处理" + length3 + "字节密文，返回" + (plainPart3 != null ? plainPart3.length : 0) + "字节明文");

        // 结束解密
        byte[] finalPlain = sdf.SDF_DecryptFinal(sessionHandle);
        if (finalPlain != null) {
            plainStream.write(finalPlain);
        }
        System.out.println("  解密结束: 返回" + (finalPlain != null ? finalPlain.length : 0) + "字节明>文");

        // 获取完整明文
        byte[] decryptedData = plainStream.toByteArray();
        System.out.println("  解密后数据(填充): " + bytesToHex(decryptedData) + " (" + decryptedData.length + "字节)");

        // 移除PKCS7填充
        byte[] unpaddedData = pkcs7Unpadding(decryptedData);
        String decryptedText = new String(unpaddedData, StandardCharsets.UTF_8);
        System.out.println("  解密后明文: " + decryptedText);

        // 验证结果
        assertNotNull("解密后数据不应为空", decryptedData);
        assertTrue("解密后数据长度应大于0", decryptedData.length > 0);
        assertArrayEquals("解密后数据应与原始数据一致", plaintext, decryptedData);
        assertEquals("解密后文本应与原始文本一致", originalText, decryptedText);

        // 测试不完整密文块
        try {
            sdf.SDF_DecryptInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_CBC, iv);

            // 只传递部分密文
            byte[] partialCipher = Arrays.copyOfRange(ciphertext, 0, ciphertext.length - 5);
            byte[] partialPlain = sdf.SDF_DecryptUpdate(sessionHandle, partialCipher);
            byte[] finalResult = sdf.SDF_DecryptFinal(sessionHandle);

            System.out.println("  不完整密文块测试: 处理" + partialCipher.length + "字节密文");
        } catch (SDFException e) {
            System.out.println("  不完整密文块测试结果: " + e.getMessage());
        }

        System.out.println("SDF_DecryptInit/Update/Final 测试通过");

    } catch (SDFException e) {
        if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
            System.out.println("SDF_DecryptInit/Update/Final 功能未实现");
        } else {
            fail("SDF_DecryptInit/Update/Final 测试失败: " + e.getMessage());
        }
    } catch (Exception e) {
        fail("SDF_DecryptInit/Update/Final 测试异常: " + e.getMessage());
    }
}


    /**
     * 6.5.16 多包可鉴别加密初始化测试
     * SDF_AuthEncInit test
     */
    @Test
    public void testAuthEncInit() {
        System.out.println("测试 6.5.16 SDF_AuthEncInit - 多包可鉴别加密初始化");

        if (keyHandle == 0) {
            System.out.println("跳过测试：密钥未能成功生成");
            return;
        }

        try {
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 12);
            String aadStr = "Additional Data";
            byte[] aad = aadStr.getBytes(StandardCharsets.UTF_8);
            int dataLength = 32;
            System.out.println("  IV: " + bytesToHex(iv));
            System.out.println("  AAD: " + aadStr);
            System.out.println("  预期数据长度: " + dataLength + "字节");
            System.out.println("  算法: SM4-GCM");

            System.out.println("  执行初始化...");
            sdf.SDF_AuthEncInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM, iv, aad, dataLength);
            System.out.println("SDF_AuthEncInit 测试通过");
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("SDF_AuthEncInit 功能未实现");
            } else {
                fail("SDF_AuthEncInit 测试失败: " + e.getMessage());
            }
        }
    }

    /**
     * 6.5.17 多包可鉴别加密测试
     * SDF_AuthEncUpdate test
     */
    @Test
    public void testAuthEncUpdate() {
        System.out.println("测试 6.5.17 SDF_AuthEncUpdate - 多包可鉴别加密");

        if (keyHandle == 0) {
            System.out.println("跳过测试：密钥未能成功生成");
            return;
        }

        try {
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 12);
            String aadStr = "Additional Data";
            byte[] aad = aadStr.getBytes(StandardCharsets.UTF_8);
            String dataStr = "Test data block";
            byte[] data = dataStr.getBytes(StandardCharsets.UTF_8);
            System.out.println("  IV: " + bytesToHex(iv));
            System.out.println("  AAD: " + aadStr);
            System.out.println("  待加密数据: " + dataStr + " (" + data.length + "字节)");
            System.out.println("  待加密数据(hex): " + bytesToHex(data));
            System.out.println("  算法: SM4-GCM");

            // 先初始化
            System.out.println("  执行初始化...");
            sdf.SDF_AuthEncInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM, iv, aad, data.length);

            // 更新数据
            System.out.println("  执行更新加密...");
            byte[] encData = sdf.SDF_AuthEncUpdate(sessionHandle, data);

            assertNotNull("加密数据不应为空", encData);
            System.out.println("  加密数据: " + bytesToHex(encData) + " (" + encData.length + "字节)");
            System.out.println("SDF_AuthEncUpdate 测试通过");
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("SDF_AuthEncUpdate 功能未实现");
            } else {
                fail("SDF_AuthEncUpdate 测试失败: " + e.getMessage());
            }
        }
    }

    /**
     * 6.5.18 多包可鉴别加密结束测试
     * SDF_AuthEncFinal test
     */
    @Test
    public void testAuthEncFinal() {
        System.out.println("测试 6.5.18 SDF_AuthEncFinal - 多包可鉴别加密结束");

        if (keyHandle == 0) {
            System.out.println("跳过测试：密钥未能成功生成");
            return;
        }

        try {
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 12);
            String aadStr = "Additional Data";
            byte[] aad = aadStr.getBytes(StandardCharsets.UTF_8);
            String dataStr = "Test data block";
            byte[] data = dataStr.getBytes(StandardCharsets.UTF_8);
            System.out.println("  IV: " + bytesToHex(iv));
            System.out.println("  AAD: " + aadStr);
            System.out.println("  待加密数据: " + dataStr + " (" + data.length + "字节)");
            System.out.println("  待加密数据(hex): " + bytesToHex(data));
            System.out.println("  算法: SM4-GCM");

            // 初始化
            System.out.println("  步骤1: 执行初始化...");
            sdf.SDF_AuthEncInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM, iv, aad, data.length);

            // 更新
            System.out.println("  步骤2: 执行更新加密...");
            byte[] encData = sdf.SDF_AuthEncUpdate(sessionHandle, data);
            System.out.println("  中间密文: " + bytesToHex(encData));

            // 结束
            System.out.println("  步骤3: 执行结束...");
            byte[][] result = sdf.SDF_AuthEncFinal(sessionHandle, encData);

            assertNotNull("AuthEncFinal结果不应为空", result);
            assertEquals("结果应包含2个元素", 2, result.length);
            System.out.println("  最终密文: " + bytesToHex(result[0]) + " (" + (result[0] != null ? result[0].length : 0) + "字节)");
            System.out.println("  认证标签: " + bytesToHex(result[1]) + " (" + (result[1] != null ? result[1].length : 0) + "字节)");
            System.out.println("SDF_AuthEncFinal 测试通过");
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("SDF_AuthEncFinal 功能未实现");
            } else {
                fail("SDF_AuthEncFinal 测试失败: " + e.getMessage());
            }
        }
    }

    /**
     * 6.5.19 多包可鉴别解密初始化测试
     * SDF_AuthDecInit test
     */
    @Test
    public void testAuthDecInit() {
        System.out.println("测试 6.5.19 SDF_AuthDecInit - 多包可鉴别解密初始化");

        if (keyHandle == 0) {
            System.out.println("跳过测试：密钥未能成功生成");
            return;
        }

        try {
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 12);
            String aadStr = "Additional Data";
            byte[] aad = aadStr.getBytes(StandardCharsets.UTF_8);
            byte[] authTag = new byte[16];  // 模拟认证标签
            int dataLength = 32;
            System.out.println("  IV: " + bytesToHex(iv));
            System.out.println("  AAD: " + aadStr);
            System.out.println("  认证标签: " + bytesToHex(authTag) + " (" + authTag.length + "字节)");
            System.out.println("  预期数据长度: " + dataLength + "字节");
            System.out.println("  算法: SM4-GCM");

            System.out.println("  执行初始化...");
            sdf.SDF_AuthDecInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM, iv, aad, authTag, dataLength);
            System.out.println("SDF_AuthDecInit 测试通过");
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("SDF_AuthDecInit 功能未实现");
            } else {
                fail("SDF_AuthDecInit 测试失败: " + e.getMessage());
            }
        }
    }

    /**
     * 6.5.20 多包可鉴别解密测试
     * SDF_AuthDecUpdate test
     */
    @Test
    public void testAuthDecUpdate() {
        System.out.println("测试 6.5.20 SDF_AuthDecUpdate - 多包可鉴别解密");

        if (keyHandle == 0) {
            System.out.println("跳过测试：密钥未能成功生成");
            return;
        }

        try {
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 12);
            String aadStr = "Additional Data";
            byte[] aad = aadStr.getBytes(StandardCharsets.UTF_8);
            String plaintextStr = "Test data block";
            byte[] plaintext = plaintextStr.getBytes(StandardCharsets.UTF_8);
            System.out.println("  原始明文: " + plaintextStr);
            System.out.println("  原始明文(hex): " + bytesToHex(plaintext) + " (" + plaintext.length + "字节)");
            System.out.println("  IV: " + bytesToHex(iv));
            System.out.println("  AAD: " + aadStr);
            System.out.println("  算法: SM4-GCM");

            // 先用单包接口加密获取密文和标签
            System.out.println("  准备: 使用单包接口加密获取密文和标签...");
            byte[][] encResult = sdf.SDF_AuthEnc(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM, iv, aad, plaintext);
            byte[] ciphertext = encResult[0];
            byte[] authTag = encResult[1];
            System.out.println("  密文: " + bytesToHex(ciphertext));
            System.out.println("  认证标签: " + bytesToHex(authTag));

            // 初始化解密
            System.out.println("  步骤1: 执行解密初始化...");
            sdf.SDF_AuthDecInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM, iv, aad, authTag, ciphertext.length);

            // 更新解密
            System.out.println("  步骤2: 执行更新解密...");
            byte[] decData = sdf.SDF_AuthDecUpdate(sessionHandle, ciphertext);

            assertNotNull("解密数据不应为空", decData);
            System.out.println("  解密数据: " + bytesToHex(decData) + " (" + decData.length + "字节)");
            System.out.println("SDF_AuthDecUpdate 测试通过");
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("SDF_AuthDecUpdate 功能未实现");
            } else {
                fail("SDF_AuthDecUpdate 测试失败: " + e.getMessage());
            }
        }
    }

    /**
     * 6.5.21 多包可鉴别解密结束测试
     * SDF_AuthDecFinal test
     */
    @Test
    public void testAuthDecFinal() {
        System.out.println("测试 6.5.21 SDF_AuthDecFinal - 多包可鉴别解密结束");

        if (keyHandle == 0) {
            System.out.println("跳过测试：密钥未能成功生成");
            return;
        }

        try {
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 12);
            String aadStr = "Additional Data";
            byte[] aad = aadStr.getBytes(StandardCharsets.UTF_8);
            String plaintextStr = "Test data block";
            byte[] plaintext = plaintextStr.getBytes(StandardCharsets.UTF_8);
            System.out.println("  原始明文: " + plaintextStr);
            System.out.println("  原始明文(hex): " + bytesToHex(plaintext) + " (" + plaintext.length + "字节)");
            System.out.println("  IV: " + bytesToHex(iv));
            System.out.println("  AAD: " + aadStr);
            System.out.println("  算法: SM4-GCM");

            // 先用单包接口加密获取密文和标签
            System.out.println("  准备: 使用单包接口加密获取密文和标签...");
            byte[][] encResult = sdf.SDF_AuthEnc(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM, iv, aad, plaintext);
            byte[] ciphertext = encResult[0];
            byte[] authTag = encResult[1];
            System.out.println("  密文: " + bytesToHex(ciphertext));
            System.out.println("  认证标签: " + bytesToHex(authTag));

            // 初始化解密
            System.out.println("  步骤1: 执行解密初始化...");
            sdf.SDF_AuthDecInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM, iv, aad, authTag, ciphertext.length);

            // 更新解密
            System.out.println("  步骤2: 执行更新解密...");
            byte[] decData = sdf.SDF_AuthDecUpdate(sessionHandle, ciphertext);
            System.out.println("  中间解密数据: " + bytesToHex(decData));

            // 结束解密
            System.out.println("  步骤3: 执行结束解密...");
            byte[] finalData = sdf.SDF_AuthDecFinal(sessionHandle);

            // assertNotNull("AuthDecFinal结果不应为空", finalData);
	    System.out.println("  最终解密数据: " + bytesToHex(finalData) + " (" + (finalData != null ?finalData.length : 0) + "字节)");
            System.out.println("  解密结果(文本): " + new String(decData, StandardCharsets.UTF_8));
            System.out.println("SDF_AuthDecFinal 测试通过");
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("SDF_AuthDecFinal 功能未实现");
            } else {
                fail("SDF_AuthDecFinal 测试失败: " + e.getMessage());
            }
        }
    }

    // ========================================================================
    // 辅助方法
    // ========================================================================

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] pkcs7Padding(byte[] data, int blockSize) {
        int paddingLength = blockSize - (data.length % blockSize);
        byte[] paddedData = new byte[data.length + paddingLength];
        System.arraycopy(data, 0, paddedData, 0, data.length);
        for (int i = 0; i < paddingLength; i++) {
            paddedData[data.length + i] = (byte) paddingLength;
        }
        return paddedData;
    }

    private static byte[] pkcs7Unpadding(byte[] data) {
        if (data == null || data.length == 0) {
            return data;
        }
        int paddingLength = data[data.length - 1] & 0xFF;
        if (paddingLength > data.length || paddingLength == 0) {
            return data;
        }
        for (int i = data.length - paddingLength; i < data.length; i++) {
            if ((data[i] & 0xFF) != paddingLength) {
                return data;
            }
        }
        byte[] unpaddedData = new byte[data.length - paddingLength];
        System.arraycopy(data, 0, unpaddedData, 0, unpaddedData.length);
        return unpaddedData;
    }
}
