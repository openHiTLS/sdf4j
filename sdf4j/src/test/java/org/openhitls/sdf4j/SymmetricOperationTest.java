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
    private boolean kekAccessRightObtained;
    private boolean keyAvailable;  // 标记密钥是否成功生成，用于测试跳过判断

    @Before
    public void setUp() throws SDFException {

        config = TestConfig.getInstance();
        keyIndex = config.getSM4InternalKeyIndex();  // Key索引，默认为4
        kekAccessRightObtained = false;
        keyAvailable = false;  // 初始化为不可用

        sdf = new SDF();
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        // 获取KEK访问权限
        try {
            String kekPassword = config.getSM4KeyAccessPassword();
            sdf.SDF_GetKEKAccessRight(sessionHandle, keyIndex, kekPassword);
            kekAccessRightObtained = true;
        } catch (SDFException e) {
            if (e.getErrorCode() == org.openhitls.sdf4j.constants.ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] KEK 权限获取功能不支持");
                Assume.assumeTrue("[跳过] KEK 权限获取功能不支持", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        }

        // 使用KEK（密钥加密密钥）生成SM4会话密钥（128位）
        try {
            KeyEncryptionResult result = sdf.SDF_GenerateKeyWithKEK(sessionHandle, 128, AlgorithmID.SGD_SM4_ECB, keyIndex);
            keyHandle = result.getKeyHandle();
            keyAvailable = true;  // 标记密钥生成成功
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SDF_GenerateKeyWithKEK 功能不支持，跳过需要密钥的测试");
                Assume.assumeTrue("SDF_GenerateKeyWithKEK 功能不支持，跳过需要密钥的测试", false);
                keyAvailable = false;
                return;
            } else if (e.getErrorCode() == ErrorCode.SDR_KEYNOTEXIST) {
                keyAvailable = false;
            }
            // 除 SDR_NOTSUPPORT 外，异常抛出并失败
            throw new SDFException(e.getErrorCode(), "setUp: 密钥生成失败 - " + e.getMessage());
        }
    }

    @After
    public void tearDown() {
        try {
            if (keyHandle != 0) {
                sdf.SDF_DestroyKey(sessionHandle, keyHandle);
            }
            if (kekAccessRightObtained) {
                try {
                    sdf.SDF_ReleaseKEKAccessRight(sessionHandle, keyIndex);
                } catch (SDFException e) {
                    System.err.println("释放KEK访问权限失败: " + e.getMessage());
                }
            }
            if (sessionHandle != 0) {
                sdf.SDF_CloseSession(sessionHandle);
            }
            if (deviceHandle != 0) {
                sdf.SDF_CloseDevice(deviceHandle);
            }
        } catch (SDFException e) {
            System.err.println("关闭资源失败: " + e.getMessage());
        }
    }

    /**
     * 检查密钥是否可用，如果不可用则跳过测试
     * 使用 Assume 来正确标记测试为跳过状态
     */
    private void assumeKeyAvailable() {
        Assume.assumeTrue("密钥未成功生成，跳过测试（可能内部密钥不存在）", keyAvailable);
    }

    /**
     * 6.5.2 单包对称加密测试
     * SDF_Encrypt test
     */
    @Test
    public void testEncrypt() throws SDFException {

        assumeKeyAvailable();

        try {
            String originalText = "Hello SDF4J!";
            byte[] plaintext = pkcs7Padding(originalText.getBytes(StandardCharsets.UTF_8), 16);

            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 16);

            byte[] ciphertext = sdf.SDF_Encrypt(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_CBC, iv, plaintext);

            assertNotNull("密文不应为空", ciphertext);
            assertTrue("密文长度应大于0", ciphertext.length > 0);

            // 解密验证
            byte[] decrypted = sdf.SDF_Decrypt(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_CBC, iv, ciphertext);
            assertNotNull("解密结果不应为空", decrypted);
            byte[] unpaddedData = pkcs7Unpadding(decrypted);
            String decryptedText = new String(unpaddedData, StandardCharsets.UTF_8);
            assertEquals("解密后应与原文一致", originalText, decryptedText);

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SDF_Encrypt 功能未实现");
                Assume.assumeTrue("SDF_Encrypt 功能未实现", false);
            } else {
                throw new SDFException(e.getErrorCode(), "SDF_Encrypt 测试失败: " + e.getMessage());
            }
        }
    }

    /**
     * 6.5.3 单包对称解密测试
     * SDF_Decrypt test
     */
    @Test
    public void testDecrypt() throws SDFException {

        assumeKeyAvailable();

        try {
            String originalText = "Hello SDF4J!";
            byte[] plaintext = pkcs7Padding(originalText.getBytes(StandardCharsets.UTF_8), 16);
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 16);
            assertNotNull("iv不应为空", iv);

            // 先加密
            byte[] ciphertext = sdf.SDF_Encrypt(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_CBC, iv, plaintext);
            assertNotNull(" 密文不应为空", ciphertext);

            // 再解密
            byte[] decrypted = sdf.SDF_Decrypt(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_CBC, iv, ciphertext);
            assertNotNull("解密结果不应为空", decrypted);
            byte[] unpaddedData = pkcs7Unpadding(decrypted);
            assertNotNull(" 去填充数据不应为空", unpaddedData);

            String decryptedText = new String(unpaddedData, StandardCharsets.UTF_8);
            assertEquals("解密后应与原文一致", originalText, decryptedText);
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SDF_Decrypt 功能未实现");
                Assume.assumeTrue("SDF_Decrypt 功能未实现", false);
            } else {
                throw new SDFException(e.getErrorCode(), "SDF_Decrypt 测试失败: " + e.getMessage());
            }
        }
    }

    /**
     * 6.5.4 计算单包MAC测试
     * SDF_CalculateMAC test
     */
    @Test
    public void testCalculateMAC() throws SDFException {

        assumeKeyAvailable();

        try {
            String message = "Message for MAC";
            byte[] data = pkcs7Padding(message.getBytes(StandardCharsets.UTF_8), 16);
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 16);

            byte[] mac = sdf.SDF_CalculateMAC(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_MAC, iv, data);

            assertNotNull("MAC值不应为空", mac);
            assertTrue("MAC长度应大于0", mac.length > 0);
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SDF_CalculateMAC 功能未实现");
                Assume.assumeTrue("SDF_CalculateMAC 功能未实现", false);
            } else {
                throw new SDFException(e.getErrorCode(), "SDF_CalculateMAC 测试失败: " + e.getMessage());
            }
        }
    }

    /**
     * 6.5.5 单包可鉴别加密测试
     * SDF_AuthEnc test
     */
    @Test
    public void testAuthEnc() throws SDFException {

        assumeKeyAvailable();

        try {
            String message = "TestAuthEncData!";  // 16字节明文
            byte[] plaintext = message.getBytes(StandardCharsets.UTF_8);
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 12);  // GCM标准12字节IV
            String aadStr = "Additional Data!";  // 16字节AAD
            byte[] aad = aadStr.getBytes(StandardCharsets.UTF_8);

            byte[][] result = sdf.SDF_AuthEnc(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM, iv, aad, plaintext);

            assertNotNull("AuthEnc结果不应为空", result);
            assertEquals("结果应包含2个元素(密文和认证标签)", 2, result.length);
            assertNotNull("密文不应为空", result[0]);
            assertNotNull("认证标签不应为空", result[1]);

            // 解密验证
            byte[] decrypted = sdf.SDF_AuthDec(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM, iv, aad, result[1], result[0]);
            assertNotNull("解密结果不应为空", decrypted);
            String decryptedText = new String(decrypted, StandardCharsets.UTF_8);
            assertEquals("解密后应与原文一致", message, decryptedText);

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SDF_AuthEnc 功能未实现");
                Assume.assumeTrue("SDF_AuthEnc 功能未实现", false);
            } else {
                throw new SDFException(e.getErrorCode(), "SDF_AuthEnc 测试失败: " + e.getMessage());
            }
        }
    }

    /**
     * 6.5.6 单包可鉴别解密测试
     * SDF_AuthDec test
     */
    @Test
    public void testAuthDec() throws SDFException {

        assumeKeyAvailable();

        try {
            String originalText = "Test AuthDec data";
            byte[] plaintext = originalText.getBytes(StandardCharsets.UTF_8);
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 12);
            String aadStr = "Additional Data";
            byte[] aad = aadStr.getBytes(StandardCharsets.UTF_8);

            // 先进行可鉴别加密
            byte[][] encResult = sdf.SDF_AuthEnc(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM, iv, aad, plaintext);
            assertNotNull("加密结果不应为空", encResult);
            byte[] ciphertext = encResult[0];
            byte[] authTag = encResult[1];

            // 再进行可鉴别解密
            byte[] decrypted = sdf.SDF_AuthDec(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM, iv, aad, authTag, ciphertext);
            assertNotNull("解密结果不应为空", decrypted);
            String decryptedText = new String(decrypted, StandardCharsets.UTF_8);
            assertEquals("解密后应与原文一致", originalText, decryptedText);
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SDF_AuthDec 功能未实现");
                Assume.assumeTrue("SDF_AuthDec 功能未实现", false);
            } else {
                throw new SDFException(e.getErrorCode(), "SDF_AuthDec 测试失败: " + e.getMessage());
            }
        }
    }

/**
 * 6.5.7-6.5.9 多包对称加密测试
 * SDF_EncryptInit/Update/Final test
 */
@Test
public void testMultiPacketEncrypt() throws SDFException {

    assumeKeyAvailable();

    try {
        // 准备测试数据
        String originalText = "这是一段用于测试多包加密的数据，需要分多次处理。This is a test message for multi-packet encryption.";
        byte[] plaintext = pkcs7Padding(originalText.getBytes(StandardCharsets.UTF_8), 16);

        // 生成IV
        byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 16);

        // 1. 单包加密（用于比较结果）
        byte[] singlePacketCipher = sdf.SDF_Encrypt(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_CBC, iv, plaintext);

        // 2. 多包加密
        // 初始化加密
        sdf.SDF_EncryptInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_CBC, iv);

        // 分多次处理数据
        int blockSize = 16;
        ByteArrayOutputStream cipherStream = new ByteArrayOutputStream();

        // 第一次更新：处理前16字节
        int offset1 = 0;
        int length1 = 16;
        byte[] data1 = Arrays.copyOfRange(plaintext, offset1, offset1 + length1);
        byte[] cipher1 = sdf.SDF_EncryptUpdate(sessionHandle, data1);
        if (cipher1 != null) {
            cipherStream.write(cipher1);
        }
        // 第二次更新：处理中间32字节
        int offset2 = offset1 + length1;
        int length2 = 32;
        byte[] data2 = Arrays.copyOfRange(plaintext, offset2, offset2 + length2);
        byte[] cipher2 = sdf.SDF_EncryptUpdate(sessionHandle, data2);
        if (cipher2 != null) {
            cipherStream.write(cipher2);
        }
        // 第三次更新：处理剩余数据
        int offset3 = offset2 + length2;
        int length3 = plaintext.length - offset3;
        byte[] data3 = Arrays.copyOfRange(plaintext, offset3, plaintext.length);
        byte[] cipher3 = sdf.SDF_EncryptUpdate(sessionHandle, data3);
        if (cipher3 != null) {
            cipherStream.write(cipher3);
        }
        // 结束加密
        byte[] finalCipher = sdf.SDF_EncryptFinal(sessionHandle);
        if (finalCipher != null) {
            cipherStream.write(finalCipher);
        }
        // 获取完整密文
        byte[] multiPacketCipher = cipherStream.toByteArray();

        // 验证结果
        assertNotNull("多包加密密文不应为空", multiPacketCipher);
        assertTrue("多包加密密文长度应大于0", multiPacketCipher.length > 0);
        assertArrayEquals("多包加密结果应与单包加密一致", singlePacketCipher, multiPacketCipher);

        // 测试小数据块
        byte[] smallData = pkcs7Padding("test".getBytes(StandardCharsets.UTF_8), 16);
        assertNotNull("pad数据不应该为空", smallData);

        sdf.SDF_EncryptInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_CBC, iv);
        byte[] smallCipher1 = sdf.SDF_EncryptUpdate(sessionHandle, smallData);

        byte[] smallCipher2 = sdf.SDF_EncryptFinal(sessionHandle);

        ByteArrayOutputStream smallStream = new ByteArrayOutputStream();
        if (smallCipher1 != null) smallStream.write(smallCipher1);
        if (smallCipher2 != null) smallStream.write(smallCipher2);

        byte[] smallEncrypted = smallStream.toByteArray();
        byte[] smallExpected = sdf.SDF_Encrypt(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_CBC, iv, smallData);

        assertArrayEquals("小数据块加密结果应一致", smallExpected, smallEncrypted);
    } catch (SDFException e) {
        if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
            System.out.println("[跳过] SDF_EncryptInit/Update/Final 功能未实现");
            Assume.assumeTrue("SDF_EncryptInit/Update/Final 功能未实现", false);
        } else {
            throw new SDFException(e.getErrorCode(), "SDF_EncryptInit/Update/Final 测试失败: " + e.getMessage());
        }
    } catch (Exception ex) {
        throw new SDFException(ErrorCode.SDR_UNKNOWERR, "SDF_EncryptInit/Update/Final 测试异常: " + ex.getMessage());
    }
}

/**
 * 6.5.10-6.5.12 多包对称解密测试
 * SDF_DecryptInit/Update/Final test
 */
@Test
public void testMultiPacketDecrypt() throws SDFException {

    try {
        // 准备测试数据
        String originalText = "这是一段用于测试多包解密的数据，需要分多次处理。This is a test message for multi-packet decryption.";
        byte[] plaintext = pkcs7Padding(originalText.getBytes(StandardCharsets.UTF_8), 16);

        // 生成IV
        byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 16);

        // 1. 先加密数据（使用单包加密函数）
        byte[] ciphertext = sdf.SDF_Encrypt(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_CBC, iv, plaintext);

        // 2. 多包解密测试
        // 初始化解密
        sdf.SDF_DecryptInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_CBC, iv);

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

        // 第二次更新：解密中间16字节
        int offset2 = offset1 + length1;
        int length2 = 16;
        byte[] cipherPart2 = Arrays.copyOfRange(ciphertext, offset2, offset2 + length2);
        byte[] plainPart2 = sdf.SDF_DecryptUpdate(sessionHandle, cipherPart2);
        if (plainPart2 != null) {
            plainStream.write(plainPart2);
        }

        // 第三次更新：解密剩余数据
        int offset3 = offset2 + length2;
        int length3 = ciphertext.length - offset3;
        byte[] cipherPart3 = Arrays.copyOfRange(ciphertext, offset3, ciphertext.length);
        byte[] plainPart3 = sdf.SDF_DecryptUpdate(sessionHandle, cipherPart3);
        if (plainPart3 != null) {
            plainStream.write(plainPart3);
        }

        // 结束解密
        byte[] finalPlain = sdf.SDF_DecryptFinal(sessionHandle);
        if (finalPlain != null) {
            plainStream.write(finalPlain);
        }

        // 获取完整明文
        byte[] decryptedData = plainStream.toByteArray();

        // 移除PKCS7填充
        byte[] unpaddedData = pkcs7Unpadding(decryptedData);
        String decryptedText = new String(unpaddedData, StandardCharsets.UTF_8);

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

        } catch (SDFException e) {
            // 预期会抛出异常，因为密文块不完整，无法正确解密
        }


    } catch (SDFException e) {
        if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
            System.out.println("[跳过] SDF_DecryptInit/Update/Final 功能未实现");
            Assume.assumeTrue("SDF_DecryptInit/Update/Final 功能未实现", false);
        } else {
            throw new SDFException(e.getErrorCode(), "SDF_DecryptInit/Update/Final 测试失败: " + e.getMessage());
        }
    } catch (Exception ex) {
        throw new SDFException(ErrorCode.SDR_UNKNOWERR, "SDF_DecryptInit/Update/Final 测试异常: " + ex.getMessage());
    }
}


    /**
     * 6.5.16 多包可鉴别加密初始化测试
     * SDF_AuthEncInit test
     */
    @Test
    public void testAuthEncInit() throws SDFException {

        assumeKeyAvailable();

        try {
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 12);
            String aadStr = "Additional Data";
            byte[] aad = aadStr.getBytes(StandardCharsets.UTF_8);
            int dataLength = 32;
            sdf.SDF_AuthEncInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM, iv, aad, dataLength);
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SDF_AuthEncInit 功能未实现");
                Assume.assumeTrue("SDF_AuthEncInit 功能未实现", false);
            } else {
                throw new SDFException(e.getErrorCode(), "SDF_AuthEncInit 测试失败: " + e.getMessage());
            }
        }
    }

    /**
     * 6.5.17 多包可鉴别加密测试
     * SDF_AuthEncUpdate test
     */
    @Test
    public void testAuthEncUpdate() throws SDFException {

        assumeKeyAvailable();

        try {
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 12);
            String aadStr = "Additional Data";
            byte[] aad = aadStr.getBytes(StandardCharsets.UTF_8);
            String dataStr = "Test data block";
            byte[] data = dataStr.getBytes(StandardCharsets.UTF_8);

            // 先初始化
            sdf.SDF_AuthEncInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM, iv, aad, data.length);

            // 更新数据
            byte[] encData = sdf.SDF_AuthEncUpdate(sessionHandle, data);

            assertNotNull("加密数据不应为空", encData);
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SDF_AuthEncUpdate 功能未实现");
                Assume.assumeTrue("SDF_AuthEncUpdate 功能未实现", false);
            } else {
                throw new SDFException(e.getErrorCode(), "SDF_AuthEncUpdate 测试失败: " + e.getMessage());
            }
        }
    }

    /**
     * 6.5.18 多包可鉴别加密结束测试
     * SDF_AuthEncFinal test
     */
    @Test
    public void testAuthEncFinal() throws SDFException {

        assumeKeyAvailable();

        try {
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 12);
            String aadStr = "Additional Data";
            byte[] aad = aadStr.getBytes(StandardCharsets.UTF_8);
            String dataStr = "Test data block";
            byte[] data = dataStr.getBytes(StandardCharsets.UTF_8);

            // 初始化
            sdf.SDF_AuthEncInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM, iv, aad, data.length);

            // 更新
            byte[] encData = sdf.SDF_AuthEncUpdate(sessionHandle, data);

            // 结束
            byte[][] result = sdf.SDF_AuthEncFinal(sessionHandle, encData);
            assertNotNull("AuthEncFinal结果不应为空", result);
            assertEquals("结果应包含2个元素", 2, result.length);
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SDF_AuthEncFinal 功能未实现");
                Assume.assumeTrue("SDF_AuthEncFinal 功能未实现", false);
            } else {
                throw new SDFException(e.getErrorCode(), "SDF_AuthEncFinal 测试失败: " + e.getMessage());
            }
        }
    }

    /**
     * 6.5.19 多包可鉴别解密初始化测试
     * SDF_AuthDecInit test
     */
    @Test
    public void testAuthDecInit() throws SDFException {

        assumeKeyAvailable();

        try {
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 12);
            String aadStr = "Additional Data";
            byte[] aad = aadStr.getBytes(StandardCharsets.UTF_8);
            byte[] authTag = new byte[16];  // 模拟认证标签
            int dataLength = 32;
            sdf.SDF_AuthDecInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM, iv, aad, authTag, dataLength);
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SDF_AuthDecInit 功能未实现");
                Assume.assumeTrue("SDF_AuthDecInit 功能未实现", false);
            } else {
                throw new SDFException(e.getErrorCode(), "SDF_AuthDecInit 测试失败: " + e.getMessage());
            }
        }
    }

    /**
     * 6.5.20 多包可鉴别解密测试
     * SDF_AuthDecUpdate test
     */
    @Test
    public void testAuthDecUpdate() throws SDFException {

        assumeKeyAvailable();

        try {
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 12);
            String aadStr = "Additional Data";
            byte[] aad = aadStr.getBytes(StandardCharsets.UTF_8);
            String plaintextStr = "Test data block";
            byte[] plaintext = plaintextStr.getBytes(StandardCharsets.UTF_8);

            // 先用单包接口加密获取密文和标签
            byte[][] encResult = sdf.SDF_AuthEnc(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM, iv, aad, plaintext);
            byte[] ciphertext = encResult[0];
            byte[] authTag = encResult[1];

            // 初始化解密
            sdf.SDF_AuthDecInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM, iv, aad, authTag, ciphertext.length);

            // 更新解密
            byte[] decData = sdf.SDF_AuthDecUpdate(sessionHandle, ciphertext);

            assertNotNull("解密数据不应为空", decData);
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SDF_AuthDecUpdate 功能未实现");
                Assume.assumeTrue("SDF_AuthDecUpdate 功能未实现", false);
            } else {
                throw new SDFException(e.getErrorCode(), "SDF_AuthDecUpdate 测试失败: " + e.getMessage());
            }
        }
    }

    /**
     * 6.5.21 多包可鉴别解密结束测试
     * SDF_AuthDecFinal test
     */
    @Test
    public void testAuthDecFinal() throws SDFException {

        assumeKeyAvailable();

        try {
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 12);
            String aadStr = "Additional Data";
            byte[] aad = aadStr.getBytes(StandardCharsets.UTF_8);
            String plaintextStr = "Test data block";
            byte[] plaintext = plaintextStr.getBytes(StandardCharsets.UTF_8);

            // 先用单包接口加密获取密文和标签
            byte[][] encResult = sdf.SDF_AuthEnc(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM, iv, aad, plaintext);
            byte[] ciphertext = encResult[0];
            byte[] authTag = encResult[1];

            // 初始化解密
            sdf.SDF_AuthDecInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM, iv, aad, authTag, ciphertext.length);

            // 更新解密
            byte[] decData = sdf.SDF_AuthDecUpdate(sessionHandle, ciphertext);
            assertNotNull("AuthDecUpdate结果不应为空", decData);

            // 结束解密
            byte[] finalData = sdf.SDF_AuthDecFinal(sessionHandle);
            assertNotNull("AuthDecFinal结果不应为空", finalData);
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SDF_AuthDecFinal 功能未实现");
                Assume.assumeTrue("SDF_AuthDecFinal 功能未实现", false);
            } else {
                throw new SDFException(e.getErrorCode(), "SDF_AuthDecFinal 测试失败: " + e.getMessage());
            }
        }
    }

    /**
     * 6.5.2 外部密钥对称加密测试
     * SDF_ExternalKeyEncrypt test
     */
    @Test
    public void testExternalKeyEncrypt() throws SDFException {

        try {
            String originalText = "Hello External Key!";
            byte[] plaintext = pkcs7Padding(originalText.getBytes(StandardCharsets.UTF_8), 16);

            // 生成外部密钥
            byte[] externalKey = sdf.SDF_GenerateRandom(sessionHandle, 16);
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 16);
            byte[] ciphertext = sdf.SDF_ExternalKeyEncrypt(sessionHandle, AlgorithmID.SGD_SM4_CBC, externalKey, iv, plaintext);

            assertNotNull("密文不应为空", ciphertext);
            assertTrue("密文长度应大于0", ciphertext.length > 0);

            // 解密验证
            byte[] decrypted = sdf.SDF_ExternalKeyDecrypt(sessionHandle, AlgorithmID.SGD_SM4_CBC, externalKey, iv, ciphertext);
            assertNotNull("解密结果不应为空", decrypted);
            byte[] unpaddedData = pkcs7Unpadding(decrypted);
            String decryptedText = new String(unpaddedData, StandardCharsets.UTF_8);
            assertEquals("解密后应与原文一致", originalText, decryptedText);

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SDF_ExternalKeyEncrypt 功能未实现");
                Assume.assumeTrue("SDF_ExternalKeyEncrypt 功能未实现", false);
            } else {
                throw new SDFException(e.getErrorCode(), "SDF_ExternalKeyEncrypt 测试失败: " + e.getMessage());
            }
        }
    }

    /**
     * 6.5.3 外部密钥对称解密测试
     * SDF_ExternalKeyDecrypt test
     */
    @Test
    public void testExternalKeyDecrypt() throws SDFException {

        try {
            String originalText = "Hello External Key!";
            byte[] plaintext = pkcs7Padding(originalText.getBytes(StandardCharsets.UTF_8), 16);

            // 生成外部密钥
            byte[] externalKey = sdf.SDF_GenerateRandom(sessionHandle, 16);
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 16);

            // 先加密
            byte[] ciphertext = sdf.SDF_ExternalKeyEncrypt(sessionHandle, AlgorithmID.SGD_SM4_CBC, externalKey, iv, plaintext);

            // 再解密
            byte[] decrypted = sdf.SDF_ExternalKeyDecrypt(sessionHandle, AlgorithmID.SGD_SM4_CBC, externalKey, iv, ciphertext);

            assertNotNull("解密结果不应为空", decrypted);
            byte[] unpaddedData = pkcs7Unpadding(decrypted);
            String decryptedText = new String(unpaddedData, StandardCharsets.UTF_8);
            assertEquals("解密后应与原文一致", originalText, decryptedText);
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SDF_ExternalKeyDecrypt 功能未实现");
                Assume.assumeTrue("SDF_ExternalKeyDecrypt 功能未实现", false);
            } else {
                throw new SDFException(e.getErrorCode(), "SDF_ExternalKeyDecrypt 测试失败: " + e.getMessage());
            }
        }
    }

    /**
     * 外部密钥多包加密测试
     * SDF_ExternalKeyEncryptInit + SDF_EncryptUpdate/Final test
     * 注意：外部密钥初始化后，使用通用的 EncryptUpdate/Final 完成多包操作
     */
    @Test
    public void testExternalKeyMultiPacketEncrypt() throws SDFException {

        try {
            String originalText = "This is a test message for external key multi-packet encryption.";
            byte[] plaintext = pkcs7Padding(originalText.getBytes(StandardCharsets.UTF_8), 16);

            // 生成外部密钥和IV
            byte[] externalKey = sdf.SDF_GenerateRandom(sessionHandle, 16);
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 16);

            // 单包加密（用于比较结果）
            byte[] singlePacketCipher = sdf.SDF_ExternalKeyEncrypt(sessionHandle, AlgorithmID.SGD_SM4_CBC, externalKey, iv, plaintext);

            // 多包加密：使用 ExternalKeyEncryptInit 初始化，然后通用的 EncryptUpdate/Final
            sdf.SDF_ExternalKeyEncryptInit(sessionHandle, AlgorithmID.SGD_SM4_CBC, externalKey, iv);

            ByteArrayOutputStream cipherStream = new ByteArrayOutputStream();

            // 分三次处理数据
            int offset = 0;
            int chunkSize = 32;
            while (offset < plaintext.length) {
                int length = Math.min(chunkSize, plaintext.length - offset);
                byte[] dataChunk = Arrays.copyOfRange(plaintext, offset, offset + length);
                byte[] cipherChunk = sdf.SDF_EncryptUpdate(sessionHandle, dataChunk);
                if (cipherChunk != null) {
                    cipherStream.write(cipherChunk);
                }
                offset += length;
            }

            byte[] finalCipher = sdf.SDF_EncryptFinal(sessionHandle);
            if (finalCipher != null) {
                cipherStream.write(finalCipher);
            }

            byte[] multiPacketCipher = cipherStream.toByteArray();

            assertNotNull("多包加密密文不应为空", multiPacketCipher);
            assertArrayEquals("多包加密结果应与单包加密一致", singlePacketCipher, multiPacketCipher);

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SDF_ExternalKeyEncryptInit 功能未实现");
                Assume.assumeTrue("SDF_ExternalKeyEncryptInit 功能未实现", false);
            } else {
                throw new SDFException(e.getErrorCode(), "SDF_ExternalKeyEncryptInit 测试失败: " + e.getMessage());
            }
        } catch (Exception ex) {
            throw new SDFException(ErrorCode.SDR_UNKNOWERR, "SDF_ExternalKeyEncryptInit 测试异常: " + ex.getMessage());
        }
    }

    /**
     * 外部密钥多包解密测试
     * SDF_ExternalKeyDecryptInit + SDF_DecryptUpdate/Final test
     */
    @Test
    public void testExternalKeyMultiPacketDecrypt() throws SDFException {

        try {
            String originalText = "This is a test message for external key multi-packet decryption.";
            byte[] plaintext = pkcs7Padding(originalText.getBytes(StandardCharsets.UTF_8), 16);
            // 生成外部密钥和IV
            byte[] externalKey = sdf.SDF_GenerateRandom(sessionHandle, 16);
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 16);

            // 先加密数据
            byte[] ciphertext = sdf.SDF_ExternalKeyEncrypt(sessionHandle, AlgorithmID.SGD_SM4_CBC, externalKey, iv, plaintext);

            // 多包解密：使用 ExternalKeyDecryptInit 初始化，然后通用的 DecryptUpdate/Final
            sdf.SDF_ExternalKeyDecryptInit(sessionHandle, AlgorithmID.SGD_SM4_CBC, externalKey, iv);

            ByteArrayOutputStream plainStream = new ByteArrayOutputStream();

            // 分三次解密
            int offset = 0;
            int chunkSize = 32;
            while (offset < ciphertext.length) {
                int length = Math.min(chunkSize, ciphertext.length - offset);
                byte[] cipherChunk = Arrays.copyOfRange(ciphertext, offset, offset + length);
                byte[] plainChunk = sdf.SDF_DecryptUpdate(sessionHandle, cipherChunk);
                if (plainChunk != null) {
                    plainStream.write(plainChunk);
                }
                offset += length;
            }

            byte[] finalPlain = sdf.SDF_DecryptFinal(sessionHandle);
            if (finalPlain != null) {
                plainStream.write(finalPlain);
            }

            byte[] decryptedData = plainStream.toByteArray();
            byte[] unpaddedData = pkcs7Unpadding(decryptedData);
            String decryptedText = new String(unpaddedData, StandardCharsets.UTF_8);

            assertArrayEquals("解密后数据应与原始数据一致", plaintext, decryptedData);
            assertEquals("解密后文本应与原始文本一致", originalText, decryptedText);

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SDF_ExternalKeyDecryptInit 功能未实现");
                Assume.assumeTrue("SDF_ExternalKeyDecryptInit 功能未实现", false);
            } else {
                throw new SDFException(e.getErrorCode(), "SDF_ExternalKeyDecryptInit 测试失败: " + e.getMessage());
            }
        } catch (Exception ex) {
            throw new SDFException(ErrorCode.SDR_UNKNOWERR, "SDF_ExternalKeyDecryptInit 测试异常: " + ex.getMessage());
        }
    }

    // ========================================================================
    // 流式MAC测试
    // ========================================================================

    /**
     * 6.5.13-6.5.15 多包MAC计算测试
     * SDF_CalculateMACInit/Update/Final test
     */
    @Test
    public void testMultiPacketCalculateMAC() throws SDFException {

        assumeKeyAvailable();

        try {
            String message = "Message for multi-packet MAC calculation. This message is longer than single packet test.";
            byte[] data = pkcs7Padding(message.getBytes(StandardCharsets.UTF_8), 16);
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 16);

            // 单包MAC（用于比较结果）
            byte[] singlePacketMAC = sdf.SDF_CalculateMAC(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_MAC, iv, data);

            // 多包MAC
            sdf.SDF_CalculateMACInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_MAC, iv);

            // 分三次处理数据
            int offset = 0;
            int chunkSize = 32;
            while (offset < data.length) {
                int length = Math.min(chunkSize, data.length - offset);
                byte[] dataChunk = Arrays.copyOfRange(data, offset, offset + length);
                sdf.SDF_CalculateMACUpdate(sessionHandle, dataChunk);
                offset += length;
            }

            byte[] multiPacketMAC = sdf.SDF_CalculateMACFinal(sessionHandle);

            assertNotNull("MAC值不应为空", multiPacketMAC);
            assertArrayEquals("多包MAC应与单包MAC一致", singlePacketMAC, multiPacketMAC);

            // 验证MAC一致性
            byte[] mac2 = sdf.SDF_CalculateMAC(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_MAC, iv, data);
            assertArrayEquals("MAC计算应一致", singlePacketMAC, mac2);
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SDF_CalculateMACInit/Update/Final 功能未实现");
                Assume.assumeTrue("SDF_CalculateMACInit/Update/Final 功能未实现", false);
            } else {
                throw new SDFException(e.getErrorCode(), "SDF_CalculateMACInit/Update/Final 测试失败: " + e.getMessage());
            }
        } catch (Exception ex) {
            throw new SDFException(ErrorCode.SDR_UNKNOWERR, "SDF_CalculateMACInit/Update/Final 测试异常: " + ex.getMessage());
        }
    }

    /**
     * 单包MAC一致性验证测试
     * 验证相同数据多次计算MAC结果相同
     */
    @Test
    public void testCalculateMACConsistency() throws SDFException {

        assumeKeyAvailable();

        try {
            String message = "Message for MAC consistency test";
            byte[] data = pkcs7Padding(message.getBytes(StandardCharsets.UTF_8), 16);
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 16);

            // 多次计算MAC
            byte[] mac1 = sdf.SDF_CalculateMAC(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_MAC, iv, data);
            byte[] mac2 = sdf.SDF_CalculateMAC(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_MAC, iv, data);
            byte[] mac3 = sdf.SDF_CalculateMAC(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_MAC, iv, data);

            assertArrayEquals("第一次和第二次MAC应相同", mac1, mac2);
            assertArrayEquals("第二次和第三次MAC应相同", mac2, mac3);

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                Assume.assumeTrue("SDF_CalculateMAC 功能未实现", false);
            } else {
                throw new SDFException(e.getErrorCode(), "SDF_CalculateMAC 测试失败: " + e.getMessage());
            }
        }
    }

    // ========================================================================
    // AuthDecFinal 正确性验证改进测试
    // ========================================================================

    /**
     * 完整的 AEAD 加密解密流程测试
     * 验证 AuthEnc -> AuthDec 完整流程的正确性
     */
    @Test
    public void testCompleteAEADProcess() throws SDFException {

        assumeKeyAvailable();

        try {
            String originalText = "Complete AEAD test data!";
            byte[] plaintext = originalText.getBytes(StandardCharsets.UTF_8);
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 12);
            String aadStr = "Additional Auth Data";
            byte[] aad = aadStr.getBytes(StandardCharsets.UTF_8);

            // 单包加密
            byte[][] encResult = sdf.SDF_AuthEnc(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM, iv, aad, plaintext);
            byte[] ciphertext = encResult[0];
            byte[] authTag = encResult[1];

            // 单包解密
            byte[] decrypted = sdf.SDF_AuthDec(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM, iv, aad, authTag, ciphertext);
            String decryptedText = new String(decrypted, StandardCharsets.UTF_8);
            assertEquals("单包解密后应与原文一致", originalText, decryptedText);

            // 多包加密
            sdf.SDF_AuthEncInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM, iv, aad, plaintext.length);
            byte[] encData = sdf.SDF_AuthEncUpdate(sessionHandle, plaintext);
            byte[][] finalResult = sdf.SDF_AuthEncFinal(sessionHandle, encData);
            byte[] ciphertext2 = finalResult[0];
            byte[] authTag2 = finalResult[1];

            // 多包解密
            sdf.SDF_AuthDecInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM, iv, aad, authTag2, ciphertext2.length);
            byte[] decData = sdf.SDF_AuthDecUpdate(sessionHandle, encData);
            byte[] finalDecrypted = sdf.SDF_AuthDecFinal(sessionHandle);
            String decDataText = new String(decData, StandardCharsets.UTF_8);
            String finalDecryptedText = new String(finalDecrypted, StandardCharsets.UTF_8);
            String result = decDataText + finalDecryptedText;
            assertEquals("多包解密后应与原文一致", originalText, result);

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] AEAD 功能未实现");
                Assume.assumeTrue("AEAD 功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
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
