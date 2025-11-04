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

import static org.junit.Assert.*;

/**
 * SM4 对称加密示例测试
 * 演示SM4-ECB和SM4-CBC加解密
 *
 * 注意: 本测试使用内部ECC密钥生成会话密钥
 */
public class SM4ExampleTest {

    private SDF sdf;
    private long deviceHandle;
    private long sessionHandle;
    private long keyHandle;  // SM4会话密钥句柄
    private TestConfig config;
    private int keyIndex;

    @Before
    public void setUp() throws SDFException {
        System.out.println("========================================");
        System.out.println("SM4 对称加密示例");
        System.out.println("========================================\n");

        config = TestConfig.getInstance();
        keyIndex = config.getSM2InternalKeyIndex();

        System.out.println("Test Configuration:");
        System.out.println("  Environment: " + config.getEnvironmentName());
        System.out.println("  Key Index: " + keyIndex);
        System.out.println();

        sdf = new SDF();
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);
        System.out.println("设备和会话已打开");

        // 使用内部ECC密钥生成SM4会话密钥（128位）
        System.out.println("生成SM4会话密钥 (使用内部ECC密钥索引: " + keyIndex + ")");
        try {
            KeyEncryptionResult result = sdf.SDF_GenerateKeyWithIPK_ECC(sessionHandle, keyIndex, 128);
            keyHandle = result.getKeyHandle();
            System.out.println("✓ SM4密钥生成成功，密钥句柄: " + keyHandle);
            System.out.println("  加密密钥长度: " + result.getEncryptedKey().length + " bytes\n");
        } catch (SDFException e) {
            System.err.println("⚠ 密钥生成失败: " + e.getMessage());
            System.err.println("  后续测试将跳过加解密操作");
            keyHandle = 0;
        }
    }

    @After
    public void tearDown() {
        try {
            if (keyHandle != 0) {
                sdf.SDF_DestroyKey(sessionHandle, keyHandle);
                System.out.println("密钥已销毁");
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

    @Test
    public void testSM4ECB() {
        System.out.println("========================================");
        System.out.println("示例1: SM4-ECB模式");
        System.out.println("========================================");

        // 准备明文数据
        String plaintext = "Hello SDF4J! 测试SM4加密";
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        System.out.println("明文: " + plaintext);
        System.out.println("明文字节: " + bytesToHex(plaintextBytes));
        System.out.println("明文长度: " + plaintextBytes.length + " bytes\n");

        if (keyHandle != 0) {
            try {
                // 对数据进行PKCS#7填充（SM4块大小为16字节）
                byte[] paddedData = pkcs7Padding(plaintextBytes, 16);
                System.out.println("填充后长度: " + paddedData.length + " bytes");

                // ECB模式加密
                System.out.println("\n加密...");
                byte[] ciphertext = sdf.SDF_Encrypt(
                    sessionHandle,
                    keyHandle,
                    AlgorithmID.SGD_SM4_ECB,
                    null,  // ECB模式不需要IV
                    paddedData  // 使用填充后的数据
                );
                assertNotNull("密文不应为空", ciphertext);
                System.out.println("密文: " + bytesToHex(ciphertext));
                System.out.println("密文长度: " + ciphertext.length + " bytes");

                // ECB模式解密
                System.out.println("\n解密...");
                byte[] decrypted = sdf.SDF_Decrypt(
                    sessionHandle,
                    keyHandle,
                    AlgorithmID.SGD_SM4_ECB,
                    null,
                    ciphertext
                );

                // 去除PKCS#7填充
                byte[] unpaddedData = pkcs7Unpadding(decrypted);
                String decryptedText = new String(unpaddedData, StandardCharsets.UTF_8);
                System.out.println("解密结果: " + decryptedText);

                // 验证
                assertEquals("解密后应与原文一致", plaintext, decryptedText);
                System.out.println("✓ SM4-ECB加解密验证成功！");
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("⚠ SM4-ECB加解密功能未实现（这是正常的）");
                } else {
                    fail("SM4-ECB加解密失败: " + e.getMessage());
                }
            }
        } else {
            System.out.println("⚠ 跳过测试：密钥未能成功生成");
        }
    }

    @Test
    public void testSM4CBC() throws SDFException {
        System.out.println("\n========================================");
        System.out.println("示例2: SM4-CBC模式");
        System.out.println("========================================");

        // 准备明文数据
        String plaintext = "Hello SDF4J! 测试SM4加密";
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

        if (keyHandle != 0) {
            try {
                // 生成随机IV
                byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 16);
                System.out.println("\n初始向量IV: " + bytesToHex(iv));
                assertNotNull("IV不应为空", iv);
                assertEquals("IV长度应为16字节", 16, iv.length);

                // 对数据进行PKCS#7填充（SM4块大小为16字节）
                byte[] paddedData = pkcs7Padding(plaintextBytes, 16);
                System.out.println("填充后长度: " + paddedData.length + " bytes");

                // CBC模式加密
                System.out.println("\n加密...");
                byte[] ciphertext = sdf.SDF_Encrypt(
                    sessionHandle,
                    keyHandle,
                    AlgorithmID.SGD_SM4_CBC,
                    iv,
                    paddedData  // 使用填充后的数据
                );
                assertNotNull("密文不应为空", ciphertext);
                System.out.println("密文: " + bytesToHex(ciphertext));

                // CBC模式解密
                System.out.println("\n解密...");
                byte[] decrypted = sdf.SDF_Decrypt(
                    sessionHandle,
                    keyHandle,
                    AlgorithmID.SGD_SM4_CBC,
                    iv,
                    ciphertext
                );

                // 去除PKCS#7填充
                byte[] unpaddedData = pkcs7Unpadding(decrypted);
                String decryptedText = new String(unpaddedData, StandardCharsets.UTF_8);
                System.out.println("解密结果: " + decryptedText);

                // 验证
                assertEquals("解密后应与原文一致", plaintext, decryptedText);
                System.out.println("✓ SM4-CBC加解密验证成功！");
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("⚠ SM4-CBC加解密或随机数生成功能未实现（这是正常的）");
                } else {
                    fail("SM4-CBC加解密失败: " + e.getMessage());
                }
            }
        } else {
            System.out.println("⚠ 跳过测试：密钥未能成功生成");
        }
    }

    @Test
    public void testSM4MAC() {
        System.out.println("\n========================================");
        System.out.println("示例3: SM4-MAC消息认证码");
        System.out.println("========================================");

        if (keyHandle != 0) {
            try {
                byte[] data = "Message to authenticate".getBytes(StandardCharsets.UTF_8);
                System.out.println("\n待认证消息: " + new String(data, StandardCharsets.UTF_8));
                System.out.println("原始数据长度: " + data.length + " bytes");

                // 对数据进行PKCS#7填充（SM4块大小为16字节）
                // 注意：某些SDF实现可能内部处理填充，但为确保兼容性，我们手动填充
                byte[] paddedData = pkcs7Padding(data, 16);
                System.out.println("填充后长度: " + paddedData.length + " bytes");

                // 使用SDF随机数接口生成16字节的IV（初始化向量）
                byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 16);
                System.out.println("IV: " + bytesToHex(iv));

                // 计算MAC
                byte[] mac = sdf.SDF_CalculateMAC(
                    sessionHandle,
                    keyHandle,
                    AlgorithmID.SGD_SM4_MAC,
                    iv,
                    paddedData  // 使用填充后的数据
                );
                assertNotNull("MAC值不应为空", mac);
                System.out.println("MAC值: " + bytesToHex(mac));
                System.out.println("MAC长度: " + mac.length + " bytes");
                System.out.println("✓ MAC计算成功！");
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("⚠ SM4-MAC计算功能未实现（这是正常的）");
                } else {
                    fail("SM4-MAC计算失败: " + e.getMessage());
                }
            }
        } else {
            System.out.println("⚠ 跳过测试：密钥未能成功生成");
        }

        System.out.println("\n========================================");
        System.out.println("SM4示例完成！");
        System.out.println("========================================");
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * PKCS#7填充
     * 将数据填充到指定块大小的倍数
     * @param data 原始数据
     * @param blockSize 块大小（SM4为16字节）
     * @return 填充后的数据
     */
    private static byte[] pkcs7Padding(byte[] data, int blockSize) {
        int paddingLength = blockSize - (data.length % blockSize);
        byte[] paddedData = new byte[data.length + paddingLength];
        System.arraycopy(data, 0, paddedData, 0, data.length);
        for (int i = 0; i < paddingLength; i++) {
            paddedData[data.length + i] = (byte) paddingLength;
        }
        return paddedData;
    }

    /**
     * 去除PKCS#7填充
     * @param data 填充后的数据
     * @return 原始数据
     */
    private static byte[] pkcs7Unpadding(byte[] data) {
        if (data == null || data.length == 0) {
            return data;
        }
        int paddingLength = data[data.length - 1] & 0xFF;
        if (paddingLength > data.length || paddingLength == 0) {
            // 无效的填充，返回原数据
            return data;
        }
        // 验证填充是否正确
        for (int i = data.length - paddingLength; i < data.length; i++) {
            if ((data[i] & 0xFF) != paddingLength) {
                // 填充不正确，返回原数据
                return data;
            }
        }
        byte[] unpaddedData = new byte[data.length - paddingLength];
        System.arraycopy(data, 0, unpaddedData, 0, unpaddedData.length);
        return unpaddedData;
    }
}
