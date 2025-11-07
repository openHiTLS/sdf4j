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
import org.openhitls.sdf4j.types.*;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

/**
 * SM2 外部密钥示例测试
 * 演示使用临时生成的外部密钥对进行SM2签名验签和加密解密操作
 *
 * 外部密钥是指在设备外部生成或临时生成的密钥对，不存储在设备内部
 */
public class SM2ExternalKeyExampleTest {

    private SDF sdf;
    private long deviceHandle;
    private long sessionHandle;
    private static final int KEY_BITS = 256;  // SM2 密钥长度 256 bits

    @Before
    public void setUp() throws SDFException {
        System.out.println("========================================");
        System.out.println("SM2 外部密钥示例测试");
        System.out.println("========================================\n");

        // 启用 native 日志输出
        SDF.setLogger(message -> System.out.println("🔔 [NATIVE] " + message));
        SDF.setFileLoggingEnabled(false);   // 禁用文件日志
        SDF.setJavaLoggingEnabled(true);    // 启用 Java 回调日志

        sdf = new SDF();
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);
        System.out.println("✓ 设备和会话已打开\n");
    }

    @After
    public void tearDown() {
        try {
            if (sessionHandle != 0) {
                sdf.SDF_CloseSession(sessionHandle);
            }
            if (deviceHandle != 0) {
                sdf.SDF_CloseDevice(deviceHandle);
            }
            System.out.println("\n✓ 资源已清理");
            System.out.println("========================================\n");
        } catch (SDFException e) {
            System.err.println("✗ 关闭资源失败: " + e.getMessage());
        }
    }

    @Test
    public void testGenerateKeyPair() throws SDFException {
        System.out.println("----------------------------------------");
        System.out.println("测试1: 生成外部 ECC 密钥对");
        System.out.println("----------------------------------------\n");

        try {
            System.out.println("生成 SM2 密钥对 (算法: SGD_SM2_1, 密钥长度: " + KEY_BITS + " bits)");

            // 生成密钥对
            Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, KEY_BITS);
            assertNotNull("密钥对不应为空", keyPair);
            assertEquals("应返回2个元素（公钥和私钥）", 2, keyPair.length);

            // 提取公钥和私钥
            ECCPublicKey publicKey = (ECCPublicKey) keyPair[0];
            ECCPrivateKey privateKey = (ECCPrivateKey) keyPair[1];

            assertNotNull("公钥不应为空", publicKey);
            assertNotNull("私钥不应为空", privateKey);

            // 显示公钥信息
            System.out.println("\n✓ 密钥对生成成功\n");
            System.out.println("公钥信息:");
            System.out.println("  密钥位数: " + publicKey.getBits() + " bits");
            System.out.println("  X 坐标长度: " + publicKey.getX().length + " bytes");
            System.out.println("  Y 坐标长度: " + publicKey.getY().length + " bytes");
            System.out.println("  X: " + bytesToHex(publicKey.getX()));
            System.out.println("  Y: " + bytesToHex(publicKey.getY()));

            // 显示私钥信息
            System.out.println("\n私钥信息:");
            System.out.println("  密钥位数: " + privateKey.getBits() + " bits");
            System.out.println("  K 值长度: " + privateKey.getK().length + " bytes");
            System.out.println("  K: " + bytesToHex(privateKey.getK()).substring(0, 32) + "... (已截断，私钥敏感)");

            assertEquals("公钥和私钥的位数应该相同", publicKey.getBits(), privateKey.getBits());
            assertTrue("密钥位数应为256", publicKey.getBits() == 256);

            System.out.println("\n✓ 密钥对生成测试完成");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("⚠ ECC 密钥对生成功能未实现（这是正常的）");
            } else {
                throw e;
            }
        }
    }

    @Test
    public void testExternalSignAndVerify() throws SDFException {
        System.out.println("----------------------------------------");
        System.out.println("测试2: 外部密钥签名和验签");
        System.out.println("----------------------------------------\n");

        try {
            // 步骤1: 生成密钥对
            System.out.println("步骤1: 生成临时密钥对");
            Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, KEY_BITS);
            ECCPublicKey publicKey = (ECCPublicKey) keyPair[0];
            ECCPrivateKey privateKey = (ECCPrivateKey) keyPair[1];
            System.out.println("✓ 密钥对生成完成\n");

            // 步骤2: 使用外部私钥签名
            String message = "使用外部密钥签名的重要文档";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);

            System.out.println("步骤2: 使用外部私钥签名");
            System.out.println("待签名数据: \"" + message + "\"");
            System.out.println("数据长度: " + data.length + " bytes");

            ECCSignature signature = sdf.SDF_ExternalSign_ECC(
                sessionHandle,
                AlgorithmID.SGD_SM2_1,
                privateKey,
                data
            );
            assertNotNull("签名结果不应为空", signature);

            System.out.println("\n签名成功:");
            System.out.println("  r 分量: " + bytesToHex(signature.getR()));
            System.out.println("  s 分量: " + bytesToHex(signature.getS()));

            // 步骤3: 使用外部公钥验签
            System.out.println("\n步骤3: 使用外部公钥验签");
            sdf.SDF_ExternalVerify_ECC(
                sessionHandle,
                AlgorithmID.SGD_SM2_1,
                publicKey,
                data,
                signature
            );
            System.out.println("✓ 外部验签成功 - 签名有效!");

            // 步骤4: 验证使用错误数据会导致验签失败
            System.out.println("\n步骤4: 验证数据完整性保护");
            byte[] tamperedData = "被篡改的文档内容".getBytes(StandardCharsets.UTF_8);
            System.out.println("篡改后的数据: \"" + new String(tamperedData, StandardCharsets.UTF_8) + "\"");

            try {
                sdf.SDF_ExternalVerify_ECC(
                    sessionHandle,
                    AlgorithmID.SGD_SM2_1,
                    publicKey,
                    tamperedData,
                    signature
                );
                fail("使用篡改数据验签应该失败");
            } catch (SDFException e) {
                System.out.println("✓ 篡改数据验签正确失败: " + e.getErrorCodeHex());
            }

            System.out.println("\n✓ 外部签名验签测试完成");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("⚠ 外部签名/验签功能未实现（这是正常的）");
            } else {
                throw e;
            }
        }
    }

    @Test
    public void testExternalEncryptDecrypt() throws SDFException {
        System.out.println("----------------------------------------");
        System.out.println("测试3: 外部密钥加密和解密");
        System.out.println("----------------------------------------\n");

        try {
            // 步骤1: 生成密钥对
            System.out.println("步骤1: 生成加密用密钥对");
            Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, KEY_BITS);
            ECCPublicKey publicKey = (ECCPublicKey) keyPair[0];
            ECCPrivateKey privateKey = (ECCPrivateKey) keyPair[1];
            System.out.println("✓ 密钥对生成完成 (公钥位数: " + publicKey.getBits() + " bits)\n");

            // 步骤2: 使用外部公钥加密
            String plaintext = "这是需要加密保护的机密信息内容";
            byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

            System.out.println("步骤2: 使用外部公钥加密");
            System.out.println("明文: \"" + plaintext + "\"");
            System.out.println("明文长度: " + plaintextBytes.length + " bytes");
            System.out.println("明文十六进制: " + bytesToHex(plaintextBytes));

            ECCCipher cipher = sdf.SDF_ExternalEncrypt_ECC(
                sessionHandle,
                AlgorithmID.SGD_SM2_1,
                publicKey,
                plaintextBytes
            );
            assertNotNull("密文不应为空", cipher);

            System.out.println("\n加密成功:");
            System.out.println("  SM2 密文结构 (C1||C3||C2):");
            System.out.println("    C1 X: " + bytesToHex(cipher.getX()).substring(0, 32) + "...");
            System.out.println("    C1 Y: " + bytesToHex(cipher.getY()).substring(0, 32) + "...");
            System.out.println("    C3 (MAC): " + bytesToHex(cipher.getM()));
            System.out.println("    C2 长度: " + cipher.getL() + " bytes");
            System.out.println("    C2 (密文): " + bytesToHex(cipher.getC()));

            // 步骤3: 使用外部私钥解密
            System.out.println("\n步骤3: 使用外部私钥解密");
            byte[] decryptedBytes = sdf.SDF_ExternalDecrypt_ECC(
                sessionHandle,
                AlgorithmID.SGD_SM2_1,
                privateKey,
                cipher
            );
            assertNotNull("解密结果不应为空", decryptedBytes);

            String decrypted = new String(decryptedBytes, StandardCharsets.UTF_8);
            System.out.println("解密成功:");
            System.out.println("  解密后明文: \"" + decrypted + "\"");
            System.out.println("  解密后长度: " + decryptedBytes.length + " bytes");

            // 验证解密结果
            assertEquals("解密后的明文应与原始明文相同", plaintext, decrypted);
            assertArrayEquals("解密后的字节数组应与原始明文字节数组相同", plaintextBytes, decryptedBytes);

            System.out.println("\n✓ 加密解密验证成功 - 明文完全一致!");
            System.out.println("✓ 外部加密解密测试完成");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("⚠ 外部加密/解密功能未实现（这是正常的）");
            } else {
                throw e;
            }
        }
    }

    @Test
    public void testMultipleKeyPairs() throws SDFException {
        System.out.println("----------------------------------------");
        System.out.println("测试4: 生成和使用多个密钥对");
        System.out.println("----------------------------------------\n");

        try {
            System.out.println("场景: 为不同用户生成独立的密钥对\n");

            String[] users = {"Alice", "Bob", "Charlie"};

            for (int i = 0; i < users.length; i++) {
                String user = users[i];
                System.out.println((i + 1) + ". 为用户 " + user + " 生成密钥对");

                // 生成密钥对
                Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, KEY_BITS);
                ECCPublicKey publicKey = (ECCPublicKey) keyPair[0];

                // 显示公钥摘要
                String pubKeyDigest = bytesToHex(publicKey.getX()).substring(0, 16);
                System.out.println("   公钥 X 坐标摘要: " + pubKeyDigest + "...");

                // 使用密钥签名
                String message = user + " 的文档";
                byte[] data = message.getBytes(StandardCharsets.UTF_8);
                ECCSignature signature = sdf.SDF_ExternalSign_ECC(
                    sessionHandle,
                    AlgorithmID.SGD_SM2_1,
                    (ECCPrivateKey) keyPair[1],
                    data
                );

                // 验证签名
                sdf.SDF_ExternalVerify_ECC(
                    sessionHandle,
                    AlgorithmID.SGD_SM2_1,
                    publicKey,
                    data,
                    signature
                );
                System.out.println("   ✓ 签名验证通过\n");
            }

            System.out.println("✓ 多密钥对测试完成");
            System.out.println("\n外部密钥优势:");
            System.out.println("  • 无需预先在设备中存储密钥");
            System.out.println("  • 适合临时性或一次性加密场景");
            System.out.println("  • 灵活支持多用户多密钥管理");
            System.out.println("  • 可以导出密钥用于互操作");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("⚠ 功能未实现");
            } else {
                throw e;
            }
        }
    }

    @Test
    public void testCrossVerification() throws SDFException {
        System.out.println("----------------------------------------");
        System.out.println("测试5: 交叉验证 - 不同密钥对之间的隔离");
        System.out.println("----------------------------------------\n");

        try {
            System.out.println("场景: 验证使用错误的公钥无法验证签名\n");

            // 生成两个不同的密钥对
            System.out.println("生成密钥对 A");
            Object[] keyPairA = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, KEY_BITS);
            ECCPublicKey publicKeyA = (ECCPublicKey) keyPairA[0];
            ECCPrivateKey privateKeyA = (ECCPrivateKey) keyPairA[1];

            System.out.println("生成密钥对 B");
            Object[] keyPairB = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, KEY_BITS);
            ECCPublicKey publicKeyB = (ECCPublicKey) keyPairB[0];

            // 使用密钥对 A 的私钥签名
            String message = "测试文档";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);

            System.out.println("\n使用密钥对 A 的私钥签名");
            ECCSignature signature = sdf.SDF_ExternalSign_ECC(
                sessionHandle,
                AlgorithmID.SGD_SM2_1,
                privateKeyA,
                data
            );
            System.out.println("✓ 签名完成");

            // 使用密钥对 A 的公钥验签（应该成功）
            System.out.println("\n使用密钥对 A 的公钥验签");
            sdf.SDF_ExternalVerify_ECC(
                sessionHandle,
                AlgorithmID.SGD_SM2_1,
                publicKeyA,
                data,
                signature
            );
            System.out.println("✓ 验签成功 - 使用正确的公钥");

            // 使用密钥对 B 的公钥验签（应该失败）
            System.out.println("\n使用密钥对 B 的公钥验签（错误的公钥）");
            try {
                sdf.SDF_ExternalVerify_ECC(
                    sessionHandle,
                    AlgorithmID.SGD_SM2_1,
                    publicKeyB,
                    data,
                    signature
                );
                fail("使用错误的公钥验签应该失败");
            } catch (SDFException e) {
                System.out.println("✓ 验签正确失败 - 密钥对不匹配: " + e.getErrorCodeHex());
            }

            System.out.println("\n✓ 交叉验证测试完成 - 密钥隔离性验证成功");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("⚠ 功能未实现");
            } else {
                throw e;
            }
        }
    }

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
