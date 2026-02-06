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
import org.openhitls.sdf4j.types.*;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Properties;

import static org.junit.Assert.*;

/**
 * SDF4J 非对称算法运算类函数测试
 * 测试 GM/T 0018-2023 标准中 6.4 节定义的非对称算法运算类函数
 *
 * 注意: RSA 相关函数暂未实现，包括:
 * - 6.4.2 SDF_ExternalPublicKeyOperation_RSA - 外部公钥 RSA 运算
 * - 6.4.3 SDF_InternalPublicKeyOperation_RSA - 内部公钥 RSA 运算
 * - 6.4.4 SDF_InternalPrivateKeyOperation_RSA - 内部私钥 RSA 运算
 * - 6.8.2 SDF_GenerateKeyPair_RSA - 产生 RSA 非对称密钥对并输出
 * - 6.8.4 SDF_ExternalPrivateKeyOperation_RSA - 外部私钥 RSA 运算
 *
 * 包含以下 ECC 接口测试：
 * - 6.4.5 SDF_ExternalVerify_ECC - 外部公钥 ECC 验证
 * - 6.4.6 SDF_InternalSign_ECC - 内部私钥 ECC 签名
 * - 6.4.7 SDF_InternalVerify_ECC - 内部公钥 ECC 验证
 * - 6.4.8 SDF_ExternalEncrypt_ECC - 外部公钥 ECC 加密
 * - 6.4.9 SDF_InternalEncrypt_ECC - 内部公钥 ECC 加密
 * - 6.4.10 SDF_InternalDecrypt_ECC - 内部私钥 ECC 解密
 *
 * 以及 6.8 节调试函数：
 * - 6.8.3 SDF_GenerateKeyPair_ECC - 产生 ECC 非对称密钥对并输出
 * - 6.8.5 SDF_ExternalSign_ECC - 外部私钥 ECC 签名
 * - 6.8.6 SDF_ExternalDecrypt_ECC - 外部私钥 ECC 解密
 */
public class AsymmetricOperationTest {

    // 配置开关：设置为 true 时从配置文件读取，false 时使用下面的默认值
    private static final boolean USE_CONFIG_FILE = true;

    // 默认配置
    private static final int DEFAULT_KEY_INDEX = 1;
    private static final String DEFAULT_KEY_PASSWORD = "123abc!@";
    private static final String DEFAULT_USER_ID = "1234567812345678";

    // ECC/SM2 密钥长度
    private static final int ECC_KEY_BITS = 256;

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
            try (InputStream is = AsymmetricOperationTest.class.getClassLoader()
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
        System.out.println("SDF4J 非对称算法运算类函数测试");
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

    // ========================================================================
    // ECC/SM2 外部密钥运算测试
    // ========================================================================

    /**
     * 测试 6.8.3 SDF_GenerateKeyPair_ECC - 生成 ECC 密钥对
     */
    @Test
    public void testGenerateECCKeyPair() throws SDFException {
        System.out.println("测试 6.8.3 SDF_GenerateKeyPair_ECC - 生成 ECC 密钥对");
        System.out.println("----------------------------------------");

        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            System.out.println("生成 SM2 密钥对，算法: SGD_SM2_1, 密钥长度: " + ECC_KEY_BITS + " bits");

            Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            assertNotNull("密钥对不应为空", keyPair);
            assertEquals("应返回2个元素（公钥和私钥）", 2, keyPair.length);

            ECCPublicKey publicKey = (ECCPublicKey) keyPair[0];
            ECCPrivateKey privateKey = (ECCPrivateKey) keyPair[1];

            assertNotNull("公钥不应为空", publicKey);
            assertNotNull("私钥不应为空", privateKey);

            System.out.println("\nECC 密钥对生成成功:");
            System.out.println("  公钥位数: " + publicKey.getBits() + " bits");
            System.out.println("  公钥 X 坐标长度: " + publicKey.getX().length + " bytes");
            System.out.println("  公钥 Y 坐标长度: " + publicKey.getY().length + " bytes");
            System.out.println("  公钥 X: " + bytesToHex(publicKey.getX()));
            System.out.println("  公钥 Y: " + bytesToHex(publicKey.getY()));

            System.out.println("\n  私钥位数: " + privateKey.getBits() + " bits");
            System.out.println("  私钥 K 长度: " + privateKey.getK().length + " bytes");

            assertEquals("公钥位数应为" + ECC_KEY_BITS, ECC_KEY_BITS, publicKey.getBits());
            assertEquals("私钥位数应为" + ECC_KEY_BITS, ECC_KEY_BITS, privateKey.getBits());

            // 验证生成的密钥对是否可用 - 进行签名和验签测试
            System.out.println("\n验证密钥对可用性（签名+验签）:");
            String message = "测试生成的密钥对";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);

            // 计算哈希
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data);
            byte[] hash = sdf.SDF_HashFinal(sessionHandle);
            System.out.println("  消息: " + message);
            System.out.println("  哈希: " + bytesToHex(hash));

            // 使用生成的私钥签名
            ECCSignature signature = sdf.SDF_ExternalSign_ECC(
                    sessionHandle, AlgorithmID.SGD_SM2_1, privateKey, hash);
            assertNotNull("签名不应为空", signature);
            System.out.println("  签名 R: " + bytesToHex(signature.getR()));
            System.out.println("  签名 S: " + bytesToHex(signature.getS()));

            // 使用生成的公钥验签
            sdf.SDF_ExternalVerify_ECC(
                    sessionHandle, AlgorithmID.SGD_SM2_1, publicKey, hash, signature);
            System.out.println("  验签成功");
            System.out.println("[通过] ECC 密钥对生成成功（已验证可用性）\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] ECC 密钥对生成功能未实现\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_INARGERR) {
                throw new SDFException(ErrorCode.SDR_INARGERR, "输入参数错误 (Invalid input argument)");
            } else {
                throw e;
            }
        }
    }

    /**
     * 测试 6.8.5 + 6.4.5 ECC 外部密钥签名和验签
     * SDF_ExternalSign_ECC + SDF_ExternalVerify_ECC
     */
    @Test
    public void testExternalECCSignVerify() throws SDFException {
        System.out.println("测试 6.8.5 + 6.4.5 ECC 外部密钥签名和验签");
        System.out.println("----------------------------------------");

        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 步骤1: 生成 ECC 密钥对
            System.out.println("步骤1: 生成 SM2 密钥对");
            Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPublicKey publicKey = (ECCPublicKey) keyPair[0];
            ECCPrivateKey privateKey = (ECCPrivateKey) keyPair[1];
            System.out.println("SM2 密钥对生成成功");

            // 步骤2: 计算待签名数据的哈希值
            String message = "这是需要使用 SM2 外部密钥签名的文档";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);
            System.out.println("\n步骤2: 计算待签名数据的 SM3 哈希");
            System.out.println("原始消息: " + message);

            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data);
            byte[] hash = sdf.SDF_HashFinal(sessionHandle);
            System.out.println("SM3 哈希值: " + bytesToHex(hash));
            System.out.println("哈希长度: " + hash.length + " bytes");

            // 步骤3: 使用外部私钥签名
            System.out.println("\n步骤3: 使用外部私钥签名");
            ECCSignature signature = sdf.SDF_ExternalSign_ECC(
                    sessionHandle,
                    AlgorithmID.SGD_SM2_1,
                    privateKey,
                    hash
            );
            assertNotNull("签名结果不应为空", signature);
            assertNotNull("签名 r 分量不应为空", signature.getR());
            assertNotNull("签名 s 分量不应为空", signature.getS());

            System.out.println("签名成功:");
            System.out.println("  r 分量: " + bytesToHex(signature.getR()));
            System.out.println("  s 分量: " + bytesToHex(signature.getS()));

            // 步骤4: 使用外部公钥验签
            System.out.println("\n步骤4: 使用外部公钥验签");

            // 重新计算原始数据的哈希值用于验签
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data);
            byte[] verifyHash = sdf.SDF_HashFinal(sessionHandle);
            System.out.println("重新计算的 SM3 哈希值: " + bytesToHex(verifyHash));

            // 验签
            sdf.SDF_ExternalVerify_ECC(
                    sessionHandle,
                    AlgorithmID.SGD_SM2_1,
                    publicKey,
                    verifyHash,
                    signature
            );
            System.out.println("验签通过");

            // 对比验签时计算的哈希值与签名时的哈希值是否一致
            assertArrayEquals("验签时计算的哈希值应与签名时的哈希值一致", hash, verifyHash);
            System.out.println("哈希值对比: 一致");
            System.out.println("验签成功！签名有效，数据未被篡改");

            // 步骤5: 验证篡改数据检测
            // 正确的篡改检测方式：用原始签名去验证篡改后的数据，验签失败说明数据被篡改
            System.out.println("\n步骤5: 验证篡改数据检测");
            byte[] tamperedData = "篡改后的数据".getBytes(StandardCharsets.UTF_8);
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, tamperedData);
            byte[] tamperedHash = sdf.SDF_HashFinal(sessionHandle);
            System.out.println("篡改后数据: " + new String(tamperedData, StandardCharsets.UTF_8));
            System.out.println("篡改后数据的 SM3 哈希值: " + bytesToHex(tamperedHash));

            // 用原始签名去验证篡改后的数据，验签应该失败
            System.out.println("使用原始签名验证篡改后的数据...");
            try {
                sdf.SDF_ExternalVerify_ECC(
                        sessionHandle,
                        AlgorithmID.SGD_SM2_1,
                        publicKey,
                        tamperedHash,
                        signature  // 使用原始数据的签名
                );
                fail("篡改数据验签应该失败");
            } catch (SDFException e) {
                // 验签失败说明数据被篡改
                System.out.println("篡改数据验签失败，错误码: " + e.getErrorCodeHex() + "错误信息: " + e.getMessage());
                System.out.println("检测结果: 数据已被篡改！验签失败证明数据与签名不匹配");
            }
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] ECC 外部密钥签名验签功能未实现\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_INARGERR) {
                throw new SDFException(ErrorCode.SDR_INARGERR, "输入参数错误 (Invalid input argument)");
            } else {
                throw e;
            }
        }
    }

    /**
     * 测试 6.4.8 + 6.8.6 ECC 外部密钥加密和解密
     * SDF_ExternalEncrypt_ECC + SDF_ExternalDecrypt_ECC
     */
    @Test
    public void testExternalECCEncryptDecrypt() throws SDFException {
        System.out.println("测试 6.4.8 + 6.8.6 ECC 外部密钥加密和解密");
        System.out.println("----------------------------------------");

        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 步骤1: 生成 ECC 密钥对
            System.out.println("步骤1: 生成 SM2 密钥对");
            Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPublicKey publicKey = (ECCPublicKey) keyPair[0];
            ECCPrivateKey privateKey = (ECCPrivateKey) keyPair[1];
            System.out.println("SM2 密钥对生成成功，密钥位数: " + publicKey.getBits() + " bits");
            System.out.println("公钥 X: " + bytesToHex(publicKey.getX()));
            System.out.println("公钥 Y: " + bytesToHex(publicKey.getY()));

            // 步骤2: 准备待加密数据
            String plaintext = "这是需要使用 SM2 加密保护的机密信息";
            byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
            System.out.println("\n步骤2: 准备待加密数据");
            System.out.println("明文: " + plaintext);
            System.out.println("明文长度: " + plaintextBytes.length + " bytes");
            System.out.println("明文十六进制: " + bytesToHex(plaintextBytes));

            // 步骤3: 使用外部公钥加密
            System.out.println("\n步骤3: 使用外部公钥加密 (0x00020800)");
            ECCCipher cipher = sdf.SDF_ExternalEncrypt_ECC(
                    sessionHandle,
                    AlgorithmID.SGD_SM2_3,
                    publicKey,
                    plaintextBytes
            );
            assertNotNull("密文不应为空", cipher);

            System.out.println("加密成功:");
            System.out.println("  SM2 密文结构 (C1||C3||C2):");
            System.out.println("    C1 X: " + bytesToHex(cipher.getX()));
            System.out.println("    C1 Y: " + bytesToHex(cipher.getY()));
            System.out.println("    C3 (MAC): " + bytesToHex(cipher.getM()));
            System.out.println("    C2 长度: " + cipher.getL() + " bytes");
            System.out.println("    C2 (密文): " + bytesToHex(cipher.getC()));

            // 步骤4: 使用外部私钥解密
            System.out.println("\n步骤4: 使用外部私钥解密");
            byte[] decryptedBytes = sdf.SDF_ExternalDecrypt_ECC(
                    sessionHandle,
                    AlgorithmID.SGD_SM2_3,
                    privateKey,
                    cipher
            );
            assertNotNull("解密结果不应为空", decryptedBytes);

            String decrypted = new String(decryptedBytes, StandardCharsets.UTF_8);
            System.out.println("解密成功:");
            System.out.println("  解密后明文: " + decrypted);
            System.out.println("  解密后长度: " + decryptedBytes.length + " bytes");

            // 验证解密结果
            assertEquals("解密后的明文应与原始明文相同", plaintext, decrypted);
            assertArrayEquals("解密后的字节数组应与原始明文字节数组相���", plaintextBytes, decryptedBytes);

            System.out.println("\n验证成功：解密后的明文与原始明文完全一致");
            System.out.println("[通过] ECC 外部密钥加密解密成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] ECC 外部密钥加密解密功能未实现\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_INARGERR) {
                throw new SDFException(ErrorCode.SDR_INARGERR, "输入参数错误 (Invalid input argument)");
            } else {
                throw e;
            }
        }
    }

    // ========================================================================
    // ECC/SM2 内部密钥运算测试
    // ========================================================================

    /**
     * 测试 6.4.6 + 6.4.7 ECC 内部密钥签名和验签
     * SDF_InternalSign_ECC + SDF_InternalVerify_ECC
     */
    @Test
    public void testInternalECCSignVerify() throws SDFException {
        System.out.println("测试 6.4.6 + 6.4.7 ECC 内部密钥签名和验签");
        System.out.println("----------------------------------------");

        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

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

            // 尝试导出 ECC 签名公钥，验证密钥存在
            try {
                ECCPublicKey publicKey = sdf.SDF_ExportSignPublicKey_ECC(sessionHandle, keyIndex);
                System.out.println("\n已导出 ECC 签名公钥");
                System.out.println("密钥位数: " + publicKey.getBits() + " bits");
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] 无法导出 ECC 内部公钥: " + e.getErrorCodeHex() + "\n");
                    return;
                }
                throw e;
            }

            // 计算待签名数据的哈希值
            String message = "这是需要使用 SM2 内部密钥签名的文档";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);
            System.out.println("\n计算待签名数据的 SM3 哈希");
            System.out.println("原始消息: " + message);

            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data);
            byte[] hash = sdf.SDF_HashFinal(sessionHandle);
            System.out.println("SM3 哈希值: " + bytesToHex(hash));

            // 使用内部私钥签名
            System.out.println("\n使用内部私钥签名，密钥索引: " + keyIndex);
            ECCSignature signature = sdf.SDF_InternalSign_ECC(sessionHandle, keyIndex, hash);
            assertNotNull("签名结果不应为空", signature);
            assertNotNull("签名 r 分量不应为空", signature.getR());
            assertNotNull("签名 s 分量不应为空", signature.getS());

            System.out.println("签名成功:");
            System.out.println("  r 分量: " + bytesToHex(signature.getR()));
            System.out.println("  s 分量: " + bytesToHex(signature.getS()));

            // 使用内部公钥验签
            System.out.println("\n使用内部公钥验签，密钥索引: " + keyIndex);
            sdf.SDF_InternalVerify_ECC(sessionHandle, keyIndex, hash, signature);
            System.out.println("验签成功！签名有效");

            // 验证篡改数据检测
            System.out.println("\n验证篡改数据检测");
            byte[] tamperedData = "篡改后的数据".getBytes(StandardCharsets.UTF_8);
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, tamperedData);
            byte[] tamperedHash = sdf.SDF_HashFinal(sessionHandle);

            try {
                sdf.SDF_InternalVerify_ECC(sessionHandle, keyIndex, tamperedHash, signature);
                fail("篡改数据验签应该失败");
            } catch (SDFException e) {
                System.out.println("篡改数据验签失败: " + e.getErrorCodeHex() + "错误信息: " + e.getMessage());
            }

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] ECC 内部密钥签名验签功能未实现\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_KEYNOTEXIST) {
                throw new SDFException(ErrorCode.SDR_KEYNOTEXIST, "ECC 内部密钥不存在，密钥索引: " + keyIndex);
            } else if (e.getErrorCode() == ErrorCode.SDR_INARGERR) {
                throw new SDFException(ErrorCode.SDR_INARGERR, "输入参数错误 (Invalid input argument)");
            } else {
                throw e;
            }
        } finally {
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
     * 测试内部密钥签名 + 外部公钥验签的互操作性
     */
    @Test
    public void testInternalSignExternalVerify() throws SDFException {
        System.out.println("测试内部密钥签名 + 外部公钥验签的互操作性");
        System.out.println("----------------------------------------");

        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

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

            // 导出内部 ECC 签名公钥
            ECCPublicKey publicKey;
            try {
                publicKey = sdf.SDF_ExportSignPublicKey_ECC(sessionHandle, keyIndex);
                System.out.println("\n已导出 ECC 签名公钥，密钥位数: " + publicKey.getBits() + " bits");
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] 无法导出 ECC 内部公钥: " + e.getErrorCodeHex() + "\n");
                    return;
                }
                throw e;
            }

            // 计算待签名数据的哈希值
            String message = "测试内部签名外部验签的互操作性";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);

            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data);
            byte[] hash = sdf.SDF_HashFinal(sessionHandle);
            System.out.println("\n消息: " + message);
            System.out.println("SM3 哈希值: " + bytesToHex(hash));

            // 使用内部私钥签名
            System.out.println("\n使用内部私钥签名");
            ECCSignature signature = sdf.SDF_InternalSign_ECC(sessionHandle, keyIndex, hash);
            System.out.println("签名成功:");
            System.out.println("  r: " + bytesToHex(signature.getR()));
            System.out.println("  s: " + bytesToHex(signature.getS()));

            // 使用导出的外部公钥验签
            System.out.println("\n使用导出的外部公钥验签");
            sdf.SDF_ExternalVerify_ECC(
                    sessionHandle,
                    AlgorithmID.SGD_SM2_1,
                    publicKey,
                    hash,
                    signature
            );
            System.out.println("外部公钥验签成功！");

            System.out.println("[通过] 内部签名 + 外部验签互操作性测试成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 功能未实现\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_KEYNOTEXIST) {
                System.out.println("[跳过] 内部密钥不存在，密钥索引: " + keyIndex + "\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_INARGERR) {
                throw new SDFException(ErrorCode.SDR_INARGERR, "输入参数错误 (Invalid input argument)");
            } else {
                throw e;
            }
        } finally {
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
     * 测试 6.4.9 + 6.4.10 ECC 内部密钥加密和解密
     * SDF_InternalEncrypt_ECC + SDF_InternalDecrypt_ECC
     */
    @Test
    public void testInternalECCEncryptDecrypt() throws SDFException {
        System.out.println("测试 6.4.9 + 6.4.10 ECC 内部密钥加密和解密");
        System.out.println("----------------------------------------");

        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

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

            // 尝试导出 ECC 加密公钥，验证密钥存在
            try {
                ECCPublicKey publicKey = sdf.SDF_ExportEncPublicKey_ECC(sessionHandle, keyIndex);
                System.out.println("\n已导出 ECC 加密公钥");
                System.out.println("密钥位数: " + publicKey.getBits() + " bits");
                System.out.println("公钥 X: " + bytesToHex(publicKey.getX()));
                System.out.println("公钥 Y: " + bytesToHex(publicKey.getY()));
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] 无法导出 ECC 内部加密公钥: " + e.getErrorCodeHex() + "\n");
                    return;
                }
                throw e;
            }

            // 准备待加密数据
            String plaintext = "Internal enc data";
            byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
            System.out.println("\n准备待加密数据");
            System.out.println("明文: " + plaintext);
            System.out.println("明文长度: " + plaintextBytes.length + " bytes");
            System.out.println("明文十六进制: " + bytesToHex(plaintextBytes));

            // 使用内部公钥加密
            System.out.println("\n使用内部公钥加密，密钥索引: " + keyIndex);
            ECCCipher cipher = sdf.SDF_InternalEncrypt_ECC(
                    sessionHandle,
                    keyIndex,
                    plaintextBytes
            );
            assertNotNull("密文不应为空", cipher);

            System.out.println("加密成功:");
            System.out.println("  SM2 密文结构 (C1||C3||C2):");
            System.out.println("    C1 X: " + bytesToHex(cipher.getX()));
            System.out.println("    C1 Y: " + bytesToHex(cipher.getY()));
            System.out.println("    C3 (MAC): " + bytesToHex(cipher.getM()));
            System.out.println("    C2 长度: " + cipher.getL() + " bytes");
            System.out.println("    C2 (密文): " + bytesToHex(cipher.getC()));

            // 使用内部私钥解密
            System.out.println("\n使用内部私钥解密，密钥索引: " + keyIndex);
            System.out.println("使用算法类型: SGD_SM2_3 (0x00020800)");
            byte[] decryptedBytes = sdf.SDF_InternalDecrypt_ECC(
                    sessionHandle,
                    keyIndex,
                    AlgorithmID.SGD_SM2_3,  // 私钥使用类型
                    cipher
            );
            assertNotNull("解密结果不应为空", decryptedBytes);

            String decrypted = new String(decryptedBytes, StandardCharsets.UTF_8);
            System.out.println("解密成功:");
            System.out.println("  解密后明文: " + decrypted);
            System.out.println("  解密后长度: " + decryptedBytes.length + " bytes");

            // 验证解密结果
            assertEquals("解密后的明文应与原始明文相同", plaintext, decrypted);
            assertArrayEquals("解密后的字节数组应与原始明文字节数组相同", plaintextBytes, decryptedBytes);

            System.out.println("\n验证成功：解密后的明文与原始明文完全一致");
            System.out.println("[通过] ECC 内部密钥加密解密成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] ECC 内部密钥加密解密功能未实现\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_KEYNOTEXIST) {
                throw new SDFException(ErrorCode.SDR_KEYNOTEXIST, "ECC 内部密钥不存在，密钥索引: " + keyIndex);
            } else if (e.getErrorCode() == ErrorCode.SDR_INARGERR) {
                throw new SDFException(ErrorCode.SDR_INARGERR, "输入参数错误 (Invalid input argument)");
            } else {
                throw e;
            }
        } finally {
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

    // ========================================================================
    // 综合测试
    // ========================================================================

    /**
     * 测试多密钥对的隔离性
     * 验证不同密钥对之间的签名不能互相验证
     */
    @Test
    public void testKeyPairIsolation() throws SDFException {
        System.out.println("测试多密钥对的隔离性");
        System.out.println("----------------------------------------");

        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成两个不同的 ECC 密钥对
            System.out.println("生成密钥对 A");
            Object[] keyPairA = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            assertNotNull("密钥对A不应为空", keyPairA);
            ECCPublicKey publicKeyA = (ECCPublicKey) keyPairA[0];
            ECCPrivateKey privateKeyA = (ECCPrivateKey) keyPairA[1];

            System.out.println("生成密钥对 B");
            Object[] keyPairB = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            assertNotNull("密钥对B不应为空", keyPairB);
            ECCPublicKey publicKeyB = (ECCPublicKey) keyPairB[0];

            // 使用密钥对 A 签名
            String message = "测试密钥隔离性";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);

            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data);
            byte[] hash = sdf.SDF_HashFinal(sessionHandle);

            System.out.println("\n使用密钥对 A 的私钥签名");
            ECCSignature signature = sdf.SDF_ExternalSign_ECC(
                    sessionHandle,
                    AlgorithmID.SGD_SM2_1,
                    privateKeyA,
                    hash
            );
            System.out.println("签名完成");

            // 使用密钥对 A 的公钥验签（应成功）
            System.out.println("\n使用密钥对 A 的公钥验签");
            sdf.SDF_ExternalVerify_ECC(
                    sessionHandle,
                    AlgorithmID.SGD_SM2_1,
                    publicKeyA,
                    hash,
                    signature
            );
            System.out.println("使用正确公钥验签成功");

            // 使用密钥对 B 的公钥验签（应失败）
            System.out.println("\n使用密钥对 B 的公钥验签（错误的公钥）");
            try {
                sdf.SDF_ExternalVerify_ECC(
                        sessionHandle,
                        AlgorithmID.SGD_SM2_1,
                        publicKeyB,
                        hash,
                        signature
                );
                fail("使用错误公钥验签应该失败");
            } catch (SDFException e) {
                System.out.println("使用错误公钥验签失败: " + e.getErrorCodeHex() + " 错误信息: " + e.getMessage());
            }

            System.out.println("[通过] 密钥对隔离性测试成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 功能未实现\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_INARGERR) {
                throw new SDFException(ErrorCode.SDR_INARGERR, "输入参数错误 (Invalid input argument)");
            } else {
                throw e;
            }
        }
    }

    /**
     * 测试签名的一致性
     * 验证相同数据多次签名后都能被正确验证
     */
    @Test
    public void testSignatureConsistency() throws SDFException {
        System.out.println("测试签名的一致性");
        System.out.println("----------------------------------------");

        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成 ECC 密钥对
            System.out.println("生成 SM2 密钥对");
            Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            assertNotNull("密钥对不应为空", keyPair);
            ECCPublicKey publicKey = (ECCPublicKey) keyPair[0];
            ECCPrivateKey privateKey = (ECCPrivateKey) keyPair[1];

            // 计算哈希值
            String message = "测试签名一致性";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);

            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data);
            byte[] hash = sdf.SDF_HashFinal(sessionHandle);
            System.out.println("消息: " + message);
            System.out.println("SM3 哈希: " + bytesToHex(hash));

            // 多次签名并验证
            int signCount = 3;
            System.out.println("\n对相同数据进行 " + signCount + " 次签名并验证:");

            ECCSignature[] signatures = new ECCSignature[signCount];
            for (int i = 0; i < signCount; i++) {
                signatures[i] = sdf.SDF_ExternalSign_ECC(
                        sessionHandle,
                        AlgorithmID.SGD_SM2_1,
                        privateKey,
                        hash
                );

                // 验证签名
                sdf.SDF_ExternalVerify_ECC(
                        sessionHandle,
                        AlgorithmID.SGD_SM2_1,
                        publicKey,
                        hash,
                        signatures[i]
                );

                System.out.println("  第 " + (i + 1) + " 次签名:");
                System.out.println("    r: " + bytesToHex(signatures[i].getR()).substring(0, 32) + "...");
                System.out.println("    验签: 通过");
            }

            // 注意：SM2 签名包含随机数，所以每次签名结果可能不同
            // 但每个签名都应该能被正确验证
            System.out.println("\n注: SM2 签名包含随机数，每次签名结果可能不同，但都应能被正确验证");
            System.out.println("[通过] 签名一致性测试成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 功能未实现\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_INARGERR) {
                throw new SDFException(ErrorCode.SDR_INARGERR, "输入参数错误 (Invalid input argument)");
            } else {
                throw e;
            }
        }
    }

    /**
     * 测试加密解密的一致性
     * 验证相同数据多次加密解密后结果一致
     */
    @Test
    public void testEncryptDecryptConsistency() throws SDFException {
        System.out.println("测试加密解密的一致性");
        System.out.println("----------------------------------------");

        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成 ECC 密钥对
            System.out.println("生成 SM2 密钥对");
            Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            assertNotNull("密钥对不应为空", keyPair);
            ECCPublicKey publicKey = (ECCPublicKey) keyPair[0];
            ECCPrivateKey privateKey = (ECCPrivateKey) keyPair[1];

            // 准备明文
            String plaintext = "测试加密解密一致性的数据";
            byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
            System.out.println("明文: " + plaintext);
            System.out.println("明文长度: " + plaintextBytes.length + " bytes");

            // 多次加密解密并验证
            int encCount = 3;
            System.out.println("\n对相同数据进行 " + encCount + " 次加密解密:");

            for (int i = 0; i < encCount; i++) {
                // 加密
                ECCCipher cipher = sdf.SDF_ExternalEncrypt_ECC(
                        sessionHandle,
                        AlgorithmID.SGD_SM2_3,
                        publicKey,
                        plaintextBytes
                );

                // 解密
                byte[] decryptedBytes = sdf.SDF_ExternalDecrypt_ECC(
                        sessionHandle,
                        AlgorithmID.SGD_SM2_3,
                        privateKey,
                        cipher
                );

                // 验证
                assertArrayEquals("第 " + (i + 1) + " 次解密结果应与原始明文相同",
                        plaintextBytes, decryptedBytes);

                String decrypted = new String(decryptedBytes, StandardCharsets.UTF_8);
                System.out.println("  第 " + (i + 1) + " 次:");
                System.out.println("    密文 C1 X: " + bytesToHex(cipher.getX()).substring(0, 32) + "...");
                System.out.println("    解密结果: " + decrypted);
                System.out.println("    验证: 通过");
            }

            System.out.println("\n注: SM2 加密包含随机数，每次密文可能不同，但解密结果应一致");
            System.out.println("[通过] 加密解密一致性测试成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 功能未实现\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_INARGERR) {
                throw new SDFException(ErrorCode.SDR_INARGERR, "输入参数错误 (Invalid input argument)");
            } else {
                throw e;
            }
        }
    }

    /**
     * 字节数组转十六进制字符串
     */
    private static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
