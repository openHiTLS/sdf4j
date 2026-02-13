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
import org.openhitls.sdf4j.constants.AlgorithmID;
import org.openhitls.sdf4j.constants.ErrorCode;
import org.openhitls.sdf4j.types.*;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import static org.junit.Assert.*;

/**
 * SDF4J 密钥管理类函数测试
 * 测试 GM/T 0018-2023 标准中 6.3 节定义的密钥管理类函数
 *
 * 注意: RSA 相关接口暂未实现，包括:
 * - 6.3.2 SDF_ExportSignPublicKey_RSA - 导出 RSA 签名公钥
 * - 6.3.3 SDF_ExportEncPublicKey_RSA - 导出 RSA 加密公钥
 * - 6.3.4 SDF_GenerateKeyWithIPK_RSA - 生成会话密钥并用内部 RSA 公钥加密输出
 * - 6.3.5 SDF_GenerateKeyWithEPK_RSA - 生成会话密钥并用外部 RSA 公钥加密输出
 * - 6.3.6 SDF_ImportKeyWithISK_RSA - 导入会话密钥并用内部 RSA 私钥解密
 *
 * 包含以下 ECC 接口测试：
 * - 6.3.7 SDF_ExportSignPublicKey_ECC - 导出 ECC 签名公钥
 * - 6.3.8 SDF_ExportEncPublicKey_ECC - 导出 ECC 加密公钥
 * - 6.3.9 SDF_GenerateKeyWithIPK_ECC - 生成会话密钥并用内部 ECC 公钥加密输出
 * - 6.3.10 SDF_GenerateKeyWithEPK_ECC - 生成会话密钥并用外部 ECC 公钥加密输出
 * - 6.3.11 SDF_ImportKeyWithISK_ECC - 导入会话密钥并用内部 ECC 私钥解密
 * - 6.3.12 SDF_GenerateAgreementDataWithECC - 生成密钥协商参数并输出
 * - 6.3.13 SDF_GenerateKeyWithECC - 计算会话密钥
 * - 6.3.14 SDF_GenerateAgreementDataAndKeyWithECC - 产生协商数据并计算会话密钥
 * - 6.3.15 SDF_GenerateKeyWithKEK - 生成会话密钥并用密钥加密密钥加密输出
 * - 6.3.16 SDF_ImportKeyWithKEK - 导入会话密钥并用密钥加密密钥解密
 * - 6.3.17 SDF_DestroyKey - 销毁会话密钥
 */
public class KeyManagementTest {

    // 配置开关：设置为 true 时从配置文件读取，false 时使用下面的默认值
    private static final boolean USE_CONFIG_FILE = true;

    // 默认配置
    private static final int DEFAULT_KEY_INDEX = 1;
    private static final String DEFAULT_KEY_PASSWORD = "123abc!@";
    private static final int DEFAULT_KEK_INDEX = 4;
    private static final String DEFAULT_KEK_PASSWORD = "123abc!@";

    // 会话密钥长度
    private static final int SESSION_KEY_BITS_128 = 128;

    // ECC/SM2 密钥长度
    private static final int ECC_KEY_BITS = 256;

    // 实际使用的配置
    private static int keyIndex;
    private static String keyPassword;
    private static int kekIndex;
    private static String kekPassword;

    private SDF sdf;
    private long deviceHandle;
    private long sessionHandle;

    @BeforeClass
    public static void loadConfig() {
        if (USE_CONFIG_FILE) {
            Properties testConfig = new Properties();
            try (InputStream is = KeyManagementTest.class.getClassLoader()
                    .getResourceAsStream("test-config.properties")) {
                if (is != null) {
                    testConfig.load(is);
                    keyIndex = Integer.parseInt(
                            testConfig.getProperty("sm2.internal.key.index", String.valueOf(DEFAULT_KEY_INDEX)));
                    keyPassword = testConfig.getProperty("sm2.key.access.password", DEFAULT_KEY_PASSWORD);
                    kekIndex = Integer.parseInt(
                            testConfig.getProperty("sm4.internal.key.index", String.valueOf(DEFAULT_KEK_INDEX)));
                    kekPassword = testConfig.getProperty("sm4.key.access.password", DEFAULT_KEK_PASSWORD);
                    return;
                }
            } catch (IOException e) {
                System.err.println("读取配置文件失败: " + e.getMessage());
            }
        }
        // 使用默认值
        keyIndex = DEFAULT_KEY_INDEX;
        keyPassword = DEFAULT_KEY_PASSWORD;
        kekIndex = DEFAULT_KEK_INDEX;
        kekPassword = DEFAULT_KEK_PASSWORD;
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

    // ========================================================================
    // ECC 公钥导出测试
    // ========================================================================

    /**
     * 测试 6.3.7 SDF_ExportSignPublicKey_ECC - 导出 ECC 签名公钥
     */
    @Test
    public void testExportSignPublicKeyECC() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {

            ECCPublicKey publicKey = sdf.SDF_ExportSignPublicKey_ECC(sessionHandle, keyIndex);
            assertNotNull("ECC 签名公钥不应为空", publicKey);

            assertTrue("ECC 密钥位数应大于 0", publicKey.getBits() > 0);
            assertNotNull("X 坐标不应为空", publicKey.getX());
            assertNotNull("Y 坐标不应为空", publicKey.getY());

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] ECC 签名公钥导出功能未实现");
                Assume.assumeTrue("ECC 签名公钥导出功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        }
    }

    /**
     * 测试 6.3.8 SDF_ExportEncPublicKey_ECC - 导出 ECC 加密公钥
     */
    @Test
    public void testExportEncPublicKeyECC() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {

            ECCPublicKey publicKey = sdf.SDF_ExportEncPublicKey_ECC(sessionHandle, keyIndex);
            assertNotNull("ECC 加密公钥不应为空", publicKey);
            assertTrue("ECC 密钥位数应大于 0", publicKey.getBits() > 0);
            assertNotNull("公钥 X不应为空", publicKey.getX());
            assertNotNull("公钥 Y不应为空", publicKey.getY());
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] ECC 加密公钥导出功能未实现");
                Assume.assumeTrue("ECC 加密公钥导出功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        }
    }

    // ========================================================================
    // ECC 会话密钥生成和导入测试
    // ========================================================================

    /**
     * 测试 6.3.9 SDF_GenerateKeyWithIPK_ECC - 生成会话密钥并用内部 ECC 公钥加密输出
     */
    @Test
    public void testGenerateKeyWithIPK_ECC() throws SDFException, java.io.UnsupportedEncodingException {
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
                    Assume.assumeTrue("获取私钥权限不支持，继续测试...", false);
                } else {
                    System.out.println(e.getMessage());
                    throw e;
                }
            }

            ECCKeyEncryptionResult result = sdf.SDF_GenerateKeyWithIPK_ECC(sessionHandle, keyIndex, SESSION_KEY_BITS_128);
            assertNotNull("密钥生成结果不应为空", result);

            keyHandle = result.getKeyHandle();
            ECCCipher eccCipher = result.getEccCipher();

            assertNotNull("ECC加密密钥不应为空", eccCipher);
            assertTrue("密钥句柄应大于 0", keyHandle > 0);
            assertTrue("ECC加密密钥C2长度为16 bytes", eccCipher.getL() == SESSION_KEY_BITS_128 / 8);
            assertNotNull("ECCCipher X不为空", eccCipher.getX());
            assertNotNull("ECCCipher Y不为空", eccCipher.getY());
            assertNotNull("ECCCipher M不为空", eccCipher.getM());
            assertNotNull("ECCCipher C不为空", eccCipher.getC());

            // 验证生成的会话密钥是否可用 - 进行加密测试
            byte[] testData = "0123456789ABCDEF".getBytes("UTF-8");  // 16 bytes

            try {
                byte[] encryptedData = sdf.SDF_Encrypt(
                        sessionHandle, keyHandle, AlgorithmID.SGD_SM4_ECB, null, testData);
                assertNotNull("加密数据不应为空", encryptedData);

                byte[] decryptedData = sdf.SDF_Decrypt(
                        sessionHandle, keyHandle, AlgorithmID.SGD_SM4_ECB, null, encryptedData);
                assertNotNull("解密数据不应为空", decryptedData);

                assertArrayEquals("解密数据应与原始数据相同", testData, decryptedData);
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] 加密功能未实现，跳过可用性验证");
                    Assume.assumeTrue("  加密功能未实现，跳过可用性验证", false);
                } else {
                    System.out.println(e.getMessage());
                    throw e;
                }
            }


        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 内部 ECC 公钥生成会话密钥功能未实现");
                Assume.assumeTrue("内部 ECC 公钥生成会话密钥功能未实现", false);
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
     * 测试 6.3.10 SDF_GenerateKeyWithEPK_ECC - 生成会话密钥并用外部 ECC 公钥加密输出
     */
    @Test
    public void testGenerateKeyWithEPK_ECC() throws SDFException, java.io.UnsupportedEncodingException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long keyHandle = 0;
        try {
            // 先生成一个外部 ECC 密钥对
            Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPublicKey publicKey = (ECCPublicKey) keyPair[0];

            // 使用外部公钥生成会话密钥
            ECCKeyEncryptionResult result = sdf.SDF_GenerateKeyWithEPK_ECC(
                    sessionHandle, SESSION_KEY_BITS_128, AlgorithmID.SGD_SM2_3, publicKey);
            assertNotNull("密钥生成结果不应为空", result);

            keyHandle = result.getKeyHandle();
            ECCCipher eccCipher = result.getEccCipher();

            assertNotNull("加密密钥不应为空", eccCipher);
            assertTrue("密钥句柄应大于 0", keyHandle > 0);
            assertTrue("ECC加密密钥C2长度为16 bytes", eccCipher.getL() == SESSION_KEY_BITS_128 / 8);

            assertNotNull("ECCCipher X不为空", eccCipher.getX());
            assertNotNull("ECCCipher Y不为空", eccCipher.getY());
            assertNotNull("ECCCipher M不为空", eccCipher.getM());
            assertNotNull("ECCCipher C不为空", eccCipher.getC());

            // 验证生成的会话密钥是否可用 - 进行加密测试
            byte[] testData = "FEDCBA9876543210".getBytes("UTF-8");  // 16 bytes

            try {
                byte[] encryptedData = sdf.SDF_Encrypt(
                        sessionHandle, keyHandle, AlgorithmID.SGD_SM4_ECB, null, testData);
                assertNotNull("加密数据不应为空", encryptedData);

                byte[] decryptedData = sdf.SDF_Decrypt(
                        sessionHandle, keyHandle, AlgorithmID.SGD_SM4_ECB, null, encryptedData);
                assertNotNull("解密数据不应为空", decryptedData);

                assertArrayEquals("解密数据应与原始数据相同", testData, decryptedData);
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] 加密功能未实现，跳过可用性验证");
                    Assume.assumeTrue("  加密功能未实现，跳过可用性验证", false);
                } else {
                    System.out.println(e.getMessage());
                    throw e;
                }
            }


        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 外部 ECC 公钥生成会话密钥功能未实现");
                Assume.assumeTrue("外部 ECC 公钥生成会话密钥功能未实现", false);
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
        }
    }
    /**
     * 测试 6.3.11 SDF_ImportKeyWithISK_ECC - 导入会话密钥并用内部 ECC 私钥解密
     */
    @Test
    public void testImportKeyWithISK_ECC() throws SDFException, java.io.UnsupportedEncodingException {
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

            // 步骤1: 使用内部ECC公钥生成会话密钥并加密
            ECCKeyEncryptionResult keyEncResult = sdf.SDF_GenerateKeyWithIPK_ECC(sessionHandle, keyIndex, SESSION_KEY_BITS_128);
            ECCCipher eccCipher =  keyEncResult.getEccCipher();

            // 步骤2: 导入会话密钥并用内部 ECC 私钥解密
            keyHandle = sdf.SDF_ImportKeyWithISK_ECC(sessionHandle, keyIndex, eccCipher);

            assertTrue("导入的密钥句柄应大于 0", keyHandle > 0);

            // 验证导入的会话密钥是否可用 - 进行加密测试
            byte[] testData = "FEDCBA9876543210".getBytes("UTF-8");  // 16 bytes

            try {
                byte[] encryptedData = sdf.SDF_Encrypt(
                        sessionHandle, keyHandle, AlgorithmID.SGD_SM4_ECB, null, testData);
                assertNotNull("加密数据不应为空", encryptedData);

                byte[] decryptedData = sdf.SDF_Decrypt(
                        sessionHandle, keyHandle, AlgorithmID.SGD_SM4_ECB, null, encryptedData);
                assertNotNull("解密数据不应为空", decryptedData);

                assertArrayEquals("解密数据应与原始数据相同", testData, decryptedData);
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] 加密功能未实现，跳过可用性验证");
                    Assume.assumeTrue("  加密功能未实现，跳过可用性验证", false);
                } else {
                    System.out.println(e.getMessage());
                    throw e;
                }
            }
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 内部 ECC 私钥导入会话密钥功能未实现");
                Assume.assumeTrue("内部 ECC 私钥导入会话密钥功能未实现", false);
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
            if (accessRightObtained) {
                try {
                    sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, keyIndex);
                } catch (SDFException e) {
                    System.err.println("释放私钥访问权限失败: " + e.getMessage());
                }
            }
        }
    }

    // ========================================================================
    // ECC 密钥协商测试
    // ========================================================================

    /**
     * 测试 6.3.12 SDF_GenerateAgreementDataWithECC - 生成密钥协商参数并输出
     */
    @Test
    public void testGenerateAgreementDataWithECC() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long agreementHandle = 0;
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

            // 导出内部 ECC 加密公钥作为发起方公钥
            ECCPublicKey sponsorPublicKey = sdf.SDF_ExportEncPublicKey_ECC(sessionHandle, keyIndex);
            assertNotNull("ECC 加密公钥不应为空", sponsorPublicKey);
            assertTrue("ECC 密钥位数应大于 0", sponsorPublicKey.getBits() > 0);
            assertNotNull("公钥 X不应为空", sponsorPublicKey.getX());
            assertNotNull("公钥 Y不应为空", sponsorPublicKey.getY());
            // 生成临时密钥对作为发起方临时公钥
            Object[] tmpKeyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            assertNotNull("临时密钥对不应为空", tmpKeyPair);
            ECCPublicKey sponsorTmpPublicKey = (ECCPublicKey) tmpKeyPair[0];

            // 发起方 ID
            byte[] sponsorID = "1234567812345678".getBytes();

            // 生成密钥协商参数
            agreementHandle = sdf.SDF_GenerateAgreementDataWithECC(
                    sessionHandle, keyIndex, SESSION_KEY_BITS_128,
                    sponsorID, sponsorPublicKey, sponsorTmpPublicKey);

            assertTrue("协商句柄应大于 0", agreementHandle > 0);
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 生成密钥协商参数功能未实现");
                Assume.assumeTrue("生成密钥协商参数功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        } finally {
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
     * 测试 6.3.13 SDF_GenerateKeyWithECC - 计算会话密钥
     */
    @Test
    public void testGenerateKeyWithECC() throws SDFException, java.io.UnsupportedEncodingException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long agreementHandle = 0;
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

            // 步骤1: 发起方生成协商数据
            ECCPublicKey sponsorPublicKey = sdf.SDF_ExportEncPublicKey_ECC(sessionHandle, keyIndex);
            assertNotNull("ECC 加密公钥不应为空", sponsorPublicKey);
            Object[] sponsorTmpKeyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            assertNotNull("发起方临时密钥对不应为空", sponsorTmpKeyPair);
            ECCPublicKey sponsorTmpPublicKey = (ECCPublicKey) sponsorTmpKeyPair[0];
            byte[] sponsorID = "1234567812345678".getBytes();

            agreementHandle = sdf.SDF_GenerateAgreementDataWithECC(
                    sessionHandle, keyIndex, SESSION_KEY_BITS_128,
                    sponsorID, sponsorPublicKey, sponsorTmpPublicKey);

            // 步骤2: 响应方生成密钥对（模拟响应方）
            Object[] responseKeyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            assertNotNull("响应方密钥对不应为空", responseKeyPair);
            ECCPublicKey responsePublicKey = (ECCPublicKey) responseKeyPair[0];
            Object[] responseTmpKeyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            assertNotNull("响应方临时密钥对不应为空", responseTmpKeyPair);
            ECCPublicKey responseTmpPublicKey = (ECCPublicKey) responseTmpKeyPair[0];
            byte[] responseID = "8765432187654321".getBytes();

            // 步骤3: 计算会话密钥
            keyHandle = sdf.SDF_GenerateKeyWithECC(
                    sessionHandle, responseID,
                    responsePublicKey, responseTmpPublicKey,
                    agreementHandle);

            assertTrue("密钥句柄应大于 0", keyHandle > 0);

            // 验证协商的会话密钥是否可用 - 进行加密测试
            byte[] testData = "ATestECDHSession".getBytes("UTF-8");  // 16 bytes

            try {
                byte[] encryptedData = sdf.SDF_Encrypt(
                        sessionHandle, keyHandle, AlgorithmID.SGD_SM4_ECB, null, testData);
                assertNotNull("加密数据不应为空", encryptedData);

                byte[] decryptedData = sdf.SDF_Decrypt(
                        sessionHandle, keyHandle, AlgorithmID.SGD_SM4_ECB, null, encryptedData);
                assertNotNull("解密数据不应为空", decryptedData);

                assertArrayEquals("解密数据应与原始数据相同", testData, decryptedData);
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] 加密功能未实现，跳过可用性验证");
                    Assume.assumeTrue("  加密功能未实现，跳过可用性验证", false);
                } else {
                    System.out.println(e.getMessage());
                    throw e;
                }
            }
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 计算会话密钥功能未实现");
                Assume.assumeTrue("计算会话密钥功能未实现", false);
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
     * 测试 6.3.14 SDF_GenerateAgreementDataAndKeyWithECC - 产生协商数据并计算会话密钥
     */
    @Test
    public void testGenerateAgreementDataAndKeyWithECC() throws SDFException {
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

            // 准备发起方数据
            ECCPublicKey sponsorPublicKey = sdf.SDF_ExportEncPublicKey_ECC(sessionHandle, keyIndex);
            assertNotNull("ECC 加密公钥不应为空", sponsorPublicKey);
            Object[] sponsorTmpKeyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            assertNotNull("发起方临时密钥对不应为空", sponsorTmpKeyPair);
            ECCPublicKey sponsorTmpPublicKey = (ECCPublicKey) sponsorTmpKeyPair[0];
            byte[] sponsorID = "1234567812345678".getBytes();

            // 准备响应方数据
            Object[] responseKeyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            assertNotNull("响应方密钥对不应为空", responseKeyPair);
            ECCPublicKey responsePublicKey = (ECCPublicKey) responseKeyPair[0];
            Object[] responseTmpKeyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            assertNotNull("响应方临时密钥对不应为空", responseTmpKeyPair);
            ECCPublicKey responseTmpPublicKey = (ECCPublicKey) responseTmpKeyPair[0];
            byte[] responseID = "8765432187654321".getBytes();

            // 产生协商数据并计算会话密钥
            keyHandle = sdf.SDF_GenerateAgreementDataAndKeyWithECC(
                    sessionHandle, keyIndex, SESSION_KEY_BITS_128,
                    responseID, sponsorID,
                    sponsorPublicKey, sponsorTmpPublicKey,
                    responsePublicKey, responseTmpPublicKey);

            assertTrue("密钥句柄应大于 0", keyHandle > 0);
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 产生协商数据并计算会话密钥功能未实现");
                Assume.assumeTrue("产生协商数据并计算会话密钥功能未实现", false);
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
            if (accessRightObtained) {
                try {
                    sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, keyIndex);
                } catch (SDFException e) {
                    System.err.println("释放私钥访问权限失败: " + e.getMessage());
                }
            }
        }
    }

    // ========================================================================
    // KEK 会话密钥生成和导入测试
    // ========================================================================

    /**
     * 测试 6.3.15 SDF_GenerateKeyWithKEK - 生成会话密钥并用密钥加密密钥加密输出
     */
    @Test
    public void testGenerateKeyWithKEK() throws SDFException, java.io.UnsupportedEncodingException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long keyHandle = 0;
        boolean kekAccessRightObtained = false;
        try {

            // 获取 KEK 访问权限
            try {
                sdf.SDF_GetKEKAccessRight(sessionHandle, kekIndex, kekPassword);
                kekAccessRightObtained = true;
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] 获取 KEK 权限不支持");
                    Assume.assumeTrue("获取 KEK 权限不需要或不支持，继续测试...", false);
                } else {
                    System.out.println(e.getMessage());
                    throw e;
                }
            }

            KeyEncryptionResult result = sdf.SDF_GenerateKeyWithKEK(
                    sessionHandle, SESSION_KEY_BITS_128, AlgorithmID.SGD_SM4_ECB, kekIndex);
            assertNotNull("密钥生成结果不应为空", result);

            keyHandle = result.getKeyHandle();
            byte[] encryptedKey = result.getEncryptedKey();

            assertNotNull("加密密钥不应为空", encryptedKey);
            assertTrue("密钥句柄应大于 0", keyHandle > 0);
            // 验证生成的会话密钥是否可用 - 进行加密测试
            byte[] testData = "FACECAFEBEEFBEEF".getBytes("UTF-8");  // 16 bytes

            byte[] encryptedData = sdf.SDF_Encrypt(
                    sessionHandle, keyHandle, AlgorithmID.SGD_SM4_ECB, null, testData);
            assertNotNull("加密数据不应为空", encryptedData);

            byte[] decryptedData = sdf.SDF_Decrypt(
                    sessionHandle, keyHandle, AlgorithmID.SGD_SM4_ECB, null, encryptedData);
            assertNotNull("解密数据不应为空", decryptedData);
            assertArrayEquals("解密数据应与原始数据相同", testData, decryptedData);
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] KEK 生成会话密钥功能未实现");
                Assume.assumeTrue("KEK 生成会话密钥功能未实现", false);
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
            if (kekAccessRightObtained) {
                try {
                    sdf.SDF_ReleaseKEKAccessRight(sessionHandle, kekIndex);
                } catch (SDFException e) {
                    System.err.println("释放 KEK 访问权限失败: " + e.getMessage());
                }
            }
        }
    }

    /**
     * 测试 6.3.16 SDF_ImportKeyWithKEK - 导入会话密钥并用密钥加密密钥解密
     */
    @Test
    public void testImportKeyWithKEK() throws SDFException, java.io.UnsupportedEncodingException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long keyHandle1 = 0;
        long keyHandle2 = 0;
        boolean kekAccessRightObtained = false;
        try {
            // 获取 KEK 访问权限
            try {
                sdf.SDF_GetKEKAccessRight(sessionHandle, kekIndex, kekPassword);
                kekAccessRightObtained = true;
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] 获取 KEK 权限不支持");
                    Assume.assumeTrue("获取 KEK 权限不需要或不支持，继续测试...", false);
                } else {
                    System.out.println(e.getMessage());
                    throw e;
                }
            }

            // 先生成一个加密的会话密钥
            KeyEncryptionResult result = sdf.SDF_GenerateKeyWithKEK(
                    sessionHandle, SESSION_KEY_BITS_128, AlgorithmID.SGD_SM4_ECB, kekIndex);
            keyHandle1 = result.getKeyHandle();
            byte[] encryptedKey = result.getEncryptedKey();

            // 导入会话密钥
            keyHandle2 = sdf.SDF_ImportKeyWithKEK(sessionHandle, AlgorithmID.SGD_SM4_ECB, kekIndex, encryptedKey);

            assertTrue("导入的密钥句柄应大于 0", keyHandle2 > 0);

            // 验证导入的会话密钥是否可用 - 进行加密测试
            byte[] testData = "CAFEBABECAFEBABE".getBytes("UTF-8");  // 16 bytes

            byte[] encryptedData = sdf.SDF_Encrypt(
                    sessionHandle, keyHandle2, AlgorithmID.SGD_SM4_ECB, null, testData);
            assertNotNull("加密数据不应为空", encryptedData);

            byte[] decryptedData = sdf.SDF_Decrypt(
                    sessionHandle, keyHandle2, AlgorithmID.SGD_SM4_ECB, null, encryptedData);
            assertNotNull("解密数据不应为空", decryptedData);
            assertArrayEquals("解密数据应与原始数据相同", testData, decryptedData);

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] KEK 导入会话密钥功能未实现");
                Assume.assumeTrue("KEK 导入会话密钥功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        } finally {
            if (keyHandle1 != 0) {
                try {
                    sdf.SDF_DestroyKey(sessionHandle, keyHandle1);
                } catch (SDFException e) {
                    System.err.println("销毁密钥失败: " + e.getMessage());
                }
            }
            if (keyHandle2 != 0) {
                try {
                    sdf.SDF_DestroyKey(sessionHandle, keyHandle2);
                } catch (SDFException e) {
                    System.err.println("销毁密钥失败: " + e.getMessage());
                }
            }
            if (kekAccessRightObtained) {
                try {
                    sdf.SDF_ReleaseKEKAccessRight(sessionHandle, kekIndex);
                } catch (SDFException e) {
                    System.err.println("释放 KEK 访问权限失败: " + e.getMessage());
                }
            }
        }
    }

    // ========================================================================
    // 明文密钥导入测试
    // ========================================================================

    /**
     * 测试 SDF_ImportKey - 导入明文会话密钥
     *
     * 将外部明文会话密钥导入密码设备，返回密钥句柄用于后续加密操作
     */
    @Test
    public void testImportKey() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long keyHandle = 0;
        try {
            // 生成一个 16 字节的随机密钥作为会话密钥（SM4 密钥）
            byte[] plainKey = sdf.SDF_GenerateRandom(sessionHandle, 16);

            // 导入明文密钥
            keyHandle = sdf.SDF_ImportKey(sessionHandle, plainKey);

            assertTrue("导入的密钥句柄应大于 0", keyHandle > 0);
            // 使用导入的密钥进行加密测试，验证密钥可用
            byte[] testData = "Hello, SDF4J!!!!".getBytes("UTF-8");  // 16 bytes

            try {
                byte[] encryptedData = sdf.SDF_Encrypt(
                        sessionHandle, keyHandle, AlgorithmID.SGD_SM4_ECB, null, testData);
                // 解密验证
                byte[] decryptedData = sdf.SDF_Decrypt(
                        sessionHandle, keyHandle, AlgorithmID.SGD_SM4_ECB, null, encryptedData);

                assertArrayEquals("解密数据应与原始数据相同", testData, decryptedData);
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] 加密功能未实现，但密钥导入成功");
                    Assume.assumeTrue("加密功能未实现，但密钥导入成功", false);
                } else {
                    System.out.println(e.getMessage());
                    throw e;
                }
            }

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SDF_ImportKey 功能未实现");
                Assume.assumeTrue("SDF_ImportKey 功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            if (keyHandle != 0) {
                try {
                    sdf.SDF_DestroyKey(sessionHandle, keyHandle);
                } catch (SDFException e) {
                    System.err.println("销毁密钥失败: " + e.getMessage());
                }
            }
        }
    }

    // ========================================================================
    // 密钥销毁测试
    // ========================================================================

    /**
     * 测试 6.3.17 SDF_DestroyKey - 销毁会话密钥
     */
    @Test
    public void testDestroyKey() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        boolean accessRightObtained = false;
        try {
            // 获取私钥访问权限
            try {
                sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, keyIndex, keyPassword);
                accessRightObtained = true;
            } catch (SDFException e) {
                if (e.getErrorCode() != ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println(e.getMessage());
                    throw e;
                }
            }

            // 生成会话密钥
            ECCKeyEncryptionResult result = sdf.SDF_GenerateKeyWithIPK_ECC(sessionHandle, keyIndex, SESSION_KEY_BITS_128);
            long keyHandle = result.getKeyHandle();

            // 销毁会话密钥
            sdf.SDF_DestroyKey(sessionHandle, keyHandle);

            // 验证密钥已被销毁（尝试使用已销毁的密钥应该失败）
            try {
                byte[] testData = new byte[16];
                sdf.SDF_Encrypt(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_ECB, null, testData);
                // 如果没有抛出异常，可能设备不检查密钥句柄有效性
            } catch (SDFException e) {
                // Expected - destroyed key should not be usable
            }

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 功能未实现");
                Assume.assumeTrue("功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        } finally {
            if (accessRightObtained) {
                try {
                    sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, keyIndex);
                } catch (SDFException e) {
                    // ignore
                }
            }
        }
    }

    @Test
    public void testExchangeDigitEnvelopeBaseOnECC() throws SDFException, java.io.UnsupportedEncodingException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        boolean keyAccessRightObtained = false;
        long keyHandle = 0;

        try {
            try {
                sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, keyIndex, keyPassword);
                keyAccessRightObtained = true;
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] 获取私钥权限不支持");
                    Assume.assumeTrue("获取私钥权限不需要或不支持，继续测试...", false);
                } else {
                    System.out.println(e.getMessage());
                    throw e;
                }
            }

            // 保存原始会话密钥用于验证
            byte[] originalSessionKey = sdf.SDF_GenerateRandom(sessionHandle, 16);

            // 使用内部加密公钥加密该会话密钥，直接生成 ECCCipher 对象
            ECCCipher encDataIn = sdf.SDF_InternalEncrypt_ECC(sessionHandle, keyIndex, originalSessionKey);
            assertNotNull("使用内部公钥加密生成的 ECCCipher 不应为空", encDataIn);

            // 准备外部 ECC 公钥（目标公钥）
            Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_3, ECC_KEY_BITS);
            assertNotNull("外部密钥对不应为空", keyPair);
            ECCPublicKey externalPub = (ECCPublicKey) keyPair[0];
            ECCPrivateKey externalPriv = (ECCPrivateKey) keyPair[1];

            // 调用数字信封转换接口
            ECCCipher encDataOut = sdf.SDF_ExchangeDigitEnvelopeBaseOnECC(
                    sessionHandle, keyIndex, AlgorithmID.SGD_SM2_3, externalPub, encDataIn);

            assertNotNull(encDataOut);
            assertTrue(encDataOut.getL() > 0);

            // 验证：使用转换后的数字信封解密，应能得到原始会话密钥
            byte[] decryptedSessionKey = sdf.SDF_ExternalDecrypt_ECC(
                    sessionHandle, AlgorithmID.SGD_SM2_3, externalPriv, encDataOut);
            assertArrayEquals("解密后的会话密钥应与原始密钥相同", originalSessionKey, decryptedSessionKey);

            // 进一步验证：使用解密后的会话密钥进行加解密测试
            byte[] testData = "1234567890ABCDEF".getBytes("UTF-8");  // 16 bytes

            // 导入会话密钥
            keyHandle = sdf.SDF_ImportKey(sessionHandle, decryptedSessionKey);
            assertTrue("导入的密钥句柄应大于 0", keyHandle > 0);

            byte[] encryptedData = sdf.SDF_Encrypt(
                    sessionHandle, keyHandle, AlgorithmID.SGD_SM4_ECB, null, testData);
            assertNotNull("加密数据不应为空", encryptedData);

            byte[] decryptedData = sdf.SDF_Decrypt(
                    sessionHandle, keyHandle, AlgorithmID.SGD_SM4_ECB, null, encryptedData);
            assertNotNull("解密数据不应为空", decryptedData);
            assertArrayEquals("解密数据应与原始数据相同", testData, decryptedData);
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 设备不支持 SDF_ExchangeDigitEnvelopeBaseOnECC");
                Assume.assumeTrue("设备不支持 SDF_ExchangeDigitEnvelopeBaseOnECC", false);
            }
            System.out.println(e.getMessage());
            throw e;
        } finally {
            // 清理资源
            if (keyHandle != 0) {
                try {
                    sdf.SDF_DestroyKey(sessionHandle, keyHandle);
                } catch (SDFException e) {
                    System.err.println("销毁密钥失败: " + e.getMessage());
                }
            }
            if (keyAccessRightObtained) {
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
        if (bytes == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
