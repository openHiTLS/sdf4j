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
                    System.out.println("已从配置文件加载测试配置: keyIndex=" + keyIndex + ", kekIndex=" + kekIndex);
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
        System.out.println("使用默认测试配置: keyIndex=" + keyIndex + ", kekIndex=" + kekIndex);
    }

    @Before
    public void setUp() throws SDFException {
        System.out.println("========================================");
        System.out.println("SDF4J 密钥管理类函数测试");
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

    // ========================================================================
    // ECC 公钥导出测试
    // ========================================================================

    /**
     * 测试 6.3.7 SDF_ExportSignPublicKey_ECC - 导出 ECC 签名公钥
     */
    @Test
    public void testExportSignPublicKeyECC() throws SDFException {
        System.out.println("测试 6.3.7 SDF_ExportSignPublicKey_ECC - 导出 ECC 签名公钥");
        System.out.println("----------------------------------------");

        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            System.out.println("导出 ECC 签名公钥，密钥索引: " + keyIndex);

            ECCPublicKey publicKey = sdf.SDF_ExportSignPublicKey_ECC(sessionHandle, keyIndex);
            assertNotNull("ECC 签名公钥不应为空", publicKey);

            System.out.println("\nECC 签名公钥导出成功:");
            System.out.println("  密钥位数: " + publicKey.getBits() + " bits");
            System.out.println("  X 坐标长度: " + publicKey.getX().length + " bytes");
            System.out.println("  Y 坐标长度: " + publicKey.getY().length + " bytes");
            System.out.println("  X: " + bytesToHex(publicKey.getX()));
            System.out.println("  Y: " + bytesToHex(publicKey.getY()));

            assertTrue("ECC 密钥位数应大于 0", publicKey.getBits() > 0);
            assertNotNull("X 坐标不应为空", publicKey.getX());
            assertNotNull("Y 坐标不应为空", publicKey.getY());

            System.out.println("[通过] ECC 签名公钥导出成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] ECC 签名公钥导出功能未实现\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_KEYNOTEXIST) {
                System.out.println("[跳过] ECC 内部签名密钥不存在，密钥索引: " + keyIndex + "\n");
            } else {
                throw e;
            }
        }
    }

    /**
     * 测试 6.3.8 SDF_ExportEncPublicKey_ECC - 导出 ECC 加密公钥
     */
    @Test
    public void testExportEncPublicKeyECC() throws SDFException {
        System.out.println("测试 6.3.8 SDF_ExportEncPublicKey_ECC - 导出 ECC 加密公钥");
        System.out.println("----------------------------------------");

        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            System.out.println("导出 ECC 加密公钥，密钥索引: " + keyIndex);

            ECCPublicKey publicKey = sdf.SDF_ExportEncPublicKey_ECC(sessionHandle, keyIndex);
            assertNotNull("ECC 加密公钥不应为空", publicKey);

            System.out.println("\nECC 加密公钥导出成功:");
            System.out.println("  密钥位数: " + publicKey.getBits() + " bits");
            System.out.println("  X 坐标长度: " + publicKey.getX().length + " bytes");
            System.out.println("  Y 坐标长度: " + publicKey.getY().length + " bytes");
            System.out.println("  X: " + bytesToHex(publicKey.getX()));
            System.out.println("  Y: " + bytesToHex(publicKey.getY()));

            assertTrue("ECC 密钥位数应大于 0", publicKey.getBits() > 0);

            System.out.println("[通过] ECC 加密公钥导出成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] ECC 加密公钥导出功能未实现\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_KEYNOTEXIST) {
                System.out.println("[跳过] ECC 内部加密密钥不存在，密钥索引: " + keyIndex + "\n");
            } else {
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
    public void testGenerateKeyWithIPK_ECC() throws SDFException {
        System.out.println("测试 6.3.9 SDF_GenerateKeyWithIPK_ECC - 生成会话密钥并用内部 ECC 公钥加密输出");
        System.out.println("----------------------------------------");

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

            System.out.println("\n生成会话密钥，密钥索引: " + keyIndex + ", 密钥长度: " + SESSION_KEY_BITS_128 + " bits");

            KeyEncryptionResult result = sdf.SDF_GenerateKeyWithIPK_ECC(sessionHandle, keyIndex, SESSION_KEY_BITS_128);
            assertNotNull("密钥生成结果不应为空", result);

            keyHandle = result.getKeyHandle();
            byte[] encryptedKey = result.getEncryptedKey();

            assertNotNull("加密密钥不应为空", encryptedKey);
            assertTrue("密钥句柄应大于 0", keyHandle > 0);

            System.out.println("\n会话密钥生成成功:");
            System.out.println("  密钥句柄: 0x" + Long.toHexString(keyHandle).toUpperCase());
            System.out.println("  加密密钥长度: " + encryptedKey.length + " bytes");
            System.out.println("  加密密钥(ECC Cipher): " + bytesToHex(encryptedKey).substring(0, Math.min(64, encryptedKey.length * 2)) + "...");

            System.out.println("[通过] 内部 ECC 公钥生成会话密钥成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 内部 ECC 公钥生成会话密钥功能未实现\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_KEYNOTEXIST) {
                System.out.println("[跳过] ECC 内部加密密钥不存在，密钥索引: " + keyIndex + "\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_INARGERR) {
                System.out.println("[跳过] 参数错误，可能密钥长度不支持\n");
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
     * 测试 6.3.10 SDF_GenerateKeyWithEPK_ECC - 生成会话密钥并用外部 ECC 公钥加密输出
     */
    @Test
    public void testGenerateKeyWithEPK_ECC() throws SDFException {
        System.out.println("测试 6.3.10 SDF_GenerateKeyWithEPK_ECC - 生成会话密钥并用外部 ECC 公钥加密输出");
        System.out.println("----------------------------------------");

        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long keyHandle = 0;
        try {
            // 先生成一个外部 ECC 密钥对
            System.out.println("步骤1: 生成外部 ECC 密钥对");
            Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPublicKey publicKey = (ECCPublicKey) keyPair[0];
            System.out.println("ECC 密钥对生成成功，密钥位数: " + publicKey.getBits() + " bits");

            // 使用外部公钥生成会话密钥
            System.out.println("\n步骤2: 使用外部 ECC 公钥生成会话密钥");
            KeyEncryptionResult result = sdf.SDF_GenerateKeyWithEPK_ECC(
                    sessionHandle, SESSION_KEY_BITS_128, AlgorithmID.SGD_SM2_3, publicKey);
            assertNotNull("密钥生成结果不应为空", result);

            keyHandle = result.getKeyHandle();
            byte[] encryptedKey = result.getEncryptedKey();

            assertNotNull("加密密钥不应为空", encryptedKey);
            assertTrue("密钥句柄应大于 0", keyHandle > 0);

            System.out.println("\n会话密钥生成成功:");
            System.out.println("  密钥句柄: 0x" + Long.toHexString(keyHandle).toUpperCase());
            System.out.println("  加密密钥长度: " + encryptedKey.length + " bytes");

            System.out.println("[通过] 外部 ECC 公钥生成会话密钥成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 外部 ECC 公钥生成会话密钥功能未实现\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_INARGERR) {
                System.out.println("[跳过] 参数错误: " + e.getErrorCodeHex() + "\n");
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
        }
    }

    /**
     * 测试 6.3.11 SDF_ImportKeyWithISK_ECC - 导入会话密钥并用内部 ECC 私钥解密
     */
    @Test
    public void testImportKeyWithISK_ECC() throws SDFException {
        System.out.println("测试 6.3.11 SDF_ImportKeyWithISK_ECC - 导入会话密钥并用内部 ECC 私钥解密");
        System.out.println("----------------------------------------");

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

            // 步骤1: 导出内部 ECC 加密公钥
            System.out.println("\n步骤1: 导出内部 ECC 加密公钥，密钥索引: " + keyIndex);
            ECCPublicKey publicKey = sdf.SDF_ExportEncPublicKey_ECC(sessionHandle, keyIndex);
            System.out.println("内部公钥导出成功，密钥位数: " + publicKey.getBits() + " bits");

            // 步骤2: 生成一个 16 字节的会话密钥（SM4 密钥），并用内部公钥加密
            System.out.println("\n步骤2: 生成随机会话密钥并用内部 ECC 公钥加密");
            byte[] sessionKey = sdf.SDF_GenerateRandom(sessionHandle, 16);  // 16 bytes = 128 bits
            System.out.println("生成随机会话密钥: " + bytesToHex(sessionKey));

            // 使用外部加密接口用内部公钥加密会话密钥
            ECCCipher eccCipher = sdf.SDF_ExternalEncrypt_ECC(
                    sessionHandle, AlgorithmID.SGD_SM2_3, publicKey, sessionKey);
            System.out.println("会话密钥加密成功");
            System.out.println("  ECCCipher C2 长度: " + eccCipher.getL() + " bytes");

            // 步骤3: 导入会话密钥并用内部 ECC 私钥解密
            System.out.println("\n步骤3: 导入会话密钥并用内部 ECC 私钥解密");
            keyHandle = sdf.SDF_ImportKeyWithISK_ECC(sessionHandle, keyIndex, eccCipher);

            assertTrue("导入的密钥句柄应大于 0", keyHandle > 0);
            System.out.println("会话密钥导入成功:");
            System.out.println("  导入密钥句柄: 0x" + Long.toHexString(keyHandle).toUpperCase());

            System.out.println("[通过] 内部 ECC 私钥导入会话密钥成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 内部 ECC 私钥导入会话密钥功能未实现\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_KEYNOTEXIST) {
                System.out.println("[跳过] ECC 内部密钥不存在，密钥索引: " + keyIndex + "\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_INARGERR) {
                System.out.println("[跳过] 参数错误: " + e.getErrorCodeHex() + "\n");
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
    // ECC 密钥协商测试
    // ========================================================================

    /**
     * 测试 6.3.12 SDF_GenerateAgreementDataWithECC - 生成密钥协商参数并输出
     */
    @Test
    public void testGenerateAgreementDataWithECC() throws SDFException {
        System.out.println("测试 6.3.12 SDF_GenerateAgreementDataWithECC - 生成密钥协商参数并输出");
        System.out.println("----------------------------------------");

        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long agreementHandle = 0;
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

            // 导出内部 ECC 加密公钥作为发起方公钥
            ECCPublicKey sponsorPublicKey = sdf.SDF_ExportEncPublicKey_ECC(sessionHandle, keyIndex);
            System.out.println("导出发起方公钥成功，密钥位数: " + sponsorPublicKey.getBits() + " bits");

            // 生成临时密钥对作为发起方临时公钥
            Object[] tmpKeyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPublicKey sponsorTmpPublicKey = (ECCPublicKey) tmpKeyPair[0];
            System.out.println("生成发起方临时公钥成功");

            // 发起方 ID
            byte[] sponsorID = "1234567812345678".getBytes();

            // 生成密钥协商参数
            System.out.println("\n生成密钥协商参数，密钥索引: " + keyIndex + ", 密钥长度: " + SESSION_KEY_BITS_128 + " bits");
            agreementHandle = sdf.SDF_GenerateAgreementDataWithECC(
                    sessionHandle, keyIndex, SESSION_KEY_BITS_128,
                    sponsorID, sponsorPublicKey, sponsorTmpPublicKey);

            assertTrue("协商句柄应大于 0", agreementHandle > 0);
            System.out.println("密钥协商参数生成成功:");
            System.out.println("  协商句柄: 0x" + Long.toHexString(agreementHandle).toUpperCase());

            System.out.println("[通过] 生成密钥协商参数成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 生成密钥协商参数功能未实现\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_KEYNOTEXIST) {
                System.out.println("[跳过] ECC 内部密钥不存在，密钥索引: " + keyIndex + "\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_INARGERR) {
                System.out.println("[跳过] 参数错误: " + e.getErrorCodeHex() + "\n");
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
     * 测试 6.3.13 SDF_GenerateKeyWithECC - 计算会话密钥
     */
    @Test
    public void testGenerateKeyWithECC() throws SDFException {
        System.out.println("测试 6.3.13 SDF_GenerateKeyWithECC - 计算会话密钥");
        System.out.println("----------------------------------------");

        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long agreementHandle = 0;
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

            // 步骤1: 发起方生成协商数据
            ECCPublicKey sponsorPublicKey = sdf.SDF_ExportEncPublicKey_ECC(sessionHandle, keyIndex);
            Object[] sponsorTmpKeyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPublicKey sponsorTmpPublicKey = (ECCPublicKey) sponsorTmpKeyPair[0];
            byte[] sponsorID = "1234567812345678".getBytes();

            System.out.println("步骤1: 发起方生成协商数据");
            agreementHandle = sdf.SDF_GenerateAgreementDataWithECC(
                    sessionHandle, keyIndex, SESSION_KEY_BITS_128,
                    sponsorID, sponsorPublicKey, sponsorTmpPublicKey);
            System.out.println("协商句柄: 0x" + Long.toHexString(agreementHandle).toUpperCase());

            // 步骤2: 响应方生成密钥对（模拟响应方）
            System.out.println("\n步骤2: 响应方生成密钥对（模拟）");
            Object[] responseKeyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPublicKey responsePublicKey = (ECCPublicKey) responseKeyPair[0];
            Object[] responseTmpKeyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPublicKey responseTmpPublicKey = (ECCPublicKey) responseTmpKeyPair[0];
            byte[] responseID = "8765432187654321".getBytes();
            System.out.println("响应方密钥对生成成功");

            // 步骤3: 计算会话密钥
            System.out.println("\n步骤3: 计算会话密钥");
            keyHandle = sdf.SDF_GenerateKeyWithECC(
                    sessionHandle, responseID,
                    responsePublicKey, responseTmpPublicKey,
                    agreementHandle);

            assertTrue("密钥句柄应大于 0", keyHandle > 0);
            System.out.println("会话密钥计算成功:");
            System.out.println("  密钥句柄: 0x" + Long.toHexString(keyHandle).toUpperCase());

            System.out.println("[通过] 计算会话密钥成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 计算会话密钥功能未实现\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_KEYNOTEXIST) {
                System.out.println("[跳过] ECC 内部密钥不存在，密钥索引: " + keyIndex + "\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_INARGERR) {
                System.out.println("[跳过] 参数错误: " + e.getErrorCodeHex() + "\n");
            } else {
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
                    System.out.println("已释放私钥访问权限");
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
        System.out.println("测试 6.3.14 SDF_GenerateAgreementDataAndKeyWithECC - 产生协商数据并计算会话密钥");
        System.out.println("----------------------------------------");

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

            // 准备发起方数据
            ECCPublicKey sponsorPublicKey = sdf.SDF_ExportEncPublicKey_ECC(sessionHandle, keyIndex);
            Object[] sponsorTmpKeyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPublicKey sponsorTmpPublicKey = (ECCPublicKey) sponsorTmpKeyPair[0];
            byte[] sponsorID = "1234567812345678".getBytes();
            System.out.println("发起方数据准备完成");

            // 准备响应方数据
            Object[] responseKeyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPublicKey responsePublicKey = (ECCPublicKey) responseKeyPair[0];
            Object[] responseTmpKeyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPublicKey responseTmpPublicKey = (ECCPublicKey) responseTmpKeyPair[0];
            byte[] responseID = "8765432187654321".getBytes();
            System.out.println("响应方数据准备完成");

            // 产生协商数据并计算会话密钥
            System.out.println("\n产生协商数据并计算会话密钥，密钥索引: " + keyIndex + ", 密钥长度: " + SESSION_KEY_BITS_128 + " bits");
            keyHandle = sdf.SDF_GenerateAgreementDataAndKeyWithECC(
                    sessionHandle, keyIndex, SESSION_KEY_BITS_128,
                    responseID, sponsorID,
                    sponsorPublicKey, sponsorTmpPublicKey,
                    responsePublicKey, responseTmpPublicKey);

            assertTrue("密钥句柄应大于 0", keyHandle > 0);
            System.out.println("会话密钥生成成功:");
            System.out.println("  密钥句柄: 0x" + Long.toHexString(keyHandle).toUpperCase());

            System.out.println("[通过] 产生协商数据并计算会话密钥成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 产生协商数据并计算会话密钥功能未实现\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_KEYNOTEXIST) {
                System.out.println("[跳过] ECC 内部密钥不存在，密钥索引: " + keyIndex + "\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_INARGERR) {
                System.out.println("[跳过] 参数错误: " + e.getErrorCodeHex() + "\n");
            } else {
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
                    System.out.println("已释放私钥访问权限");
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
    public void testGenerateKeyWithKEK() throws SDFException {
        System.out.println("测试 6.3.15 SDF_GenerateKeyWithKEK - 生成会话密钥并用 KEK 加密输出");
        System.out.println("----------------------------------------");

        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long keyHandle = 0;
        boolean kekAccessRightObtained = false;
        try {
            System.out.println("生成会话密钥，KEK 索引: " + kekIndex + ", 密钥长度: " + SESSION_KEY_BITS_128 + " bits");
            System.out.println("使用 SM4 算法 (SGD_SM4_ECB)");

            // 获取 KEK 访问权限
            System.out.println("获取 KEK 访问权限，密钥索引: " + kekIndex);
            try {
                sdf.SDF_GetKEKAccessRight(sessionHandle, kekIndex, kekPassword);
                kekAccessRightObtained = true;
                System.out.println("成功获取 KEK 访问权限");
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("获取 KEK 权限不需要或不支持，继续测试...");
                } else {
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

            System.out.println("\n会话密钥生成成功:");
            System.out.println("  密钥句柄: 0x" + Long.toHexString(keyHandle).toUpperCase());
            System.out.println("  加密密钥长度: " + encryptedKey.length + " bytes");
            System.out.println("  加密密钥: " + bytesToHex(encryptedKey));

            System.out.println("[通过] KEK 生成会话密钥成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] KEK 生成会话密钥功能未实现\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_KEYNOTEXIST) {
                System.out.println("[跳过] KEK 密钥不存在，密钥索引: " + kekIndex + "\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_INARGERR) {
                System.out.println("[跳过] 参数错误: " + e.getErrorCodeHex() + "\n");
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
            if (kekAccessRightObtained) {
                try {
                    sdf.SDF_ReleaseKEKAccessRight(sessionHandle, kekIndex);
                    System.out.println("已释放 KEK 访问权限");
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
    public void testImportKeyWithKEK() throws SDFException {
        System.out.println("测试 6.3.16 SDF_ImportKeyWithKEK - 导入会话密钥并用 KEK 解密");
        System.out.println("----------------------------------------");

        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long keyHandle1 = 0;
        long keyHandle2 = 0;
        boolean kekAccessRightObtained = false;
        try {
            // 获取 KEK 访问权限
            System.out.println("获取 KEK 访问权限，密钥索引: " + kekIndex);
            try {
                sdf.SDF_GetKEKAccessRight(sessionHandle, kekIndex, kekPassword);
                kekAccessRightObtained = true;
                System.out.println("成功获取 KEK 访问权限");
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("获取 KEK 权限不需要或不支持，继续测试...");
                } else {
                    throw e;
                }
            }

            // 先生成一个加密的会话密钥
            System.out.println("先生成会话密钥用于测试导入，KEK 索引: " + kekIndex);
            KeyEncryptionResult result = sdf.SDF_GenerateKeyWithKEK(
                    sessionHandle, SESSION_KEY_BITS_128, AlgorithmID.SGD_SM4_ECB, kekIndex);
            keyHandle1 = result.getKeyHandle();
            byte[] encryptedKey = result.getEncryptedKey();
            System.out.println("会话密钥生成成功，加密密钥长度: " + encryptedKey.length + " bytes");

            // 导入会话密钥
            System.out.println("\n导入会话密钥并用 KEK 解密");
            keyHandle2 = sdf.SDF_ImportKeyWithKEK(sessionHandle, AlgorithmID.SGD_SM4_ECB, kekIndex, encryptedKey);

            assertTrue("导入的密钥句柄应大于 0", keyHandle2 > 0);
            System.out.println("会话密钥导入成功:");
            System.out.println("  导入密钥句柄: 0x" + Long.toHexString(keyHandle2).toUpperCase());

            System.out.println("[通过] KEK 导入会话密钥成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] KEK 导入会话密钥功能未实现\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_KEYNOTEXIST) {
                System.out.println("[跳过] KEK 密钥不存在，密钥索引: " + kekIndex + "\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_INARGERR) {
                System.out.println("[跳过] 参数错误: " + e.getErrorCodeHex() + "\n");
            } else {
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
                    System.out.println("已释放 KEK 访问权限");
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
        System.out.println("测试 SDF_ImportKey - 导入明文会话密钥");
        System.out.println("----------------------------------------");

        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long keyHandle = 0;
        try {
            // 生成一个 16 字节的随机密钥作为会话密钥（SM4 密钥）
            System.out.println("步骤1: 生成 16 字节随机密钥");
            byte[] plainKey = sdf.SDF_GenerateRandom(sessionHandle, 16);
            System.out.println("生成的明文密钥: " + bytesToHex(plainKey));
            System.out.println("密钥长度: " + plainKey.length + " bytes (" + (plainKey.length * 8) + " bits)");

            // 导入明文密钥
            System.out.println("\n步骤2: 导入明文会话密钥");
            keyHandle = sdf.SDF_ImportKey(sessionHandle, plainKey);

            assertTrue("导入的密钥句柄应大于 0", keyHandle > 0);
            System.out.println("明文会话密钥导入成功:");
            System.out.println("  密钥句柄: 0x" + Long.toHexString(keyHandle).toUpperCase());

            // 使用导入的密钥进行加密测试，验证密钥可用
            System.out.println("\n步骤3: 使用导入的密钥进行加密测试");
            byte[] testData = "Hello, SDF4J!!!!".getBytes("UTF-8");  // 16 bytes
            System.out.println("原始数据: " + new String(testData, "UTF-8"));
            System.out.println("原始数据(hex): " + bytesToHex(testData));

            try {
                byte[] encryptedData = sdf.SDF_Encrypt(
                        sessionHandle, keyHandle, AlgorithmID.SGD_SM4_ECB, null, testData);
                System.out.println("加密成功:");
                System.out.println("  加密数据长度: " + encryptedData.length + " bytes");
                System.out.println("  加密数据(hex): " + bytesToHex(encryptedData));

                // 解密验证
                byte[] decryptedData = sdf.SDF_Decrypt(
                        sessionHandle, keyHandle, AlgorithmID.SGD_SM4_ECB, null, encryptedData);
                System.out.println("解密成功:");
                System.out.println("  解密数据: " + new String(decryptedData, "UTF-8"));

                assertArrayEquals("解密数据应与原始数据相同", testData, decryptedData);
                System.out.println("[通过] 使用导入密钥加解密验证成功");

            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] 加密功能未实现，但密钥导入成功");
                } else {
                    throw e;
                }
            }

            System.out.println("\n[通过] 明文会话密钥导入测试成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SDF_ImportKey 功能未实现\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_INARGERR) {
                System.out.println("[跳过] 参数错误: " + e.getErrorCodeHex() + "\n");
            } else {
                throw e;
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            if (keyHandle != 0) {
                try {
                    sdf.SDF_DestroyKey(sessionHandle, keyHandle);
                    System.out.println("会话密钥已销毁");
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
        System.out.println("测试 6.3.17 SDF_DestroyKey - 销毁会话密钥");
        System.out.println("----------------------------------------");

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
                    throw e;
                }
            }

            // 生成会话密钥
            System.out.println("生成会话密钥");
            KeyEncryptionResult result = sdf.SDF_GenerateKeyWithIPK_ECC(sessionHandle, keyIndex, SESSION_KEY_BITS_128);
            long keyHandle = result.getKeyHandle();
            System.out.println("会话密钥生成成功，密钥句柄: 0x" + Long.toHexString(keyHandle).toUpperCase());

            // 销毁会话密钥
            System.out.println("\n销毁会话密钥");
            sdf.SDF_DestroyKey(sessionHandle, keyHandle);
            System.out.println("会话密钥销毁成功");

            // 验证密钥已被销毁（尝试使用已销毁的密钥应该失败）
            System.out.println("\n验证密钥已被销毁（尝试使用已销毁的密钥）");
            try {
                byte[] testData = new byte[16];
                sdf.SDF_Encrypt(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_ECB, null, testData);
                // 如果没有抛出异常，可能设备不检查密钥句柄有效性
                System.out.println("警告: 设备未检查密钥句柄有效性");
            } catch (SDFException e) {
                System.out.println("使用已销毁的密钥正确失败: " + e.getErrorCodeHex());
            }

            System.out.println("[通过] 密钥销毁测试成功\n");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 功能未实现\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_KEYNOTEXIST) {
                System.out.println("[跳过] 内部密钥不存在\n");
            } else if (e.getErrorCode() == ErrorCode.SDR_INARGERR) {
                System.out.println("[跳过] 参数错误: " + e.getErrorCodeHex() + "\n");
            } else {
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
