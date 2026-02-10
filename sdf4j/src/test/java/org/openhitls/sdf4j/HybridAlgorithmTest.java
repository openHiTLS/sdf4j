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
import org.openhitls.sdf4j.types.*;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

import static org.junit.Assert.*;

/**
 * SDF4J 混合算法运算类函数测试
 *
 * <p>测试混合加密和混合签名相关接口
 * 包含以下接口测试：
 * - SDF_ExportPublicKey_Hybrid - 导出混合加密公钥
 * - SDF_ImportKeyWithISK_Hybrid - 导入会话密钥并用内部混合私钥解密
 * - SDF_GenerateKeyWithEPK_Hybrid - 使用外部公钥进行混合加密
 * - SDF_InternalSign_Composite - 使用内部私钥进行混合签名
 * - SDF_ExternalVerify_Composite - 使用外部公钥进行混合验签
 */
public class HybridAlgorithmTest {

    // 配置开关：设置为 true 时从配置文件读取，false 时使用下面的默认值
    private static final boolean USE_CONFIG_FILE = true;

    private static final int KEY_INDEX_DIGIT = 20;

    // 默认配置
    private static final int DEFAULT_HYBRID_ENCRYPT_KEY_INDEX = 1;
    private static final String DEFAULT_HYBRID_ENCRYPT_KEY_PASSWORD = "123abc!@";

    private static final int DEFAULT_COMPOSITE_SIGN_KEY_INDEX = 1;
    private static final String DEFAULT_COMPOSITE_SIGN_KEY_PASSWORD = "123abc!@";

    // 实际使用的配置
    private static int hybridEncryptKeyIndex = 1;
    private static String hybridEncryptKeyPassword = "123abc!@";

    private static int compositeSignKeyIndex = 1;
    private static String compositeSignKeyPassword = "123abc!@";

    private SDF sdf;
    private long deviceHandle;
    private long sessionHandle1;
    private long sessionHandle2;

    @BeforeClass
    public static void loadConfig() {
        if (USE_CONFIG_FILE) {
            Properties testConfig = new Properties();
            try (InputStream is = HybridAlgorithmTest.class.getClassLoader()
                    .getResourceAsStream("test-config.properties")) {
                if (is != null) {
                    testConfig.load(is);
                    hybridEncryptKeyIndex = Integer.parseInt(
                            testConfig.getProperty("hybrid.key.index",
                                    String.valueOf(DEFAULT_HYBRID_ENCRYPT_KEY_INDEX)));
                    hybridEncryptKeyPassword = testConfig.getProperty("hybrid.key.access.password",
                            DEFAULT_HYBRID_ENCRYPT_KEY_PASSWORD);
                    compositeSignKeyIndex = Integer.parseInt(
                            testConfig.getProperty("composite.key.index",
                                    String.valueOf(DEFAULT_COMPOSITE_SIGN_KEY_INDEX)));
                    compositeSignKeyPassword = testConfig.getProperty("composite.key.access.password",
                            DEFAULT_COMPOSITE_SIGN_KEY_PASSWORD);
                    return;
                }
            } catch (IOException e) {
                System.err.println("读取配置文件失败: " + e.getMessage());
            }
        }
    }

    @Before
    public void setUp() throws SDFException {
        sdf = new SDF();
        deviceHandle = 0;
        sessionHandle1 = 0;
        sessionHandle2 = 0;
    }

    @After
    public void tearDown() {
        try {
            if (sessionHandle1 != 0) {
                sdf.SDF_CloseSession(sessionHandle1);
                sessionHandle1 = 0;
            }
            if (sessionHandle2 != 0) {
                sdf.SDF_CloseSession(sessionHandle2);
                sessionHandle2 = 0;
            }
            if (deviceHandle != 0) {
                sdf.SDF_CloseDevice(deviceHandle);
                deviceHandle = 0;
            }
        } catch (SDFException e) {
            System.err.println("关闭资源失败: " + e.getMessage());
        }
    }

    @Test
    public void testHybridEncrypt() throws SDFException, java.io.UnsupportedEncodingException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle1 = sdf.SDF_OpenSession(deviceHandle);
        sessionHandle2 = sdf.SDF_OpenSession(deviceHandle);

        boolean accessRightObtained = false;
        long keyHandle = 0;
        int sessionIndex = (hybridEncryptKeyIndex | (AlgorithmID.SGD_HYBRID << KEY_INDEX_DIGIT));
        try {
            // 步骤1：导出混合加密公钥
            byte[] publicKey = sdf.SDF_ExportPublicKey_Hybrid(sessionHandle1, hybridEncryptKeyIndex);
            assertNotNull("公钥不应为null", publicKey);

            // 步骤2：使用外部公钥进行混合加密
            byte[] data = "Hello openhitls!".getBytes(StandardCharsets.UTF_8);
            HybridCipher cipher = sdf.SDF_GenerateKeyWithEPK_Hybrid(
                    sessionHandle2, AlgorithmID.SGD_HYBRID_ENV_SM2_MLKEM_512, publicKey);
            assertNotNull("混合密文不应为null", cipher);
            assertNotEquals("密文对象密钥句柄应不为0", 0, cipher.getKeyHandle());

            // 步骤3：获取私钥访问权限
            sdf.SDF_GetPrivateKeyAccessRight(sessionHandle1, sessionIndex, hybridEncryptKeyPassword);
            accessRightObtained = true;

            // 步骤4：导入混合加密密钥
            keyHandle = sdf.SDF_ImportKeyWithISK_Hybrid(sessionHandle1, sessionIndex, cipher);
            assertNotEquals("导入后密钥句柄应不为0", 0, keyHandle);

            byte[] testData = "FEDCBA9876543210".getBytes("UTF-8");  // 16 bytes
            byte[] encryptedData = sdf.SDF_Encrypt(
                    sessionHandle2, cipher.getKeyHandle(), AlgorithmID.SGD_SM4_ECB, null, testData);
            assertNotNull("加密数据不应为空", encryptedData);

            byte[] decryptedData = sdf.SDF_Decrypt(
                    sessionHandle1, keyHandle, AlgorithmID.SGD_SM4_ECB, null, encryptedData);
            assertNotNull("解密数据不应为空", decryptedData);
            assertArrayEquals("解密数据应与原始数据相同", testData, decryptedData);

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 混合加密流程功能未实现");
                Assume.assumeTrue("混合加密流程功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        } finally {
            if (accessRightObtained) {
                try {
                    sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle1, sessionIndex);
                } catch (SDFException e) {
                    System.err.println("释放私钥访问权限失败: " + e.getMessage());
                }
            }
        }
    }

    @Test
    public void testHybridSign() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle1 = sdf.SDF_OpenSession(deviceHandle);
        sessionHandle2 = sdf.SDF_OpenSession(deviceHandle);

        boolean accessRightObtained = false;
        int sessionIndex = (compositeSignKeyIndex | (AlgorithmID.SGD_HYBRID << KEY_INDEX_DIGIT));
        try {
            // 步骤1：导出混合加密公钥
            byte[] publicKey = sdf.SDF_ExportPublicKey_Hybrid(sessionHandle1, compositeSignKeyIndex);
            assertNotNull("公钥不应为null", publicKey);

            // 步骤2：获取私钥访问权限
            sdf.SDF_GetPrivateKeyAccessRight(sessionHandle1, sessionIndex, compositeSignKeyPassword);
            accessRightObtained = true;

            // 步骤3：内部签名
            String message = "Hello openHitls!";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);
            HybridSignature signature = sdf.SDF_InternalSign_Composite(sessionHandle1, sessionIndex, data);
            assertNotNull("签名不应为null", signature);
            assertNotNull("ECC签名部分不应为null", signature.getSigS());
            assertNotNull("后量子签名值不应为null", signature.getSigM());

            // 步骤4：外部验签
            sdf.SDF_ExternalVerify_Composite(
                    sessionHandle2,
                    AlgorithmID.SGD_COMPOSITE_MLDSA44_SM2,
                    publicKey,
                    data,
                    signature);
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 混合签名流程功能未实现");
                Assume.assumeTrue("混合签名流程功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        } finally {
            if (accessRightObtained) {
                try {
                    sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle1, sessionIndex);
                } catch (SDFException e) {
                    System.err.println("释放私钥访问权限失败: " + e.getMessage());
                }
            }
        }
    }
}
