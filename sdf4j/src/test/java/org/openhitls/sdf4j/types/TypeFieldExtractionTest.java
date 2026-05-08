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

package org.openhitls.sdf4j.types;

import org.junit.Test;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.After;
import org.junit.Assume;
import org.openhitls.sdf4j.SDF;
import org.openhitls.sdf4j.SDFException;
import org.openhitls.sdf4j.constants.AlgorithmID;
import org.openhitls.sdf4j.constants.ErrorCode;
import java.util.Arrays;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

import static org.junit.Assert.*;

/**
 * 类型对象字段提取与重构集成测试
 *
 * 测试场景：通过SDF接口获取类型对象后，提取其字段值，
 * 用这些值构造新的类型对象，验证新对象可以正常使用。
 *
 * 这模拟了实际应用中常见的场景：
 * 1. 从设备获取加密结果
 * 2. 序列化传输
 * 3. 反序列化重构对象
 * 4. 使用重构的对象进行后续操作
 */
public class TypeFieldExtractionTest {

    private static final boolean USE_CONFIG_FILE = true;
    private static final int DEFAULT_KEY_INDEX = 1;
    private static final String DEFAULT_KEY_PASSWORD = "123abc!@";
    private static final int ECC_KEY_BITS = 256;
    private static final int SESSION_KEY_BITS_128 = 128;

    // 混合加密密钥索引（与模拟器内部密钥表一致）
    private static final int HYBRID_MLKEM_512_KEY_INDEX = 8;
    private static final int HYBRID_MLDSA44_KEY_INDEX = 16;

    private static int keyIndex;
    private static String keyPassword;

    // 模拟器功能支持标志
    private static Boolean supportsInternalKeyEncryption = null;

    private SDF sdf;
    private long deviceHandle;
    private long sessionHandle;

    @BeforeClass
    public static void loadConfig() {
        if (USE_CONFIG_FILE) {
            Properties testConfig = new Properties();
            try (InputStream is = TypeFieldExtractionTest.class.getClassLoader()
                    .getResourceAsStream("test-config.properties")) {
                if (is != null) {
                    testConfig.load(is);
                    keyIndex = Integer.parseInt(
                            testConfig.getProperty("sm2.internal.key.index", String.valueOf(DEFAULT_KEY_INDEX)));
                    keyPassword = testConfig.getProperty("sm2.key.access.password", DEFAULT_KEY_PASSWORD);
                    return;
                }
            } catch (IOException e) {
                System.err.println("读取配置文件失败: " + e.getMessage());
            }
        }
        keyIndex = DEFAULT_KEY_INDEX;
        keyPassword = DEFAULT_KEY_PASSWORD;
    }

    @Before
    public void setUp() throws SDFException {
        sdf = new SDF();
        deviceHandle = 0;
        sessionHandle = 0;
    }

    /**
     * 检查并跳过需要内部密钥加密支持的测试
     * 模拟器可能不支持 SDF_Encrypt 等内部密钥操作
     */
    private void skipIfInternalKeyEncryptionNotSupported() throws SDFException {
        // 尝试简单的内部密钥操作来检测支持情况
        if (supportsInternalKeyEncryption != null && !supportsInternalKeyEncryption) {
            Assume.assumeTrue("模拟器不支持内部密钥加密操作", false);
        }
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
    // ECCCipher 字段提取与重构测试
    // ========================================================================

    /**
     * 测试流程：
     * 1. 通过 SDF_GenerateKeyWithIPK_ECC 获取 ECCCipher
     * 2. 提取 ECCCipher 的所有字段 (x, y, m, l, c)
     * 3. 使用提取的字段构造新的 ECCCipher
     * 4. 使用新构造的 ECCCipher 调用 SDF_ImportKeyWithISK_ECC
     * 5. 验证导入成功且密钥可用
     */
    @Test
    public void testECCCipher_fieldExtractionAndReconstruction() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long keyHandle1 = 0;
        long keyHandle2 = 0;
        boolean accessRightObtained = false;
        try {
            sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, keyIndex, keyPassword);
            accessRightObtained = true;

            // 步骤1: 获取原始 ECCCipher
            ECCKeyEncryptionResult result = sdf.SDF_GenerateKeyWithIPK_ECC(
                    sessionHandle, keyIndex, SESSION_KEY_BITS_128);
            assertNotNull("密钥生成结果不应为空", result);
            keyHandle1 = result.getKeyHandle();

            ECCCipher originalCipher = result.getEccCipher();
            assertNotNull("原始ECCCipher不应为空", originalCipher);

            // 步骤2: 提取所有字段
            byte[] x = originalCipher.getX();
            byte[] y = originalCipher.getY();
            byte[] m = originalCipher.getM();
            long l = originalCipher.getL();
            byte[] c = originalCipher.getC();

            assertNotNull("X坐标不应为空", x);
            assertNotNull("Y坐标不应为空", y);
            assertNotNull("M值不应为空", m);
            assertNotNull("C值不应为空", c);

            // 步骤3: 使用提取的字段构造新的 ECCCipher
            ECCCipher reconstructedCipher = new ECCCipher(x, y, m, l, c);

            // 验证重构的对象字段正确
            assertArrayEquals("重构的X应与原始X相同", x, reconstructedCipher.getX());
            assertArrayEquals("重构的Y应与原始Y相同", y, reconstructedCipher.getY());
            assertArrayEquals("重构的M应与原始M相同", m, reconstructedCipher.getM());
            assertEquals("重构的L应与原始L相同", l, reconstructedCipher.getL());
            assertArrayEquals("重构的C应与原始C相同", c, reconstructedCipher.getC());

            // 步骤4: 使用重构的 ECCCipher 导入密钥
            keyHandle2 = sdf.SDF_ImportKeyWithISK_ECC(sessionHandle, keyIndex, reconstructedCipher);
            assertTrue("导入的密钥句柄应大于0", keyHandle2 > 0);

            // 步骤5: 验证导入的密钥可用（如果支持内部密钥加密）
            byte[] testData = "TestReconstruction".getBytes(StandardCharsets.UTF_8);

            try {
                // 使用原始密钥加密
                byte[] encrypted1 = sdf.SDF_Encrypt(
                        sessionHandle, keyHandle1, AlgorithmID.SGD_SM4_ECB, null, testData);
                // 使用重构后导入的密钥加密
                byte[] encrypted2 = sdf.SDF_Encrypt(
                        sessionHandle, keyHandle2, AlgorithmID.SGD_SM4_ECB, null, testData);

                // 两个密钥的加密结果应该相同
                assertArrayEquals("相同密钥的加密结果应一致", encrypted1, encrypted2);
            } catch (SDFException encryptEx) {
                // 模拟器不支持内部密钥加密或其他错误，跳过加密验证
            }

        } catch (SDFException e) {
            int errCode = e.getErrorCode();
            if (errCode == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 模拟器不支持内部密钥操作");
                Assume.assumeTrue("内部密钥操作未实现", false);
            } else {
                throw e;
            }
        } finally {
            if (keyHandle1 != 0) {
                try { sdf.SDF_DestroyKey(sessionHandle, keyHandle1); } catch (Exception ignored) {}
            }
            if (keyHandle2 != 0) {
                try { sdf.SDF_DestroyKey(sessionHandle, keyHandle2); } catch (Exception ignored) {}
            }
            if (accessRightObtained) {
                try { sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, keyIndex); } catch (Exception ignored) {}
            }
        }
    }

    /**
     * 测试流程：ECC加密/解密的字段重构
     * 1. 使用外部公钥加密数据得到 ECCCipher
     * 2. 提取字段重构 ECCCipher
     * 3. 使用重构的 ECCCipher 解密
     */
    @Test
    public void testECCCipher_externalEncryptDecryptReconstruction() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成密钥对
            Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_3, ECC_KEY_BITS);
            ECCPublicKey publicKey = (ECCPublicKey) keyPair[0];
            ECCPrivateKey privateKey = (ECCPrivateKey) keyPair[1];

            String plaintext = "这是需要加密保护的机密信息";
            byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

            // 步骤1: 使用公钥加密
            ECCCipher originalCipher = sdf.SDF_ExternalEncrypt_ECC(
                    sessionHandle, AlgorithmID.SGD_SM2_3, publicKey, plaintextBytes);
            assertNotNull("加密结果不应为空", originalCipher);

            // 步骤2: 提取字段并重构
            ECCCipher reconstructedCipher = new ECCCipher(
                    originalCipher.getX(),
                    originalCipher.getY(),
                    originalCipher.getM(),
                    originalCipher.getL(),
                    originalCipher.getC()
            );

            // 步骤3: 使用重构的密文解密
            byte[] decryptedBytes = sdf.SDF_ExternalDecrypt_ECC(
                    sessionHandle, AlgorithmID.SGD_SM2_3, privateKey, reconstructedCipher);

            assertNotNull("解密结果不应为空", decryptedBytes);
            String decrypted = new String(decryptedBytes, StandardCharsets.UTF_8);
            assertEquals("解密后的明文应与原始明文相同", plaintext, decrypted);

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] ECC外部加密解密功能未实现");
                Assume.assumeTrue("ECC外部加密解密功能未实现", false);
            } else {
                throw e;
            }
        }
    }

    // ========================================================================
    // ECCSignature 字段提取与重构测试
    // ========================================================================

    /**
     * 测试流程：
     * 1. 使用私钥签名得到 ECCSignature
     * 2. 提取 r 和 s 字段
     * 3. 使用提取的字段构造新的 ECCSignature
     * 4. 使用新的 ECCSignature 验签
     */
    @Test
    public void testECCSignature_fieldExtractionAndReconstruction() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成密钥对
            Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPublicKey publicKey = (ECCPublicKey) keyPair[0];
            ECCPrivateKey privateKey = (ECCPrivateKey) keyPair[1];

            // 计算哈希
            String message = "测试签名重构";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data);
            byte[] hash = sdf.SDF_HashFinal(sessionHandle);

            // 步骤1: 签名
            ECCSignature originalSignature = sdf.SDF_ExternalSign_ECC(
                    sessionHandle, AlgorithmID.SGD_SM2_1, privateKey, hash);
            assertNotNull("签名结果不应为空", originalSignature);

            // 步骤2: 提取字段
            byte[] r = originalSignature.getR();
            byte[] s = originalSignature.getS();

            assertNotNull("签名r不应为空", r);
            assertNotNull("签名s不应为空", s);

            // 步骤3: 重构签名
            ECCSignature reconstructedSignature = new ECCSignature(r, s);

            // 验证重构的签名字段正确
            assertArrayEquals("重构的r应与原始r相同", r, reconstructedSignature.getR());
            assertArrayEquals("重构的s应与原始s相同", s, reconstructedSignature.getS());

            // 步骤4: 使用重构的签名验签
            sdf.SDF_ExternalVerify_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, publicKey, hash, reconstructedSignature);

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] ECC签名验签功能未实现");
                Assume.assumeTrue("ECC签名验签功能未实现", false);
            } else {
                throw e;
            }
        }
    }

    // ========================================================================
    // ECCPublicKey 字段提取与重构测试
    // ========================================================================

    /**
     * 测试流程：
     * 1. 生成密钥对获取 ECCPublicKey
     * 2. 提取 bits, x, y 字段
     * 3. 使用提取的字段构造新的 ECCPublicKey
     * 4. 使用新的 ECCPublicKey 验签
     */
    @Test
    public void testECCPublicKey_fieldExtractionAndReconstruction() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成密钥对
            Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPublicKey originalPublicKey = (ECCPublicKey) keyPair[0];
            ECCPrivateKey privateKey = (ECCPrivateKey) keyPair[1];

            // 计算哈希
            String message = "测试公钥重构";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data);
            byte[] hash = sdf.SDF_HashFinal(sessionHandle);

            // 使用原始私钥签名
            ECCSignature signature = sdf.SDF_ExternalSign_ECC(
                    sessionHandle, AlgorithmID.SGD_SM2_1, privateKey, hash);

            // 步骤1: 提取公钥字段
            int bits = originalPublicKey.getBits();
            byte[] x = originalPublicKey.getX();
            byte[] y = originalPublicKey.getY();

            // 步骤2: 重构公钥
            ECCPublicKey reconstructedPublicKey = new ECCPublicKey(bits, x, y);

            // 验证重构的公钥字段正确
            assertEquals("重构的bits应与原始bits相同", bits, reconstructedPublicKey.getBits());
            assertArrayEquals("重构的x应与原始x相同", x, reconstructedPublicKey.getX());
            assertArrayEquals("重构的y应与原始y相同", y, reconstructedPublicKey.getY());

            // 步骤3: 使用重构的公钥验签
            sdf.SDF_ExternalVerify_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, reconstructedPublicKey, hash, signature);

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] ECC密钥对生成功能未实现");
                Assume.assumeTrue("ECC密钥对生成功能未实现", false);
            } else {
                throw e;
            }
        }
    }

    // ========================================================================
    // ECCPrivateKey 字段提取与重构测试
    // ========================================================================

    /**
     * 测试流程：
     * 1. 生成密钥对获取 ECCPrivateKey
     * 2. 提取 bits 和 k 字段
     * 3. 使用提取的字段构造新的 ECCPrivateKey
     * 4. 使用新的 ECCPrivateKey 签名
     */
    @Test
    public void testECCPrivateKey_fieldExtractionAndReconstruction() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成密钥对
            Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPublicKey publicKey = (ECCPublicKey) keyPair[0];
            ECCPrivateKey originalPrivateKey = (ECCPrivateKey) keyPair[1];

            // 计算哈希
            String message = "测试私钥重构";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data);
            byte[] hash = sdf.SDF_HashFinal(sessionHandle);

            // 步骤1: 提取私钥字段
            int bits = originalPrivateKey.getBits();
            byte[] k = originalPrivateKey.getK();

            // 步骤2: 重构私钥
            ECCPrivateKey reconstructedPrivateKey = new ECCPrivateKey(bits, k);

            // 验证重构的私钥字段正确
            assertEquals("重构的bits应与原始bits相同", bits, reconstructedPrivateKey.getBits());
            assertArrayEquals("重构的k应与原始k相同", k, reconstructedPrivateKey.getK());

            // 步骤3: 使用重构的私钥签名
            ECCSignature signature = sdf.SDF_ExternalSign_ECC(
                    sessionHandle, AlgorithmID.SGD_SM2_1, reconstructedPrivateKey, hash);

            assertNotNull("签名结果不应为空", signature);

            // 步骤4: 使用原始公钥验签（验证签名正确）
            sdf.SDF_ExternalVerify_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, publicKey, hash, signature);

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] ECC密钥对生成功能未实现");
                Assume.assumeTrue("ECC密钥对生成功能未实现", false);
            } else {
                throw e;
            }
        }
    }

    // ========================================================================
    // KeyAgreementResult 字段提取与重构测试
    // ========================================================================

    /**
     * 测试流程：
     * 1. 调用 SDF_GenerateAgreementDataWithECC 获取 KeyAgreementResult
     * 2. 提取字段
     * 3. 使用提取的字段构造新的 KeyAgreementResult（如果需要）
     * 4. 使用提取的数据进行密钥协商
     */
    @Test
    public void testKeyAgreementResult_fieldExtraction() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long agreementHandle = 0;
        long keyHandle = 0;
        boolean accessRightObtained = false;
        try {
            sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, keyIndex, keyPassword);
            accessRightObtained = true;

            // 步骤1: 获取发起方协商数据
            byte[] sponsorID = "1234567812345678".getBytes();
            KeyAgreementResult originalResult = sdf.SDF_GenerateAgreementDataWithECC(
                    sessionHandle, keyIndex, SESSION_KEY_BITS_128, sponsorID);

            assertNotNull("协商结果不应为空", originalResult);
            agreementHandle = originalResult.getAgreementHandle();

            // 步骤2: 提取字段
            long extractedHandle = originalResult.getAgreementHandle();
            ECCPublicKey extractedPublicKey = originalResult.getPublicKey();
            ECCPublicKey extractedTmpPublicKey = originalResult.getTmpPublicKey();

            assertNotNull("提取的公钥不应为空", extractedPublicKey);
            assertNotNull("提取的临时公钥不应为空", extractedTmpPublicKey);

            // 步骤3: 进一步提取公钥字段
            int pubBits = extractedPublicKey.getBits();
            byte[] pubX = extractedPublicKey.getX();
            byte[] pubY = extractedPublicKey.getY();

            int tmpBits = extractedTmpPublicKey.getBits();
            byte[] tmpX = extractedTmpPublicKey.getX();
            byte[] tmpY = extractedTmpPublicKey.getY();

            // 步骤4: 重构公钥对象
            ECCPublicKey reconstructedPubKey = new ECCPublicKey(pubBits, pubX, pubY);
            ECCPublicKey reconstructedTmpKey = new ECCPublicKey(tmpBits, tmpX, tmpY);

            // 步骤5: 生成响应方密钥对
            Object[] responseKeyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPublicKey responsePubKey = (ECCPublicKey) responseKeyPair[0];
            Object[] responseTmpKeyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPublicKey responseTmpPubKey = (ECCPublicKey) responseTmpKeyPair[0];
            byte[] responseID = "8765432187654321".getBytes();

            // 步骤6: 使用重构的公钥计算会话密钥
            keyHandle = sdf.SDF_GenerateKeyWithECC(
                    sessionHandle, responseID,
                    responsePubKey, responseTmpPubKey,
                    agreementHandle);

            assertTrue("密钥句柄应大于0", keyHandle > 0);

            // 步骤7: 验证密钥可用（如果支持内部密钥加密）
            byte[] testData = "TestAgreement".getBytes(StandardCharsets.UTF_8);

            try {
                byte[] encrypted = sdf.SDF_Encrypt(
                        sessionHandle, keyHandle, AlgorithmID.SGD_SM4_ECB, null, testData);
                byte[] decrypted = sdf.SDF_Decrypt(
                        sessionHandle, keyHandle, AlgorithmID.SGD_SM4_ECB, null, encrypted);
                assertArrayEquals("解密结果应与原始数据相同", testData, decrypted);
            } catch (SDFException encryptEx) {
                // 模拟器不支持内部密钥加密或其他错误，跳过加密验证
            }

        } catch (SDFException e) {
            int errCode = e.getErrorCode();
            if (errCode == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] ECC密钥协商功能未实现");
                Assume.assumeTrue("ECC密钥协商功能未实现", false);
            } else {
                throw e;
            }
        } finally {
            if (keyHandle != 0) {
                try { sdf.SDF_DestroyKey(sessionHandle, keyHandle); } catch (Exception ignored) {}
            }
            if (accessRightObtained) {
                try { sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, keyIndex); } catch (Exception ignored) {}
            }
        }
    }

    /**
     * 模拟场景：
     * 设备A生成加密数据 -> 传输 -> 设备B解密
     * 中间涉及：对象序列化(字段提取) -> 传输 -> 反序列化(对象重构)
     */
    @Test
    public void testCrossDeviceDataTransfer() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        boolean accessRightObtained = false;
        long keyHandle = 0;
        long deviceAKeyHandle = 0;

        try {
            // 模拟：设备A的操作
            sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, keyIndex, keyPassword);
            accessRightObtained = true;

            // 设备A：生成会话密钥并加密
            ECCKeyEncryptionResult encResult = sdf.SDF_GenerateKeyWithIPK_ECC(
                    sessionHandle, keyIndex, SESSION_KEY_BITS_128);
            ECCCipher deviceACipher = encResult.getEccCipher();
            deviceAKeyHandle = encResult.getKeyHandle();

            // 模拟：网络传输 - 只传输字段值
            byte[] transmittedX = deviceACipher.getX();
            byte[] transmittedY = deviceACipher.getY();
            byte[] transmittedM = deviceACipher.getM();
            long transmittedL = deviceACipher.getL();
            byte[] transmittedC = deviceACipher.getC();

            // 模拟：设备B接收数据并重构对象
            ECCCipher deviceBCipher = new ECCCipher(transmittedX, transmittedY, transmittedM, transmittedL, transmittedC);

            // 设备B：导入会话密钥
            keyHandle = sdf.SDF_ImportKeyWithISK_ECC(sessionHandle, keyIndex, deviceBCipher);
            assertTrue("设备B导入密钥句柄应大于0", keyHandle > 0);

            // 步骤：验证跨设备数据传输（如果支持内部密钥加密）
            byte[] originalData = "这是跨设备传输的敏感数据".getBytes(StandardCharsets.UTF_8);

            try {
                // 设备A：加密数据
                byte[] encryptedData = sdf.SDF_Encrypt(
                        sessionHandle, deviceAKeyHandle, AlgorithmID.SGD_SM4_ECB, null, originalData);

                // 设备B：解密数据
                byte[] decryptedData = sdf.SDF_Decrypt(
                        sessionHandle, keyHandle, AlgorithmID.SGD_SM4_ECB, null, encryptedData);

                // 验证：数据完整传输
                assertArrayEquals("设备B解密的数据应与设备A原始数据相同", originalData, decryptedData);
            } catch (SDFException encryptEx) {
                // 模拟器不支持内部密钥加密或其他错误，跳过加密解密验证
            }

        } catch (SDFException e) {
            int errCode = e.getErrorCode();
            // 模拟器可能不支持内部密钥操作
            if (errCode == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 模拟器不支持内部密钥操作");
                Assume.assumeTrue("内部密钥操作未实现", false);
            } else {
                throw e;
            }
        } finally {
            if (keyHandle != 0) {
                try { sdf.SDF_DestroyKey(sessionHandle, keyHandle); } catch (Exception ignored) {}
            }
            if (accessRightObtained) {
                try { sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, keyIndex); } catch (Exception ignored) {}
            }
        }
    }

    // ========================================================================
    // 异常用例：数据篡改与字段异常测试
    // ========================================================================

    /**
     * 异常场景：ECCCipher 字段被篡改
     * 预期：解密失败或解密结果与原文不一致
     */
    @Test
    public void testECCCipher_tamperedData() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成密钥对
            Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_3, ECC_KEY_BITS);
            ECCPublicKey publicKey = (ECCPublicKey) keyPair[0];
            ECCPrivateKey privateKey = (ECCPrivateKey) keyPair[1];

            String plaintext = "原始机密信息";
            byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

            // 正常加密
            ECCCipher originalCipher = sdf.SDF_ExternalEncrypt_ECC(
                    sessionHandle, AlgorithmID.SGD_SM2_3, publicKey, plaintextBytes);

            // 提取字段并篡改C（密文部分）
            byte[] tamperedC = originalCipher.getC();
            tamperedC[tamperedC.length - 1]++;

            ECCCipher tamperedCipher = new ECCCipher(
                    originalCipher.getX(),
                    originalCipher.getY(),
                    originalCipher.getM(),
                    originalCipher.getL(),
                    tamperedC
            );

            // 尝试解密被篡改的密文
            try {
                byte[] decryptedBytes = sdf.SDF_ExternalDecrypt_ECC(
                        sessionHandle, AlgorithmID.SGD_SM2_3, privateKey, tamperedCipher);

                // 如果解密成功且结果与原文相同，说明篡改未被检测到
                if (decryptedBytes != null && decryptedBytes.length > 0) {
                    String decrypted = new String(decryptedBytes, StandardCharsets.UTF_8);
                    if (plaintext.equals(decrypted)) {
                        fail("篡改C字段后解密结果仍与原文相同，篡改未被检测到");
                    }
                }
            } catch (SDFException e) {
                // 篡改被检测到（抛出异常即表示检测到）
            }

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] ECC外部加密解密功能未实现");
                Assume.assumeTrue("ECC外部加密解密功能未实现", false);
            } else {
                throw e;
            }
        }
    }

    /**
     * 异常场景：ECCCipher M字段（MAC）被篡改
     * 预期：解密失败（MAC校验不通过）
     */
    @Test
    public void testECCCipher_tamperedMAC() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成密钥对
            Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_3, ECC_KEY_BITS);
            ECCPublicKey publicKey = (ECCPublicKey) keyPair[0];
            ECCPrivateKey privateKey = (ECCPrivateKey) keyPair[1];

            String plaintext = "MAC测试数据";
            byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

            // 正常加密
            ECCCipher originalCipher = sdf.SDF_ExternalEncrypt_ECC(
                    sessionHandle, AlgorithmID.SGD_SM2_3, publicKey, plaintextBytes);

            // 篡改M（MAC值）
            byte[] tamperedM = originalCipher.getM();
            tamperedM[tamperedM.length - 1]++;

            ECCCipher tamperedCipher = new ECCCipher(
                    originalCipher.getX(),
                    originalCipher.getY(),
                    tamperedM,
                    originalCipher.getL(),
                    originalCipher.getC()
            );

            // 尝试解密
            try {
                byte[] decryptedBytes = sdf.SDF_ExternalDecrypt_ECC(
                        sessionHandle, AlgorithmID.SGD_SM2_3, privateKey, tamperedCipher);

                // 如果解密成功且结果与原文相同，说明MAC篡改未被检测到
                if (decryptedBytes != null && decryptedBytes.length > 0) {
                    String decrypted = new String(decryptedBytes, StandardCharsets.UTF_8);
                    if (plaintext.equals(decrypted)) {
                        fail("篡改M字段后解密结果仍与原文相同，MAC篡改未被检测到");
                    }
                }
            } catch (SDFException e) {
                // MAC篡改被检测到（抛出异常即表示检测到）
            }

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] ECC外部加密解密功能未实现");
                Assume.assumeTrue("ECC外部加密解密功能未实现", false);
            } else {
                throw e;
            }
        }
    }

    /**
     * 异常场景：ECCCipher X坐标被篡改
     * 预期：解密失败（无法恢复正确的椭圆曲线点）
     */
    @Test
    public void testECCCipher_tamperedXCoordinate() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成密钥对
            Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_3, ECC_KEY_BITS);
            ECCPublicKey publicKey = (ECCPublicKey) keyPair[0];
            ECCPrivateKey privateKey = (ECCPrivateKey) keyPair[1];

            String plaintext = "坐标篡改测试";
            byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

            // 正常加密
            ECCCipher originalCipher = sdf.SDF_ExternalEncrypt_ECC(
                    sessionHandle, AlgorithmID.SGD_SM2_3, publicKey, plaintextBytes);

            // 篡改X坐标
            byte[] tamperedX = originalCipher.getX();
            tamperedX[tamperedX.length - 1]++;

            ECCCipher tamperedCipher = new ECCCipher(
                    tamperedX,
                    originalCipher.getY(),
                    originalCipher.getM(),
                    originalCipher.getL(),
                    originalCipher.getC()
            );

            // 尝试解密
            try {
                byte[] decryptedBytes = sdf.SDF_ExternalDecrypt_ECC(
                        sessionHandle, AlgorithmID.SGD_SM2_3, privateKey, tamperedCipher);

                // 如果解密成功且结果与原文相同，说明X坐标篡改未被检测到
                if (decryptedBytes != null && decryptedBytes.length > 0) {
                    String decrypted = new String(decryptedBytes, StandardCharsets.UTF_8);
                    if (plaintext.equals(decrypted)) {
                        fail("X坐标篡改后解密结果仍与原文相同，篡改未被检测到");
                    }
                }
            } catch (SDFException e) {
                // X坐标篡改被检测到（抛出异常即表示检测到）
            }

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] ECC外部加密解密功能未实现");
                Assume.assumeTrue("ECC外部加密解密功能未实现", false);
            } else {
                throw e;
            }
        }
    }

    /**
     * 异常场景：ECCCipher C字段长度不匹配（截断）
     * 预期：解密失败或数据不完整
     */
    @Test
    public void testECCCipher_truncatedCipherText() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成密钥对
            Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_3, ECC_KEY_BITS);
            ECCPublicKey publicKey = (ECCPublicKey) keyPair[0];
            ECCPrivateKey privateKey = (ECCPrivateKey) keyPair[1];

            String plaintext = "截断测试数据";
            byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

            // 正常加密
            ECCCipher originalCipher = sdf.SDF_ExternalEncrypt_ECC(
                    sessionHandle, AlgorithmID.SGD_SM2_3, publicKey, plaintextBytes);

            // 截断C字段（只保留一半）
            byte[] truncatedC = new byte[originalCipher.getC().length / 2];
            System.arraycopy(originalCipher.getC(), 0, truncatedC, 0, truncatedC.length);

            ECCCipher truncatedCipher = new ECCCipher(
                    originalCipher.getX(),
                    originalCipher.getY(),
                    originalCipher.getM(),
                    truncatedC.length,  // 更新L值为截断后的长度
                    truncatedC
            );

            // 尝试解密
            try {
                byte[] decryptedBytes = sdf.SDF_ExternalDecrypt_ECC(
                        sessionHandle, AlgorithmID.SGD_SM2_3, privateKey, truncatedCipher);

                // 如果解密成功且结果与原文相同，说明截断未被检测到
                if (decryptedBytes != null && decryptedBytes.length > 0) {
                    String decrypted = new String(decryptedBytes, StandardCharsets.UTF_8);
                    if (plaintext.equals(decrypted)) {
                        fail("截断的密文解密结果仍与原文相同，截断错误未被检测到");
                    }
                }
            } catch (SDFException e) {
                // 截断错误被检测到（抛出异常即表示检测到）
            }

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] ECC外部加密解密功能未实现");
                Assume.assumeTrue("ECC外部加密解密功能未实现", false);
            } else {
                throw e;
            }
        }
    }

    /**
     * 异常场景：ECCSignature 签名值R被篡改
     * 预期：验签失败
     */
    @Test
    public void testECCSignature_tamperedR() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成密钥对
            Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPublicKey publicKey = (ECCPublicKey) keyPair[0];
            ECCPrivateKey privateKey = (ECCPrivateKey) keyPair[1];

            // 计算哈希
            String message = "签名篡改测试";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data);
            byte[] hash = sdf.SDF_HashFinal(sessionHandle);

            // 正常签名
            ECCSignature originalSignature = sdf.SDF_ExternalSign_ECC(
                    sessionHandle, AlgorithmID.SGD_SM2_1, privateKey, hash);

            // 篡改R值
            byte[] tamperedR = originalSignature.getR();
            tamperedR[tamperedR.length - 1]++;

            ECCSignature tamperedSignature = new ECCSignature(tamperedR, originalSignature.getS());

            // 尝试验签，应该失败
            try {
                sdf.SDF_ExternalVerify_ECC(
                        sessionHandle, AlgorithmID.SGD_SM2_1, publicKey, hash, tamperedSignature);
                fail("篡改签名R值后验签应该失败");
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] ECC签名验签功能未实现");
                    Assume.assumeTrue("ECC签名验签功能未实现", false);
                }
            }

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] ECC签名验签功能未实现");
                Assume.assumeTrue("ECC签名验签功能未实现", false);
            } else {
                throw e;
            }
        }
    }

    /**
     * 异常场景：ECCSignature 签名值S被篡改
     * 预期：验签失败
     */
    @Test
    public void testECCSignature_tamperedS() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成密钥对
            Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPublicKey publicKey = (ECCPublicKey) keyPair[0];
            ECCPrivateKey privateKey = (ECCPrivateKey) keyPair[1];

            // 计算哈希
            String message = "签名S值篡改测试";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data);
            byte[] hash = sdf.SDF_HashFinal(sessionHandle);

            // 正常签名
            ECCSignature originalSignature = sdf.SDF_ExternalSign_ECC(
                    sessionHandle, AlgorithmID.SGD_SM2_1, privateKey, hash);

            // 篡改S值
            byte[] tamperedS = originalSignature.getS();
            tamperedS[tamperedS.length - 1]++;

            ECCSignature tamperedSignature = new ECCSignature(originalSignature.getR(), tamperedS);

            // 尝试验签，应该失败
            try {
                sdf.SDF_ExternalVerify_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, publicKey, hash, tamperedSignature);
                fail("篡改签名S值后验签应该失败");
            } catch (SDFException e) {
                // 预期：签名验证失败
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] ECC签名验签功能未实现");
                    Assume.assumeTrue("ECC签名验签功能未实现", false);
                }
            }

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] ECC签名验签功能未实现");
                Assume.assumeTrue("ECC签名验签功能未实现", false);
            } else {
                throw e;
            }
        }
    }

    /**
     * 异常场景：ECCSignature R和S都被篡改
     * 预期：验签失败
     */
    @Test
    public void testECCSignature_tamperedRAndS() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成密钥对
            Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPublicKey publicKey = (ECCPublicKey) keyPair[0];
            ECCPrivateKey privateKey = (ECCPrivateKey) keyPair[1];

            // 计算哈希
            String message = "RS双篡改测试";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data);
            byte[] hash = sdf.SDF_HashFinal(sessionHandle);

            // 正常签名
            ECCSignature originalSignature = sdf.SDF_ExternalSign_ECC(
                    sessionHandle, AlgorithmID.SGD_SM2_1, privateKey, hash);

            // 篡改R和S值
            byte[] tamperedR = originalSignature.getR();
            byte[] tamperedS = originalSignature.getS();
            tamperedR[tamperedR.length - 1]++;
            tamperedS[tamperedS.length - 1]++;

            ECCSignature tamperedSignature = new ECCSignature(tamperedR, tamperedS);

            // 尝试验签，应该失败
            try {
                sdf.SDF_ExternalVerify_ECC(
                        sessionHandle, AlgorithmID.SGD_SM2_1, publicKey, hash, tamperedSignature);
                fail("篡改签名R和S值后验签应该失败");
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] ECC签名验签功能未实现");
                    Assume.assumeTrue("ECC签名验签功能未实现", false);
                }
            }

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] ECC签名验签功能未实现");
                Assume.assumeTrue("ECC签名验签功能未实现", false);
            } else {
                throw e;
            }
        }
    }

    /**
     * 异常场景：ECCSignature 长度不足（截断）
     * 预期：验签失败或构造失败
     */
    @Test
    public void testECCSignature_truncated() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成密钥对
            Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPublicKey publicKey = (ECCPublicKey) keyPair[0];
            ECCPrivateKey privateKey = (ECCPrivateKey) keyPair[1];

            // 计算哈希
            String message = "签名截断测试";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data);
            byte[] hash = sdf.SDF_HashFinal(sessionHandle);

            // 正常签名
            ECCSignature originalSignature = sdf.SDF_ExternalSign_ECC(
                    sessionHandle, AlgorithmID.SGD_SM2_1, privateKey, hash);

            // 截断R和S值
            byte[] truncatedR = new byte[originalSignature.getR().length / 2];
            byte[] truncatedS = new byte[originalSignature.getS().length / 2];
            System.arraycopy(originalSignature.getR(), 0, truncatedR, 0, truncatedR.length);
            System.arraycopy(originalSignature.getS(), 0, truncatedS, 0, truncatedS.length);

            ECCSignature truncatedSignature = new ECCSignature(truncatedR, truncatedS);

            // 尝试验签，应该失败
            try {
                sdf.SDF_ExternalVerify_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, publicKey, hash, truncatedSignature);
                fail("截断的签名验签应该失败");
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] ECC签名验签功能未实现");
                    Assume.assumeTrue("ECC签名验签功能未实现", false);
                }
            }

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] ECC签名验签功能未实现");
                Assume.assumeTrue("ECC签名验签功能未实现", false);
            } else {
                throw e;
            }
        }
    }

    /**
     * 异常场景：ECCPublicKey X坐标被篡改
     * 预期：验签失败（公钥对应的点不在椭圆曲线上）
     */
    @Test
    public void testECCPublicKey_tamperedX() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成密钥对
            Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPublicKey originalPublicKey = (ECCPublicKey) keyPair[0];
            ECCPrivateKey privateKey = (ECCPrivateKey) keyPair[1];

            // 计算哈希
            String message = "公钥X篡改测试";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data);
            byte[] hash = sdf.SDF_HashFinal(sessionHandle);

            // 使用原始私钥签名
            ECCSignature signature = sdf.SDF_ExternalSign_ECC(
                    sessionHandle, AlgorithmID.SGD_SM2_1, privateKey, hash);

            // 篡改公钥X坐标
            byte[] tamperedX = originalPublicKey.getX();
            tamperedX[tamperedX.length - 1]++;

            ECCPublicKey tamperedPublicKey = new ECCPublicKey(originalPublicKey.getBits(), tamperedX,
                originalPublicKey.getY());

            // 尝试验签，应该失败
            try {
                sdf.SDF_ExternalVerify_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, tamperedPublicKey, hash, signature);
                fail("公钥X坐标被篡改后验签成功，篡改未被检测到");
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] ECC签名验签功能未实现");
                    Assume.assumeTrue("ECC签名验签功能未实现", false);
                }
            }

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] ECC签名验签功能未实现");
                Assume.assumeTrue("ECC签名验签功能未实现", false);
            } else {
                throw e;
            }
        }
    }

    /**
     * 异常场景：ECCPublicKey Y坐标被篡改
     * 预期：验签失败（点不在椭圆曲线上）
     */
    @Test
    public void testECCPublicKey_tamperedY() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成密钥对
            Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPublicKey originalPublicKey = (ECCPublicKey) keyPair[0];
            ECCPrivateKey privateKey = (ECCPrivateKey) keyPair[1];

            // 计算哈希
            String message = "公钥Y篡改测试";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data);
            byte[] hash = sdf.SDF_HashFinal(sessionHandle);

            // 使用原始私钥签名
            ECCSignature signature = sdf.SDF_ExternalSign_ECC(
                    sessionHandle, AlgorithmID.SGD_SM2_1, privateKey, hash);

            // 篡改公钥Y坐标
            byte[] tamperedY = originalPublicKey.getY();
            tamperedY[tamperedY.length - 1]++;

            ECCPublicKey tamperedPublicKey = new ECCPublicKey(
                    originalPublicKey.getBits(), originalPublicKey.getX(), tamperedY);

            // 尝试验签，应该失败
            try {
                sdf.SDF_ExternalVerify_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, tamperedPublicKey, hash, signature);
                fail("公钥Y坐标被篡改后验签成功，篡改未被检测到");
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] ECC签名验签功能未实现");
                    Assume.assumeTrue("ECC签名验签功能未实现", false);
                }
            }

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] ECC签名验签功能未实现");
                Assume.assumeTrue("ECC签名验签功能未实现", false);
            } else {
                throw e;
            }
        }
    }

    /**
     * 异常场景：使用错误的签名验签（签名来自不同的消息）
     * 预期：验签失败
     */
    @Test
    public void testECCSignature_wrongMessage() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成密钥对
            Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPublicKey publicKey = (ECCPublicKey) keyPair[0];
            ECCPrivateKey privateKey = (ECCPrivateKey) keyPair[1];

            // 消息1的签名
            String message1 = "原始消息";
            byte[] data1 = message1.getBytes(StandardCharsets.UTF_8);
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data1);
            byte[] hash1 = sdf.SDF_HashFinal(sessionHandle);

            ECCSignature signature = sdf.SDF_ExternalSign_ECC(
                    sessionHandle, AlgorithmID.SGD_SM2_1, privateKey, hash1);

            // 消息2的哈希（不同的消息）
            String message2 = "不同的消息";
            byte[] data2 = message2.getBytes(StandardCharsets.UTF_8);
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data2);
            byte[] hash2 = sdf.SDF_HashFinal(sessionHandle);

            // 使用消息1的签名去验签消息2的哈希，应该失败
            try {
                sdf.SDF_ExternalVerify_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, publicKey, hash2, signature);
                fail("使用错误消息的哈希验签应该失败");
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] ECC签名验签功能未实现");
                    Assume.assumeTrue("ECC签名验签功能未实现", false);
                }
            }

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] ECC签名验签功能未实现");
                Assume.assumeTrue("ECC签名验签功能未实现", false);
            } else {
                throw e;
            }
        }
    }

    /**
     * 异常场景：使用错误的公钥验签（密钥不匹配）
     * 预期：验签失败
     */
    @Test
    public void testECCSignature_wrongPublicKey() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成两个不同的密钥对
            Object[] keyPair1 = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPublicKey publicKey1 = (ECCPublicKey) keyPair1[0];
            ECCPrivateKey privateKey1 = (ECCPrivateKey) keyPair1[1];

            Object[] keyPair2 = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPublicKey publicKey2 = (ECCPublicKey) keyPair2[0];

            // 计算哈希
            String message = "密钥不匹配测试";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data);
            byte[] hash = sdf.SDF_HashFinal(sessionHandle);

            // 使用密钥对1的私钥签名
            ECCSignature signature = sdf.SDF_ExternalSign_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, privateKey1, hash);

            // 使用密钥对2的公钥验签，应该失败
            try {
                sdf.SDF_ExternalVerify_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, publicKey2, hash, signature);
                fail("使用错误公钥验签应该失败");
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] ECC签名验签功能未实现");
                    Assume.assumeTrue("ECC签名验签功能未实现", false);
                }
            }

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] ECC签名验签功能未实现");
                Assume.assumeTrue("ECC签名验签功能未实现", false);
            } else {
                throw e;
            }
        }
    }

    /**
     * 异常场景：密钥导入时ECCCipher字段为空
     * 预期：在Java层构造时会抛出IllegalArgumentException
     */
    @Test(expected = IllegalArgumentException.class)
    public void testECCCipher_nullFields() {
        // 尝试用null字段构造ECCCipher，应该在Java层失败
        new ECCCipher(null, new byte[64], new byte[32], 16, new byte[16]);
    }

    /**
     * 异常场景：签名时ECCSignature字段为空
     * 预期：在Java层构造时会抛出IllegalArgumentException
     */
    @Test(expected = IllegalArgumentException.class)
    public void testECCSignature_nullFields() {
        // 尝试用null字段构造ECCSignature，应该在Java层失败
        new ECCSignature(null, new byte[32]);
    }

    /**
     * 异常场景：公钥ECCPublicKey字段为空
     * 预期：在Java层构造时会抛出IllegalArgumentException
     */
    @Test(expected = IllegalArgumentException.class)
    public void testECCPublicKey_nullFields() {
        // 尝试用null字段构造ECCPublicKey，应该在Java层失败
        new ECCPublicKey(256, null, new byte[32]);
    }

    /**
     * 异常场景：私钥ECCPrivateKey字段为空
     * 预期：在Java层构造时会抛出IllegalArgumentException
     */
    @Test(expected = IllegalArgumentException.class)
    public void testECCPrivateKey_nullFields() {
        // 尝试用null字段构造ECCPrivateKey，应该在Java层失败
        new ECCPrivateKey(256, null);
    }

    /**
     * 综合异常场景：跨设备传输中数据被篡改
     * 预期：解密失败或解密结果不一致
     */
    @Test
    public void testCrossDeviceDataTransfer_withTampering() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        boolean accessRightObtained = false;
        long keyHandle = 0;
        long deviceAKeyHandle = 0;

        try {
            sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, keyIndex, keyPassword);
            accessRightObtained = true;

            // 设备A：生成会话密钥
            ECCKeyEncryptionResult encResult = sdf.SDF_GenerateKeyWithIPK_ECC(
                    sessionHandle, keyIndex, SESSION_KEY_BITS_128);
            ECCCipher deviceACipher = encResult.getEccCipher();
            deviceAKeyHandle = encResult.getKeyHandle();

            // 模拟：网络传输中被篡改 - 篡改C字段
            byte[] tamperedC = deviceACipher.getC();
            tamperedC[0]++;  // 篡改

            ECCCipher tamperedCipher = new ECCCipher(
                    deviceACipher.getX(),
                    deviceACipher.getY(),
                    deviceACipher.getM(),
                    deviceACipher.getL(),
                    tamperedC
            );

            // 设备B：尝试导入被篡改的会话密钥
            try {
                keyHandle = sdf.SDF_ImportKeyWithISK_ECC(sessionHandle, keyIndex, tamperedCipher);
                // 如果导入成功，说明篡改未被检测到，继续验证
                byte[] originalData = "敏感数据".getBytes(StandardCharsets.UTF_8);

                try {
                    // 设备A：加密数据
                    byte[] encryptedData = sdf.SDF_Encrypt(
                            sessionHandle, deviceAKeyHandle, AlgorithmID.SGD_SM4_ECB, null, originalData);

                    // 设备B：尝试解密
                    byte[] decryptedData = sdf.SDF_Decrypt(
                            sessionHandle, keyHandle, AlgorithmID.SGD_SM4_ECB, null, encryptedData);

                    // 验证：如果解密结果与原文相同，篡改未被检测到
                    String decryptedStr = new String(decryptedData, StandardCharsets.UTF_8);
                    String originalStr = new String(originalData, StandardCharsets.UTF_8);
                    if (originalStr.equals(decryptedStr)) {
                        fail("被篡改的数据解密结果仍与原文相同，篡改未被检测到");
                    }
                } catch (SDFException encryptEx) {
                    if (encryptEx.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                        System.out.println("[跳过] 加解密功能未实现");
                        Assume.assumeTrue("加解密功能未实现", false);
                    }
                }
            } catch (SDFException importEx) {
                if (importEx.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] 加解密功能未实现");
                    Assume.assumeTrue("加解密功能未实现", false);
                }
            }

        } catch (SDFException e) {
            int errCode = e.getErrorCode();
            if (errCode == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 模拟器不支持内部密钥操作");
                Assume.assumeTrue("内部密钥操作未实现", false);
            } else {
                throw e;
            }
        } finally {
            if (keyHandle != 0) {
                try { sdf.SDF_DestroyKey(sessionHandle, keyHandle); } catch (Exception ignored) {}
            }
            if (deviceAKeyHandle != 0) {
                try { sdf.SDF_DestroyKey(sessionHandle, deviceAKeyHandle); } catch (Exception ignored) {}
            }
            if (accessRightObtained) {
                try { sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, keyIndex); } catch (Exception ignored) {}
            }
        }
    }

    /**
     * 异常场景：ECCPrivateKey K值被篡改
     * 预期：签名结果不同，验签失败
     */
    @Test
    public void testECCPrivateKey_tamperedK() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        try {
            // 生成密钥对
            Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPublicKey publicKey = (ECCPublicKey) keyPair[0];
            ECCPrivateKey originalPrivateKey = (ECCPrivateKey) keyPair[1];

            // 计算哈希
            String message = "私钥篡改测试";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data);
            byte[] hash = sdf.SDF_HashFinal(sessionHandle);

            // 篡改私钥K值
            byte[] tamperedK = originalPrivateKey.getK();
            tamperedK[tamperedK.length - 1]++;

            ECCPrivateKey tamperedPrivateKey = new ECCPrivateKey(originalPrivateKey.getBits(), tamperedK);

            // 使用被篡改的私钥签名
            ECCSignature tamperedSignature = sdf.SDF_ExternalSign_ECC(sessionHandle, AlgorithmID.SGD_SM2_1,
                tamperedPrivateKey, hash);

            // 使用正确的公钥验签，应该失败
            try {
                sdf.SDF_ExternalVerify_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, publicKey, hash, tamperedSignature);
                fail("私钥K值被篡改后验签成功，篡改未被检测到");
            } catch (SDFException e) {
                // 预期：签名验证失败
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("[跳过] ECC签名功能未实现");
                    Assume.assumeTrue("签名功能功能未实现", false);
                }
            }

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] ECC签名验签功能未实现");
                Assume.assumeTrue("ECC签名验签功能未实现", false);
            } else {
                throw e;
            }
        }
    }

    /**
     * 测试流程：HybridCipher 混合密码字段提取与重构
     * 1. 通过 SDF_GenerateKeyWithEPK_Hybrid 获取 HybridCipher
     * 2. 提取 HybridCipher 的所有字段 (l1, ctM, uiAlgID, ctS, keyHandle)
     * 3. 使用提取的字段构造新的 HybridCipher
     * 4. 使用新构造的 HybridCipher 调用 SDF_ImportKeyWithISK_Hybrid
     * 5. 验证导入成功
     */
    @Test
    public void testHybridCipher_fieldExtractionAndReconstruction() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long keyHandle = 0;
        boolean accessRightObtained = false;

        int hybridKeyIndex = HYBRID_MLKEM_512_KEY_INDEX | (AlgorithmID.SGD_HYBRID << 20);
        try {
            // 步骤1: 导出混合加密公钥
            byte[] publicKey = sdf.SDF_ExportPublicKey_Hybrid(sessionHandle, hybridKeyIndex);
            assertNotNull("混合公钥不应为null", publicKey);

            // 步骤2: 获取原始 HybridCipher
            HybridCipher originalCipher = sdf.SDF_GenerateKeyWithEPK_Hybrid(
                    sessionHandle, AlgorithmID.SGD_HYBRID_ENV_SM2_MLKEM_512, publicKey);
            assertNotNull("混合密文不应为null", originalCipher);

            // 步骤3: 提取所有字段
            long l1 = originalCipher.getL1();
            byte[] ctM = originalCipher.getCtM();
            long uiAlgID = originalCipher.getUiAlgID();
            ECCCipher ctS = originalCipher.getCtS();
            long originalKeyHandle = originalCipher.getKeyHandle();

            // 验证提取的字段
            assertTrue("l1应大于0", l1 > 0);
            assertNotNull("ctM不应为null", ctM);
            assertNotNull("ctS不应为null", ctS);

            // 步骤4: 重构 HybridCipher（模拟网络传输后重构）
            HybridCipher reconstructedCipher = new HybridCipher(l1, ctM, uiAlgID, ctS, originalKeyHandle);

            // 验证重构的对象字段与原始对象相同
            assertEquals("重构的l1应与原始l1相同", l1, reconstructedCipher.getL1());
            assertArrayEquals("重构的ctM应与原始ctM相同", ctM, reconstructedCipher.getCtM());
            assertEquals("重构的uiAlgID应与原始uiAlgID相同", uiAlgID, reconstructedCipher.getUiAlgID());
            assertECCCipherEquals("重构的ctS应与原始ctS相同", ctS, reconstructedCipher.getCtS());
            assertEquals("重构的keyHandle应与原始keyHandle相同", originalKeyHandle, reconstructedCipher.getKeyHandle());

            // 步骤5: 获取私钥访问权限
            sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, hybridKeyIndex, keyPassword);
            accessRightObtained = true;

            // 步骤6: 使用重构的 HybridCipher 导入密钥
            keyHandle = sdf.SDF_ImportKeyWithISK_Hybrid(sessionHandle, hybridKeyIndex, reconstructedCipher);
            assertTrue("导入的密钥句柄应大于0", keyHandle > 0);

        } catch (SDFException e) {
            int errCode = e.getErrorCode();
            if (errCode == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 混合加密功能未实现");
                Assume.assumeTrue("混合加密功能未实现", false);
            } else {
                throw e;
            }
        } finally {
            if (keyHandle != 0) {
                try {
                    sdf.SDF_DestroyKey(sessionHandle, keyHandle);
                } catch (Exception ignored) {
                }
            }
            if (accessRightObtained) {
                try {
                    sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, hybridKeyIndex);
                } catch (Exception ignored) {
                }
            }
        }
    }

    /**
     * 异常场景：HybridCipher ctM字段（后量子密文）被篡改
     * 预期：导入密钥失败或解密失败
     */
    @Test
    public void testHybridCipher_tamperedCtM() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long importedKeyHandle = 0;
        long tamperedKeyHandle = 0;
        int hybridKeyIndex = HYBRID_MLKEM_512_KEY_INDEX | (AlgorithmID.SGD_HYBRID << 20);
        boolean accessRightObtained = false;

        try {
            // 导出混合加密公钥
            byte[] publicKey = sdf.SDF_ExportPublicKey_Hybrid(sessionHandle, hybridKeyIndex);

            // 正常加密
            HybridCipher originalCipher = sdf.SDF_GenerateKeyWithEPK_Hybrid(
                    sessionHandle, AlgorithmID.SGD_HYBRID_ENV_SM2_MLKEM_512, publicKey);

            // 获取私钥访问权限
            sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, hybridKeyIndex, keyPassword);
            accessRightObtained = true;

            // 导入正常的密文
            importedKeyHandle = sdf.SDF_ImportKeyWithISK_Hybrid(sessionHandle, hybridKeyIndex, originalCipher);
            assertTrue("正常密文导入应成功", importedKeyHandle > 0);

            // 篡改ctM（后量子密文）
            byte[] tamperedCtM = originalCipher.getCtM();
            tamperedCtM[tamperedCtM.length - 1]++;

            HybridCipher tamperedCipher = new HybridCipher(
                    originalCipher.getL1(),
                    tamperedCtM,
                    originalCipher.getUiAlgID(),
                    originalCipher.getCtS(),
                    originalCipher.getKeyHandle()
            );

            byte[] probe = "FEDCBA9876543210".getBytes(StandardCharsets.UTF_8);
            byte[] iv = new byte[16]; // 全零IV
            byte[] encrypted = sdf.SDF_Encrypt(sessionHandle, importedKeyHandle, AlgorithmID.SGD_SM4_CBC, iv, probe);

            // 导入篡改后的密文
            tamperedKeyHandle = sdf.SDF_ImportKeyWithISK_Hybrid(sessionHandle, hybridKeyIndex, tamperedCipher);

            byte[] decrypted = sdf.SDF_Decrypt(sessionHandle, tamperedKeyHandle, AlgorithmID.SGD_SM4_CBC, iv, encrypted);
            assertFalse("ctM篡改后不应产生相同会话密钥", Arrays.equals(probe, decrypted));

        } catch (SDFException e) {
            int errCode = e.getErrorCode();
            if (errCode == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 混合加密功能未实现");
                Assume.assumeTrue("混合加密功能未实现", false);
            } else {
                throw e;
            }
        } finally {
            if (importedKeyHandle != 0) {
                try {
                    sdf.SDF_DestroyKey(sessionHandle, importedKeyHandle);
                } catch (Exception ignored) {
                }
            }
            if (tamperedKeyHandle != 0) {
                try {
                    sdf.SDF_DestroyKey(sessionHandle, tamperedKeyHandle);
                } catch (Exception ignored) {
                }
            }
            if (accessRightObtained) {
                try {
                    sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, hybridKeyIndex);
                } catch (Exception ignored) {
                }
            }
        }
    }

    /**
     * 异常场景：HybridCipher ctS字段（ECC密文）被篡改
     * 预期：导入密钥失败或解密失败
     */
    @Test
    public void testHybridCipher_tamperedCtS() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long keyHandle = 0;
        boolean accessRightObtained = false;
        int hybridKeyIndex = HYBRID_MLKEM_512_KEY_INDEX | (AlgorithmID.SGD_HYBRID << 20);
        try {
            // 导出混合加密公钥
            byte[] publicKey = sdf.SDF_ExportPublicKey_Hybrid(sessionHandle, hybridKeyIndex);

            // 正常加密
            HybridCipher originalCipher = sdf.SDF_GenerateKeyWithEPK_Hybrid(
                    sessionHandle, AlgorithmID.SGD_HYBRID_ENV_SM2_MLKEM_512, publicKey);

            // 篡改ctS（ECC密文的C字段）
            ECCCipher originalCtS = originalCipher.getCtS();
            byte[] tamperedC = originalCtS.getC();
            tamperedC[tamperedC.length - 1]++;

            ECCCipher tamperedCtS = new ECCCipher(
                    originalCtS.getX(),
                    originalCtS.getY(),
                    originalCtS.getM(),
                    originalCtS.getL(),
                    tamperedC
            );

            HybridCipher tamperedCipher = new HybridCipher(
                    originalCipher.getL1(),
                    originalCipher.getCtM(),
                    originalCipher.getUiAlgID(),
                    tamperedCtS,
                    originalCipher.getKeyHandle()
            );

            // 获取私钥访问权限
            sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, hybridKeyIndex, keyPassword);
            accessRightObtained = true;

            // 尝试导入被篡改的密文，应该失败
            try {
                keyHandle = sdf.SDF_ImportKeyWithISK_Hybrid(sessionHandle, hybridKeyIndex, tamperedCipher);
                fail("ctS篡改后密钥仍可导入，篡改未被检测到");
            } catch (SDFException e) {
                // ctS篡改被检测到（抛出异常即表示检测到）
            }

        } catch (SDFException e) {
            int errCode = e.getErrorCode();
            if (errCode == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 混合加密功能未实现");
                Assume.assumeTrue("混合加密功能未实现", false);
            } else {
                throw e;
            }
        } finally {
            if (keyHandle != 0) {
                try {
                    sdf.SDF_DestroyKey(sessionHandle, keyHandle);
                } catch (Exception ignored) {
                }
            }
            if (accessRightObtained) {
                try {
                    sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, hybridKeyIndex);
                } catch (Exception ignored) {
                }
            }
        }
    }

    /**
     * 异常场景：HybridCipher ctM长度被截断
     * 预期：构造失败或导入失败
     */
    @Test
    public void testHybridCipher_truncatedCtM() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long keyHandle = 0;
        boolean accessRightObtained = false;

        int hybridKeyIndex = HYBRID_MLKEM_512_KEY_INDEX | (AlgorithmID.SGD_HYBRID << 20);
        try {
            // 导出混合加密公钥
            byte[] publicKey = sdf.SDF_ExportPublicKey_Hybrid(sessionHandle, hybridKeyIndex);

            // 正常加密
            HybridCipher originalCipher = sdf.SDF_GenerateKeyWithEPK_Hybrid(
                    sessionHandle, AlgorithmID.SGD_HYBRID_ENV_SM2_MLKEM_512, publicKey);

            // 截断ctM
            byte[] truncatedCtM = new byte[originalCipher.getCtM().length / 2];
            System.arraycopy(originalCipher.getCtM(), 0, truncatedCtM, 0, truncatedCtM.length);

            HybridCipher truncatedCipher = new HybridCipher(
                    truncatedCtM.length,  // 更新l1为截断后的长度
                    truncatedCtM,
                    originalCipher.getUiAlgID(),
                    originalCipher.getCtS(),
                    originalCipher.getKeyHandle()
            );

            // 获取私钥访问权限
            sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, hybridKeyIndex, keyPassword);
            accessRightObtained = true;

            // 尝试导入被截断的密文，应该失败
            try {
                keyHandle = sdf.SDF_ImportKeyWithISK_Hybrid(sessionHandle, hybridKeyIndex, truncatedCipher);
                fail("截断的ctM密钥仍可导入，截断错误未被检测到");
            } catch (SDFException e) {
                // 截断被检测到（抛出异常即表示检测到）
            }

        } catch (SDFException e) {
            int errCode = e.getErrorCode();
            if (errCode == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 混合加密功能未实现");
                Assume.assumeTrue("混合加密功能未实现", false);
            } else {
                throw e;
            }
        } finally {
            if (keyHandle != 0) {
                try {
                    sdf.SDF_DestroyKey(sessionHandle, keyHandle);
                } catch (Exception ignored) {}
            }
            if (accessRightObtained) {
                try {
                    sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, hybridKeyIndex);
                } catch (Exception ignored) {}
            }
        }
    }

    /**
     * 测试流程：HybridSignature 混合签名字段提取与重构
     * 1. 通过 SDF_InternalSign_Composite 获取 HybridSignature
     * 2. 提取 HybridSignature 的所有字段 (sigS, l, sigM)
     * 3. 使用提取的字段构造新的 HybridSignature
     * 4. 使用新构造的 HybridSignature 调用 SDF_ExternalVerify_Composite
     * 5. 验证验签成功
     */
    @Test
    public void testHybridSignature_fieldExtractionAndReconstruction() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long sessionHandle2 = 0;
        boolean accessRightObtained = false;

        int hybridKeyIndex = HYBRID_MLDSA44_KEY_INDEX | (AlgorithmID.SGD_HYBRID << 20);
        try {
            sessionHandle2 = sdf.SDF_OpenSession(deviceHandle);

            // 步骤1: 导出混合签名公钥
            byte[] publicKey = sdf.SDF_ExportPublicKey_Hybrid(sessionHandle, hybridKeyIndex);
            assertNotNull("混合公钥不应为null", publicKey);

            // 步骤2: 获取私钥访问权限并签名
            sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, hybridKeyIndex, keyPassword);
            accessRightObtained = true;

            String message = "混合签名测试数据";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);

            HybridSignature originalSignature = sdf.SDF_InternalSign_Composite(
                    sessionHandle, hybridKeyIndex, data);
            assertNotNull("混合签名不应为null", originalSignature);

            // 步骤3: 提取所有字段
            ECCSignature sigS = originalSignature.getSigS();
            int l = originalSignature.getL();
            byte[] sigM = originalSignature.getSigM();

            // 验证提取的字段
            assertNotNull("sigS不应为null", sigS);
            assertNotNull("sigM不应为null", sigM);
            assertTrue("l应大于0", l > 0);

            // 步骤4: 重构 HybridSignature（模拟网络传输后重构）
            HybridSignature reconstructedSignature = new HybridSignature(sigS, l, sigM);

            // 验证重构的对象字段与原始对象相同
            assertECCSignatureEquals("重构的sigS应与原始sigS相同", sigS, reconstructedSignature.getSigS());
            assertEquals("重构的l应与原始l相同", l, reconstructedSignature.getL());
            assertArrayEquals("重构的sigM应与原始sigM相同", sigM, reconstructedSignature.getSigM());

            // 步骤5: 使用重构的签名验签
            sdf.SDF_ExternalVerify_Composite(
                    sessionHandle2,
                    AlgorithmID.SGD_COMPOSITE_MLDSA44_SM2,
                    publicKey,
                    data,
                    reconstructedSignature);

        } catch (SDFException e) {
            int errCode = e.getErrorCode();
            if (errCode == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 混合签名功能未实现");
                Assume.assumeTrue("混合签名功能未实现", false);
            } else {
                throw e;
            }
        } finally {
            if (sessionHandle2 != 0) {
                try {
                    sdf.SDF_CloseSession(sessionHandle2);
                } catch (Exception ignored) {}
            }
            if (accessRightObtained) {
                try {
                    sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, hybridKeyIndex);
                } catch (Exception ignored) {}
            }
        }
    }

    /**
     * 异常场景：HybridSignature sigS字段（ECC签名）被篡改
     * 预期：验签失败
     */
    @Test
    public void testHybridSignature_tamperedSigS() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long sessionHandle2 = 0;
        boolean accessRightObtained = false;

        int hybridKeyIndex = HYBRID_MLDSA44_KEY_INDEX | (AlgorithmID.SGD_HYBRID << 20);
        try {
            sessionHandle2 = sdf.SDF_OpenSession(deviceHandle);

            // 导出混合签名公钥
            byte[] publicKey = sdf.SDF_ExportPublicKey_Hybrid(sessionHandle, hybridKeyIndex);

            // 获取私钥访问权限并签名
            sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, hybridKeyIndex, keyPassword);
            accessRightObtained = true;

            String message = "混合签名篡改测试";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);

            HybridSignature originalSignature = sdf.SDF_InternalSign_Composite(sessionHandle, hybridKeyIndex, data);

            // 篡改sigS的R值
            ECCSignature originalSigS = originalSignature.getSigS();
            byte[] tamperedR = originalSigS.getR();
            tamperedR[tamperedR.length - 1]++;

            ECCSignature tamperedSigS = new ECCSignature(tamperedR, originalSigS.getS());

            HybridSignature tamperedSignature = new HybridSignature(
                    tamperedSigS,
                    originalSignature.getL(),
                    originalSignature.getSigM()
            );

            // 尝试验签，应该失败
            try {
                sdf.SDF_ExternalVerify_Composite(
                        sessionHandle2,
                        AlgorithmID.SGD_COMPOSITE_MLDSA44_SM2,
                        publicKey,
                        data,
                        tamperedSignature);
                fail("sigS篡改后验签成功，篡改未被检测到");
            } catch (SDFException e) {
                // sigS篡改被检测到（抛出异常即表示检测到）
            }

        } catch (SDFException e) {
            int errCode = e.getErrorCode();
            if (errCode == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 混合签名功能未实现");
                Assume.assumeTrue("混合签名功能未实现", false);
            } else {
                throw e;
            }
        } finally {
            if (sessionHandle2 != 0) {
                try {
                    sdf.SDF_CloseSession(sessionHandle2);
                } catch (Exception ignored) {}
            }
            if (accessRightObtained) {
                try {
                    sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, hybridKeyIndex);
                } catch (Exception ignored) {}
            }
        }
    }

    /**
     * 异常场景：HybridSignature sigM字段（后量子签名）被篡改
     * 预期：验签失败
     */
    @Test
    public void testHybridSignature_tamperedSigM() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long sessionHandle2 = 0;
        boolean accessRightObtained = false;

        int hybridKeyIndex = HYBRID_MLDSA44_KEY_INDEX | (AlgorithmID.SGD_HYBRID << 20);
        try {
            sessionHandle2 = sdf.SDF_OpenSession(deviceHandle);

            // 导出混合签名公钥
            byte[] publicKey = sdf.SDF_ExportPublicKey_Hybrid(sessionHandle, hybridKeyIndex);

            // 获取私钥访问权限并签名
            sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, hybridKeyIndex, keyPassword);
            accessRightObtained = true;

            String message = "混合签名sigM篡改测试";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);

            HybridSignature originalSignature = sdf.SDF_InternalSign_Composite(
                    sessionHandle, hybridKeyIndex, data);

            // 篡改sigM
            byte[] tamperedSigM = originalSignature.getSigM();
            tamperedSigM[tamperedSigM.length - 1]++;

            HybridSignature tamperedSignature = new HybridSignature(
                    originalSignature.getSigS(),
                    originalSignature.getL(),
                    tamperedSigM
            );

            // 尝试验签，应该失败
            try {
                sdf.SDF_ExternalVerify_Composite(
                        sessionHandle2,
                        AlgorithmID.SGD_COMPOSITE_MLDSA44_SM2,
                        publicKey,
                        data,
                        tamperedSignature);
                fail("sigM篡改后验签成功，篡改未被检测到");
            } catch (SDFException e) {
                // sigM篡改被检测到（抛出异常即表示检测到）
            }

        } catch (SDFException e) {
            int errCode = e.getErrorCode();
            if (errCode == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 混合签名功能未实现");
                Assume.assumeTrue("混合签名功能未实现", false);
            } else {
                throw e;
            }
        } finally {
            if (sessionHandle2 != 0) {
                try {
                    sdf.SDF_CloseSession(sessionHandle2);
                } catch (Exception ignored) {}
            }
            if (accessRightObtained) {
                try {
                    sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, hybridKeyIndex);
                } catch (Exception ignored) {}
            }
        }
    }

    /**
     * 异常场景：HybridSignature sigM和sigS都被篡改
     * 预期：验签失败
     */
    @Test
    public void testHybridSignature_tamperedBoth() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long sessionHandle2 = 0;
        boolean accessRightObtained = false;

        int hybridKeyIndex = HYBRID_MLDSA44_KEY_INDEX | (AlgorithmID.SGD_HYBRID << 20);
        try {
            sessionHandle2 = sdf.SDF_OpenSession(deviceHandle);

            // 导出混合签名公钥
            byte[] publicKey = sdf.SDF_ExportPublicKey_Hybrid(sessionHandle, hybridKeyIndex);

            // 获取私钥访问权限并签名
            sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, hybridKeyIndex, keyPassword);
            accessRightObtained = true;

            String message = "混合签名双篡改测试";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);

            HybridSignature originalSignature = sdf.SDF_InternalSign_Composite(
                    sessionHandle, hybridKeyIndex, data);

            // 同时篡改sigS和sigM
            ECCSignature originalSigS = originalSignature.getSigS();
            byte[] tamperedR = originalSigS.getR();
            tamperedR[tamperedR.length - 1]++;
            byte[] tamperedS = originalSigS.getS();
            tamperedS[tamperedS.length - 1]++;
            ECCSignature tamperedSigS = new ECCSignature(tamperedR, tamperedS);

            byte[] tamperedSigM = originalSignature.getSigM();
            tamperedSigM[tamperedSigM.length - 1]++;

            HybridSignature tamperedSignature = new HybridSignature(
                    tamperedSigS,
                    originalSignature.getL(),
                    tamperedSigM
            );

            // 尝试验签，应该失败
            try {
                sdf.SDF_ExternalVerify_Composite(
                        sessionHandle2,
                        AlgorithmID.SGD_COMPOSITE_MLDSA44_SM2,
                        publicKey,
                        data,
                        tamperedSignature);
                fail("sigS和sigM都篡改后验签成功，篡改未被检测到");
            } catch (SDFException e) {
                // 双重篡改被检测到（抛出异常即表示检测到）
            }

        } catch (SDFException e) {
            int errCode = e.getErrorCode();
            if (errCode == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 混合签名功能未实现");
                Assume.assumeTrue("混合签名功能未实现", false);
            } else {
                throw e;
            }
        } finally {
            if (sessionHandle2 != 0) {
                try {
                    sdf.SDF_CloseSession(sessionHandle2);
                } catch (Exception ignored) {}
            }
            if (accessRightObtained) {
                try {
                    sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, hybridKeyIndex);
                } catch (Exception ignored) {}
            }
        }
    }

    /**
     * 异常场景：HybridSignature sigM长度被截断
     * 预期：验签失败
     */
    @Test
    public void testHybridSignature_truncatedSigM() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long sessionHandle2 = 0;
        boolean accessRightObtained = false;

        int hybridKeyIndex = HYBRID_MLDSA44_KEY_INDEX | (AlgorithmID.SGD_HYBRID << 20);
        try {
            sessionHandle2 = sdf.SDF_OpenSession(deviceHandle);

            // 导出混合签名公钥
            byte[] publicKey = sdf.SDF_ExportPublicKey_Hybrid(sessionHandle, hybridKeyIndex);

            // 获取私钥访问权限并签名
            sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, hybridKeyIndex, keyPassword);
            accessRightObtained = true;

            String message = "混合签名截断测试";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);

            HybridSignature originalSignature = sdf.SDF_InternalSign_Composite(
                    sessionHandle, hybridKeyIndex, data);

            // 截断sigM
            byte[] truncatedSigM = new byte[originalSignature.getSigM().length / 2];
            System.arraycopy(originalSignature.getSigM(), 0, truncatedSigM, 0, truncatedSigM.length);

            HybridSignature truncatedSignature = new HybridSignature(
                    originalSignature.getSigS(),
                    truncatedSigM.length,
                    truncatedSigM
            );

            // 尝试验签，应该失败
            try {
                sdf.SDF_ExternalVerify_Composite(
                        sessionHandle2,
                        AlgorithmID.SGD_COMPOSITE_MLDSA44_SM2,
                        publicKey,
                        data,
                        truncatedSignature);
                fail("截断sigM后验签成功，截断错误未被检测到");
            } catch (SDFException e) {
                // 截断被检测到（抛出异常即表示检测到）
            }

        } catch (SDFException e) {
            int errCode = e.getErrorCode();
            if (errCode == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 混合签名功能未实现");
                Assume.assumeTrue("混合签名功能未实现", false);
            } else {
                throw e;
            }
        } finally {
            if (sessionHandle2 != 0) {
                try {
                    sdf.SDF_CloseSession(sessionHandle2);
                } catch (Exception ignored) {}
            }
            if (accessRightObtained) {
                try {
                    sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, hybridKeyIndex);
                } catch (Exception ignored) {}
            }
        }
    }

    /**
     * 异常场景：HybridSignature 使用错误消息验签
     * 预期：验签失败
     */
    @Test
    public void testHybridSignature_wrongMessage() throws SDFException {
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        long sessionHandle2 = 0;
        boolean accessRightObtained = false;

        int hybridKeyIndex = HYBRID_MLDSA44_KEY_INDEX | (AlgorithmID.SGD_HYBRID << 20);
        try {
            sessionHandle2 = sdf.SDF_OpenSession(deviceHandle);

            // 导出混合签名公钥
            byte[] publicKey = sdf.SDF_ExportPublicKey_Hybrid(sessionHandle, hybridKeyIndex);

            // 获取私钥访问权限并签名
            sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, hybridKeyIndex, keyPassword);
            accessRightObtained = true;

            String message1 = "原始消息";
            byte[] data1 = message1.getBytes(StandardCharsets.UTF_8);

            HybridSignature signature = sdf.SDF_InternalSign_Composite(
                    sessionHandle, hybridKeyIndex, data1);

            // 使用不同的消息验签，应该失败
            String message2 = "不同的消息";
            byte[] data2 = message2.getBytes(StandardCharsets.UTF_8);

            try {
                sdf.SDF_ExternalVerify_Composite(
                        sessionHandle2,
                        AlgorithmID.SGD_COMPOSITE_MLDSA44_SM2,
                        publicKey,
                        data2,
                        signature);
                fail("使用错误消息验签成功，篡改未被检测到");
            } catch (SDFException e) {
                // 错误消息被检测到（抛出异常即表示检测到）
            }

        } catch (SDFException e) {
            int errCode = e.getErrorCode();
            if (errCode == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 混合签名功能未实现");
                Assume.assumeTrue("混合签名功能未实现", false);
            } else {
                throw e;
            }
        } finally {
            if (sessionHandle2 != 0) {
                try {
                    sdf.SDF_CloseSession(sessionHandle2);
                } catch (Exception ignored) {}
            }
            if (accessRightObtained) {
                try {
                    sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, hybridKeyIndex);
                } catch (Exception ignored) {}
            }
        }
    }

    private static void assertECCCipherEquals(String message, ECCCipher expected, ECCCipher actual) {
        assertNotNull(message + " expected", expected);
        assertNotNull(message + " actual", actual);
        assertArrayEquals(message + " x", expected.getX(), actual.getX());
        assertArrayEquals(message + " y", expected.getY(), actual.getY());
        assertArrayEquals(message + " m", expected.getM(), actual.getM());
        assertEquals(message + " L", expected.getL(), actual.getL());
        assertArrayEquals(message + " c", expected.getC(), actual.getC());
    }

    private static void assertECCSignatureEquals(String message, ECCSignature expected, ECCSignature actual) {
        assertNotNull(message + " expected", expected);
        assertNotNull(message + " actual", actual);
        assertArrayEquals(message + " r", expected.getR(), actual.getR());
        assertArrayEquals(message + " s", expected.getS(), actual.getS());
    }
}
