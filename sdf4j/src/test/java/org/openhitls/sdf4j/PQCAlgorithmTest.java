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
import org.openhitls.sdf4j.constants.AlgorithmID;
import org.openhitls.sdf4j.constants.ErrorCode;
import org.openhitls.sdf4j.types.KeyEncryptionResult;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

import static org.junit.Assert.*;

/**
 * SDF4J 纯后量子算法接口测试。
 */
public class PQCAlgorithmTest {

    private static final int KEY_INDEX_DIGIT = 20;
    private static final int SESSION_KEY_BITS = 128;

    private static int pqcKemKeyIndex = 8;
    private static String pqcKemKeyPassword = "123abc!@";
    private static int pqcSignKeyIndex = 16;
    private static String pqcSignKeyPassword = "123abc!@";

    private SDF sdf;
    private long deviceHandle;
    private long sessionHandle1;
    private long sessionHandle2;

    @BeforeClass
    public static void loadConfig() {
        Properties testConfig = new Properties();
        try (InputStream is = PQCAlgorithmTest.class.getClassLoader()
                .getResourceAsStream("test-config.properties")) {
            if (is != null) {
                testConfig.load(is);
                pqcKemKeyIndex = Integer.parseInt(
                        testConfig.getProperty("pqc.kem.key.index", String.valueOf(pqcKemKeyIndex)));
                pqcKemKeyPassword = testConfig.getProperty("pqc.kem.key.access.password", pqcKemKeyPassword);
                pqcSignKeyIndex = Integer.parseInt(
                        testConfig.getProperty("pqc.sign.key.index", String.valueOf(pqcSignKeyIndex)));
                pqcSignKeyPassword = testConfig.getProperty("pqc.sign.key.access.password", pqcSignKeyPassword);
            }
        } catch (IOException e) {
            System.err.println("读取PQC测试配置失败: " + e.getMessage());
        }
    }

    @Before
    public void setUp() throws SDFException {
        sdf = new SDF();
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle1 = sdf.SDF_OpenSession(deviceHandle);
        sessionHandle2 = sdf.SDF_OpenSession(deviceHandle);
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
            System.err.println("关闭PQC测试资源失败: " + e.getMessage());
        }
    }

    @Test
    public void testPQCSignatureFlow() throws SDFException {
        int algID = AlgorithmID.SGD_PQC_ML_DSA_44;
        int format = 0;
        int sessionIndex = pqcIndex(pqcSignKeyIndex);
        boolean accessRightObtained = false;

        try {
            byte[] publicKey = sdf.SDF_ExportPublicKey_PQC(
                    sessionHandle1, pqcSignKeyIndex, algID, format);
            assertNotNull("PQC公钥不应为null", publicKey);
            assertTrue("PQC公钥长度应大于0", publicKey.length > 0);

            sdf.SDF_GetPrivateKeyAccessRight(sessionHandle1, sessionIndex, pqcSignKeyPassword);
            accessRightObtained = true;

            byte[] data = "PQC ML-DSA signature test".getBytes(StandardCharsets.UTF_8);
            byte[] signature = sdf.SDF_InternalSign_PQC(
                    sessionHandle1, sessionIndex, algID, format, data);
            assertNotNull("PQC签名不应为null", signature);
            assertTrue("PQC签名长度应大于0", signature.length > 0);

            sdf.SDF_InternalVerify_PQC(
                    sessionHandle1, pqcSignKeyIndex, algID, format, data, signature);
            sdf.SDF_ExternalVerify_PQC(
                    sessionHandle2, algID, publicKey, format, data, signature);

            byte[] tampered = "PQC ML-DSA signature tampered".getBytes(StandardCharsets.UTF_8);
            try {
                sdf.SDF_ExternalVerify_PQC(sessionHandle2, algID, publicKey, format, tampered, signature);
                fail("篡改数据后PQC验签应失败");
            } catch (SDFException e) {
                // 篡改数据应触发验签失败
            }
        } catch (SDFException e) {
            skipIfUnsupported("纯PQC签名流程功能未实现", e);
        } finally {
            if (accessRightObtained) {
                releasePrivateKey(sessionHandle1, sessionIndex);
            }
        }
    }

    @Test
    public void testPQCKemGenerateWithEPKAndImport() throws SDFException {
        int algID = AlgorithmID.SGD_PQC_ML_KEM_512;
        int format = 0;
        int sessionIndex = pqcIndex(pqcKemKeyIndex);
        boolean accessRightObtained = false;
        long generatedKeyHandle = 0;
        long importedKeyHandle = 0;

        try {
            byte[] publicKey = sdf.SDF_ExportPublicKey_PQC(sessionHandle1, pqcKemKeyIndex, algID, format);
            KeyEncryptionResult result = sdf.SDF_GenerateKeyWithEPK_PQC(
                    sessionHandle2, algID, SESSION_KEY_BITS, format, publicKey);
            assertNotNull("PQC封装结果不应为null", result);
            assertNotNull("PQC密文不应为null", result.getEncryptedKey());
            assertNotEquals("生成端会话密钥句柄不应为0", 0, result.getKeyHandle());
            generatedKeyHandle = result.getKeyHandle();

            sdf.SDF_GetPrivateKeyAccessRight(sessionHandle1, sessionIndex, pqcKemKeyPassword);
            accessRightObtained = true;

            importedKeyHandle = sdf.SDF_ImportKeyWithISK_PQC(
                    sessionHandle1, sessionIndex, algID, format, result.getEncryptedKey());
            assertNotEquals("导入端会话密钥句柄不应为0", 0, importedKeyHandle);

            assertSessionKeysEquivalent(generatedKeyHandle, importedKeyHandle);
        } catch (SDFException e) {
            skipIfUnsupported("纯PQC EPK封装/ISK导入流程功能未实现", e);
        } finally {
            destroyKey(sessionHandle2, generatedKeyHandle);
            destroyKey(sessionHandle1, importedKeyHandle);
            if (accessRightObtained) {
                releasePrivateKey(sessionHandle1, sessionIndex);
            }
        }
    }

    @Test
    public void testPQCKemGenerateWithIPKAndImport() throws SDFException {
        int algID = AlgorithmID.SGD_PQC_ML_KEM_512;
        int format = 0;
        int sessionIndex = pqcIndex(pqcKemKeyIndex);
        boolean accessRightObtained = false;
        long generatedKeyHandle = 0;
        long importedKeyHandle = 0;

        try {
            KeyEncryptionResult result = sdf.SDF_GenerateKeyWithIPK_PQC(
                    sessionHandle2, pqcKemKeyIndex, algID, SESSION_KEY_BITS, format);
            assertNotNull("PQC内部公钥封装结果不应为null", result);
            assertNotNull("PQC密文不应为null", result.getEncryptedKey());
            assertNotEquals("生成端会话密钥句柄不应为0", 0, result.getKeyHandle());
            generatedKeyHandle = result.getKeyHandle();

            sdf.SDF_GetPrivateKeyAccessRight(sessionHandle1, sessionIndex, pqcKemKeyPassword);
            accessRightObtained = true;

            importedKeyHandle = sdf.SDF_ImportKeyWithISK_PQC(
                    sessionHandle1, sessionIndex, algID, format, result.getEncryptedKey());
            assertNotEquals("导入端会话密钥句柄不应为0", 0, importedKeyHandle);

            assertSessionKeysEquivalent(generatedKeyHandle, importedKeyHandle);
        } catch (SDFException e) {
            skipIfUnsupported("纯PQC IPK封装/ISK导入流程功能未实现", e);
        } finally {
            destroyKey(sessionHandle2, generatedKeyHandle);
            destroyKey(sessionHandle1, importedKeyHandle);
            if (accessRightObtained) {
                releasePrivateKey(sessionHandle1, sessionIndex);
            }
        }
    }

    private int pqcIndex(int keyIndex) {
        return keyIndex | (AlgorithmID.SGD_HYBRID << KEY_INDEX_DIGIT);
    }

    private void assertSessionKeysEquivalent(long generatedKeyHandle, long importedKeyHandle)
            throws SDFException {
        byte[] plaintext = "PQCSessionKey123".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = sdf.SDF_Encrypt(
                sessionHandle2, generatedKeyHandle, AlgorithmID.SGD_SM4_ECB, null, plaintext);
        byte[] decrypted = sdf.SDF_Decrypt(
                sessionHandle1, importedKeyHandle, AlgorithmID.SGD_SM4_ECB, null, encrypted);
        assertArrayEquals("PQC封装和解封装得到的会话密钥应一致", plaintext, decrypted);
    }

    private void destroyKey(long sessionHandle, long keyHandle) {
        if (keyHandle == 0) {
            return;
        }
        try {
            sdf.SDF_DestroyKey(sessionHandle, keyHandle);
        } catch (SDFException e) {
            System.err.println("销毁PQC会话密钥失败: " + e.getMessage());
        }
    }

    private void releasePrivateKey(long sessionHandle, int keyIndex) {
        try {
            sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, keyIndex);
        } catch (SDFException e) {
            System.err.println("释放PQC私钥权限失败: " + e.getMessage());
        }
    }

    private void skipIfUnsupported(String message, SDFException e) throws SDFException {
        int errorCode = e.getErrorCode();
        if (errorCode == ErrorCode.SDR_NOTSUPPORT || errorCode == ErrorCode.SDR_ALGNOTSUPPORT) {
            System.out.println("[跳过] " + message);
            Assume.assumeTrue(message, false);
            return;
        }
        throw e;
    }
}
