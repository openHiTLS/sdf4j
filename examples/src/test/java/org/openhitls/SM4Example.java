/*
 * Copyright (c) 2025 OpenHitls
 * SDF4J is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

package org.openhitls;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.openhitls.sdf4j.*;
import org.openhitls.sdf4j.constants.AlgorithmID;
import org.openhitls.sdf4j.types.KeyEncryptionResult;
import java.util.Properties;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

/**
 * SM4 对称加密测试
 */
public class SM4Example {

    private static int KEY_INDEX = 4;
    private static String KEY_PASSWORD = "123abc!@";
    private static int SM4_KEY_BITS = 128;

    private SDF sdf;
    private long deviceHandle;
    private long sessionHandle;
    long ecbKeyHandle;

    public static void loadConfig() {
        Properties testConfig = new Properties();
        try (InputStream is = SM4Example.class.getClassLoader()
                .getResourceAsStream("test-config.properties")) {
            if (is != null) {
                testConfig.load(is);
                KEY_INDEX = Integer.parseInt(
                        testConfig.getProperty("sm4.internal.key.index", String.valueOf(KEY_INDEX)));
                KEY_PASSWORD = testConfig.getProperty("sm4.key.access.password", KEY_PASSWORD);
                return;
            }
        } catch (IOException e) {
            System.err.println("读取配置文件失败: " + e.getMessage());
        }
    }

    @Before
    public void setUp() throws SDFException {
        sdf = new SDF();
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);
        loadConfig();
        // 获取KEK访问权限并生成密钥
        sdf.SDF_GetKEKAccessRight(sessionHandle, KEY_INDEX, KEY_PASSWORD);
        KeyEncryptionResult result = sdf.SDF_GenerateKeyWithKEK(sessionHandle, SM4_KEY_BITS, AlgorithmID.SGD_SM4_ECB, KEY_INDEX);
        ecbKeyHandle = result.getKeyHandle();
    }

    @After
    public void tearDown() throws SDFException {
        if (sdf != null) {
            if (ecbKeyHandle != 0) {
                sdf.SDF_DestroyKey(sessionHandle, ecbKeyHandle);
            }
            if (sessionHandle != 0) {
                sdf.SDF_ReleaseKEKAccessRight(sessionHandle, KEY_INDEX);
                sdf.SDF_CloseSession(sessionHandle);
            }
            if (deviceHandle != 0) {
                sdf.SDF_CloseDevice(deviceHandle);
            }
        }
    }

    @Test
    public void testSM4ECB() throws SDFException {
        String plaintext = "Hello SM4 ECB Test - 16bytes!";
        byte[] data = pkcs7Padding(plaintext.getBytes(StandardCharsets.UTF_8), 16);

        byte[] encrypted = sdf.SDF_Encrypt(sessionHandle, ecbKeyHandle, AlgorithmID.SGD_SM4_ECB, null, data);
        assertNotNull("加密结果不能为空", encrypted);

        byte[] decrypted = sdf.SDF_Decrypt(sessionHandle, ecbKeyHandle, AlgorithmID.SGD_SM4_ECB, null, encrypted);
        assertNotNull("解密结果不能为空", decrypted);

        String decryptedText = new String(pkcs7Unpadding(decrypted), StandardCharsets.UTF_8);
        assertEquals("解密结果与原文不一致", plaintext, decryptedText);
    }

    @Test
    public void testSM4CBC() throws SDFException {
        KeyEncryptionResult result = sdf.SDF_GenerateKeyWithKEK(sessionHandle, SM4_KEY_BITS, AlgorithmID.SGD_SM4_CBC, KEY_INDEX);
        long cbcKeyHandle = result.getKeyHandle();

        try {
            String plaintext = "Hello SM4 CBC Test - 16bytes!";
            byte[] data = pkcs7Padding(plaintext.getBytes(StandardCharsets.UTF_8), 16);
            byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 16);
            assertNotNull("IV不能为空", iv);
            assertEquals("IV长度应为16字节", 16, iv.length);

            byte[] encrypted = sdf.SDF_Encrypt(sessionHandle, cbcKeyHandle, AlgorithmID.SGD_SM4_CBC, iv, data);
            assertNotNull("加密结果不能为空", encrypted);

            byte[] decrypted = sdf.SDF_Decrypt(sessionHandle, cbcKeyHandle, AlgorithmID.SGD_SM4_CBC, iv, encrypted);
            assertNotNull("解密结果不能为空", decrypted);

            String decryptedText = new String(pkcs7Unpadding(decrypted), StandardCharsets.UTF_8);
            assertEquals("解密结果与原文不一致", plaintext, decryptedText);
        } finally {
            sdf.SDF_DestroyKey(sessionHandle, cbcKeyHandle);
        }
    }

    private static byte[] pkcs7Padding(byte[] data, int blockSize) {
        int paddingLength = blockSize - (data.length % blockSize);
        byte[] padded = new byte[data.length + paddingLength];
        System.arraycopy(data, 0, padded, 0, data.length);
        for (int i = data.length; i < padded.length; i++) {
            padded[i] = (byte) paddingLength;
        }
        return padded;
    }

    private static byte[] pkcs7Unpadding(byte[] data) {
        if (data == null || data.length == 0) {
            return data;
        }
        int paddingLength = data[data.length - 1];
        if (paddingLength < 1 || paddingLength > data.length) {
            return data;
        }
        for (int i = data.length - paddingLength; i < data.length; i++) {
            if (data[i] != paddingLength) {
                return data;
            }
        }
        byte[] unpadded = new byte[data.length - paddingLength];
        System.arraycopy(data, 0, unpadded, 0, unpadded.length);
        return unpadded;
    }
}
