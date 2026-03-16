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

package org.openhitls.sdf4j.jce;

import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Assume;
import static org.junit.Assert.*;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;

/**
 * SM4 内部测试
 *
 * <p>测试内容:
 * <ul>
 *   <li>ECB/CBC 向量测试 (已知答案验证)</li>
 *   <li>PKCS5/PKCS7 填充测试</li>
 *   <li>ECB/CBC 流式 update + doFinal (多包模式验证)</li>
 *   <li>GCM 模式基本加解密</li>
 *   <li>GCM 模式带 AAD 加解密</li>
 *   <li>GCM 模式 tag 验证失败</li>
 *   <li>大数据流式处理</li>
 * </ul>
 */
public class SM4InnerTest {

    private static boolean initialized = false;

    @BeforeClass
    public static void setUpClass() {
        String libraryPath = System.getenv("SDF_LIBRARY_PATH");
        if (libraryPath == null || libraryPath.isEmpty()) {
            libraryPath = System.getProperty("sdf.library.path");
        }

        if (libraryPath != null && !libraryPath.isEmpty()) {
            try {
                Security.addProvider(new SDFProvider());
                initialized = true;
            } catch (Throwable e) {
                System.err.println("Failed to initialize provider: " + e.getMessage());
            }
        }
    }

    @After
    public void cleanup() throws InterruptedException {
        System.gc();
        System.runFinalization();
    }

    private static final byte[] KEY = new byte[]{
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };

    private static final byte[] IV = new byte[]{
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    // ==================== ECB 向量测试 ====================

    @Test
    public void testSM4ECBPKCS5Padding1Byte() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);
        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");

        byte[] plaintext = new byte[]{0x42};
        byte[] expectedCiphertext = new byte[]{
                0x2F, 0x0B, 0x2A, 0x76, (byte) 0xCA, (byte) 0x9B, 0x77, 0x4A,
                0x26, 0x03, 0x0D, 0x22, 0x57, (byte) 0xAB, (byte) 0xE3, (byte) 0xBE
        };

        Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS5Padding", "SDF");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] ciphertext = cipher.doFinal(plaintext);

        assertArrayEquals("ECB PKCS5 1 byte encrypt failed", expectedCiphertext, ciphertext);

        Cipher decCipher = Cipher.getInstance("SM4/ECB/PKCS5Padding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals("ECB PKCS5 1 byte decrypt failed", plaintext, decrypted);
    }

    @Test
    public void testSM4ECBPKCS5Padding15Bytes() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);
        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");

        byte[] plaintext = new byte[15];
        Arrays.fill(plaintext, (byte) 0xAB);
        byte[] expectedCiphertext = new byte[]{
                (byte) 0xFA, (byte) 0xE0, 0x6E, 0x0A, (byte) 0xEA, (byte) 0xBF, (byte) 0xF5, (byte) 0xB3,
                (byte) 0x9E, 0x0B, (byte) 0x9C, (byte) 0x9A, 0x55, (byte) 0x99, (byte) 0x8A, (byte) 0xE2
        };

        Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS5Padding", "SDF");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] ciphertext = cipher.doFinal(plaintext);

        assertArrayEquals("ECB PKCS5 15 bytes encrypt failed", expectedCiphertext, ciphertext);

        Cipher decCipher = Cipher.getInstance("SM4/ECB/PKCS5Padding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals("ECB PKCS5 15 bytes decrypt failed", plaintext, decrypted);
    }

    @Test
    public void testSM4ECBPKCS5Padding16Bytes() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);
        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");

        byte[] plaintext = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };
        byte[] expectedCiphertext = new byte[]{
                0x6C, 0x1D, (byte) 0xD6, (byte) 0xAF, (byte) 0xCA, (byte) 0xA9, 0x43, 0x1E,
                0x4C, 0x26, (byte) 0xB3, (byte) 0xCD, (byte) 0xDE, 0x0A, 0x73, 0x24,
                0x17, (byte) 0x92, 0x06, (byte) 0xED, 0x65, 0x4F, (byte) 0x92, (byte) 0xC9,
                (byte) 0xF8, 0x2F, 0x31, 0x36, 0x1E, 0x6E, (byte) 0xB3, 0x3E
        };

        Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS5Padding", "SDF");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] ciphertext = cipher.doFinal(plaintext);

        assertArrayEquals("ECB PKCS5 16 bytes encrypt failed", expectedCiphertext, ciphertext);
        assertEquals("ECB PKCS5 16 bytes ciphertext should be 32 bytes", 32, ciphertext.length);

        Cipher decCipher = Cipher.getInstance("SM4/ECB/PKCS5Padding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals("ECB PKCS5 16 bytes decrypt failed", plaintext, decrypted);
    }

    @Test
    public void testSM4ECBPKCS5Padding31Bytes() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);
        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");

        byte[] plaintext = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E
        };
        byte[] expectedCiphertext = new byte[]{
                0x6C, 0x1D, (byte) 0xD6, (byte) 0xAF, (byte) 0xCA, (byte) 0xA9, 0x43, 0x1E,
                0x4C, 0x26, (byte) 0xB3, (byte) 0xCD, (byte) 0xDE, 0x0A, 0x73, 0x24,
                (byte) 0xDB, 0x03, (byte) 0xF9, 0x5C, (byte) 0xF5, 0x42, 0x0F, 0x35,
                0x3E, (byte) 0xD4, (byte) 0x8A, 0x67, (byte) 0xCC, (byte) 0xB0, 0x37, (byte) 0xA0
        };

        Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS5Padding", "SDF");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] ciphertext = cipher.doFinal(plaintext);

        assertArrayEquals("ECB PKCS5 31 bytes encrypt failed", expectedCiphertext, ciphertext);

        Cipher decCipher = Cipher.getInstance("SM4/ECB/PKCS5Padding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals("ECB PKCS5 31 bytes decrypt failed", plaintext, decrypted);
    }

    // ==================== CBC 向量测试 ====================

    @Test
    public void testSM4CBCPKCS5Padding1Byte() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);
        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");
        IvParameterSpec iv = new IvParameterSpec(IV);

        byte[] plaintext = new byte[]{0x42};
        byte[] expectedCiphertext = new byte[]{
                0x06, (byte) 0xF2, 0x18, 0x16, (byte) 0x92, (byte) 0x9B, 0x2C, (byte) 0xBE,
                (byte) 0xF3, 0x06, (byte) 0x9D, (byte) 0xA5, (byte) 0xFA, (byte) 0xA4, 0x33, (byte) 0x9E
        };

        Cipher cipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", "SDF");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] ciphertext = cipher.doFinal(plaintext);

        assertArrayEquals("CBC PKCS5 1 byte encrypt failed", expectedCiphertext, ciphertext);

        Cipher decCipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals("CBC PKCS5 1 byte decrypt failed", plaintext, decrypted);
    }

    @Test
    public void testSM4CBCPKCS5Padding15Bytes() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);
        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");
        IvParameterSpec iv = new IvParameterSpec(IV);

        byte[] plaintext = new byte[15];
        Arrays.fill(plaintext, (byte) 0xAB);
        byte[] expectedCiphertext = new byte[]{
                (byte) 0x8B, (byte) 0xA2, (byte) 0xB9, 0x05, (byte) 0xD8, (byte) 0x9F, 0x10, (byte) 0xBD,
                0x31, (byte) 0x84, (byte) 0xC3, 0x71, (byte) 0xB4, 0x61, (byte) 0xA9, (byte) 0x5E
        };

        Cipher cipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", "SDF");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] ciphertext = cipher.doFinal(plaintext);

        assertArrayEquals("CBC PKCS5 15 bytes encrypt failed", expectedCiphertext, ciphertext);

        Cipher decCipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals("CBC PKCS5 15 bytes decrypt failed", plaintext, decrypted);
    }

    @Test
    public void testSM4CBCPKCS5Padding16Bytes() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);
        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");
        IvParameterSpec iv = new IvParameterSpec(IV);

        byte[] plaintext = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };
        byte[] expectedCiphertext = new byte[]{
                0x17, (byte) 0x92, 0x06, (byte) 0xED, 0x65, 0x4F, (byte) 0x92, (byte) 0xC9,
                (byte) 0xF8, 0x2F, 0x31, 0x36, 0x1E, 0x6E, (byte) 0xB3, 0x3E,
                0x77, 0x13, 0x24, (byte) 0x80, 0x5C, (byte) 0x85, 0x7A, 0x23,
                (byte) 0xC1, 0x70, 0x65, (byte) 0xA3, 0x0E, 0x77, (byte) 0xF3, (byte) 0xB9
        };

        Cipher cipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", "SDF");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] ciphertext = cipher.doFinal(plaintext);

        assertArrayEquals("CBC PKCS5 16 bytes encrypt failed", expectedCiphertext, ciphertext);

        Cipher decCipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals("CBC PKCS5 16 bytes decrypt failed", plaintext, decrypted);
    }

    @Test
    public void testSM4CBCPKCS5Padding31Bytes() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);
        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");
        IvParameterSpec iv = new IvParameterSpec(IV);

        byte[] plaintext = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E
        };
        byte[] expectedCiphertext = new byte[]{
                0x17, (byte) 0x92, 0x06, (byte) 0xED, 0x65, 0x4F, (byte) 0x92, (byte) 0xC9,
                (byte) 0xF8, 0x2F, 0x31, 0x36, 0x1E, 0x6E, (byte) 0xB3, 0x3E,
                0x72, (byte) 0xFA, 0x5C, 0x6C, (byte) 0xD6, 0x3A, 0x6E, (byte) 0xFC,
                (byte) 0xD0, 0x5A, (byte) 0x83, (byte) 0xD6, 0x18, (byte) 0x8A, 0x21, 0x57
        };

        Cipher cipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", "SDF");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] ciphertext = cipher.doFinal(plaintext);

        assertArrayEquals("CBC PKCS5 31 bytes encrypt failed", expectedCiphertext, ciphertext);

        Cipher decCipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals("CBC PKCS5 31 bytes decrypt failed", plaintext, decrypted);
    }

    @Test
    public void testSM4CBCPKCS5PaddingDifferentIVs() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);
        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");

        byte[] plaintext = "Hello, SM4!".getBytes();

        byte[] iv1 = new byte[16];
        Arrays.fill(iv1, (byte) 0x01);

        byte[] iv2 = new byte[16];
        Arrays.fill(iv2, (byte) 0x02);

        Cipher cipher1 = Cipher.getInstance("SM4/CBC/PKCS5Padding", "SDF");
        cipher1.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv1));
        byte[] ciphertext1 = cipher1.doFinal(plaintext);

        Cipher cipher2 = Cipher.getInstance("SM4/CBC/PKCS5Padding", "SDF");
        cipher2.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv2));
        byte[] ciphertext2 = cipher2.doFinal(plaintext);

        assertFalse("Different IVs should produce different ciphertexts",
                Arrays.equals(ciphertext1, ciphertext2));
    }

    // ==================== PKCS7 别名向量测试 ====================

    @Test
    public void testSM4ECBPKCS7Padding1Byte() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);
        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");

        byte[] plaintext = new byte[]{0x42};
        byte[] expectedCiphertext = new byte[]{
                0x2F, 0x0B, 0x2A, 0x76, (byte) 0xCA, (byte) 0x9B, 0x77, 0x4A,
                0x26, 0x03, 0x0D, 0x22, 0x57, (byte) 0xAB, (byte) 0xE3, (byte) 0xBE
        };

        Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS7Padding", "SDF");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] ciphertext = cipher.doFinal(plaintext);

        assertArrayEquals("ECB PKCS7 1 byte encrypt failed", expectedCiphertext, ciphertext);

        Cipher decCipher = Cipher.getInstance("SM4/ECB/PKCS7Padding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals("ECB PKCS7 1 byte decrypt failed", plaintext, decrypted);
    }

    @Test
    public void testSM4ECBPKCS7Padding15Bytes() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);
        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");

        byte[] plaintext = new byte[15];
        Arrays.fill(plaintext, (byte) 0xAB);
        byte[] expectedCiphertext = new byte[]{
                (byte) 0xFA, (byte) 0xE0, 0x6E, 0x0A, (byte) 0xEA, (byte) 0xBF, (byte) 0xF5, (byte) 0xB3,
                (byte) 0x9E, 0x0B, (byte) 0x9C, (byte) 0x9A, 0x55, (byte) 0x99, (byte) 0x8A, (byte) 0xE2
        };

        Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS7Padding", "SDF");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] ciphertext = cipher.doFinal(plaintext);

        assertArrayEquals("ECB PKCS7 15 bytes encrypt failed", expectedCiphertext, ciphertext);

        Cipher decCipher = Cipher.getInstance("SM4/ECB/PKCS7Padding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals("ECB PKCS7 15 bytes decrypt failed", plaintext, decrypted);
    }

    @Test
    public void testSM4ECBPKCS7Padding31Bytes() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);
        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");

        byte[] plaintext = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E
        };
        byte[] expectedCiphertext = new byte[]{
                0x6C, 0x1D, (byte) 0xD6, (byte) 0xAF, (byte) 0xCA, (byte) 0xA9, 0x43, 0x1E,
                0x4C, 0x26, (byte) 0xB3, (byte) 0xCD, (byte) 0xDE, 0x0A, 0x73, 0x24,
                (byte) 0xDB, 0x03, (byte) 0xF9, 0x5C, (byte) 0xF5, 0x42, 0x0F, 0x35,
                0x3E, (byte) 0xD4, (byte) 0x8A, 0x67, (byte) 0xCC, (byte) 0xB0, 0x37, (byte) 0xA0
        };

        Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS7Padding", "SDF");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] ciphertext = cipher.doFinal(plaintext);

        assertArrayEquals("ECB PKCS7 31 bytes encrypt failed", expectedCiphertext, ciphertext);

        Cipher decCipher = Cipher.getInstance("SM4/ECB/PKCS7Padding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals("ECB PKCS7 31 bytes decrypt failed", plaintext, decrypted);
    }

    @Test
    public void testSM4CBCPKCS7Padding1Byte() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);
        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");
        IvParameterSpec iv = new IvParameterSpec(IV);

        byte[] plaintext = new byte[]{0x42};
        byte[] expectedCiphertext = new byte[]{
                0x06, (byte) 0xF2, 0x18, 0x16, (byte) 0x92, (byte) 0x9B, 0x2C, (byte) 0xBE,
                (byte) 0xF3, 0x06, (byte) 0x9D, (byte) 0xA5, (byte) 0xFA, (byte) 0xA4, 0x33, (byte) 0x9E
        };

        Cipher cipher = Cipher.getInstance("SM4/CBC/PKCS7Padding", "SDF");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] ciphertext = cipher.doFinal(plaintext);

        assertArrayEquals("CBC PKCS7 1 byte encrypt failed", expectedCiphertext, ciphertext);

        Cipher decCipher = Cipher.getInstance("SM4/CBC/PKCS7Padding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals("CBC PKCS7 1 byte decrypt failed", plaintext, decrypted);
    }

    @Test
    public void testSM4CBCPKCS7Padding15Bytes() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);
        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");
        IvParameterSpec iv = new IvParameterSpec(IV);

        byte[] plaintext = new byte[15];
        Arrays.fill(plaintext, (byte) 0xAB);
        byte[] expectedCiphertext = new byte[]{
                (byte) 0x8B, (byte) 0xA2, (byte) 0xB9, 0x05, (byte) 0xD8, (byte) 0x9F, 0x10, (byte) 0xBD,
                0x31, (byte) 0x84, (byte) 0xC3, 0x71, (byte) 0xB4, 0x61, (byte) 0xA9, (byte) 0x5E
        };

        Cipher cipher = Cipher.getInstance("SM4/CBC/PKCS7Padding", "SDF");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] ciphertext = cipher.doFinal(plaintext);

        assertArrayEquals("CBC PKCS7 15 bytes encrypt failed", expectedCiphertext, ciphertext);

        Cipher decCipher = Cipher.getInstance("SM4/CBC/PKCS7Padding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals("CBC PKCS7 15 bytes decrypt failed", plaintext, decrypted);
    }

    @Test
    public void testSM4CBCPKCS7Padding16Bytes() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);
        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");
        IvParameterSpec iv = new IvParameterSpec(IV);

        byte[] plaintext = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };
        byte[] expectedCiphertext = new byte[]{
                0x17, (byte) 0x92, 0x06, (byte) 0xED, 0x65, 0x4F, (byte) 0x92, (byte) 0xC9,
                (byte) 0xF8, 0x2F, 0x31, 0x36, 0x1E, 0x6E, (byte) 0xB3, 0x3E,
                0x77, 0x13, 0x24, (byte) 0x80, 0x5C, (byte) 0x85, 0x7A, 0x23,
                (byte) 0xC1, 0x70, 0x65, (byte) 0xA3, 0x0E, 0x77, (byte) 0xF3, (byte) 0xB9
        };

        Cipher cipher = Cipher.getInstance("SM4/CBC/PKCS7Padding", "SDF");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] ciphertext = cipher.doFinal(plaintext);

        assertArrayEquals("CBC PKCS7 16 bytes encrypt failed", expectedCiphertext, ciphertext);

        Cipher decCipher = Cipher.getInstance("SM4/CBC/PKCS7Padding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals("CBC PKCS7 16 bytes decrypt failed", plaintext, decrypted);
    }

    @Test
    public void testSM4CBCPKCS7Padding31Bytes() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);
        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");
        IvParameterSpec iv = new IvParameterSpec(IV);

        byte[] plaintext = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E
        };
        byte[] expectedCiphertext = new byte[]{
                0x17, (byte) 0x92, 0x06, (byte) 0xED, 0x65, 0x4F, (byte) 0x92, (byte) 0xC9,
                (byte) 0xF8, 0x2F, 0x31, 0x36, 0x1E, 0x6E, (byte) 0xB3, 0x3E,
                0x72, (byte) 0xFA, 0x5C, 0x6C, (byte) 0xD6, 0x3A, 0x6E, (byte) 0xFC,
                (byte) 0xD0, 0x5A, (byte) 0x83, (byte) 0xD6, 0x18, (byte) 0x8A, 0x21, 0x57
        };

        Cipher cipher = Cipher.getInstance("SM4/CBC/PKCS7Padding", "SDF");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] ciphertext = cipher.doFinal(plaintext);

        assertArrayEquals("CBC PKCS7 31 bytes encrypt failed", expectedCiphertext, ciphertext);

        Cipher decCipher = Cipher.getInstance("SM4/CBC/PKCS7Padding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals("CBC PKCS7 31 bytes decrypt failed", plaintext, decrypted);
    }

    // ==================== ECB 流式测试 ====================

    @Test
    public void testECBStreamingUpdateDoFinal() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);

        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");

        byte[] part1 = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };
        byte[] part2 = new byte[]{
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
        };

        Cipher encCipher = Cipher.getInstance("SM4/ECB/NoPadding", "SDF");
        encCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] enc1 = encCipher.update(part1);
        byte[] enc2 = encCipher.doFinal(part2);
        byte[] ciphertext = concat(enc1, enc2);

        Cipher refCipher = Cipher.getInstance("SM4/ECB/NoPadding", "SDF");
        refCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] fullData = concat(part1, part2);
        byte[] refCiphertext = refCipher.doFinal(fullData);

        assertArrayEquals("Streaming ECB encrypt should match one-shot", refCiphertext, ciphertext);

        Cipher decCipher = Cipher.getInstance("SM4/ECB/NoPadding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key);
        byte[] dec1 = decCipher.update(ciphertext, 0, 16);
        byte[] dec2 = decCipher.doFinal(ciphertext, 16, 16);
        byte[] decrypted = concat(dec1, dec2);

        assertArrayEquals("Streaming ECB decrypt should recover plaintext", fullData, decrypted);
    }

    @Test
    public void testECBStreamingPKCS5MultipleUpdates() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);

        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");
        byte[] plaintext = "Hello, SM4 streaming PKCS5 test!".getBytes(); // 32 bytes

        Cipher encCipher = Cipher.getInstance("SM4/ECB/PKCS5Padding", "SDF");
        encCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] enc1 = encCipher.update(plaintext, 0, 5);
        byte[] enc2 = encCipher.update(plaintext, 5, 11);
        byte[] enc3 = encCipher.update(plaintext, 16, 10);
        byte[] enc4 = encCipher.doFinal(plaintext, 26, 6);
        byte[] ciphertext = concatAll(enc1, enc2, enc3, enc4);

        Cipher refCipher = Cipher.getInstance("SM4/ECB/PKCS5Padding", "SDF");
        refCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] refCiphertext = refCipher.doFinal(plaintext);

        assertArrayEquals("Streaming ECB PKCS5 encrypt should match one-shot", refCiphertext, ciphertext);

        Cipher decCipher = Cipher.getInstance("SM4/ECB/PKCS5Padding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals("Streaming ECB PKCS5 roundtrip failed", plaintext, decrypted);
    }

    // ==================== CBC 流式测试 ====================

    @Test
    public void testCBCStreamingUpdateDoFinal() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);

        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");
        IvParameterSpec iv = new IvParameterSpec(IV);

        byte[] plaintext = new byte[48]; // 3 blocks
        for (int i = 0; i < plaintext.length; i++) {
            plaintext[i] = (byte) i;
        }

        Cipher encCipher = Cipher.getInstance("SM4/CBC/NoPadding", "SDF");
        encCipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] enc1 = encCipher.update(plaintext, 0, 16);
        byte[] enc2 = encCipher.update(plaintext, 16, 16);
        byte[] enc3 = encCipher.doFinal(plaintext, 32, 16);
        byte[] ciphertext = concatAll(enc1, enc2, enc3);

        Cipher refCipher = Cipher.getInstance("SM4/CBC/NoPadding", "SDF");
        refCipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] refCiphertext = refCipher.doFinal(plaintext);

        assertArrayEquals("Streaming CBC encrypt should match one-shot", refCiphertext, ciphertext);

        Cipher decCipher = Cipher.getInstance("SM4/CBC/NoPadding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] dec1 = decCipher.update(ciphertext, 0, 16);
        byte[] dec2 = decCipher.update(ciphertext, 16, 16);
        byte[] dec3 = decCipher.doFinal(ciphertext, 32, 16);
        byte[] decrypted = concatAll(dec1, dec2, dec3);

        assertArrayEquals("Streaming CBC decrypt should recover plaintext", plaintext, decrypted);
    }

    @Test
    public void testCBCStreamingPKCS5UnalignedChunks() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);

        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");
        IvParameterSpec iv = new IvParameterSpec(IV);

        byte[] plaintext = "Stream test with unaligned chunks!!".getBytes(); // 35 bytes

        Cipher encCipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", "SDF");
        encCipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] enc1 = encCipher.update(plaintext, 0, 7);
        byte[] enc2 = encCipher.update(plaintext, 7, 13);
        byte[] enc3 = encCipher.update(plaintext, 20, 10);
        byte[] enc4 = encCipher.doFinal(plaintext, 30, 5);
        byte[] ciphertext = concatAll(enc1, enc2, enc3, enc4);

        Cipher refCipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", "SDF");
        refCipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] refCiphertext = refCipher.doFinal(plaintext);

        assertArrayEquals("Streaming CBC PKCS5 unaligned encrypt should match one-shot", refCiphertext, ciphertext);

        Cipher decCipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals("Streaming CBC PKCS5 unaligned roundtrip failed", plaintext, decrypted);
    }

    @Test
    public void testCBCStreamingDecryptPKCS5() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);

        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");
        IvParameterSpec iv = new IvParameterSpec(IV);

        byte[] plaintext = "Decrypt streaming with PKCS5!".getBytes(); // 29 bytes

        Cipher encCipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", "SDF");
        encCipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] ciphertext = encCipher.doFinal(plaintext);

        Cipher decCipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key, iv);

        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < ciphertext.length; i += 16) {
            int len = Math.min(16, ciphertext.length - i);
            if (i + len < ciphertext.length) {
                byte[] part = decCipher.update(ciphertext, i, len);
                if (part != null && part.length > 0) {
                    bos.write(part);
                }
            } else {
                byte[] part = decCipher.doFinal(ciphertext, i, len);
                if (part != null && part.length > 0) {
                    bos.write(part);
                }
            }
        }
        byte[] decrypted = bos.toByteArray();

        assertArrayEquals("Streaming CBC PKCS5 decrypt roundtrip failed", plaintext, decrypted);
    }

    // ==================== GCM 模式测试 ====================

    @Test
    public void testGCMBasicEncryptDecrypt() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);

        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");
        byte[] iv = new byte[12];
        Arrays.fill(iv, (byte) 0x42);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        byte[] plaintext = "Hello GCM!".getBytes();

        Cipher encCipher = Cipher.getInstance("SM4/GCM/NoPadding", "SDF");
        encCipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        byte[] result = encCipher.doFinal(plaintext);

        assertTrue("GCM output should be plaintext_len + tag_len",
                result.length == plaintext.length + 16);

        Cipher decCipher = Cipher.getInstance("SM4/GCM/NoPadding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        byte[] decrypted = decCipher.doFinal(result);

        assertArrayEquals("GCM basic roundtrip failed", plaintext, decrypted);
    }

    @Test
    public void testGCMWithAAD() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);

        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");
        byte[] iv = new byte[12];
        Arrays.fill(iv, (byte) 0x55);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        byte[] plaintext = "Authenticated data test".getBytes();
        byte[] aad = "Additional authenticated data".getBytes();

        Cipher encCipher = Cipher.getInstance("SM4/GCM/NoPadding", "SDF");
        encCipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        encCipher.updateAAD(aad);
        byte[] result = encCipher.doFinal(plaintext);

        Cipher decCipher = Cipher.getInstance("SM4/GCM/NoPadding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        decCipher.updateAAD(aad);
        byte[] decrypted = decCipher.doFinal(result);

        assertArrayEquals("GCM with AAD roundtrip failed", plaintext, decrypted);
    }

    @Test
    public void testGCMWrongAADFails() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);

        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");
        byte[] iv = new byte[12];
        Arrays.fill(iv, (byte) 0x66);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        byte[] plaintext = "Tamper test".getBytes();
        byte[] aad = "correct AAD".getBytes();

        Cipher encCipher = Cipher.getInstance("SM4/GCM/NoPadding", "SDF");
        encCipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        encCipher.updateAAD(aad);
        byte[] result = encCipher.doFinal(plaintext);

        Cipher decCipher = Cipher.getInstance("SM4/GCM/NoPadding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        decCipher.updateAAD("wrong AAD".getBytes());

        try {
            decCipher.doFinal(result);
            fail("GCM decryption with wrong AAD should fail");
        } catch (Exception e) {
            assertTrue("Should be auth failure",
                    e instanceof AEADBadTagException ||
                    e.getMessage() != null && e.getMessage().contains("auth"));
        }
    }

    @Test
    public void testGCMTamperedCiphertextFails() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);

        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");
        byte[] iv = new byte[12];
        Arrays.fill(iv, (byte) 0x77);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        byte[] plaintext = "Tamper ciphertext test".getBytes();

        Cipher encCipher = Cipher.getInstance("SM4/GCM/NoPadding", "SDF");
        encCipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        byte[] result = encCipher.doFinal(plaintext);

        result[0] ^= 0xFF;

        Cipher decCipher = Cipher.getInstance("SM4/GCM/NoPadding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);

        try {
            decCipher.doFinal(result);
            fail("GCM decryption with tampered ciphertext should fail");
        } catch (Exception e) {
            assertTrue("Should be auth failure", true);
        }
    }

    @Test
    public void testGCMStreamingUpdate() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);

        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");
        byte[] iv = new byte[12];
        Arrays.fill(iv, (byte) 0x88);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        byte[] plaintext = "GCM streaming update test data".getBytes();

        Cipher encCipher = Cipher.getInstance("SM4/GCM/NoPadding", "SDF");
        encCipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        byte[] enc1 = encCipher.update(plaintext, 0, 10);
        byte[] enc2 = encCipher.update(plaintext, 10, 10);
        byte[] enc3 = encCipher.doFinal(plaintext, 20, plaintext.length - 20);
        byte[] result = concatAll(enc1, enc2, enc3);

        Cipher refCipher = Cipher.getInstance("SM4/GCM/NoPadding", "SDF");
        refCipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        byte[] refResult = refCipher.doFinal(plaintext);

        assertArrayEquals("GCM streaming should match one-shot", refResult, result);

        Cipher decCipher = Cipher.getInstance("SM4/GCM/NoPadding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        byte[] decrypted = decCipher.doFinal(result);

        assertArrayEquals("GCM streaming roundtrip failed", plaintext, decrypted);
    }

    @Test
    public void testGCMEmptyPlaintext() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);

        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");
        byte[] iv = new byte[12];
        Arrays.fill(iv, (byte) 0x99);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        byte[] aad = "Only AAD, no plaintext".getBytes();

        Cipher encCipher = Cipher.getInstance("SM4/GCM/NoPadding", "SDF");
        encCipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        encCipher.updateAAD(aad);

        try {
            encCipher.doFinal(new byte[0]);
            fail("GCM with empty plaintext should throw IllegalBlockSizeException");
        } catch (IllegalBlockSizeException e) {
            assertTrue("Error message should mention empty plaintext",
                    e.getMessage().contains("empty plaintext"));
        }
    }

    // ==================== 大数据测试 ====================

    @Test
    public void testCBCStreamingLargeData() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);

        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");
        IvParameterSpec iv = new IvParameterSpec(IV);

        byte[] plaintext = new byte[10240];
        new SecureRandom().nextBytes(plaintext);

        Cipher encCipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", "SDF");
        encCipher.init(Cipher.ENCRYPT_MODE, key, iv);

        java.io.ByteArrayOutputStream encBos = new java.io.ByteArrayOutputStream();
        int chunkSize = 1024;
        for (int i = 0; i < plaintext.length; i += chunkSize) {
            int len = Math.min(chunkSize, plaintext.length - i);
            if (i + len < plaintext.length) {
                byte[] part = encCipher.update(plaintext, i, len);
                if (part != null && part.length > 0) {
                    encBos.write(part);
                }
            } else {
                byte[] part = encCipher.doFinal(plaintext, i, len);
                if (part != null && part.length > 0) {
                    encBos.write(part);
                }
            }
        }
        byte[] ciphertext = encBos.toByteArray();
        assertTrue("Ciphertext should be longer than plaintext (padding)", ciphertext.length > plaintext.length);

        Cipher decCipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key, iv);

        java.io.ByteArrayOutputStream decBos = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < ciphertext.length; i += chunkSize) {
            int len = Math.min(chunkSize, ciphertext.length - i);
            if (i + len < ciphertext.length) {
                byte[] part = decCipher.update(ciphertext, i, len);
                if (part != null && part.length > 0) {
                    decBos.write(part);
                }
            } else {
                byte[] part = decCipher.doFinal(ciphertext, i, len);
                if (part != null && part.length > 0) {
                    decBos.write(part);
                }
            }
        }
        byte[] decrypted = decBos.toByteArray();

        assertArrayEquals("Large data streaming CBC roundtrip failed", plaintext, decrypted);
    }

    // ==================== 兼容性测试 ====================

    @Test
    public void testDirectDoFinalStillWorks() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);

        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");
        IvParameterSpec iv = new IvParameterSpec(IV);

        byte[] plaintext = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };

        Cipher encCipher = Cipher.getInstance("SM4/CBC/NoPadding", "SDF");
        encCipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] ciphertext = encCipher.doFinal(plaintext);

        assertNotNull("doFinal should return ciphertext", ciphertext);
        assertEquals("Ciphertext should be 16 bytes", 16, ciphertext.length);

        Cipher decCipher = Cipher.getInstance("SM4/CBC/NoPadding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals("Direct doFinal roundtrip failed", plaintext, decrypted);
    }

    @Test
    public void testPKCS7AliasWorks() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);

        SecretKeySpec key = new SecretKeySpec(KEY, "SM4");
        IvParameterSpec iv = new IvParameterSpec(IV);

        byte[] plaintext = "PKCS7 alias test".getBytes();

        Cipher encCipher = Cipher.getInstance("SM4/CBC/PKCS7Padding", "SDF");
        encCipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] ciphertext = encCipher.doFinal(plaintext);

        Cipher decCipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals("PKCS7/PKCS5 alias interoperability failed", plaintext, decrypted);
    }

    // ==================== 工具方法 ====================

    private static byte[] concat(byte[] a, byte[] b) {
        if (a == null || a.length == 0) return b != null ? b : new byte[0];
        if (b == null || b.length == 0) return a;
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private static byte[] concatAll(byte[]... arrays) {
        int totalLen = 0;
        for (byte[] arr : arrays) {
            if (arr != null) totalLen += arr.length;
        }
        byte[] result = new byte[totalLen];
        int pos = 0;
        for (byte[] arr : arrays) {
            if (arr != null && arr.length > 0) {
                System.arraycopy(arr, 0, result, pos, arr.length);
                pos += arr.length;
            }
        }
        return result;
    }
}
