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

import org.junit.*;
import static org.junit.Assert.*;
import static org.junit.Assume.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;

import org.openhitls.sdf4j.jce.key.SM2PublicKey;
import org.openhitls.sdf4j.jce.spec.SM2ParameterSpec;

/**
 * Integration tests for SDF JCE Provider.
 * These tests require an SDF device/library to be available.
 *
 * Set environment variable SDF_LIBRARY_PATH to the SDF library path to run these tests.
 * If not set, tests will be skipped.
 */
public class SDFJceAlgorithmTest {

    private static SDFProvider provider;
    private static boolean initialized = false;
    private static KeyPair sm2KeyPair;

    @BeforeClass
    public static void setUpClass() {
        String libraryPath = System.getenv("SDF_LIBRARY_PATH");
        if (libraryPath == null || libraryPath.isEmpty()) {
            libraryPath = System.getProperty("sdf.library.path");
        }

        if (libraryPath != null && !libraryPath.isEmpty()) {
            try {
                provider = new SDFProvider(libraryPath);
                Security.addProvider(provider);
                initialized = true;
                // Reuse one SM2 KeyPair across all SM2 tests to reduce session usage
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "SDF");
                kpg.initialize(256);
                sm2KeyPair = kpg.generateKeyPair();
            } catch (Exception e) {
                System.err.println("Failed to initialize SDF JCE Provider: " + e.getMessage());
                initialized = false;
            }
        }
    }

    @AfterClass
    public static void tearDownClass() {
        if (provider != null) {
            provider.shutdown();
            Security.removeProvider("SDF");
        }
    }

    @Before
    public void checkInitialized() {
        assumeTrue("SDF device not available, skipping test", initialized);
    }

    @After
    public void cleanup() throws InterruptedException {
        // Force garbage collection to release SDF sessions
        System.gc();
        System.runFinalization();
    }

    /**
     * 统一异常处理：如果是 SDR_NOTSUPPORT 则跳过测试，否则打印并抛出
     */
    private void handleSdfException(Exception e, String testName) throws Exception {
        if (e instanceof SDFJceException) {
            SDFJceException sdfEx = (SDFJceException) e;
            if (sdfEx.getErrorCode() == SDFJceErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] " + testName + ": 操作不支持");
                Assume.assumeTrue(testName + " not supported", false);
                return;
            }
            System.err.println("[错误] " + testName + ": " + e.getMessage());
        }
        throw e;
    }

    @Test
    public void testSM3Digest() throws Exception {
        try {
            MessageDigest md = MessageDigest.getInstance("SM3", "SDF");

            byte[] data = "Hello, SM3!".getBytes();
            byte[] hash = md.digest(data);

            assertNotNull(hash);
            assertEquals("SM3 hash should be 32 bytes", 32, hash.length);
        } catch (Exception e) {
            handleSdfException(e, "SM3 Digest");
        }
    }

    @Test
    public void testSM3DigestStreaming() throws Exception {
        try {
            MessageDigest md = MessageDigest.getInstance("SM3", "SDF");

            md.update("Hello, ".getBytes());
            md.update("SM3!".getBytes());
            byte[] hash1 = md.digest();

            md.reset();
            byte[] hash2 = md.digest("Hello, SM3!".getBytes());

            assertArrayEquals("Streaming and one-shot should produce same hash", hash1, hash2);
        } catch (Exception e) {
            handleSdfException(e, "SM3 Streaming");
        }
    }

    @Test
    public void testSM3KnownVector() throws Exception {
        byte[] data = "abc".getBytes();
        String expectedHex = "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0";

        MessageDigest sdfMd = MessageDigest.getInstance("SM3", "SDF");
        byte[] sdfHash = sdfMd.digest(data);

        // 转换为十六进制字符串比较
        StringBuilder sdfHex = new StringBuilder();
        for (byte b : sdfHash) {
            sdfHex.append(String.format("%02X", b & 0xFF));
        }
        assertEquals("SDF SM3 should match known vector", expectedHex, sdfHex.toString());
    }

    @Test
    public void testSM3DigestEmpty() throws Exception {
        try {
            MessageDigest md = MessageDigest.getInstance("SM3", "SDF");
            byte[] hash = md.digest(new byte[0]);

            assertNotNull(hash);
            assertEquals(32, hash.length);
        } catch (Exception e) {
            handleSdfException(e, "SM3 Empty Digest");
        }
    }

    @Test
    public void testSM4ECB() throws Exception {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("SM4", "SDF");
            SecretKey key = kg.generateKey();

            Cipher encCipher = Cipher.getInstance("SM4/ECB/NoPadding", "SDF");
            encCipher.init(Cipher.ENCRYPT_MODE, key);

            byte[] plaintext = new byte[32]; // Must be multiple of block size
            Arrays.fill(plaintext, (byte) 0x42);

            byte[] ciphertext = encCipher.doFinal(plaintext);
            assertNotNull(ciphertext);
            assertEquals(32, ciphertext.length);
            assertFalse("Ciphertext should differ from plaintext",
                    Arrays.equals(plaintext, ciphertext));

            Cipher decCipher = Cipher.getInstance("SM4/ECB/NoPadding", "SDF");
            decCipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decrypted = decCipher.doFinal(ciphertext);

            assertArrayEquals("Decrypted should match plaintext", plaintext, decrypted);
        } catch (Exception e) {
            handleSdfException(e, "SM4 ECB");
        }
    }

    @Test
    public void testSM4CBC() throws Exception {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("SM4", "SDF");
            SecretKey key = kg.generateKey();

            byte[] iv = new byte[16];
            Arrays.fill(iv, (byte) 0x01);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            Cipher encCipher = Cipher.getInstance("SM4/CBC/NoPadding", "SDF");
            encCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

            byte[] plaintext = new byte[32];
            Arrays.fill(plaintext, (byte) 0x42);

            byte[] ciphertext = encCipher.doFinal(plaintext);

            Cipher decCipher = Cipher.getInstance("SM4/CBC/NoPadding", "SDF");
            decCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            byte[] decrypted = decCipher.doFinal(ciphertext);

            assertArrayEquals("Decrypted should match plaintext", plaintext, decrypted);
        } catch (Exception e) {
            handleSdfException(e, "SM4 CBC");
        }
    }

    @Test
    public void testSM4KeyGeneration() throws Exception {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("SM4", "SDF");
            SecretKey key = kg.generateKey();

            assertNotNull(key);
            assertEquals("SM4", key.getAlgorithm());
            assertEquals(16, key.getEncoded().length);
        } catch (Exception e) {
            handleSdfException(e, "SM4 KeyGeneration");
        }
    }

    // ==================== SM2 Signature Tests ====================

    @Test
    public void testSM2SignVerify() throws Exception {
        try {
            assertNotNull(sm2KeyPair);
            assertNotNull(sm2KeyPair.getPublic());
            assertNotNull(sm2KeyPair.getPrivate());

            Signature signer = Signature.getInstance("SM3withSM2", "SDF");
            signer.initSign(sm2KeyPair.getPrivate());
            signer.setParameter(new SM2ParameterSpec((SM2PublicKey) sm2KeyPair.getPublic()));

            byte[] data = "Test data for SM2 signature".getBytes();
            signer.update(data);
            byte[] signature = signer.sign();

            assertNotNull(signature);
            assertTrue("Signature should not be empty", signature.length > 0);

            Signature verifier = Signature.getInstance("SM3withSM2", "SDF");
            verifier.initVerify(sm2KeyPair.getPublic());
            verifier.update(data);
            boolean valid = verifier.verify(signature);

            assertTrue("Signature should be valid", valid);
        } catch (Exception e) {
            handleSdfException(e, "SM2 SignVerify");
        }
    }

    @Test
    public void testSM2SignVerifyFail() throws Exception {
        try {
            Signature signer = Signature.getInstance("SM3withSM2", "SDF");
            signer.initSign(sm2KeyPair.getPrivate());
            signer.setParameter(new SM2ParameterSpec((SM2PublicKey) sm2KeyPair.getPublic()));

            byte[] data = "Test data".getBytes();
            signer.update(data);
            byte[] signature = signer.sign();

            Signature verifier = Signature.getInstance("SM3withSM2", "SDF");
            verifier.initVerify(sm2KeyPair.getPublic());
            verifier.update("Modified data".getBytes());
            boolean valid = verifier.verify(signature);

            assertFalse("Signature should be invalid for modified data", valid);
        } catch (Exception e) {
            handleSdfException(e, "SM2 SignVerifyFail");
        }
    }

    @Test
    public void testSM2EncryptDecrypt() throws Exception {
        try {
            Cipher encCipher = Cipher.getInstance("SM2", "SDF");
            encCipher.init(Cipher.ENCRYPT_MODE, sm2KeyPair.getPublic());

            byte[] plaintext = "Hello, SM2 Encryption!".getBytes();
            byte[] ciphertext = encCipher.doFinal(plaintext);

            assertNotNull(ciphertext);
            assertTrue("Ciphertext should be larger than plaintext",
                    ciphertext.length > plaintext.length);

            Cipher decCipher = Cipher.getInstance("SM2", "SDF");
            decCipher.init(Cipher.DECRYPT_MODE, sm2KeyPair.getPrivate());
            byte[] decrypted = decCipher.doFinal(ciphertext);

            assertArrayEquals("Decrypted should match plaintext", plaintext, decrypted);
        } catch (Exception e) {
            handleSdfException(e, "SM2 EncryptDecrypt");
        }
    }

    // ==================== SecureRandom Tests ====================

    @Test
    public void testSecureRandom() throws Exception {
        try {
            SecureRandom sr = SecureRandom.getInstance("SDF", "SDF");

            byte[] random1 = new byte[32];
            byte[] random2 = new byte[32];

            sr.nextBytes(random1);
            sr.nextBytes(random2);

            assertFalse("Random bytes should be different",
                    Arrays.equals(random1, random2));
        } catch (Exception e) {
            handleSdfException(e, "SecureRandom");
        }
    }

    @Test
    public void testGenerateSeed() throws Exception {
        try {
            SecureRandom sr = SecureRandom.getInstance("SDF", "SDF");

            byte[] seed = sr.generateSeed(32);

            assertNotNull(seed);
            assertEquals(32, seed.length);
        } catch (Exception e) {
            handleSdfException(e, "GenerateSeed");
        }
    }

    // ==================== MAC Tests ====================

    @Test
    public void testHmacSM3() throws Exception {
        byte[] keyBytes = new byte[32];
        Arrays.fill(keyBytes, (byte) 0xAB);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "HmacSM3");

        Mac mac = Mac.getInstance("HmacSM3", "SDF");
        mac.init(key);

        byte[] data = "Test data for HMAC-SM3".getBytes();

        try {
            byte[] hmac1 = mac.doFinal(data);
            assertNotNull(hmac1);
            assertEquals("HMAC-SM3 should be 32 bytes", 32, hmac1.length);

            // Same input should produce same output
            byte[] hmac2 = mac.doFinal(data);
            assertArrayEquals("Same input should produce same HMAC", hmac1, hmac2);
        } catch (Exception e) {
            handleSdfException(e, "HMAC-SM3");
        }
    }

    @Test
    public void testSM4Mac() throws Exception {
        byte[] keyBytes = new byte[16];
        Arrays.fill(keyBytes, (byte) 0xCD);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "SM4-MAC");

        Mac mac = Mac.getInstance("SM4-MAC", "SDF");
        mac.init(key);

        byte[] data = "Test data for SM4-MAC".getBytes();

        try {
            byte[] macValue = mac.doFinal(data);
            assertNotNull(macValue);
            assertEquals("SM4-MAC should be 16 bytes", 16, macValue.length);
        } catch (Exception e) {
            handleSdfException(e, "SM4-MAC");
        }
    }

    // ==================== Initialization Status ====================

    @Test
    public void testInitializationStatus() {
        assertTrue("Provider should be initialized", provider.isInitialized());
    }
}
