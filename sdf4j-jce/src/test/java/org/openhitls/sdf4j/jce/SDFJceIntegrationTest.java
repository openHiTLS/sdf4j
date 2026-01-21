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

import org.openhitls.sdf4j.jce.key.SM2PrivateKey;
import org.openhitls.sdf4j.jce.key.SM2PublicKey;

/**
 * Integration tests for SDF JCE Provider.
 * These tests require an SDF device/library to be available.
 *
 * Set environment variable SDF_LIBRARY_PATH to the SDF library path to run these tests.
 * If not set, tests will be skipped.
 */
public class SDFJceIntegrationTest {

    private static SDFProvider provider;
    private static boolean initialized = false;

    @BeforeClass
    public static void setUpClass() {
        String libraryPath = System.getenv("SDF_LIBRARY_PATH");
        if (libraryPath == null || libraryPath.isEmpty()) {
            libraryPath = System.getProperty("sdf.library.path");
        }

        if (libraryPath != null && !libraryPath.isEmpty()) {
            try {
                provider = new SDFProvider(libraryPath, 4);
                Security.addProvider(provider);
                initialized = true;
                System.out.println("SDF JCE Provider initialized with library: " + libraryPath);
            } catch (Exception e) {
                System.err.println("Failed to initialize SDF JCE Provider: " + e.getMessage());
                initialized = false;
            }
        } else {
            System.out.println("SDF_LIBRARY_PATH not set, skipping integration tests");
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

    // ==================== SM3 Tests ====================

    @Test
    public void testSM3Digest() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SM3", "SDF");

        byte[] data = "Hello, SM3!".getBytes();
        byte[] hash = md.digest(data);

        assertNotNull(hash);
        assertEquals("SM3 hash should be 32 bytes", 32, hash.length);
    }

    @Test
    public void testSM3DigestStreaming() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SM3", "SDF");

        md.update("Hello, ".getBytes());
        md.update("SM3!".getBytes());
        byte[] hash1 = md.digest();

        md.reset();
        byte[] hash2 = md.digest("Hello, SM3!".getBytes());

        assertArrayEquals("Streaming and one-shot should produce same hash", hash1, hash2);
    }

    @Test
    public void testSM3DigestEmpty() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SM3", "SDF");
        byte[] hash = md.digest(new byte[0]);

        assertNotNull(hash);
        assertEquals(32, hash.length);
    }

    // ==================== SM4 Tests ====================

    @Test
    public void testSM4ECB() throws Exception {
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
    }

    @Test
    public void testSM4CBC() throws Exception {
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
    }

    @Test
    public void testSM4KeyGeneration() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("SM4", "SDF");
        SecretKey key = kg.generateKey();

        assertNotNull(key);
        assertEquals("SM4", key.getAlgorithm());
        assertEquals(16, key.getEncoded().length);
    }

    // ==================== SM2 Signature Tests ====================

    @Test
    public void testSM2SignVerify() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "SDF");
        kpg.initialize(256);
        KeyPair keyPair = kpg.generateKeyPair();

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());

        Signature signer = Signature.getInstance("SM3withSM2", "SDF");
        signer.initSign(keyPair.getPrivate());

        byte[] data = "Test data for SM2 signature".getBytes();
        signer.update(data);
        byte[] signature = signer.sign();

        assertNotNull(signature);
        assertTrue("Signature should not be empty", signature.length > 0);

        Signature verifier = Signature.getInstance("SM3withSM2", "SDF");
        verifier.initVerify(keyPair.getPublic());
        verifier.update(data);
        boolean valid = verifier.verify(signature);

        assertTrue("Signature should be valid", valid);
    }

    @Test
    public void testSM2SignVerifyFail() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "SDF");
        kpg.initialize(256);
        KeyPair keyPair = kpg.generateKeyPair();

        Signature signer = Signature.getInstance("SM3withSM2", "SDF");
        signer.initSign(keyPair.getPrivate());

        byte[] data = "Test data".getBytes();
        signer.update(data);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SM3withSM2", "SDF");
        verifier.initVerify(keyPair.getPublic());
        verifier.update("Modified data".getBytes());
        boolean valid = verifier.verify(signature);

        assertFalse("Signature should be invalid for modified data", valid);
    }

    // ==================== SM2 Encryption Tests ====================

    @Test
    public void testSM2EncryptDecrypt() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "SDF");
        kpg.initialize(256);
        KeyPair keyPair = kpg.generateKeyPair();

        Cipher encCipher = Cipher.getInstance("SM2", "SDF");
        encCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        byte[] plaintext = "Hello, SM2 Encryption!".getBytes();
        byte[] ciphertext = encCipher.doFinal(plaintext);

        assertNotNull(ciphertext);
        assertTrue("Ciphertext should be larger than plaintext",
                ciphertext.length > plaintext.length);

        Cipher decCipher = Cipher.getInstance("SM2", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals("Decrypted should match plaintext", plaintext, decrypted);
    }

    // ==================== SecureRandom Tests ====================

    @Test
    public void testSecureRandom() throws Exception {
        SecureRandom sr = SecureRandom.getInstance("SDF", "SDF");

        byte[] random1 = new byte[32];
        byte[] random2 = new byte[32];

        sr.nextBytes(random1);
        sr.nextBytes(random2);

        assertFalse("Random bytes should be different",
                Arrays.equals(random1, random2));
    }

    @Test
    public void testGenerateSeed() throws Exception {
        SecureRandom sr = SecureRandom.getInstance("SDF", "SDF");

        byte[] seed = sr.generateSeed(32);

        assertNotNull(seed);
        assertEquals(32, seed.length);
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
        byte[] hmac1 = mac.doFinal(data);

        assertNotNull(hmac1);
        assertEquals("HMAC-SM3 should be 32 bytes", 32, hmac1.length);

        // Same input should produce same output
        byte[] hmac2 = mac.doFinal(data);
        assertArrayEquals("Same input should produce same HMAC", hmac1, hmac2);
    }

    @Test
    public void testSM4Mac() throws Exception {
        byte[] keyBytes = new byte[16];
        Arrays.fill(keyBytes, (byte) 0xCD);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "SM4-MAC");

        Mac mac = Mac.getInstance("SM4-MAC", "SDF");
        mac.init(key);

        byte[] data = "Test data for SM4-MAC".getBytes();
        byte[] macValue = mac.doFinal(data);

        assertNotNull(macValue);
        assertEquals("SM4-MAC should be 16 bytes", 16, macValue.length);
    }

    // ==================== Pool Statistics ====================

    @Test
    public void testPoolStats() {
        int[] stats = provider.getPoolStats();

        assertNotNull(stats);
        assertEquals(2, stats.length);
        assertTrue("Total sessions should be positive", stats[0] > 0);
        assertTrue("Available sessions should be <= total", stats[1] <= stats[0]);
    }
}
