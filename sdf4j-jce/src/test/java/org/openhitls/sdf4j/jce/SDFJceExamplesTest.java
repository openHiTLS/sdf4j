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

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;

import org.junit.*;
import org.openhitls.sdf4j.jce.key.SM2PublicKey;
import org.openhitls.sdf4j.jce.spec.SM2ParameterSpec;
import static org.junit.Assert.*;
import static org.junit.Assume.*;

/**
 * Example usage of SDF JCE Provider as JUnit tests.
 * This class demonstrates how to use the SDF JCE Provider APIs.
 *
 * <p>Usage:
 * <pre>
 * // Set environment variable: export SDF_LIBRARY_PATH=/path/to/libsdf.so
 * // SDF is automatically initialized when native library loads
 * SDFProvider provider = new SDFProvider();
 * Security.addProvider(provider);
 * </pre>
 */
public class SDFJceExamplesTest {

    private static SDFProvider provider;
    private static boolean initialized = false;
    private static KeyPair sm2KeyPair;

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
                // Reuse one SM2 KeyPair across SM2 tests to reduce session usage
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
        System.gc();
        System.runFinalization();
    }

    // ==================== SM3 Hash ====================

    @Test
    public void testSM3Hash() throws Exception {
        try {
            MessageDigest md = MessageDigest.getInstance("SM3", "SDF");

            String message = "Hello, SM3!";
            byte[] hash = md.digest(message.getBytes());

            assertNotNull(hash);
            assertEquals("SM3 hash should be 32 bytes", 32, hash.length);

        } catch (Exception e) {
            handleSdfException(e, "SM3 Hash");
        }
    }

    // ==================== SM4 Encryption ====================

    @Test
    public void testSM4Encryption() throws Exception {
        try {

            // Generate key
            KeyGenerator kg = KeyGenerator.getInstance("SM4", "SDF");
            SecretKey key = kg.generateKey();
            assertNotNull(key);

            // Prepare IV
            byte[] iv = new byte[16];
            SecureRandom.getInstance("SDF", "SDF").nextBytes(iv);

            // Prepare plaintext (must be multiple of 16 for NoPadding)
            byte[] plaintext = "Hello, SM4 CBC!!".getBytes(); // 16 bytes

            // Encrypt
            Cipher encCipher = Cipher.getInstance("SM4/CBC/NoPadding", "SDF");
            encCipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] ciphertext = encCipher.doFinal(plaintext);
            assertNotNull(ciphertext);

            // Decrypt
            Cipher decCipher = Cipher.getInstance("SM4/CBC/NoPadding", "SDF");
            decCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] decrypted = decCipher.doFinal(ciphertext);

            assertArrayEquals("Decrypted should match plaintext", plaintext, decrypted);

        } catch (Exception e) {
            handleSdfException(e, "SM4 Encryption");
        }
    }

    // ==================== SM2 Signature ====================

    @Test
    public void testSM2Signature() throws Exception {
        try {
            assertNotNull(sm2KeyPair);

            byte[] data = "Data to be signed".getBytes();

            // Sign
            Signature signer = Signature.getInstance("SM3withSM2", "SDF");
            signer.initSign(sm2KeyPair.getPrivate());
            signer.setParameter(new SM2ParameterSpec((SM2PublicKey) sm2KeyPair.getPublic()));
            signer.update(data);
            byte[] signature = signer.sign();
            assertNotNull(signature);
            assertTrue("Signature should not be empty", signature.length > 0);

            // Verify
            Signature verifier = Signature.getInstance("SM3withSM2", "SDF");
            verifier.initVerify(sm2KeyPair.getPublic());
            verifier.update(data);
            boolean valid = verifier.verify(signature);

            assertTrue("Signature should be valid", valid);
        } catch (Exception e) {
            handleSdfException(e, "SM2 Signature");
        }
    }

    // ==================== SM2 Encryption ====================

    @Test
    public void testSM2Encryption() throws Exception {
        try {
            byte[] plaintext = "Secret message for SM2".getBytes();

            // Encrypt
            Cipher encCipher = Cipher.getInstance("SM2", "SDF");
            encCipher.init(Cipher.ENCRYPT_MODE, sm2KeyPair.getPublic());
            byte[] ciphertext = encCipher.doFinal(plaintext);
            assertNotNull(ciphertext);

            // Decrypt
            Cipher decCipher = Cipher.getInstance("SM2", "SDF");
            decCipher.init(Cipher.DECRYPT_MODE, sm2KeyPair.getPrivate());
            byte[] decrypted = decCipher.doFinal(ciphertext);

            assertArrayEquals("Decrypted should match plaintext", plaintext, decrypted);

        } catch (Exception e) {
            handleSdfException(e, "SM2 Encryption");
        }
    }

    // ==================== Hardware Random ====================

    @Test
    public void testSecureRandom() throws Exception {
        try {
            SecureRandom sr = SecureRandom.getInstance("SDF", "SDF");

            byte[] random = new byte[32];
            sr.nextBytes(random);

            assertNotNull(random);
            // Check not all zeros
            boolean allZero = true;
            for (byte b : random) {
                if (b != 0) { allZero = false; break; }
            }
            assertFalse("Random bytes should not be all zeros", allZero);
        } catch (Exception e) {
            handleSdfException(e, "SecureRandom");
        }
    }

    // ==================== HMAC-SM3 ====================

    @Test
    public void testHmacSM3() throws Exception {
        try {
            // Generate a key
            byte[] keyBytes = new byte[32];
            SecureRandom.getInstance("SDF", "SDF").nextBytes(keyBytes);
            SecretKeySpec key = new SecretKeySpec(keyBytes, "HmacSM3");

            byte[] data = "Data for HMAC".getBytes();

            Mac mac = Mac.getInstance("HmacSM3", "SDF");
            mac.init(key);
            byte[] hmac = mac.doFinal(data);

            assertNotNull(hmac);
            assertEquals("HMAC-SM3 should be 32 bytes", 32, hmac.length);
        } catch (Exception e) {
            handleSdfException(e, "HMAC-SM3");
        }
    }
}
