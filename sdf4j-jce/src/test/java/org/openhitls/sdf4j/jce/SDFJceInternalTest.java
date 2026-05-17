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
import java.io.InputStream;
import java.security.*;
import java.util.Arrays;
import java.util.Properties;

import org.openhitls.sdf4j.jce.key.SDFInternalPrivateKey;
import org.openhitls.sdf4j.jce.key.SDFInternalPublicKey;
import org.openhitls.sdf4j.jce.key.SDFInternalSymmetricKey;

/**
 * Integration tests for SDF JCE Provider Internal key operations.
 *
 * These tests require:
 * 1. An SDF device/library to be available (set SDF_LIBRARY_PATH env var)
 * 2. Pre-provisioned internal keys at indices specified in test-config.properties
 *
 * Configuration is loaded from test-config.properties on classpath.
 */
public class SDFJceInternalTest {

    private static SDFProvider provider;
    private static boolean initialized = false;

    // SM2 Internal key config
    private static int sm2KeyIndex;
    private static String sm2Password;
    private static String sm2UserId;

    // SM4 Internal key config (KEK)
    private static int sm4KekIndex;
    private static String sm4KekPassword;

    @BeforeClass
    public static void setUpClass() {
        // Load test configuration
        Properties props = new Properties();
        try (InputStream is = SDFJceInternalTest.class.getClassLoader()
                .getResourceAsStream("test-config.properties")) {
            if (is != null) {
                props.load(is);
            }
        } catch (Exception e) {
            System.err.println("Failed to load test-config.properties: " + e.getMessage());
        }

        sm2KeyIndex = Integer.parseInt(props.getProperty("sm2.internal.key.index", "1"));
        sm2Password = props.getProperty("sm2.key.access.password", "");
        sm2UserId = props.getProperty("sm2.default.user.id", "1234567812345678");
        sm4KekIndex = Integer.parseInt(props.getProperty("sm4.internal.key.index", "4"));
        sm4KekPassword = props.getProperty("sm4.key.access.password", "");

        try {
            provider = new SDFProvider();
            Security.addProvider(provider);
            initialized = true;
        } catch (Throwable e) {
            System.err.println("Failed to initialize SDF JCE Provider: " + e.getMessage());
            e.printStackTrace();
            initialized = false;
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

    // ==================== SM2 Internal Signature Tests ====================

    @Test
    public void testSM2InternalSignVerify() throws Exception {
        try {
            // Create Internal private key for signing
            SDFInternalPrivateKey privKey = new SDFInternalPrivateKey(
                sm2KeyIndex, sm2Password.toCharArray(), SDFInternalPrivateKey.KeyUsage.SIGN);

            // Sign
            Signature signer = Signature.getInstance("SM3withSM2", "SDF");
            signer.initSign(privKey);

            byte[] data = "Hello, Internal SM2 Signature!".getBytes();
            signer.update(data);
            byte[] signature = signer.sign();

            assertNotNull("Signature should not be null", signature);
            assertTrue("Signature should not be empty", signature.length > 0);

            // Verify using Internal public key
            SDFInternalPublicKey pubKey = new SDFInternalPublicKey(
                sm2KeyIndex, SDFInternalPrivateKey.KeyUsage.SIGN);

            Signature verifier = Signature.getInstance("SM3withSM2", "SDF");
            verifier.initVerify(pubKey);
            verifier.update(data);
            boolean valid = verifier.verify(signature);

            assertTrue("Internal SM2 signature should be valid", valid);
        } catch (Exception e) {
            handleSdfException(e, "SM2 Internal SignVerify");
        }
    }

    @Test
    public void testSM2InternalSignVerifyFail() throws Exception {
        try {
            SDFInternalPrivateKey privKey = new SDFInternalPrivateKey(
                sm2KeyIndex, sm2Password.toCharArray(), SDFInternalPrivateKey.KeyUsage.SIGN);

            Signature signer = Signature.getInstance("SM3withSM2", "SDF");
            signer.initSign(privKey);
            signer.update("Original data".getBytes());
            byte[] signature = signer.sign();

            // Verify with different data should fail
            SDFInternalPublicKey pubKey = new SDFInternalPublicKey(
                sm2KeyIndex, SDFInternalPrivateKey.KeyUsage.SIGN);

            Signature verifier = Signature.getInstance("SM3withSM2", "SDF");
            verifier.initVerify(pubKey);
            verifier.update("Modified data".getBytes());
            boolean valid = verifier.verify(signature);

            assertFalse("Signature should be invalid for modified data", valid);
        } catch (Exception e) {
            handleSdfException(e, "SM2 Internal SignVerifyFail");
        }
    }

    @Test
    public void testSM2InternalSignWithCustomUserId() throws Exception {
        try {
            SDFInternalPrivateKey privKey = new SDFInternalPrivateKey(
                sm2KeyIndex, sm2Password.toCharArray(), SDFInternalPrivateKey.KeyUsage.SIGN);

            Signature signer = Signature.getInstance("SM3withSM2", "SDF");
            signer.initSign(privKey);

            byte[] data = "Custom user ID test".getBytes();
            signer.update(data);
            byte[] signature = signer.sign();

            assertNotNull(signature);
            assertTrue(signature.length > 0);
        } catch (Exception e) {
            handleSdfException(e, "SM2 Internal Sign Custom UserID");
        }
    }

    // ==================== SM2 Internal Encryption Tests ====================

    @Test
    public void testSM2InternalEncryptDecrypt() throws Exception {
        try {
            // Encrypt using Internal public key (encryption key slot)
            SDFInternalPublicKey pubKey = new SDFInternalPublicKey(
                sm2KeyIndex, SDFInternalPrivateKey.KeyUsage.ENCRYPT);
            SDFInternalPrivateKey privKey = new SDFInternalPrivateKey(
                sm2KeyIndex, sm2Password.toCharArray(), SDFInternalPrivateKey.KeyUsage.ENCRYPT);

            Cipher encCipher = Cipher.getInstance("SM2", "SDF");
            encCipher.init(Cipher.ENCRYPT_MODE, pubKey);

            byte[] plaintext = "Hello, Internal SM2 Encryption!".getBytes();
            byte[] ciphertext = encCipher.doFinal(plaintext);

            assertNotNull("Ciphertext should not be null", ciphertext);
            assertTrue("Ciphertext should be larger", ciphertext.length > plaintext.length);

            // Decrypt using Internal private key
            Cipher decCipher = Cipher.getInstance("SM2", "SDF");
            decCipher.init(Cipher.DECRYPT_MODE, privKey);
            byte[] decrypted = decCipher.doFinal(ciphertext);

            assertArrayEquals("Decrypted should match plaintext", plaintext, decrypted);
        } catch (Exception e) {
            handleSdfException(e, "SM2 Internal EncryptDecrypt");
        }
    }

    // ==================== SM2 Export Public Key Tests ====================

    @Test
    public void testSM2ExportSignPublicKey() throws Exception {
        try {
            long session = SDFJceNative.openSession();
            try {
                byte[] pubKeyBytes = SDFJceNative.exportSignPublicKeyECC(session, sm2KeyIndex);
                assertNotNull("Public key should not be null", pubKeyBytes);
                assertEquals("Public key should be 64 bytes (X||Y)", 64, pubKeyBytes.length);
            } finally {
                SDFJceNative.closeSession(session);
            }
        } catch (Exception e) {
            handleSdfException(e, "SM2 ExportSignPublicKey");
        }
    }

    // ==================== SM4 Internal (KEK) Tests ====================

    @Test
    public void testSM4InternalCBCEncryptDecrypt() throws Exception {
        try {
            SDFInternalSymmetricKey key = new SDFInternalSymmetricKey(
                sm4KekIndex, sm4KekPassword.toCharArray());

            byte[] iv = new byte[16];
            Arrays.fill(iv, (byte) 0x01);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            byte[] plaintext = new byte[32];
            Arrays.fill(plaintext, (byte) 0x42);

            // --- Encrypt ---
            Cipher encCipher = Cipher.getInstance("SM4/CBC/NoPadding", "SDF");
            encCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            byte[] ciphertext = encCipher.doFinal(plaintext);

            assertNotNull("Ciphertext should not be null", ciphertext);
            assertEquals("Ciphertext length should match plaintext length", 32, ciphertext.length);
            assertFalse("Ciphertext should differ from plaintext",
                Arrays.equals(plaintext, ciphertext));

            // After encryption the blob must have been stored in the key object.
            assertTrue("Encrypted key blob must be set after encryption",
                key.hasEncryptedKeyBlob());

            // --- Decrypt (reusing the same key object that holds the blob) ---
            Cipher decCipher = Cipher.getInstance("SM4/CBC/NoPadding", "SDF");
            decCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            byte[] decrypted = decCipher.doFinal(ciphertext);

            assertNotNull("Decrypted result should not be null", decrypted);
            assertArrayEquals("Decrypted plaintext must match original", plaintext, decrypted);
        } catch (Exception e) {
            handleSdfException(e, "SM4 Internal CBC EncryptDecrypt");
        }
    }


    @Test
    public void testSM4InternalCBCBlobTransfer() throws Exception {
        try {
            SDFInternalSymmetricKey encKey = new SDFInternalSymmetricKey(
                sm4KekIndex, sm4KekPassword.toCharArray());

            byte[] iv = new byte[16];
            new java.security.SecureRandom().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            byte[] plaintext = "KEK blob transfer test data!!!!!".getBytes("UTF-8"); // 32 bytes

            // --- Encrypt ---
            Cipher encCipher = Cipher.getInstance("SM4/CBC/NoPadding", "SDF");
            encCipher.init(Cipher.ENCRYPT_MODE, encKey, ivSpec);
            byte[] ciphertext = encCipher.doFinal(plaintext);

            // Retrieve the blob that must be transmitted to the decryption side.
            byte[] blob = encKey.getEncryptedKeyBlob();
            assertNotNull("Encrypted key blob must not be null after encryption", blob);
            assertTrue("Blob must be non-empty", blob.length > 0);

            // --- Simulate decryption side: create a brand-new key object with the blob ---
            SDFInternalSymmetricKey decKey = new SDFInternalSymmetricKey(
                sm4KekIndex, sm4KekPassword.toCharArray());
            decKey.setEncryptedKeyBlob(blob);

            Cipher decCipher = Cipher.getInstance("SM4/CBC/NoPadding", "SDF");
            decCipher.init(Cipher.DECRYPT_MODE, decKey, ivSpec);
            byte[] decrypted = decCipher.doFinal(ciphertext);

            assertArrayEquals("Decrypted plaintext must match original after blob transfer",
                plaintext, decrypted);
        } catch (Exception e) {
            handleSdfException(e, "SM4 Internal CBC BlobTransfer");
        }
    }

    @Test
    public void testSM4InternalCBCPkcs5PaddingEncryptDecrypt() throws Exception {
        try {
            SDFInternalSymmetricKey key = new SDFInternalSymmetricKey(
                sm4KekIndex, sm4KekPassword.toCharArray());

            byte[] iv = new byte[16];
            Arrays.fill(iv, (byte) 0x55);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // 20 bytes — intentionally not block-aligned to exercise PKCS5 padding
            byte[] plaintext = "Hello KEK PKCS5!!!!!".getBytes("UTF-8");
            assertEquals("Plaintext must be 20 bytes", 20, plaintext.length);

            // --- Encrypt ---
            Cipher encCipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", "SDF");
            encCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            byte[] ciphertext = encCipher.doFinal(plaintext);

            assertNotNull("Ciphertext should not be null", ciphertext);
            assertEquals("Padded ciphertext must be one full block (32 bytes)", 32, ciphertext.length);

            // --- Decrypt ---
            Cipher decCipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", "SDF");
            decCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            byte[] decrypted = decCipher.doFinal(ciphertext);

            assertArrayEquals("Decrypted plaintext must match original after PKCS5 unpadding",
                plaintext, decrypted);
        } catch (Exception e) {
            handleSdfException(e, "SM4 Internal CBC PKCS5Padding");
        }
    }

    // ==================== Key Type Tests (no device required) ====================

    @Test
    public void testSDFInternalPrivateKeyProperties() {
        SDFInternalPrivateKey key = new SDFInternalPrivateKey(
            1, "password".toCharArray(), SDFInternalPrivateKey.KeyUsage.SIGN);

        assertEquals("SM2", key.getAlgorithm());
        assertEquals("SDF_INTERNAL", key.getFormat());
        assertNull("Internal key should not be exportable", key.getEncoded());
        assertEquals(1, key.getKeyIndex());
        assertEquals(SDFInternalPrivateKey.KeyUsage.SIGN, key.getUsage());

        char[] pwd = key.getPassword();
        assertNotNull(pwd);
        assertArrayEquals("password".toCharArray(), pwd);

        key.destroy();
        assertNull("Password should be cleared after destroy", key.getPassword());
    }

    @Test
    public void testSDFInternalPublicKeyProperties() {
        SDFInternalPublicKey key = new SDFInternalPublicKey(
            1, SDFInternalPrivateKey.KeyUsage.SIGN);

        assertEquals("SM2", key.getAlgorithm());
        assertEquals("SDF_INTERNAL", key.getFormat());
        assertFalse("Coordinates should not be loaded yet", key.isLoaded());
        assertNull("Encoded should be null before loading", key.getEncoded());

        byte[] x = new byte[32], y = new byte[32];
        Arrays.fill(x, (byte) 0x01);
        Arrays.fill(y, (byte) 0x02);
        key.setCoordinates(x, y);

        assertTrue("Coordinates should be loaded", key.isLoaded());
        assertNotNull("Encoded should be non-null after loading", key.getEncoded());
        assertEquals(64, key.getEncoded().length);
    }

    @Test
    public void testSDFInternalSymmetricKeyProperties() {
        SDFInternalSymmetricKey key = new SDFInternalSymmetricKey(
            4, "password".toCharArray());

        assertEquals("SM4", key.getAlgorithm());
        assertEquals("SDF_INTERNAL", key.getFormat());
        assertNull("Internal key should not be exportable", key.getEncoded());
        assertEquals(4, key.getKekIndex());
        assertFalse("Blob should not be set on a fresh key", key.hasEncryptedKeyBlob());

        // Simulate a blob being stored (e.g. after encryption)
        key.setEncryptedKeyBlob(new byte[]{0x01, 0x02, 0x03});
        assertTrue("Blob should be present after setEncryptedKeyBlob", key.hasEncryptedKeyBlob());
        assertNotNull("getEncryptedKeyBlob() should return a copy", key.getEncryptedKeyBlob());

        key.destroy();
        assertNull("Password should be cleared after destroy", key.getPassword());
        assertNull("Encrypted key blob should be cleared after destroy", key.getEncryptedKeyBlob());
        assertFalse("hasEncryptedKeyBlob() should return false after destroy", key.hasEncryptedKeyBlob());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSDFInternalPrivateKeyInvalidIndex() {
        new SDFInternalPrivateKey(-1, null, SDFInternalPrivateKey.KeyUsage.SIGN);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSDFInternalPublicKeyInvalidIndex() {
        new SDFInternalPublicKey(-1, SDFInternalPrivateKey.KeyUsage.SIGN);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSDFInternalSymmetricKeyInvalidIndex() {
        new SDFInternalSymmetricKey(-1, null);
    }
}
