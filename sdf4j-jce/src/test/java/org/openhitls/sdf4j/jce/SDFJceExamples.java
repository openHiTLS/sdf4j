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

/**
 * Example usage of SDF JCE Provider.
 * This class demonstrates how to use the SDF JCE Provider APIs.
 *
 * <p>Usage Examples:</p>
 *
 * <h2>1. Initialize Provider</h2>
 * <pre>{@code
 * // Create and register provider
 * SDFProvider provider = new SDFProvider("/path/to/libsdf.so", 16);
 * Security.addProvider(provider);
 *
 * // Or register without initialization (initialize later)
 * SDFProvider provider = new SDFProvider();
 * Security.addProvider(provider);
 * provider.initialize("/path/to/libsdf.so", 16);
 * }</pre>
 *
 * <h2>2. SM3 Message Digest</h2>
 * <pre>{@code
 * MessageDigest md = MessageDigest.getInstance("SM3", "SDF");
 * byte[] hash = md.digest("Hello".getBytes());
 * }</pre>
 *
 * <h2>3. SM4 Symmetric Encryption</h2>
 * <pre>{@code
 * // Generate key
 * KeyGenerator kg = KeyGenerator.getInstance("SM4", "SDF");
 * SecretKey key = kg.generateKey();
 *
 * // Encrypt
 * Cipher cipher = Cipher.getInstance("SM4/CBC/NoPadding", "SDF");
 * cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
 * byte[] ciphertext = cipher.doFinal(plaintext);
 *
 * // Decrypt
 * cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
 * byte[] decrypted = cipher.doFinal(ciphertext);
 * }</pre>
 *
 * <h2>4. SM2 Signature</h2>
 * <pre>{@code
 * // Generate key pair
 * KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "SDF");
 * kpg.initialize(256);
 * KeyPair keyPair = kpg.generateKeyPair();
 *
 * // Sign
 * Signature signer = Signature.getInstance("SM3withSM2", "SDF");
 * signer.initSign(keyPair.getPrivate());
 * signer.update(data);
 * byte[] signature = signer.sign();
 *
 * // Verify
 * Signature verifier = Signature.getInstance("SM3withSM2", "SDF");
 * verifier.initVerify(keyPair.getPublic());
 * verifier.update(data);
 * boolean valid = verifier.verify(signature);
 * }</pre>
 *
 * <h2>5. SM2 Encryption</h2>
 * <pre>{@code
 * // Encrypt with public key
 * Cipher cipher = Cipher.getInstance("SM2", "SDF");
 * cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
 * byte[] ciphertext = cipher.doFinal(plaintext);
 *
 * // Decrypt with private key
 * cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
 * byte[] decrypted = cipher.doFinal(ciphertext);
 * }</pre>
 *
 * <h2>6. Hardware Random Number Generation</h2>
 * <pre>{@code
 * SecureRandom sr = SecureRandom.getInstance("SDF", "SDF");
 * byte[] random = new byte[32];
 * sr.nextBytes(random);
 * }</pre>
 *
 * <h2>7. HMAC-SM3</h2>
 * <pre>{@code
 * Mac mac = Mac.getInstance("HmacSM3", "SDF");
 * mac.init(new SecretKeySpec(keyBytes, "HmacSM3"));
 * byte[] hmac = mac.doFinal(data);
 * }</pre>
 */
public class SDFJceExamples {

    /**
     * Example: Complete workflow demonstration
     */
    public static void main(String[] args) {
        // Check for library path
        String libraryPath = System.getenv("SDF_LIBRARY_PATH");
        if (libraryPath == null) {
            System.out.println("Set SDF_LIBRARY_PATH environment variable to run examples");
            System.out.println("Example: export SDF_LIBRARY_PATH=/opt/sdf/lib/libsdf.so");
            return;
        }

        SDFProvider provider = null;
        try {
            // 1. Initialize provider
            System.out.println("=== Initializing SDF JCE Provider ===");
            provider = new SDFProvider(libraryPath, 8);
            Security.addProvider(provider);
            System.out.println("Provider initialized successfully");
            System.out.println("Pool stats: total=" + provider.getPoolStats()[0] +
                    ", available=" + provider.getPoolStats()[1]);

            // 2. SM3 Hash
            System.out.println("\n=== SM3 Hash ===");
            demonstrateSM3();

            // 3. SM4 Encryption
            System.out.println("\n=== SM4 Encryption ===");
            demonstrateSM4();

            // 4. SM2 Signature
            System.out.println("\n=== SM2 Signature ===");
            demonstrateSM2Signature();

            // 5. SM2 Encryption
            System.out.println("\n=== SM2 Encryption ===");
            demonstrateSM2Encryption();

            // 6. SecureRandom
            System.out.println("\n=== Hardware Random ===");
            demonstrateSecureRandom();

            // 7. HMAC
            System.out.println("\n=== HMAC-SM3 ===");
            demonstrateHmacSM3();

            System.out.println("\n=== All examples completed successfully! ===");

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            if (provider != null) {
                provider.shutdown();
                Security.removeProvider("SDF");
            }
        }
    }

    private static void demonstrateSM3() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SM3", "SDF");

        String message = "Hello, SM3!";
        byte[] hash = md.digest(message.getBytes());

        System.out.println("Message: " + message);
        System.out.println("SM3 Hash: " + bytesToHex(hash));
        System.out.println("Hash length: " + hash.length + " bytes");
    }

    private static void demonstrateSM4() throws Exception {
        // Generate key
        KeyGenerator kg = KeyGenerator.getInstance("SM4", "SDF");
        SecretKey key = kg.generateKey();

        // Prepare IV
        byte[] iv = new byte[16];
        SecureRandom.getInstance("SDF", "SDF").nextBytes(iv);

        // Prepare plaintext (must be multiple of 16 for NoPadding)
        byte[] plaintext = "Hello, SM4 CBC!!".getBytes(); // 16 bytes

        // Encrypt
        Cipher encCipher = Cipher.getInstance("SM4/CBC/NoPadding", "SDF");
        encCipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] ciphertext = encCipher.doFinal(plaintext);

        // Decrypt
        Cipher decCipher = Cipher.getInstance("SM4/CBC/NoPadding", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] decrypted = decCipher.doFinal(ciphertext);

        System.out.println("Plaintext: " + new String(plaintext));
        System.out.println("Ciphertext: " + bytesToHex(ciphertext));
        System.out.println("Decrypted: " + new String(decrypted));
        System.out.println("Match: " + Arrays.equals(plaintext, decrypted));
    }

    private static void demonstrateSM2Signature() throws Exception {
        // Generate key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "SDF");
        kpg.initialize(256);
        KeyPair keyPair = kpg.generateKeyPair();

        byte[] data = "Data to be signed".getBytes();

        // Sign
        Signature signer = Signature.getInstance("SM3withSM2", "SDF");
        signer.initSign(keyPair.getPrivate());
        signer.update(data);
        byte[] signature = signer.sign();

        // Verify
        Signature verifier = Signature.getInstance("SM3withSM2", "SDF");
        verifier.initVerify(keyPair.getPublic());
        verifier.update(data);
        boolean valid = verifier.verify(signature);

        System.out.println("Data: " + new String(data));
        System.out.println("Signature: " + bytesToHex(signature));
        System.out.println("Signature length: " + signature.length + " bytes");
        System.out.println("Verification: " + (valid ? "PASSED" : "FAILED"));
    }

    private static void demonstrateSM2Encryption() throws Exception {
        // Generate key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "SDF");
        kpg.initialize(256);
        KeyPair keyPair = kpg.generateKeyPair();

        byte[] plaintext = "Secret message for SM2".getBytes();

        // Encrypt
        Cipher encCipher = Cipher.getInstance("SM2", "SDF");
        encCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] ciphertext = encCipher.doFinal(plaintext);

        // Decrypt
        Cipher decCipher = Cipher.getInstance("SM2", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decrypted = decCipher.doFinal(ciphertext);

        System.out.println("Plaintext: " + new String(plaintext));
        System.out.println("Ciphertext length: " + ciphertext.length + " bytes");
        System.out.println("Decrypted: " + new String(decrypted));
        System.out.println("Match: " + Arrays.equals(plaintext, decrypted));
    }

    private static void demonstrateSecureRandom() throws Exception {
        SecureRandom sr = SecureRandom.getInstance("SDF", "SDF");

        byte[] random = new byte[32];
        sr.nextBytes(random);

        System.out.println("Random bytes: " + bytesToHex(random));
        System.out.println("Length: " + random.length + " bytes");
    }

    private static void demonstrateHmacSM3() throws Exception {
        // Generate a key
        byte[] keyBytes = new byte[32];
        SecureRandom.getInstance("SDF", "SDF").nextBytes(keyBytes);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "HmacSM3");

        byte[] data = "Data for HMAC".getBytes();

        Mac mac = Mac.getInstance("HmacSM3", "SDF");
        mac.init(key);
        byte[] hmac = mac.doFinal(data);

        System.out.println("Data: " + new String(data));
        System.out.println("HMAC-SM3: " + bytesToHex(hmac));
        System.out.println("HMAC length: " + hmac.length + " bytes");
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
