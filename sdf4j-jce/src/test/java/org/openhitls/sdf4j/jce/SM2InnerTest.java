/*
 * Copyright (c) 2025 OpenHitls
 * SDF4J is licensed under Mulan PSL v2.
 * You can obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

package org.openhitls.sdf4j.jce;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

import java.security.*;
import java.util.Arrays;

import org.openhitls.sdf4j.jce.key.SM2PublicKey;
import org.openhitls.sdf4j.jce.key.SM2PrivateKey;
import org.openhitls.sdf4j.jce.spec.SM2ParameterSpec;
import org.openhitls.sdf4j.jce.util.DERCodec;

import javax.crypto.Cipher;

/**
 * SM2 测试
 *
 */
public class SM2InnerTest {

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
                Security.addProvider(new SDFProvider());
                initialized = true;
                // Reuse one KeyPairGenerator and KeyPair across SM2 tests
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "SDF");
                sm2KeyPair = kpg.generateKeyPair();
            } catch (Exception e) {
                System.err.println("Failed to initialize provider: " + e.getMessage());
            }
        }
    }

    @After
    public void cleanup() throws InterruptedException {
        System.gc();
        System.runFinalization();
    }

    @Test
    public void testSDFSignatureIsDER() throws Exception {
        SM2PublicKey sdfPubKey = (SM2PublicKey) sm2KeyPair.getPublic();
        java.security.PrivateKey sdfPrivKey = sm2KeyPair.getPrivate();

        byte[] data = "Test data for signature".getBytes();

        java.security.Signature signer = java.security.Signature.getInstance("SM3withSM2", "SDF");
        signer.initSign(sdfPrivKey);
        signer.setParameter(new SM2ParameterSpec(sdfPubKey));
        signer.update(data);
        byte[] signature = signer.sign();

        // SDF 输出 DER 格式
        assertEquals("SDF signature should start with SEQUENCE tag", 0x30, signature[0] & 0xFF);
        assertTrue("DER signature should be longer than 64 bytes", signature.length > 64);
    }

    @Test
    public void testSDFVerifyOwnSignature() throws Exception {
        SM2PublicKey sdfPubKey = (SM2PublicKey) sm2KeyPair.getPublic();
        java.security.PrivateKey sdfPrivKey = sm2KeyPair.getPrivate();

        byte[] data = "Test data for verification".getBytes();

        // SDF 签名 (DER 格式)
        java.security.Signature signer = java.security.Signature.getInstance("SM3withSM2", "SDF");
        signer.initSign(sdfPrivKey);
        signer.setParameter(new SM2ParameterSpec(sdfPubKey));
        signer.update(data);
        byte[] signature = signer.sign();

        // SDF 验签 (DER 格式)
        java.security.Signature verifier = java.security.Signature.getInstance("SM3withSM2", "SDF");
        verifier.initVerify(sdfPubKey);
        verifier.setParameter(new SM2ParameterSpec(sdfPubKey));
        verifier.update(data);
        assertTrue("SDF should verify its own DER signature", verifier.verify(signature));
    }

    @Test
    public void testDERRawToDerConversion() {
        // 使用随机数创建测试签名 (r||s 格式, 64 bytes)
        byte[] rawSignature = new byte[64];
        new java.util.Random().nextBytes(rawSignature);

        // 转换为 DER
        byte[] derSignature = DERCodec.rawToDer(rawSignature);

        // 验证 DER 格式 (以 0x30 开头)
        assertEquals("DER signature should start with SEQUENCE tag", 0x30, derSignature[0] & 0xFF);
        assertTrue("DER signature should be longer than raw", derSignature.length > rawSignature.length);

        // 转换回 RAW
        byte[] rawAgain = DERCodec.derToRaw(derSignature);
        assertArrayEquals("Round-trip conversion should preserve data", rawSignature, rawAgain);
    }

    @Test
    public void testSDFEncryptDecrypt() throws Exception {
        byte[] plaintext = "Test data for encryption".getBytes();

        Cipher encCipher = Cipher.getInstance("SM2", "SDF");
        encCipher.init(Cipher.ENCRYPT_MODE, sm2KeyPair.getPublic());
        byte[] ciphertext = encCipher.doFinal(plaintext);

        Cipher decCipher = Cipher.getInstance("SM2", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, sm2KeyPair.getPrivate());
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals("Decrypted should match original", plaintext, decrypted);
    }

    @Test
    public void testPublicKeyRAWFormat() {
        byte[] x = new byte[32];
        byte[] y = new byte[32];
        new java.util.Random().nextBytes(x);
        new java.util.Random().nextBytes(y);

        SM2PublicKey pubKey = new SM2PublicKey(x, y);

        // 默认 RAW 格式
        assertEquals("Default format should be RAW", "RAW", pubKey.getFormat());
        assertEquals("RAW encoded should be 64 bytes", 64, pubKey.getEncoded().length);

        byte[] encoded = pubKey.getEncoded();
        byte[] xFromEncoded = Arrays.copyOfRange(encoded, 0, 32);
        byte[] yFromEncoded = Arrays.copyOfRange(encoded, 32, 64);
        assertArrayEquals("X should match", x, xFromEncoded);
        assertArrayEquals("Y should match", y, yFromEncoded);
    }

    @Test
    public void testPrivateKeyRAWFormat() {
        byte[] keyBytes = new byte[32];
        new java.util.Random().nextBytes(keyBytes);

        SM2PrivateKey privKey = new SM2PrivateKey(keyBytes);

        // 默认 RAW 格式
        assertEquals("Default format should be RAW", "RAW", privKey.getFormat());
        assertEquals("RAW encoded should be 32 bytes", 32, privKey.getEncoded().length);
        assertArrayEquals("Key bytes should match", keyBytes, privKey.getEncoded());
    }
}
