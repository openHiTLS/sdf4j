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
import org.junit.Assume;
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

    @Test
    public void testSignEmptyData() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);
        SM2PublicKey sdfPubKey = (SM2PublicKey) sm2KeyPair.getPublic();
        java.security.PrivateKey sdfPrivKey = sm2KeyPair.getPrivate();

        // 签名空数据（不调用 update）
        java.security.Signature signer = java.security.Signature.getInstance("SM3withSM2", "SDF");
        signer.initSign(sdfPrivKey);
        signer.setParameter(new SM2ParameterSpec(sdfPubKey));
        byte[] signature = signer.sign();
        assertNotNull("Empty data should still produce a signature", signature);

        // 验签空数据
        java.security.Signature verifier = java.security.Signature.getInstance("SM3withSM2", "SDF");
        verifier.initVerify(sdfPubKey);
        verifier.setParameter(new SM2ParameterSpec(sdfPubKey));
        assertTrue("Empty data signature should verify", verifier.verify(signature));
    }

    @Test
    public void testSignWithoutPublicKeyFails() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);
        java.security.PrivateKey sdfPrivKey = sm2KeyPair.getPrivate();

        java.security.Signature signer = java.security.Signature.getInstance("SM3withSM2", "SDF");
        signer.initSign(sdfPrivKey);
        // 不设置 SM2ParameterSpec（没有 publicKey）
        signer.update("test data".getBytes());

        try {
            signer.sign();
            fail("Sign without publicKey should throw SignatureException");
        } catch (SignatureException e) {
            assertTrue(e.getMessage().contains("Public key"));
        }
    }

    @Test
    public void testVerifyTamperedSignature() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);
        SM2PublicKey sdfPubKey = (SM2PublicKey) sm2KeyPair.getPublic();
        java.security.PrivateKey sdfPrivKey = sm2KeyPair.getPrivate();

        byte[] data = "Tamper test data".getBytes();

        java.security.Signature signer = java.security.Signature.getInstance("SM3withSM2", "SDF");
        signer.initSign(sdfPrivKey);
        signer.setParameter(new SM2ParameterSpec(sdfPubKey));
        signer.update(data);
        byte[] signature = signer.sign();

        // 篡改签名的 DER 内容中间的一个字节
        signature[signature.length / 2] ^= 0xFF;

        java.security.Signature verifier = java.security.Signature.getInstance("SM3withSM2", "SDF");
        verifier.initVerify(sdfPubKey);
        verifier.setParameter(new SM2ParameterSpec(sdfPubKey));
        verifier.update(data);
        assertFalse("Tampered signature should not verify", verifier.verify(signature));
    }

    @Test
    public void testVerifyWrongSignature() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);
        SM2PublicKey sdfPubKey = (SM2PublicKey) sm2KeyPair.getPublic();

        byte[] data = "Test data".getBytes();

        java.security.Signature verifier = java.security.Signature.getInstance("SM3withSM2", "SDF");
        verifier.initVerify(sdfPubKey);
        verifier.setParameter(new SM2ParameterSpec(sdfPubKey));
        verifier.update(data);

        try {
            // 完全随机的数据作为签名
            byte[] garbage = new byte[]{0x00, 0x01, 0x02, 0x03};
            boolean result = verifier.verify(garbage);
            // 如果没有抛异常，应返回 false
            assertFalse("Garbage signature should not verify", result);
        } catch (SignatureException | IllegalArgumentException e) {
            // 预期行为：非法 DER 格式抛异常
        }
    }

    @Test
    public void testVerifyWrongData() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);
        SM2PublicKey sdfPubKey = (SM2PublicKey) sm2KeyPair.getPublic();
        java.security.PrivateKey sdfPrivKey = sm2KeyPair.getPrivate();

        java.security.Signature signer = java.security.Signature.getInstance("SM3withSM2", "SDF");
        signer.initSign(sdfPrivKey);
        signer.setParameter(new SM2ParameterSpec(sdfPubKey));
        signer.update("original data".getBytes());
        byte[] signature = signer.sign();

        // 用不同的数据验签
        java.security.Signature verifier = java.security.Signature.getInstance("SM3withSM2", "SDF");
        verifier.initVerify(sdfPubKey);
        verifier.setParameter(new SM2ParameterSpec(sdfPubKey));
        verifier.update("different data".getBytes());
        assertFalse("Verify with wrong data should return false", verifier.verify(signature));
    }

    @Test
    public void testInitVerifyWithWrongKeyType() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);

        // 使用非 SM2PublicKey 的 PublicKey 调用 initVerify 应报错
        java.security.Signature verifier = java.security.Signature.getInstance("SM3withSM2", "SDF");
        try {
            PublicKey fakeKey = new PublicKey() {
                public String getAlgorithm() { return "RSA"; }
                public String getFormat() { return "RAW"; }
                public byte[] getEncoded() { return new byte[64]; }
            };
            verifier.initVerify(fakeKey);
            fail("initVerify with non-SM2 PublicKey should throw InvalidKeyException");
        } catch (InvalidKeyException e) {
            // expected
        }
    }

    @Test
    public void testEncryptEmptyData() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);

        Cipher encCipher = Cipher.getInstance("SM2", "SDF");
        encCipher.init(Cipher.ENCRYPT_MODE, sm2KeyPair.getPublic());

        try {
            encCipher.doFinal(new byte[0]);
            fail("SM2 encrypt with empty plaintext should throw");
        } catch (Exception e) {
            // 预期：native 层拒绝空明文
            assertTrue(e.getMessage().contains("plain") || e.getMessage().contains("invalid"));
        }
    }

    @Test
    public void testEncryptLargeData() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);

        byte[] plaintext = new byte[1024];
        new java.util.Random(42).nextBytes(plaintext);

        Cipher encCipher = Cipher.getInstance("SM2", "SDF");
        encCipher.init(Cipher.ENCRYPT_MODE, sm2KeyPair.getPublic());
        byte[] ciphertext = encCipher.doFinal(plaintext);

        Cipher decCipher = Cipher.getInstance("SM2", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, sm2KeyPair.getPrivate());
        byte[] decrypted = decCipher.doFinal(ciphertext);

        assertArrayEquals("Large data roundtrip", plaintext, decrypted);
    }

    @Test
    public void testDecryptWithWrongKeyFails() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);

        byte[] plaintext = "Secret message".getBytes();

        Cipher encCipher = Cipher.getInstance("SM2", "SDF");
        encCipher.init(Cipher.ENCRYPT_MODE, sm2KeyPair.getPublic());
        byte[] ciphertext = encCipher.doFinal(plaintext);

        // 生成另一个密钥对
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "SDF");
        KeyPair anotherKeyPair = kpg.generateKeyPair();

        Cipher decCipher = Cipher.getInstance("SM2", "SDF");
        decCipher.init(Cipher.DECRYPT_MODE, anotherKeyPair.getPrivate());

        try {
            decCipher.doFinal(ciphertext);
            fail("Decrypt with wrong key should fail");
        } catch (Exception e) {
            // Expected: BadPaddingException, IllegalBlockSizeException, or SDFJceException
        }
    }

    @Test
    public void testSignatureReusability() throws Exception {
        Assume.assumeTrue("SDF not initialized", initialized);
        SM2PublicKey sdfPubKey = (SM2PublicKey) sm2KeyPair.getPublic();
        java.security.PrivateKey sdfPrivKey = sm2KeyPair.getPrivate();

        java.security.Signature signer = java.security.Signature.getInstance("SM3withSM2", "SDF");

        // 签两次不同的数据，验证 Signature 对象可复用
        for (int i = 0; i < 3; i++) {
            byte[] data = ("Message " + i).getBytes();
            signer.initSign(sdfPrivKey);
            signer.setParameter(new SM2ParameterSpec(sdfPubKey));
            signer.update(data);
            byte[] sig = signer.sign();

            java.security.Signature verifier = java.security.Signature.getInstance("SM3withSM2", "SDF");
            verifier.initVerify(sdfPubKey);
            verifier.setParameter(new SM2ParameterSpec(sdfPubKey));
            verifier.update(data);
            assertTrue("Reuse iteration " + i + " failed", verifier.verify(sig));
        }
    }
}

