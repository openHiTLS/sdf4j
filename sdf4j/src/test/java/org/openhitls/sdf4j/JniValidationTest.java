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

import org.junit.Test;
import org.openhitls.sdf4j.types.*;
import org.openhitls.sdf4j.constants.ErrorCode;
import java.lang.reflect.Field;
import static org.junit.Assert.*;

/**
 * Tests for JNI-layer length validation in java_to_native_* functions.
 */
public class JniValidationTest extends BaseSDFTest {

    private static void setField(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    @Test
    public void testRSA_modulusExceedsMaxLen() throws Exception {
        requireDevice();

        RSAPublicKey key = new RSAPublicKey();
        setField(key, "bits", 2048);
        setField(key, "m", new byte[1024]); // > 512
        setField(key, "e", new byte[3]);

        try {
            sdf.SDF_ExternalPublicKeyOperation_RSA(sessionHandle, key, new byte[256]);
            fail("Expected SDFException for oversized modulus");
        } catch (SDFException e) {
            // no action
        }
    }

    @Test
    public void testRSA_exponentExceedsMaxLen() throws Exception {
        requireDevice();

        RSAPublicKey key = new RSAPublicKey();
        setField(key, "bits", 2048);
        setField(key, "m", new byte[256]);
        setField(key, "e", new byte[1024]); // > 512

        try {
            sdf.SDF_ExternalPublicKeyOperation_RSA(sessionHandle, key, new byte[256]);
            fail("Expected SDFException for oversized exponent");
        } catch (SDFException e) {
            // no action
        }
    }

    @Test
    public void testECCCipher_hashExceeds32Bytes() throws Exception {
        requireDevice();

        // Create valid ECCPrivateKey via reflection (need for decrypt call)
        ECCPrivateKey privKey = new ECCPrivateKey(256, new byte[32]);

        // Create ECCCipher with oversized M field via reflection
        ECCCipher cipher = new ECCCipher();
        setField(cipher, "x", new byte[64]);
        setField(cipher, "y", new byte[64]);
        setField(cipher, "m", new byte[64]); // > 32
        setField(cipher, "l", 16L);
        setField(cipher, "c", new byte[16]);

        try {
            sdf.SDF_ExternalDecrypt_ECC(sessionHandle, 0x00020200, privKey, cipher);
            fail("Expected SDFException for oversized M");
        } catch (SDFException e) {
            // no action
        }
    }

    @Test
    public void testRSAPrivateKey_modulusExceedsMaxLen() throws Exception {
        requireDevice();

        RSAPrivateKey key = new RSAPrivateKey();
        setField(key, "bits", 2048);
        setField(key, "m", new byte[1024]); // > 512
        setField(key, "e", new byte[3]);
        setField(key, "d", new byte[256]);

        try {
            sdf.SDF_ExternalPrivateKeyOperation_RSA(sessionHandle, key, new byte[256]);
            fail("Expected SDFException for oversized modulus");
        } catch (SDFException e) {
            // no action
        }
    }

    @Test
    public void testRSAPrivateKey_privateExpExceedsMaxLen() throws Exception {
        requireDevice();

        RSAPrivateKey key = new RSAPrivateKey();
        setField(key, "bits", 2048);
        setField(key, "m", new byte[256]);
        setField(key, "e", new byte[3]);
        setField(key, "d", new byte[1024]); // > 512

        try {
            sdf.SDF_ExternalPrivateKeyOperation_RSA(sessionHandle, key, new byte[256]);
            fail("Expected SDFException for oversized private exponent");
        } catch (SDFException e) {
            // no action
        }
    }

    @Test
    public void testRSAPrivateKey_primeExceedsMaxPLen() throws Exception {
        requireDevice();

        RSAPrivateKey key = new RSAPrivateKey();
        setField(key, "bits", 2048);
        setField(key, "m", new byte[256]);
        setField(key, "e", new byte[3]);
        setField(key, "d", new byte[256]);
        // prime array with oversized elements
        byte[][] prime = {new byte[512], new byte[256]}; // prime[0] > RSAref_MAX_PLEN (256)
        setField(key, "prime", prime);

        try {
            sdf.SDF_ExternalPrivateKeyOperation_RSA(sessionHandle, key, new byte[256]);
            fail("Expected SDFException for oversized prime");
        } catch (SDFException e) {
            // no action
        }
    }

    @Test
    public void testRSAPrivateKey_coefExceedsMaxPLen() throws Exception {
        requireDevice();

        RSAPrivateKey key = new RSAPrivateKey();
        setField(key, "bits", 2048);
        setField(key, "m", new byte[256]);
        setField(key, "e", new byte[3]);
        setField(key, "d", new byte[256]);
        setField(key, "coef", new byte[512]); // > RSAref_MAX_PLEN (256)

        try {
            sdf.SDF_ExternalPrivateKeyOperation_RSA(sessionHandle, key, new byte[256]);
            fail("Expected SDFException for oversized coef");
        } catch (SDFException e) {
            // no action
        }
    }

    @Test
    public void testHybridCipher_ctMExceedsMaxLen() throws Exception {
        requireDevice();

        HybridCipher cipher = new HybridCipher();
        setField(cipher, "l1", 2000L);
        setField(cipher, "ctM", new byte[2000]); // > HYBRIDENCref_MAX_LEN (1576)
        setField(cipher, "uiAlgID", 0x00000401L);

        try {
            sdf.SDF_ImportKeyWithISK_Hybrid(sessionHandle, 1, cipher);
            fail("Expected SDFException for oversized ctM");
        } catch (SDFException e) {
            // no action
        }
    }

    @Test
    public void testHybridSignature_lExceedsMaxLen() throws Exception {
        requireDevice();

        HybridSignature sig = new HybridSignature();
        setField(sig, "sigS", new ECCSignature(new byte[32], new byte[32]));
        setField(sig, "l", 5000); // > HYBRIDSIGref_MAX_LEN (4636)
        setField(sig, "sigM", new byte[5000]);

        try {
            sdf.SDF_ExternalVerify_Composite(sessionHandle, 0x00020200,
                    new byte[256], new byte[32], sig);
            fail("Expected SDFException for oversized L");
        } catch (SDFException e) {
            // no action
        }
    }

    @Test
    public void testRSAPublicKey_nullModulus() throws Exception {
        requireDevice();

        RSAPublicKey key = new RSAPublicKey();
        setField(key, "bits", 2048);
        setField(key, "m", null); // bypass Java check
        setField(key, "e", new byte[3]);

        try {
            sdf.SDF_ExternalPublicKeyOperation_RSA(sessionHandle, key, new byte[256]);
            fail("Expected SDFException");
        } catch (SDFException e) {
            // no action
        }
    }

    @Test
    public void testRSAPrivateKey_nullModulus() throws Exception {
        requireDevice();

        RSAPrivateKey key = new RSAPrivateKey();
        setField(key, "bits", 2048);
        setField(key, "m", null); // bypass Java check
        setField(key, "e", new byte[3]);
        setField(key, "d", new byte[256]);

        try {
            sdf.SDF_ExternalPrivateKeyOperation_RSA(sessionHandle, key, new byte[256]);
            fail("Expected SDFException");
        } catch (SDFException e) {
            // no action
        }
    }

    @Test
    public void testECCCipher_nullFields() throws Exception {
        requireDevice();

        ECCPrivateKey privKey = new ECCPrivateKey(256, new byte[32]);

        ECCCipher cipher = new ECCCipher();
        setField(cipher, "x", null); // bypass Java check
        setField(cipher, "y", null);
        setField(cipher, "m", null);
        setField(cipher, "l", 16L);
        setField(cipher, "c", null);
        try {
            sdf.SDF_ExternalDecrypt_ECC(sessionHandle, 0x00020200, privKey, cipher);
            fail("Expected SDFException");
        } catch (SDFException e) {
            // no action
        }
    }

    @Test
    public void testHybridCipher_nullCtM() throws Exception {
        requireDevice();

        HybridCipher cipher = new HybridCipher();
        setField(cipher, "l1", 100L);
        setField(cipher, "ctM", null); // bypass Java check
        setField(cipher, "uiAlgID", 0x00000401L);

        try {
            sdf.SDF_ImportKeyWithISK_Hybrid(sessionHandle, 1, cipher);
            fail("Expected SDFException");
        } catch (SDFException e) {
            // no action
        }
    }

    @Test
    public void testHybridCipher_nullCtS() throws Exception {
        requireDevice();

        HybridCipher cipher = new HybridCipher();
        setField(cipher, "l1", 10L);
        setField(cipher, "ctM", new byte[10]);
        setField(cipher, "uiAlgID", 0x00000401L);
        setField(cipher, "ctS", null); // bypass Java check

        try {
            sdf.SDF_ImportKeyWithISK_Hybrid(sessionHandle, 1, cipher);
            fail("Expected SDFException");
        } catch (SDFException e) {
            // no action
        }
    }

    @Test
    public void testHybridSignature_nullSigS() throws Exception {
        requireDevice();

        HybridSignature sig = new HybridSignature();
        setField(sig, "sigS", null); // bypass Java check
        setField(sig, "l", 32);
        setField(sig, "sigM", new byte[32]);

        try {
            sdf.SDF_ExternalVerify_Composite(sessionHandle, 0x00020200,
                    new byte[256], new byte[32], sig);
            fail("Expected SDFException");
        } catch (SDFException e) {
            // no action
        }
    }

    @Test
    public void testHybridSignature_nullSigM() throws Exception {
        requireDevice();

        HybridSignature sig = new HybridSignature();
        setField(sig, "sigS", new ECCSignature(new byte[32], new byte[32]));
        setField(sig, "l", 32);
        setField(sig, "sigM", null); // bypass Java check

        try {
            sdf.SDF_ExternalVerify_Composite(sessionHandle, 0x00020200,
                    new byte[256], new byte[32], sig);
            fail("Expected SDFException");
        } catch (SDFException e) {
            // no action
        }
    }

    @Test
    public void testECCSignature_nullR() throws Exception {
        requireDevice();

        ECCSignature sig = new ECCSignature(new byte[32], new byte[32]);
        setField(sig, "r", null); // bypass Java check

        ECCPublicKey pubKey = sdf.SDF_ExportSignPublicKey_ECC(sessionHandle, 1);
        try {
            sdf.SDF_ExternalVerify_ECC(sessionHandle, 0x00020200, pubKey,
                    new byte[32], sig);
            fail("Expected SDFException");
        } catch (SDFException e) {
            // no action
        }
    }

    @Test
    public void testECCPublicKey_nullX() throws Exception {
        requireDevice();

        ECCPublicKey key = new ECCPublicKey();
        setField(key, "bits", 256);
        setField(key, "x", null);
        setField(key, "y", new byte[32]);

        try {
            sdf.SDF_ExternalVerify_ECC(sessionHandle, 0x00020200, key,
                    new byte[32], new ECCSignature(new byte[32], new byte[32]));
            fail("Expected SDFException");
        } catch (SDFException e) {
            // no action
        }
    }

    @Test
    public void testECCCipher_xExceedsMaxLen() throws Exception {
        requireDevice();

        ECCPrivateKey privKey = new ECCPrivateKey(256, new byte[32]);

        ECCCipher cipher = new ECCCipher();
        setField(cipher, "x", new byte[128]); // > ECCref_MAX_LEN (64)
        setField(cipher, "y", new byte[64]);
        setField(cipher, "m", new byte[32]);
        setField(cipher, "l", 16L);
        setField(cipher, "c", new byte[16]);

        try {
            sdf.SDF_ExternalDecrypt_ECC(sessionHandle, 0x00020200, privKey, cipher);
            fail("Expected SDFException for oversized X");
        } catch (SDFException e) {
            // no action
        }
    }

    @Test
    public void testECCCipher_yExceedsMaxLen() throws Exception {
        requireDevice();

        ECCPrivateKey privKey = new ECCPrivateKey(256, new byte[32]);

        ECCCipher cipher = new ECCCipher();
        setField(cipher, "x", new byte[64]);
        setField(cipher, "y", new byte[128]); // > ECCref_MAX_LEN (64)
        setField(cipher, "m", new byte[32]);
        setField(cipher, "l", 16L);
        setField(cipher, "c", new byte[16]);

        try {
            sdf.SDF_ExternalDecrypt_ECC(sessionHandle, 0x00020200, privKey, cipher);
            fail("Expected SDFException for oversized Y");
        } catch (SDFException e) {
            // no action
        }
    }

    @Test
    public void testECCPublicKey_xExceedsMaxLen() throws Exception {
        requireDevice();

        ECCPublicKey key = new ECCPublicKey();
        setField(key, "bits", 256);
        setField(key, "x", new byte[128]); // > ECCref_MAX_LEN (64)
        setField(key, "y", new byte[32]);

        try {
            sdf.SDF_ExternalVerify_ECC(sessionHandle, 0x00020200, key,
                    new byte[32], new ECCSignature(new byte[32], new byte[32]));
            fail("Expected SDFException for oversized X");
        } catch (SDFException e) {
            // no action
        }
    }

    @Test
    public void testECCPublicKey_yExceedsMaxLen() throws Exception {
        requireDevice();

        ECCPublicKey key = new ECCPublicKey();
        setField(key, "bits", 256);
        setField(key, "x", new byte[32]);
        setField(key, "y", new byte[128]); // > ECCref_MAX_LEN (64)

        try {
            sdf.SDF_ExternalVerify_ECC(sessionHandle, 0x00020200, key,
                    new byte[32], new ECCSignature(new byte[32], new byte[32]));
            fail("Expected SDFException for oversized Y");
        } catch (SDFException e) {
            // no action
        }
    }

    @Test
    public void testECCSignature_rExceedsMaxLen() throws Exception {
        requireDevice();

        ECCSignature sig = new ECCSignature(new byte[32], new byte[32]);
        setField(sig, "r", new byte[128]); // > ECCref_MAX_LEN (64)
        ECCPublicKey pubKey = sdf.SDF_ExportSignPublicKey_ECC(sessionHandle, 1);
        try {
            sdf.SDF_ExternalVerify_ECC(sessionHandle, 0x00020200, pubKey,
                    new byte[32], sig);
            fail("Expected SDFException for oversized r");
        } catch (SDFException e) {
            // no action
        }
    }

    @Test
    public void testECCSignature_sExceedsMaxLen() throws Exception {
        requireDevice();

        ECCSignature sig = new ECCSignature(new byte[32], new byte[32]);
        setField(sig, "s", new byte[128]); // > ECCref_MAX_LEN (64)

        ECCPublicKey pubKey = sdf.SDF_ExportSignPublicKey_ECC(sessionHandle, 1);
        try {
            sdf.SDF_ExternalVerify_ECC(sessionHandle, 0x00020200, pubKey,
                    new byte[32], sig);
            fail("Expected SDFException for oversized s");
        } catch (SDFException e) {
            // no action
        }
    }

    @Test
    public void testECCPrivateKey_kExceedsMaxLen() throws Exception {
        requireDevice();

        ECCPrivateKey key = new ECCPrivateKey(256, new byte[32]);
        setField(key, "k", new byte[128]); // > ECCref_MAX_LEN (64)

        try {
            sdf.SDF_ExternalSign_ECC(sessionHandle, 0x00020200, key, new byte[32]);
            fail("Expected SDFException for oversized K");
        } catch (SDFException e) {
            // no action
        }
    }
}
