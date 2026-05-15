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

package org.openhitls.sdf4j.types;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import org.junit.Test;

/**
 * Tests for Java-layer constructor and setter validation in type classes.
 */
public class TypeValidationTest {

    @Test(expected = IllegalArgumentException.class)
    public void testDeviceInfo_nullIssuerName() {
        new DeviceInfo(null, "dev", "sn", 1, 1, new long[2], 1, 1, 4096);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDeviceInfo_nullDeviceName() {
        new DeviceInfo("issuer", null, "sn", 1, 1, new long[2], 1, 1, 4096);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDeviceInfo_nullDeviceSerial() {
        new DeviceInfo("issuer", "dev", null, 1, 1, new long[2], 1, 1, 4096);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDeviceInfo_nullAsymAlgAbility() {
        new DeviceInfo("issuer", "dev", "sn", 1, 1, null, 1, 1, 4096);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRSAPublicKey_invalidBits_zero() {
        new RSAPublicKey(0, new byte[64], new byte[64]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRSAPublicKey_invalidBits_negative() {
        new RSAPublicKey(-1, new byte[64], new byte[64]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRSAPublicKey_nullModulus() {
        new RSAPublicKey(2048, null, new byte[64]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRSAPublicKey_nullExponent() {
        new RSAPublicKey(2048, new byte[64], null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRSAPublicKey_setBits_zero() {
        RSAPublicKey key = new RSAPublicKey();
        key.setBits(0);
    }

    @Test
    public void testRSAPublicKey_validConstruction() {
        RSAPublicKey key = new RSAPublicKey(2048, new byte[256], new byte[256]);
        assertEquals(2048, key.getBits());
        assertNotNull(key.getM());
        assertNotNull(key.getE());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testECCPublicKey_invalidBits() {
        new ECCPublicKey(0, new byte[32], new byte[32]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testECCPublicKey_nullX() {
        new ECCPublicKey(256, null, new byte[32]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testECCPublicKey_nullY() {
        new ECCPublicKey(256, new byte[32], null);
    }

    @Test
    public void testECCPublicKey_validConstruction() {
        ECCPublicKey key = new ECCPublicKey(256, new byte[32], new byte[32]);
        assertEquals(256, key.getBits());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testECCPrivateKey_invalidBits() {
        new ECCPrivateKey(0, new byte[32]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testECCPrivateKey_nullK() {
        new ECCPrivateKey(256, null);
    }

    @Test
    public void testECCPrivateKey_validConstruction() {
        ECCPrivateKey key = new ECCPrivateKey(256, new byte[32]);
        assertEquals(256, key.getBits());
        assertNotNull(key.getK());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testECCSignature_nullR() {
        new ECCSignature(null, new byte[32]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testECCSignature_nullS() {
        new ECCSignature(new byte[32], null);
    }

    @Test
    public void testECCSignature_validConstruction() {
        ECCSignature sig = new ECCSignature(new byte[32], new byte[32]);
        assertNotNull(sig.getR());
        assertNotNull(sig.getS());
    }

    @Test
    public void testECCSignature_settersCloneInputs() {
        ECCSignature sig = new ECCSignature();
        byte[] r = new byte[] {1, 2};
        byte[] s = new byte[] {3, 4};

        sig.setR(r);
        sig.setS(s);
        r[0] = 9;
        s[0] = 9;

        assertArrayEquals(new byte[] {1, 2}, sig.getR());
        assertArrayEquals(new byte[] {3, 4}, sig.getS());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testECCCipher_nullX() {
        new ECCCipher(null, new byte[64], new byte[32], 16, new byte[16]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testECCCipher_nullY() {
        new ECCCipher(new byte[64], null, new byte[32], 16, new byte[16]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testECCCipher_nullM() {
        new ECCCipher(new byte[64], new byte[64], null, 16, new byte[16]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testECCCipher_nullC() {
        new ECCCipher(new byte[64], new byte[64], new byte[32], 16, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testECCCipher_lGreaterThanCLength() {
        new ECCCipher(new byte[64], new byte[64], new byte[32], 100, new byte[16]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testECCCipher_lNegative() {
        new ECCCipher(new byte[64], new byte[64], new byte[32], -1, new byte[16]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testECCCipher_setInvalidCipher() {
        ECCCipher cipher = new ECCCipher();
        cipher.setL(10);
        cipher.setC(new byte[5]);
    }

    @Test
    public void testECCCipher_validConstruction() {
        ECCCipher cipher = new ECCCipher(new byte[64], new byte[64], new byte[32], 13, new byte[16]);
        assertEquals(13, cipher.getL());
    }

    @Test
    public void testECCCipher_settersCloneInputs() {
        ECCCipher cipher = new ECCCipher();
        byte[] x = new byte[] {1, 2};
        byte[] y = new byte[] {3, 4};
        byte[] m = new byte[] {5, 6};
        byte[] c = new byte[] {7, 8};

        cipher.setX(x);
        cipher.setY(y);
        cipher.setM(m);
        cipher.setL(2);
        cipher.setC(c);
        x[0] = 9;
        y[0] = 9;
        m[0] = 9;
        c[0] = 9;

        assertArrayEquals(new byte[] {1, 2}, cipher.getX());
        assertArrayEquals(new byte[] {3, 4}, cipher.getY());
        assertArrayEquals(new byte[] {5, 6}, cipher.getM());
        assertArrayEquals(new byte[] {7, 8}, cipher.getC());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testHybridCipher_nullCtM() {
        ECCCipher ctS = new ECCCipher(new byte[64], new byte[64], new byte[32], 13, new byte[16]);
        HybridCipher hybridCipher = new HybridCipher(100, null, 0x00000401L, ctS, 0);
        assertEquals(13, hybridCipher.getL1());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testHybridCipher_nullCtS() {
        new HybridCipher(100, new byte[100], 0x00000401L, null, 0);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testHybridCipher_l1Negative() {
        ECCCipher ctS = new ECCCipher(new byte[64], new byte[64], new byte[32], 13, new byte[16]);
        new HybridCipher(-1, new byte[100], 0x00000401L, ctS, 0);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testHybridCipher_l1ExceedsCtMLength() {
        ECCCipher ctS = new ECCCipher(new byte[64], new byte[64], new byte[32], 13, new byte[16]);
        new HybridCipher(200, new byte[100], 0x00000401L, ctS, 0);
    }

    @Test
    public void testHybridCipher_validConstruction() {
        ECCCipher ctS = new ECCCipher(new byte[64], new byte[64], new byte[32], 16, new byte[16]);
        HybridCipher cipher = new HybridCipher(50, new byte[100], 0x00000401L, ctS, 0);
        assertEquals(50, cipher.getL1());
        assertNotNull(cipher.getCtM());
        assertNotNull(cipher.getCtS());
    }

    @Test
    public void testHybridCipher_gettersAndSettersCloneMutableFields() {
        HybridCipher cipher = new HybridCipher(1, new byte[] {0}, 0x00000401L, createECCCipher((byte) 1), 0);
        byte[] ctM = new byte[] {1, 2, 3};
        ECCCipher ctS = createECCCipher((byte) 4);

        cipher.setCtM(ctM);
        cipher.setCtS(ctS);
        ctM[0] = 9;
        ctS.setC(new byte[] {9, 9, 9});

        ECCCipher returnedCtS = cipher.getCtS();
        returnedCtS.setC(new byte[] {8, 8, 8});

        assertArrayEquals(new byte[] {1, 2, 3}, cipher.getCtM());
        assertNotSame(ctS, returnedCtS);
        assertArrayEquals(new byte[] {4, 2, 3}, cipher.getCtS().getC());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testHybridCipher_setInvalidCipher() {
        HybridCipher cipher = new HybridCipher();
        cipher.setL1(15);
        cipher.setCtM(new byte[5]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testHybridSignature_nullSigS() {
        new HybridSignature(null, 32, new byte[32]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testHybridSignature_nullSigM() {
        ECCSignature sigS = new ECCSignature(new byte[32], new byte[32]);
        new HybridSignature(sigS, 32, null);
    }

    @Test
    public void testHybridSignature_validConstruction() {
        ECCSignature sigS = new ECCSignature(new byte[32], new byte[32]);
        HybridSignature sig = new HybridSignature(sigS, 32, new byte[32]);
        assertEquals(32, sig.getL());
        assertNotNull(sig.getSigS());
        assertNotNull(sig.getSigM());
    }

    @Test
    public void testHybridSignature_gettersAndSettersCloneMutableFields() {
        HybridSignature sig = new HybridSignature(new ECCSignature(new byte[] {0}, new byte[] {0}), 1, new byte[] {0});
        ECCSignature sigS = new ECCSignature(new byte[] {1, 2}, new byte[] {3, 4});
        byte[] sigM = new byte[] {5, 6};

        sig.setSigS(sigS);
        sig.setSigM(sigM);
        sigS.setR(new byte[] {9, 9});
        sigM[0] = 9;

        ECCSignature returnedSigS = sig.getSigS();
        returnedSigS.setS(new byte[] {8, 8});

        assertNotSame(sigS, returnedSigS);
        assertArrayEquals(new byte[] {1, 2}, sig.getSigS().getR());
        assertArrayEquals(new byte[] {3, 4}, sig.getSigS().getS());
        assertArrayEquals(new byte[] {5, 6}, sig.getSigM());
    }

    @Test
    public void testNestedResultGettersCloneMutableObjects() {
        ECCCipher eccCipher = createECCCipher((byte) 1);
        ECCKeyEncryptionResult encResult = new ECCKeyEncryptionResult(eccCipher, 1);
        ECCCipher returnedCipher = encResult.getEccCipher();
        returnedCipher.setC(new byte[] {9, 9, 9});

        ECCPublicKey publicKey = new ECCPublicKey(256, new byte[] {1, 2}, new byte[] {3, 4});
        ECCPublicKey tmpPublicKey = new ECCPublicKey(256, new byte[] {5, 6}, new byte[] {7, 8});
        KeyAgreementResult agreementResult = new KeyAgreementResult(1, publicKey, tmpPublicKey);
        ECCPublicKey returnedPublicKey = agreementResult.getPublicKey();
        ECCPublicKey returnedTmpPublicKey = agreementResult.getTmpPublicKey();
        returnedPublicKey.setX(new byte[] {9, 9});
        returnedTmpPublicKey.setY(new byte[] {8, 8});

        assertNotSame(eccCipher, returnedCipher);
        assertArrayEquals(new byte[] {1, 2, 3}, encResult.getEccCipher().getC());
        assertNotSame(publicKey, returnedPublicKey);
        assertNotSame(tmpPublicKey, returnedTmpPublicKey);
        assertArrayEquals(new byte[] {1, 2}, agreementResult.getPublicKey().getX());
        assertArrayEquals(new byte[] {7, 8}, agreementResult.getTmpPublicKey().getY());
    }

    @Test
    public void testRSAPrivateKey_settersCloneInputs() {
        RSAPrivateKey key = new RSAPrivateKey();
        byte[] m = new byte[] {1};
        byte[] e = new byte[] {2};
        byte[] d = new byte[] {3};
        byte[][] prime = new byte[][] {new byte[] {4}, new byte[] {5}};
        byte[][] pexp = new byte[][] {new byte[] {6}, new byte[] {7}};
        byte[] coef = new byte[] {8};

        key.setM(m);
        key.setE(e);
        key.setD(d);
        key.setPrime(prime);
        key.setPexp(pexp);
        key.setCoef(coef);
        m[0] = 9;
        e[0] = 9;
        d[0] = 9;
        prime[0][0] = 9;
        pexp[0][0] = 9;
        coef[0] = 9;

        assertArrayEquals(new byte[] {1}, key.getM());
        assertArrayEquals(new byte[] {2}, key.getE());
        assertArrayEquals(new byte[] {3}, key.getD());
        assertArrayEquals(new byte[] {4}, key.getPrime()[0]);
        assertArrayEquals(new byte[] {6}, key.getPexp()[0]);
        assertArrayEquals(new byte[] {8}, key.getCoef());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testHybridCipher_inValidConstruction() {
        ECCSignature sigS = new ECCSignature(new byte[32], new byte[32]);
        HybridSignature sig = new HybridSignature(sigS, 32, new byte[16]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testHybridCipher_setCtM_null() {
        HybridCipher cipher = new HybridCipher();
        cipher.setCtM(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testHybridSignature_setSigS_null() {
        HybridSignature sig = new HybridSignature();
        sig.setSigS(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testHybridSignature_setSigM_null() {
        HybridSignature sig = new HybridSignature();
        sig.setSigM(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testHybridCipher_setCtS_null() {
        HybridCipher cipher = new HybridCipher();
        cipher.setCtS(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testECCCipher_setL_negative() {
        ECCCipher cipher = new ECCCipher();
        cipher.setL(-1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testHybridSignature_setInvalidCipher() {
        HybridSignature sig = new HybridSignature();
        sig.setL(10);
        sig.setSigM(new byte[5]);
    }

    private static ECCCipher createECCCipher(byte c0) {
        return new ECCCipher(new byte[] {1, 2}, new byte[] {3, 4}, new byte[] {5, 6}, 3, new byte[] {c0, 2, 3});
    }
}
