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

import org.junit.Test;

import static org.junit.Assert.*;
import org.openhitls.sdf4j.constants.ErrorCode;

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
}
