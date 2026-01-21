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

package org.openhitls.sdf4j.jce.key;

import org.junit.Test;
import static org.junit.Assert.*;

import java.util.Arrays;

/**
 * Tests for SM2 key classes (no SDF device required)
 */
public class SM2KeyTest {

    private static final byte[] TEST_PRIVATE_KEY = new byte[32];
    private static final byte[] TEST_X = new byte[32];
    private static final byte[] TEST_Y = new byte[32];

    static {
        Arrays.fill(TEST_PRIVATE_KEY, (byte) 0x01);
        Arrays.fill(TEST_X, (byte) 0x02);
        Arrays.fill(TEST_Y, (byte) 0x03);
    }

    // ==================== SM2PrivateKey Tests ====================

    @Test
    public void testPrivateKeyCreation() {
        SM2PrivateKey key = new SM2PrivateKey(TEST_PRIVATE_KEY);
        assertNotNull(key);
        assertEquals("SM2", key.getAlgorithm());
        assertEquals("RAW", key.getFormat());
    }

    @Test
    public void testPrivateKeyEncoding() {
        SM2PrivateKey key = new SM2PrivateKey(TEST_PRIVATE_KEY);
        byte[] encoded = key.getEncoded();

        assertNotNull(encoded);
        assertEquals(32, encoded.length);
        assertArrayEquals(TEST_PRIVATE_KEY, encoded);

        // Verify defensive copy
        encoded[0] = (byte) 0xFF;
        assertArrayEquals(TEST_PRIVATE_KEY, key.getEncoded());
    }

    @Test
    public void testPrivateKeyGetKeyBytes() {
        SM2PrivateKey key = new SM2PrivateKey(TEST_PRIVATE_KEY);
        byte[] keyBytes = key.getKeyBytes();

        assertArrayEquals(TEST_PRIVATE_KEY, keyBytes);

        // Verify defensive copy
        keyBytes[0] = (byte) 0xFF;
        assertArrayEquals(TEST_PRIVATE_KEY, key.getKeyBytes());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPrivateKeyNullInput() {
        new SM2PrivateKey(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPrivateKeyWrongLength() {
        new SM2PrivateKey(new byte[16]);
    }

    @Test
    public void testPrivateKeyEquals() {
        SM2PrivateKey key1 = new SM2PrivateKey(TEST_PRIVATE_KEY);
        SM2PrivateKey key2 = new SM2PrivateKey(TEST_PRIVATE_KEY.clone());
        SM2PrivateKey key3 = new SM2PrivateKey(new byte[32]);

        assertEquals(key1, key2);
        assertNotEquals(key1, key3);
        assertEquals(key1.hashCode(), key2.hashCode());
    }

    @Test
    public void testPrivateKeyDestroy() {
        byte[] keyData = TEST_PRIVATE_KEY.clone();
        SM2PrivateKey key = new SM2PrivateKey(keyData);
        key.destroy();

        // After destroy, getKeyBytes should return zeroed bytes
        byte[] destroyed = key.getKeyBytes();
        byte[] expected = new byte[32];
        assertArrayEquals(expected, destroyed);
    }

    @Test
    public void testPrivateKeyToString() {
        SM2PrivateKey key = new SM2PrivateKey(TEST_PRIVATE_KEY);
        String str = key.toString();

        // Should not contain actual key material
        assertFalse(str.contains("01"));
        assertTrue(str.contains("SM2PrivateKey"));
    }

    // ==================== SM2PublicKey Tests ====================

    @Test
    public void testPublicKeyCreationWithXY() {
        SM2PublicKey key = new SM2PublicKey(TEST_X, TEST_Y);
        assertNotNull(key);
        assertEquals("SM2", key.getAlgorithm());
        assertEquals("RAW", key.getFormat());
    }

    @Test
    public void testPublicKeyCreationWithCombined() {
        byte[] combined = new byte[64];
        System.arraycopy(TEST_X, 0, combined, 0, 32);
        System.arraycopy(TEST_Y, 0, combined, 32, 32);

        SM2PublicKey key = new SM2PublicKey(combined);
        assertArrayEquals(TEST_X, key.getX());
        assertArrayEquals(TEST_Y, key.getY());
    }

    @Test
    public void testPublicKeyEncoding() {
        SM2PublicKey key = new SM2PublicKey(TEST_X, TEST_Y);
        byte[] encoded = key.getEncoded();

        assertNotNull(encoded);
        assertEquals(64, encoded.length);

        byte[] x = Arrays.copyOfRange(encoded, 0, 32);
        byte[] y = Arrays.copyOfRange(encoded, 32, 64);

        assertArrayEquals(TEST_X, x);
        assertArrayEquals(TEST_Y, y);
    }

    @Test
    public void testPublicKeyGetXY() {
        SM2PublicKey key = new SM2PublicKey(TEST_X, TEST_Y);

        assertArrayEquals(TEST_X, key.getX());
        assertArrayEquals(TEST_Y, key.getY());

        // Verify defensive copy
        key.getX()[0] = (byte) 0xFF;
        assertArrayEquals(TEST_X, key.getX());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPublicKeyNullX() {
        new SM2PublicKey(null, TEST_Y);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPublicKeyNullY() {
        new SM2PublicKey(TEST_X, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPublicKeyWrongXLength() {
        new SM2PublicKey(new byte[16], TEST_Y);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPublicKeyCombinedWrongLength() {
        new SM2PublicKey(new byte[32]);
    }

    @Test
    public void testPublicKeyEquals() {
        SM2PublicKey key1 = new SM2PublicKey(TEST_X, TEST_Y);
        SM2PublicKey key2 = new SM2PublicKey(TEST_X.clone(), TEST_Y.clone());
        SM2PublicKey key3 = new SM2PublicKey(new byte[32], TEST_Y);

        assertEquals(key1, key2);
        assertNotEquals(key1, key3);
        assertEquals(key1.hashCode(), key2.hashCode());
    }
}
