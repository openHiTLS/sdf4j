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

/**
 * ECC Public Key (ECCrefPublicKey)
 *
 * <p>Corresponds to C struct: ECCrefPublicKey_st
 * <p>Defined in GM/T 0018-2023 Section 5.6
 * <p>Supports up to 512-bit keys
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
public class ECCPublicKey {
    /**
     * Key bit length
     */
    private int bits;

    /**
     * X coordinate
     */
    private byte[] x;

    /**
     * Y coordinate
     */
    private byte[] y;

    /**
     * Default constructor.
     */
    public ECCPublicKey() {
    }

    /**
     * Parameterized constructor.
     *
     * @param bits key bit length
     * @param x    X coordinate
     * @param y    Y coordinate
     */
    public ECCPublicKey(int bits, byte[] x, byte[] y) {
        if (bits <= 0) {
            throw new IllegalArgumentException("Invalid bits: " + bits);
        }
        if (x == null || y == null || x.length == 0 || y.length == 0) {
            throw new IllegalArgumentException("X and Y coordinates cannot be null");
        }
        this.bits = bits;
        this.x = x.clone();
        this.y = y.clone();
    }

    /* Parameterized constructor used by JNI layer for efficient object creation. */
    private ECCPublicKey(int bits, byte[] x, byte[] y, boolean adopt) {
        this.bits = bits;
        this.x = x;
        this.y = y;
    }

    // ========================================================================
    // Getters and Setters
    // ========================================================================

    /**
     * Get key bit length.
     *
     * @return key bit length (e.g., 256 for SM2)
     */
    public int getBits() {
        return bits;
    }

    /**
     * Set key bit length.
     *
     * @param bits key bit length
     * @throws IllegalArgumentException if bits is not positive
     */
    public void setBits(int bits) {
        if (bits <= 0) {
            throw new IllegalArgumentException("Invalid bits: " + bits);
        }
        this.bits = bits;
    }

    /**
     * Get X coordinate of the elliptic curve point.
     *
     * <p>Returns a copy of the internal array for safety.
     *
     * @return X coordinate byte array, or null if not set
     */
    public byte[] getX() {
        return x != null ? x.clone() : null;
    }

    /**
     * Set X coordinate.
     *
     * @param x X coordinate byte array
     * @throws IllegalArgumentException if x is null
     */
    public void setX(byte[] x) {
        if (x == null || x.length == 0) {
            throw new IllegalArgumentException("X coordinate cannot be null");
        }
        this.x = x.clone();
    }

    /**
     * Get Y coordinate of the elliptic curve point.
     *
     * <p>Returns a copy of the internal array for safety.
     *
     * @return Y coordinate byte array, or null if not set
     */
    public byte[] getY() {
        return y != null ? y.clone() : null;
    }

    /**
     * Set Y coordinate.
     *
     * @param y Y coordinate byte array
     * @throws IllegalArgumentException if y is null
     */
    public void setY(byte[] y) {
        if (y == null || y.length == 0) {
            throw new IllegalArgumentException("Y coordinate cannot be null");
        }
        this.y = y.clone();
    }

    /**
     * Create a deep copy of the given public key, returning null if the input is null.
     *
     * @param key the public key to duplicate
     * @return a new ECCPublicKey instance, or null
     */
    public static ECCPublicKey dup(ECCPublicKey key) {
        if (key == null) {
            return null;
        }
        ECCPublicKey copy = new ECCPublicKey();
        if (key.bits > 0) {
            copy.bits = key.bits;
        }
        if (key.x != null) {
            copy.x = key.x.clone();
        }
        if (key.y != null) {
            copy.y = key.y.clone();
        }
        return copy;
    }

    @Override
    public String toString() {
        return "ECCPublicKey{" +
                "bits=" + bits +
                ", x=" + bytesToHex(x) +
                ", y=" + bytesToHex(y) +
                '}';
    }

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02X", bytes[i]));
        }
        return sb.toString();
    }
}
