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
 * ECC Cipher Structure (ECCCipher)
 *
 * <p>Corresponds to C struct: ECCCipher_st
 * <p>Defined in GM/T 0018-2023 Section 5.7
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
public class ECCCipher {

    /**
     * X coordinate
     */
    private byte[] x;

    /**
     * Y coordinate
     */
    private byte[] y;

    /**
     * Hash value M
     */
    private byte[] m;

    /**
     * Ciphertext length L (corresponds to ULONG L field in C struct)
     */
    private long l;

    /**
     * Ciphertext C (variable length)
     */
    private byte[] c;

    /**
     * Default constructor.
     */
    public ECCCipher() {
    }

    /**
     * Parameterized constructor used by JNI layer for efficient object creation.
     *
     * @param x X coordinate
     * @param y Y coordinate
     * @param m hash value
     * @param l ciphertext length
     * @param c ciphertext data
     */
    public ECCCipher(byte[] x, byte[] y, byte[] m, long l, byte[] c) {
        if (x == null || y == null || m == null || c == null || x.length == 0 || y.length == 0 ||
                m.length == 0 || c.length == 0) {
            throw new IllegalArgumentException("x, y, m, c cannot be null");
        }
        if (l < 0 || l > c.length) {
            throw new IllegalArgumentException("l is invalid");
        }
        this.x = x.clone();
        this.y = y.clone();
        this.m = m.clone();
        this.l = l;
        this.c = c.clone();
    }

    // ========================================================================
    // Getters and Setters
    // ========================================================================

    /**
     * Get X coordinate.
     *
     * <p>Returns a copy of the internal array for safety.
     *
     * @return X coordinate byte array
     */
    public byte[] getX() {
        return x != null ? x.clone() : null;
    }

    /**
     * Set X coordinate.
     *
     * <p>Stores a copy of the provided array.
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
     * Get Y coordinate.
     *
     * <p>Returns a copy of the internal array for safety.
     *
     * @return Y coordinate byte array
     */
    public byte[] getY() {
        return y != null ? y.clone() : null;
    }

    /**
     * Set Y coordinate.
     *
     * <p>Stores a copy of the provided array.
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
     * Get hash value M.
     *
     * <p>Returns a copy of the internal array for safety.
     *
     * @return hash value M byte array
     */
    public byte[] getM() {
        return m != null ? m.clone() : null;
    }

    /**
     * Set hash value M.
     *
     * <p>Stores a copy of the provided array.
     *
     * @param m hash value M byte array
     * @throws IllegalArgumentException if m is null
     */
    public void setM(byte[] m) {
        if (m == null || m.length == 0) {
            throw new IllegalArgumentException("Hash value M cannot be null");
        }
        this.m = m.clone();
    }

    /**
     * Get ciphertext data C.
     *
     * <p>Returns a copy of the internal array for safety.
     *
     * @return ciphertext byte array
     */
    public byte[] getC() {
        return c != null ? c.clone() : null;
    }

    /**
     * Set ciphertext data C.
     *
     * <p>Stores a copy of the provided array.
     *
     * @param c ciphertext byte array
     * @throws IllegalArgumentException if c is null or length is inconsistent with L
     */
    public void setC(byte[] c) {
        if (c == null || c.length == 0 || this.l > c.length) {
            throw new IllegalArgumentException("cipher value is invalid");
        }
        this.c = c.clone();
    }

    /**
     * Get ciphertext length L (corresponds to ULONG L field in C struct)
     *
     * @return ciphertext length
     */
    public long getL() {
        return l;
    }

    /**
     * Set ciphertext length L
     *
     * @param l ciphertext length
     */
    public void setL(long l) {
        if (l < 0) {
            throw new IllegalArgumentException("Ciphertext length cannot be negative");
        }
        if (c != null && l > c.length) {
            throw new IllegalArgumentException("cipher length cannot exceed data length");
        }
        this.l = l;
    }

    /**
     * Get ciphertext length (convenience method, returns int)
     *
     * @return ciphertext length in bytes
     */
    public int getCipherLength() {
        return c != null ? c.length : 0;
    }

    /**
     * Create a deep copy of the given cipher, returning null if the input is null.
     *
     * @param cipher the cipher to duplicate
     * @return a new ECCCipher instance, or null
     */
    public static ECCCipher dup(ECCCipher cipher) {
        if (cipher == null) {
            return null;
        }
        ECCCipher copy = new ECCCipher();
        if (cipher.x != null) {
            copy.x = cipher.x.clone();
        }
        if (cipher.y != null) {
            copy.y = cipher.y.clone();
        }
        if (cipher.m != null) {
            copy.m = cipher.m.clone();
        }
        if (cipher.c != null) {
            copy.c = cipher.c.clone();
        }
        copy.l = cipher.l;
        return copy;
    }

    @Override
    public String toString() {
        return "ECCCipher{" +
                "x=" + bytesToHex(x) +
                ", y=" + bytesToHex(y) +
                ", m=" + bytesToHex(m) +
                ", L=" + l +
                ", c.length=" + (c != null ? c.length : 0) +
                '}';
    }

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
