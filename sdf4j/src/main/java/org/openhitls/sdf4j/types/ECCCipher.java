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

import java.util.Arrays;

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
        if (x == null || y == null || m == null || c == null) {
            throw new IllegalArgumentException("x, y, m, c cannot be null");
        }
        if (l < 0 || l > c.length) {
            throw new IllegalArgumentException("l is invalid");
        }
        this.x = x;
        this.y = y;
        this.m = m;
        this.l = l;
        this.c = c;
    }

    // ========================================================================
    // Getters and Setters
    // ========================================================================

    /**
     * Get X coordinate.
     *
     * <p>Returns a direct reference to the internal array. Callers should not modify the returned value.
     *
     * @return X coordinate byte array
     */
    public byte[] getX() {
        return x;
    }

    /**
     * Set X coordinate.
     *
     * @param x X coordinate byte array
     * @throws IllegalArgumentException if x is null
     */
    public void setX(byte[] x) {
        if (x == null) {
            throw new IllegalArgumentException("X coordinate cannot be null");
        }
        this.x = x;
    }

    /**
     * Get Y coordinate.
     *
     * <p>Returns a direct reference to the internal array. Callers should not modify the returned value.
     *
     * @return Y coordinate byte array
     */
    public byte[] getY() {
        return y;
    }

    /**
     * Set Y coordinate.
     *
     * @param y Y coordinate byte array
     * @throws IllegalArgumentException if y is null
     */
    public void setY(byte[] y) {
        if (y == null) {
            throw new IllegalArgumentException("Y coordinate cannot be null");
        }
        this.y = y;
    }

    /**
     * Get hash value M.
     *
     * <p>Returns a direct reference to the internal array. Callers should not modify the returned value.
     *
     * @return hash value M byte array
     */
    public byte[] getM() {
        return m;
    }

    /**
     * Set hash value M.
     *
     * @param m hash value M byte array
     * @throws IllegalArgumentException if m is null
     */
    public void setM(byte[] m) {
        if (m == null) {
            throw new IllegalArgumentException("Hash value M cannot be null");
        }
        this.m = m;
    }

    /**
     * Get ciphertext data C.
     *
     * <p>Returns a direct reference to the internal array. Callers should not modify the returned value.
     *
     * @return ciphertext byte array
     */
    public byte[] getC() {
        return c;
    }

    /**
     * Set ciphertext data C.
     *
     * @param c ciphertext byte array
     * @throws IllegalArgumentException if c is null or length is inconsistent with L
     */
    public void setC(byte[] c) {
        if (c == null || this.l > c.length) {
            throw new IllegalArgumentException("cipher value is invalid");
        }
        this.c = c;
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

    @Override
    public String toString() {
        return "ECCCipher{" +
                "x=" + bytesToHex(x, 16) +
                ", y=" + bytesToHex(y, 16) +
                ", m=" + bytesToHex(m, 16) +
                ", L=" + l +
                ", c.length=" + (c != null ? c.length : 0) +
                '}';
    }

    private static String bytesToHex(byte[] bytes, int limit) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(bytes.length, limit); i++) {
            sb.append(String.format("%02X", bytes[i]));
        }
        if (bytes.length > limit) {
            sb.append("...");
        }
        return sb.toString();
    }
}
