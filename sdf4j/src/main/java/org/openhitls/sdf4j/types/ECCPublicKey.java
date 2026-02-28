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
        if (x == null || y == null) {
            throw new IllegalArgumentException("X and Y coordinates cannot be null");
        }
        this.bits = bits;
        this.x = x;
        this.y = y;
    }

    // ========================================================================
    // Getters and Setters
    // ========================================================================

    public int getBits() {
        return bits;
    }

    public void setBits(int bits) {
        if (bits <= 0) {
            throw new IllegalArgumentException("Invalid bits: " + bits);
        }
        this.bits = bits;
    }

    /**
     * Returns a direct reference to the internal array. Callers should not modify the returned value.
     */
    public byte[] getX() {
        return x;
    }

    public void setX(byte[] x) {
        if (x == null) {
            throw new IllegalArgumentException("X coordinate cannot be null");
        }
        this.x = x;
    }

    /**
     * Returns a direct reference to the internal array. Callers should not modify the returned value.
     */
    public byte[] getY() {
        return y;
    }

    public void setY(byte[] y) {
        if (y == null) {
            throw new IllegalArgumentException("Y coordinate cannot be null");
        }
        this.y = y;
    }

    // ========================================================================
    // Utility Methods
    // ========================================================================

    /**
     * Get effective X coordinate data (trimmed by bit length).
     *
     * @return effective X coordinate data
     */
    public byte[] getEffectiveX() {
        if (x == null) {
            return null;
        }
        int len = (bits + 7) / 8;
        return Arrays.copyOf(x, len);
    }

    /**
     * Get effective Y coordinate data (trimmed by bit length).
     *
     * @return effective Y coordinate data
     */
    public byte[] getEffectiveY() {
        if (y == null) {
            return null;
        }
        int len = (bits + 7) / 8;
        return Arrays.copyOf(y, len);
    }

    @Override
    public String toString() {
        return "ECCPublicKey{" +
                "bits=" + bits +
                ", x=" + bytesToHex(getEffectiveX()) +
                ", y=" + bytesToHex(getEffectiveY()) +
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
