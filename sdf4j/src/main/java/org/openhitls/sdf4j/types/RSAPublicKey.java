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
 * RSA Public Key (RSArefPublicKey)
 *
 * <p>Corresponds to C struct: RSArefPublicKey_st
 * <p>Defined in GM/T 0018-2023 Section 5.5
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
public class RSAPublicKey {

    /**
     * Modulus bit length
     */
    private int bits;

    /**
     * Modulus m
     */
    private byte[] m;

    /**
     * Public exponent e
     */
    private byte[] e;

    /**
     * Default constructor.
     */
    public RSAPublicKey() {
    }

    /**
     * Parameterized constructor.
     *
     * @param bits modulus bit length
     * @param m    modulus
     * @param e    public exponent
     */
    public RSAPublicKey(int bits, byte[] m, byte[] e) {
        if (bits <= 0) {
            throw new IllegalArgumentException("Invalid bits: " + bits);
        }
        if (m == null || e == null) {
            throw new IllegalArgumentException("Modulus and exponent cannot be null");
        }
        this.bits = bits;
        this.m = m;
        this.e = e;
    }

    // ========================================================================
    // Getters and Setters
    // ========================================================================

    /**
     * Get modulus bit length.
     *
     * @return modulus bit length (e.g., 2048)
     */
    public int getBits() {
        return bits;
    }

    /**
     * Set modulus bit length.
     *
     * @param bits modulus bit length
     * @throws IllegalArgumentException if bits is not positive
     */
    public void setBits(int bits) {
        if (bits <= 0) {
            throw new IllegalArgumentException("Invalid bits: " + bits);
        }
        this.bits = bits;
    }

    /**
     * Get modulus m.
     *
     * <p>Returns a direct reference to the internal array. Callers should not modify the returned value.
     *
     * @return modulus byte array
     */
    public byte[] getM() {
        return m;
    }

    /**
     * Set modulus m.
     *
     * @param m modulus byte array
     * @throws IllegalArgumentException if m is null
     */
    public void setM(byte[] m) {
        if (m == null) {
            throw new IllegalArgumentException("Modulus cannot be null");
        }
        this.m = m;
    }

    /**
     * Get public exponent e.
     *
     * <p>Returns a direct reference to the internal array. Callers should not modify the returned value.
     *
     * @return public exponent byte array
     */
    public byte[] getE() {
        return e;
    }

    /**
     * Set public exponent e.
     *
     * @param e public exponent byte array
     * @throws IllegalArgumentException if e is null
     */
    public void setE(byte[] e) {
        if (e == null) {
            throw new IllegalArgumentException("Exponent cannot be null");
        }
        this.e = e;
    }

    // ========================================================================
    // Utility Methods
    // ========================================================================

    /**
     * Get effective modulus data (trimmed by bit length).
     *
     * @return effective modulus data
     */
    public byte[] getEffectiveM() {
        if (m == null) {
            return null;
        }
        int len = (bits + 7) / 8;
        return Arrays.copyOf(m, len);
    }

    /**
     * Get effective public exponent data (stripped of leading zeros).
     *
     * @return effective public exponent data
     */
    public byte[] getEffectiveE() {
        if (e == null) {
            return null;
        }
        // Find first non-zero byte
        int start = 0;
        while (start < e.length && e[start] == 0) {
            start++;
        }
        if (start == e.length) {
            return new byte[]{0};
        }
        return Arrays.copyOfRange(e, start, e.length);
    }

    @Override
    public String toString() {
        return "RSAPublicKey{" +
                "bits=" + bits +
                ", m=" + bytesToHex(getEffectiveM()) +
                ", e=" + bytesToHex(getEffectiveE()) +
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
