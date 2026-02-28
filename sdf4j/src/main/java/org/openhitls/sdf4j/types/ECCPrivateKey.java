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
 * ECC Private Key (ECCrefPrivateKey)
 *
 * <p>Corresponds to C struct: ECCrefPrivateKey_st
 * <p>Defined in GM/T 0018-2023 Section 5.6
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
public class ECCPrivateKey {

    /**
     * Key bit length
     */
    private int bits;

    /**
     * Private key value K
     */
    private byte[] k;

    /**
     * Default constructor.
     */
    public ECCPrivateKey() {
    }

    /**
     * Parameterized constructor.
     *
     * @param bits key bit length
     * @param k    private key value
     */
    public ECCPrivateKey(int bits, byte[] k) {
        if (bits <= 0) {
            throw new IllegalArgumentException("Invalid bits: " + bits);
        }
        if (k == null) {
            throw new IllegalArgumentException("Private key value cannot be null");
        }
        this.bits = bits;
        this.k = k;
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
    public byte[] getK() {
        return k;
    }

    public void setK(byte[] k) {
        if (k == null) {
            throw new IllegalArgumentException("Private key value cannot be null");
        }
        this.k = k;
    }

    /**
     * Get effective private key data (trimmed by bit length).
     *
     * @return effective private key data
     */
    public byte[] getEffectiveK() {
        if (k == null) {
            return null;
        }
        int len = (bits + 7) / 8;
        return Arrays.copyOf(k, len);
    }

    @Override
    public String toString() {
        return "ECCPrivateKey{" +
                "bits=" + bits +
                ", k=[REDACTED]" +
                '}';
    }
}
