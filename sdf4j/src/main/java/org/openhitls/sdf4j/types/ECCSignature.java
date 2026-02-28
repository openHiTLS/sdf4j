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
 * ECC Signature (ECCSignature)
 *
 * <p>Corresponds to C struct: ECCSignature_st
 * <p>Defined in GM/T 0018-2023 Section 5.8
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
public class ECCSignature {

    /**
     * Signature r value
     */
    private byte[] r;

    /**
     * Signature s value
     */
    private byte[] s;

    /**
     * Default constructor.
     */
    public ECCSignature() {
    }

    /**
     * Parameterized constructor.
     *
     * @param r signature r value
     * @param s signature s value
     */
    public ECCSignature(byte[] r, byte[] s) {
        if (r == null || s == null) {
            throw new IllegalArgumentException("Signature r and s cannot be null");
        }
        this.r = r;
        this.s = s;
    }

    // ========================================================================
    // Getters and Setters
    // ========================================================================

    /**
     * Returns a direct reference to the internal array. Callers should not modify the returned value.
     */
    public byte[] getR() {
        return r;
    }

    public void setR(byte[] r) {
        if (r == null) {
            throw new IllegalArgumentException("Signature r cannot be null");
        }
        this.r = r;
    }

    /**
     * Returns a direct reference to the internal array. Callers should not modify the returned value.
     */
    public byte[] getS() {
        return s;
    }

    public void setS(byte[] s) {
        if (s == null) {
            throw new IllegalArgumentException("Signature s cannot be null");
        }
        this.s = s;
    }

    @Override
    public String toString() {
        return "ECCSignature{" +
                "r=" + bytesToHex(r) +
                ", s=" + bytesToHex(s) +
                '}';
    }

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02X", bytes[i]));
        }
        return sb.toString();
    }
}
