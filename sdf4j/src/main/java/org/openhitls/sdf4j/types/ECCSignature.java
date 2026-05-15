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
        if (r == null || s == null || r.length == 0 || s.length == 0) {
            throw new IllegalArgumentException("Signature r and s cannot be null");
        }
        this.r = r.clone();
        this.s = s.clone();
    }

    // ========================================================================
    // Getters and Setters
    // ========================================================================

    /**
     * Get signature r value.
     *
     * <p>Returns a copy of the internal array for safety.
     *
     * @return signature r component byte array
     */
    public byte[] getR() {
        return r != null ? r.clone() : null;
    }

    /**
     * Set signature r value.
     *
     * <p>Stores a copy of the provided array.
     *
     * @param r signature r component byte array
     * @throws IllegalArgumentException if r is null
     */
    public void setR(byte[] r) {
        if (r == null || r.length == 0) {
            throw new IllegalArgumentException("Signature r cannot be null");
        }
        this.r = r.clone();
    }

    /**
     * Get signature s value.
     *
     * <p>Returns a copy of the internal array for safety.
     *
     * @return signature s component byte array
     */
    public byte[] getS() {
        return s != null ? s.clone() : null;
    }

    /**
     * Set signature s value.
     *
     * <p>Stores a copy of the provided array.
     *
     * @param s signature s component byte array
     * @throws IllegalArgumentException if s is null
     */
    public void setS(byte[] s) {
        if (s == null || s.length == 0) {
            throw new IllegalArgumentException("Signature s cannot be null");
        }
        this.s = s.clone();
    }

    /**
     * Create a deep copy of the given signature, returning null if the input is null.
     *
     * @param sig the signature to duplicate
     * @return a new ECCSignature instance, or null
     */
    public static ECCSignature dup(ECCSignature sig) {
        if (sig == null) {
            return null;
        }
        ECCSignature copy = new ECCSignature();
        if (sig.r != null) {
            copy.r = sig.r.clone();
        }
        if (sig.s != null) {
            copy.s = sig.s.clone();
        }
        return copy;
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
