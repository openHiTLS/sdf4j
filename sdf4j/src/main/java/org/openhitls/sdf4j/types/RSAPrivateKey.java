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
 * RSA Private Key (RSArefPrivateKey)
 *
 * <p>Corresponds to C struct: RSArefPrivateKey_st
 * <p>Defined in GM/T 0018-2023 Section 5.5
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
public class RSAPrivateKey {

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
     * Private exponent d
     */
    private byte[] d;

    /**
     * Prime factors p and q
     */
    private byte[][] prime;

    /**
     * CRT exponents dp and dq
     */
    private byte[][] pexp;

    /**
     * CRT coefficient
     */
    private byte[] coef;

    /**
     * Default constructor.
     */
    public RSAPrivateKey() {
    }

    /**
     * Parameterized constructor.
     *
     * @param bits  modulus bit length
     * @param m     modulus; stored by reference without cloning
     * @param e     public exponent; stored by reference without cloning
     * @param d     private exponent; stored by reference without cloning
     * @param prime prime factors [p, q]; stored by reference without cloning
     * @param pexp  CRT exponents [dp, dq]; stored by reference without cloning
     * @param coef  CRT coefficient; stored by reference without cloning
     */
    public RSAPrivateKey(int bits, byte[] m, byte[] e, byte[] d,
                         byte[][] prime, byte[][] pexp, byte[] coef) {
        if (bits <= 0) {
            throw new IllegalArgumentException("Invalid bits: " + bits);
        }
        if (m == null || e == null || d == null || prime == null || pexp == null || coef == null) {
            throw new IllegalArgumentException("Invalid parameters");
        }
        this.bits = bits;
        this.m = m;
        this.e = e;
        this.d = d;
        this.prime = prime;
        this.pexp = pexp;
        this.coef = coef;
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
     * <p>Returns a copy of the internal array for safety.
     *
     * @return modulus byte array
     */
    public byte[] getM() {
        return m != null ? m.clone() : null;
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
        this.m = m.clone();
    }

    /**
     * Get public exponent e.
     *
     * <p>Returns a copy of the internal array for safety.
     *
     * @return public exponent byte array
     */
    public byte[] getE() {
        return e != null ? e.clone() : null;
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
        this.e = e.clone();
    }

    /**
     * Get private exponent d.
     *
     * <p>Returns a copy of the internal array for safety.
     *
     * @return private exponent byte array
     */
    public byte[] getD() {
        return d != null ? d.clone() : null;
    }

    /**
     * Set private exponent d.
     *
     * @param d private exponent byte array
     * @throws IllegalArgumentException if d is null
     */
    public void setD(byte[] d) {
        if (d == null) {
            throw new IllegalArgumentException("Exponent cannot be null");
        }
        this.d = d.clone();
    }

    /**
     * Get prime factors [p, q].
     *
     * <p>Returns a copy of the internal array for safety.
     *
     * @return prime factors array, where index 0 is p and index 1 is q
     */
    public byte[][] getPrime() {
        if (prime == null) {
            return null;
        }
        byte[][] copy = new byte[prime.length][];
        for (int i = 0; i < prime.length; i++) {
            copy[i] = prime[i] != null ? prime[i].clone() : null;
        }
        return copy;
    }

    /**
     * Set prime factors [p, q].
     *
     * @param prime prime factors array
     * @throws IllegalArgumentException if prime is null
     */
    public void setPrime(byte[][] prime) {
        if (prime == null) {
            throw new IllegalArgumentException("Prime cannot be null");
        }
        this.prime = cloneParams(prime);
    }

    /**
     * Get CRT exponents.
     *
     * <p>Returns a copy of the internal array for safety.
     *
     * @return CRT exponents array, where index 0 is dp and index 1 is dq
     */
    public byte[][] getPexp() {
        if (pexp == null) {
            return null;
        }
        byte[][] copy = new byte[pexp.length][];
        for (int i = 0; i < pexp.length; i++) {
            copy[i] = pexp[i] != null ? pexp[i].clone() : null;
        }
        return copy;
    }

    /**
     * Set CRT exponents.
     *
     * @param pexp CRT exponents array
     * @throws IllegalArgumentException if pexp is null
     */
    public void setPexp(byte[][] pexp) {
        if (pexp == null) {
            throw new IllegalArgumentException("CRT exponents cannot be null");
        }
        this.pexp = cloneParams(pexp);
    }

    /**
     * Get CRT coefficient.
     *
     * <p>Returns a copy of the internal array for safety.
     *
     * @return CRT coefficient byte array
     */
    public byte[] getCoef() {
        return coef != null ? coef.clone() : null;
    }

    /**
     * Set CRT coefficient.
     *
     * @param coef CRT coefficient byte array
     * @throws IllegalArgumentException if coef is null
     */
    public void setCoef(byte[] coef) {
        if (coef == null) {
            throw new IllegalArgumentException("CRT coefficient cannot be null");
        }
        this.coef = coef.clone();
    }

    @Override
    public String toString() {
        return "RSAPrivateKey{" +
                "bits=" + bits +
                ", m=" + bytesToHex(m) +
                ", e=" + bytesToHex(e) +
                ", d=[REDACTED]" +
                ", prime=[REDACTED]" +
                ", pexp=[REDACTED]" +
                ", coef=[REDACTED]" +
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

    private static byte[][] cloneParams(byte[][] values) {
        byte[][] copy = new byte[values.length][];
        for (int i = 0; i < values.length; i++) {
            copy[i] = values[i] != null ? values[i].clone() : null;
        }
        return copy;
    }
}
