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
     * @param m     modulus
     * @param e     public exponent
     * @param d     private exponent
     * @param prime prime factors [p, q]
     * @param pexp  CRT exponents [dp, dq]
     * @param coef  CRT coefficient
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

    /**
     * Get private exponent d.
     *
     * <p>Returns a direct reference to the internal array. Callers should not modify the returned value.
     *
     * @return private exponent byte array
     */
    public byte[] getD() {
        return d;
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
        this.d = d;
    }

    /**
     * Get prime factors [p, q].
     *
     * <p>Returns a direct reference to the internal array. Callers should not modify the returned value.
     *
     * @return prime factors array, where index 0 is p and index 1 is q
     */
    public byte[][] getPrime() {
        return prime;
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
        this.prime = prime;
    }

    /**
     * Get CRT exponents.
     *
     * <p>Returns a direct reference to the internal array. Callers should not modify the returned value.
     *
     * @return CRT exponents array, where index 0 is dp and index 1 is dq
     */
    public byte[][] getPexp() {
        return pexp;
    }

    /**
     * Set CRT exponents.
     *
     * @param pexp CRT exponents array
     */
    public void setPexp(byte[][] pexp) {
        this.pexp = pexp;
    }

    /**
     * Get CRT coefficient.
     *
     * <p>Returns a direct reference to the internal array. Callers should not modify the returned value.
     *
     * @return CRT coefficient byte array
     */
    public byte[] getCoef() {
        return coef;
    }

    /**
     * Set CRT coefficient.
     *
     * @param coef CRT coefficient byte array
     */
    public void setCoef(byte[] coef) {
        this.coef = coef;
    }
}
