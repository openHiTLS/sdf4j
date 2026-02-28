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
    public byte[] getM() {
        return m;
    }

    public void setM(byte[] m) {
        if (m == null) {
            throw new IllegalArgumentException("Modulus cannot be null");
        }
        this.m = m;
    }

    /**
     * Returns a direct reference to the internal array. Callers should not modify the returned value.
     */
    public byte[] getE() {
        return e;
    }

    public void setE(byte[] e) {
        if (e == null) {
            throw new IllegalArgumentException("Exponent cannot be null");
        }
        this.e = e;
    }

    /**
     * Returns a direct reference to the internal array. Callers should not modify the returned value.
     */
    public byte[] getD() {
        return d;
    }

    public void setD(byte[] d) {
        if (d == null) {
            throw new IllegalArgumentException("Exponent cannot be null");
        }
        this.d = d;
    }

    /**
     * Returns a direct reference to the internal array. Callers should not modify the returned value.
     */
    public byte[][] getPrime() {
        return prime;
    }

    public void setPrime(byte[][] prime) {
        if (prime == null) {
            throw new IllegalArgumentException("Prime cannot be null");
        }
        this.prime = prime;
    }

    /**
     * Returns a direct reference to the internal array. Callers should not modify the returned value.
     */
    public byte[][] getPexp() {
        return pexp;
    }

    public void setPexp(byte[][] pexp) {
        this.pexp = pexp;
    }

    /**
     * Returns a direct reference to the internal array. Callers should not modify the returned value.
     */
    public byte[] getCoef() {
        return coef;
    }

    public void setCoef(byte[] coef) {
        this.coef = coef;
    }
}
