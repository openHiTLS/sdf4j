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
 * RSA私钥
 * RSA Private Key (RSArefPrivateKey)
 *
 * <p>对应C结构体: RSArefPrivateKey_st
 * <p>定义于GM/T 0018-2023 5.5节
 * <p>最大支持4096位密钥
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
public class RSAPrivateKey {

    /**
     * 最大位数
     */
    public static final int RSA_MAX_BITS = 4096;

    /**
     * 最大字节数
     */
    public static final int RSA_MAX_LEN = (RSA_MAX_BITS + 7) / 8;

    /**
     * 最大素数位数
     */
    public static final int RSA_MAX_PBITS = (RSA_MAX_BITS + 1) / 2;

    /**
     * 最大素数字节数
     */
    public static final int RSA_MAX_PLEN = (RSA_MAX_PBITS + 7) / 8;

    /**
     * 模数位数
     */
    private int bits;

    /**
     * 模数 m (最大512字节)
     * Modulus
     */
    private byte[] m;

    /**
     * 公钥指数 e (最大512字节)
     * Public exponent
     */
    private byte[] e;

    /**
     * 私钥指数 d (最大512字节)
     * Private exponent
     */
    private byte[] d;

    /**
     * 素数 p 和 q (2个，每个最大256字节)
     * Prime factors [p, q]
     */
    private byte[][] prime;

    /**
     * CRT指数 dp 和 dq (2个，每个最大256字节)
     * CRT exponents [dp, dq]
     */
    private byte[][] pexp;

    /**
     * CRT系数 coef (最大256字节)
     * CRT coefficient
     */
    private byte[] coef;

    /**
     * 默认构造函数
     */
    public RSAPrivateKey() {
        this.m = new byte[RSA_MAX_LEN];
        this.e = new byte[RSA_MAX_LEN];
        this.d = new byte[RSA_MAX_LEN];
        this.prime = new byte[2][RSA_MAX_PLEN];
        this.pexp = new byte[2][RSA_MAX_PLEN];
        this.coef = new byte[RSA_MAX_PLEN];
    }

    /**
     * 构造函数
     *
     * @param bits  模数位数
     * @param m     模数
     * @param e     公钥指数
     * @param d     私钥指数
     * @param prime 素数[p, q]
     * @param pexp  CRT指数[dp, dq]
     * @param coef  CRT系数
     */
    public RSAPrivateKey(int bits, byte[] m, byte[] e, byte[] d,
                         byte[][] prime, byte[][] pexp, byte[] coef) {
        if (bits <= 0 || bits > RSA_MAX_BITS) {
            throw new IllegalArgumentException("Invalid bits: " + bits);
        }
        this.bits = bits;
        this.m = Arrays.copyOf(m, RSA_MAX_LEN);
        this.e = Arrays.copyOf(e, RSA_MAX_LEN);
        this.d = Arrays.copyOf(d, RSA_MAX_LEN);
        this.prime = new byte[2][RSA_MAX_PLEN];
        this.pexp = new byte[2][RSA_MAX_PLEN];
        if (prime != null && prime.length >= 2) {
            System.arraycopy(prime[0], 0, this.prime[0], 0, Math.min(prime[0].length, RSA_MAX_PLEN));
            System.arraycopy(prime[1], 0, this.prime[1], 0, Math.min(prime[1].length, RSA_MAX_PLEN));
        }
        if (pexp != null && pexp.length >= 2) {
            System.arraycopy(pexp[0], 0, this.pexp[0], 0, Math.min(pexp[0].length, RSA_MAX_PLEN));
            System.arraycopy(pexp[1], 0, this.pexp[1], 0, Math.min(pexp[1].length, RSA_MAX_PLEN));
        }
        this.coef = Arrays.copyOf(coef, RSA_MAX_PLEN);
    }

    // ========================================================================
    // Getters and Setters
    // ========================================================================

    public int getBits() {
        return bits;
    }

    public void setBits(int bits) {
        if (bits <= 0 || bits > RSA_MAX_BITS) {
            throw new IllegalArgumentException("Invalid bits: " + bits);
        }
        this.bits = bits;
    }

    public byte[] getM() {
        return m != null ? Arrays.copyOf(m, m.length) : null;
    }

    public void setM(byte[] m) {
        this.m = Arrays.copyOf(m, RSA_MAX_LEN);
    }

    public byte[] getE() {
        return e != null ? Arrays.copyOf(e, e.length) : null;
    }

    public void setE(byte[] e) {
        this.e = Arrays.copyOf(e, RSA_MAX_LEN);
    }

    public byte[] getD() {
        return d != null ? Arrays.copyOf(d, d.length) : null;
    }

    public void setD(byte[] d) {
        this.d = Arrays.copyOf(d, RSA_MAX_LEN);
    }

    public byte[][] getPrime() {
        if (prime == null) {
            return null;
        }
        byte[][] copy = new byte[2][];
        copy[0] = Arrays.copyOf(prime[0], prime[0].length);
        copy[1] = Arrays.copyOf(prime[1], prime[1].length);
        return copy;
    }

    public void setPrime(byte[][] prime) {
        if (prime != null && prime.length >= 2) {
            this.prime = new byte[2][RSA_MAX_PLEN];
            System.arraycopy(prime[0], 0, this.prime[0], 0, Math.min(prime[0].length, RSA_MAX_PLEN));
            System.arraycopy(prime[1], 0, this.prime[1], 0, Math.min(prime[1].length, RSA_MAX_PLEN));
        }
    }

    public byte[][] getPexp() {
        if (pexp == null) {
            return null;
        }
        byte[][] copy = new byte[2][];
        copy[0] = Arrays.copyOf(pexp[0], pexp[0].length);
        copy[1] = Arrays.copyOf(pexp[1], pexp[1].length);
        return copy;
    }

    public void setPexp(byte[][] pexp) {
        if (pexp != null && pexp.length >= 2) {
            this.pexp = new byte[2][RSA_MAX_PLEN];
            System.arraycopy(pexp[0], 0, this.pexp[0], 0, Math.min(pexp[0].length, RSA_MAX_PLEN));
            System.arraycopy(pexp[1], 0, this.pexp[1], 0, Math.min(pexp[1].length, RSA_MAX_PLEN));
        }
    }

    public byte[] getCoef() {
        return coef != null ? Arrays.copyOf(coef, coef.length) : null;
    }

    public void setCoef(byte[] coef) {
        this.coef = Arrays.copyOf(coef, RSA_MAX_PLEN);
    }

    @Override
    public String toString() {
        return "RSAPrivateKey{" +
                "bits=" + bits +
                ", m=[REDACTED]" +
                ", e=[REDACTED]" +
                ", d=[REDACTED]" +
                '}';
    }
}
