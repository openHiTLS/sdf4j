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
 * RSA公钥
 * RSA Public Key (RSArefPublicKey)
 *
 * <p>对应C结构体: RSArefPublicKey_st
 * <p>定义于GM/T 0018-2023 5.5节
 * <p>最大支持2048位密钥
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
public class RSAPublicKey {

    /**
     * 最大位数
     */
    public static final int RSA_MAX_BITS = 2048;

    /**
     * 最大字节数
     */
    public static final int RSA_MAX_LEN = (RSA_MAX_BITS + 7) / 8;

    /**
     * 模数位数
     */
    private int bits;

    /**
     * 模数 m (最大256字节)
     * Modulus
     */
    private byte[] m;

    /**
     * 公钥指数 e (最大256字节)
     * Public exponent
     */
    private byte[] e;

    /**
     * 默认构造函数
     */
    public RSAPublicKey() {
        this.m = new byte[RSA_MAX_LEN];
        this.e = new byte[RSA_MAX_LEN];
    }

    /**
     * 构造函数
     *
     * @param bits 模数位数
     * @param m    模数
     * @param e    公钥指数
     */
    public RSAPublicKey(int bits, byte[] m, byte[] e) {
        if (bits <= 0 || bits > RSA_MAX_BITS) {
            throw new IllegalArgumentException("Invalid bits: " + bits + ", must be in (0, " + RSA_MAX_BITS + "]");
        }
        if (m == null || e == null) {
            throw new IllegalArgumentException("Modulus and exponent cannot be null");
        }
        this.bits = bits;
        this.m = Arrays.copyOf(m, RSA_MAX_LEN);
        this.e = Arrays.copyOf(e, RSA_MAX_LEN);
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
        if (m == null) {
            throw new IllegalArgumentException("Modulus cannot be null");
        }
        this.m = Arrays.copyOf(m, RSA_MAX_LEN);
    }

    public byte[] getE() {
        return e != null ? Arrays.copyOf(e, e.length) : null;
    }

    public void setE(byte[] e) {
        if (e == null) {
            throw new IllegalArgumentException("Exponent cannot be null");
        }
        this.e = Arrays.copyOf(e, RSA_MAX_LEN);
    }

    // ========================================================================
    // Utility Methods
    // ========================================================================

    /**
     * 获取有效的模数数据（去除前导零）
     *
     * @return 有效的模数数据
     */
    public byte[] getEffectiveM() {
        if (m == null) {
            return null;
        }
        int len = (bits + 7) / 8;
        return Arrays.copyOf(m, len);
    }

    /**
     * 获取有效的公钥指数数据（去除前导零）
     *
     * @return 有效的公钥指数数据
     */
    public byte[] getEffectiveE() {
        if (e == null) {
            return null;
        }
        // 查找第一个非零字节
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
        if (bytes.length > 32) {
            // 只显示前32字节
            byte[] preview = Arrays.copyOf(bytes, 32);
            StringBuilder sb = new StringBuilder();
            for (byte b : preview) {
                sb.append(String.format("%02X", b));
            }
            sb.append("...(").append(bytes.length).append(" bytes)");
            return sb.toString();
        } else {
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02X", b));
            }
            return sb.toString();
        }
    }
}
