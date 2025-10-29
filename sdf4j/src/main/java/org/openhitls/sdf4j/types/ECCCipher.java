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
 * ECC加密数据结构
 * ECC Cipher Structure (ECCCipher)
 *
 * <p>对应C结构体: ECCCipher_st
 * <p>定义于GM/T 0018-2023 5.7节
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
public class ECCCipher {

    /**
     * ECC最大字节数
     */
    public static final int ECC_MAX_LEN = 64;

    /**
     * 杂凑值长度
     */
    public static final int HASH_LEN = 32;

    /**
     * X坐标 (最大64字节)
     * X coordinate
     */
    private byte[] x;

    /**
     * Y坐标 (最大64字节)
     * Y coordinate
     */
    private byte[] y;

    /**
     * 杂凑值M (32字节)
     * Hash value M
     */
    private byte[] m;

    /**
     * 密文数据长度L (对应C结构体的ULONG L字段)
     * Ciphertext length L (corresponds to ULONG L field in C struct)
     */
    private long l;

    /**
     * 密文数据C (变长)
     * Ciphertext C (variable length)
     */
    private byte[] c;

    /**
     * 默认构造函数
     */
    public ECCCipher() {
        this.x = new byte[ECC_MAX_LEN];
        this.y = new byte[ECC_MAX_LEN];
        this.m = new byte[HASH_LEN];
        this.l = 0;
        this.c = new byte[0];
    }

    /**
     * 构造函数
     *
     * @param x X坐标
     * @param y Y坐标
     * @param m 杂凑值
     * @param c 密文数据
     */
    public ECCCipher(byte[] x, byte[] y, byte[] m, byte[] c) {
        if (x == null || y == null || m == null) {
            throw new IllegalArgumentException("X, Y, and M cannot be null");
        }
        this.x = Arrays.copyOf(x, ECC_MAX_LEN);
        this.y = Arrays.copyOf(y, ECC_MAX_LEN);
        this.m = Arrays.copyOf(m, HASH_LEN);
        this.c = c != null ? Arrays.copyOf(c, c.length) : new byte[0];
        this.l = this.c.length;
    }

    // ========================================================================
    // Getters and Setters
    // ========================================================================

    public byte[] getX() {
        return x != null ? Arrays.copyOf(x, x.length) : null;
    }

    public void setX(byte[] x) {
        if (x == null) {
            throw new IllegalArgumentException("X coordinate cannot be null");
        }
        this.x = Arrays.copyOf(x, ECC_MAX_LEN);
    }

    public byte[] getY() {
        return y != null ? Arrays.copyOf(y, y.length) : null;
    }

    public void setY(byte[] y) {
        if (y == null) {
            throw new IllegalArgumentException("Y coordinate cannot be null");
        }
        this.y = Arrays.copyOf(y, ECC_MAX_LEN);
    }

    public byte[] getM() {
        return m != null ? Arrays.copyOf(m, m.length) : null;
    }

    public void setM(byte[] m) {
        if (m == null) {
            throw new IllegalArgumentException("Hash value M cannot be null");
        }
        this.m = Arrays.copyOf(m, HASH_LEN);
    }

    public byte[] getC() {
        return c != null ? Arrays.copyOf(c, c.length) : null;
    }

    public void setC(byte[] c) {
        this.c = c != null ? Arrays.copyOf(c, c.length) : new byte[0];
        this.l = this.c.length;
    }

    /**
     * 获取密文长度L (对应C结构体的ULONG L字段)
     * Get ciphertext length L (corresponds to ULONG L field in C struct)
     *
     * @return 密文长度 / Ciphertext length
     */
    public long getL() {
        return l;
    }

    /**
     * 设置密文长度L
     * Set ciphertext length L
     *
     * @param l 密文长度 / Ciphertext length
     */
    public void setL(long l) {
        this.l = l;
    }

    /**
     * 获取密文长度 (便捷方法，返回int类型)
     * Get ciphertext length (convenience method, returns int)
     *
     * @return 密文字节长度 / Ciphertext length in bytes
     */
    public int getCipherLength() {
        return c != null ? c.length : 0;
    }

    @Override
    public String toString() {
        return "ECCCipher{" +
                "x=" + bytesToHex(x, 16) +
                ", y=" + bytesToHex(y, 16) +
                ", m=" + bytesToHex(m, 16) +
                ", L=" + l +
                ", c.length=" + (c != null ? c.length : 0) +
                '}';
    }

    private static String bytesToHex(byte[] bytes, int limit) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(bytes.length, limit); i++) {
            sb.append(String.format("%02X", bytes[i]));
        }
        if (bytes.length > limit) {
            sb.append("...");
        }
        return sb.toString();
    }
}
