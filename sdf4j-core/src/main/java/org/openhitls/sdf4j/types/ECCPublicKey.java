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
 * ECC公钥
 * ECC Public Key (ECCrefPublicKey)
 *
 * <p>对应C结构体: ECCrefPublicKey_st
 * <p>定义于GM/T 0018-2023 5.6节
 * <p>最大支持512位密钥
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
public class ECCPublicKey {

    /**
     * 最大位数
     */
    public static final int ECC_MAX_BITS = 512;

    /**
     * 最大字节数
     */
    public static final int ECC_MAX_LEN = (ECC_MAX_BITS + 7) / 8;

    /**
     * 密钥位数
     */
    private int bits;

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
     * 默认构造函数
     */
    public ECCPublicKey() {
        this.x = new byte[ECC_MAX_LEN];
        this.y = new byte[ECC_MAX_LEN];
    }

    /**
     * 构造函数
     *
     * @param bits 密钥位数
     * @param x    X坐标
     * @param y    Y坐标
     */
    public ECCPublicKey(int bits, byte[] x, byte[] y) {
        if (bits <= 0 || bits > ECC_MAX_BITS) {
            throw new IllegalArgumentException("Invalid bits: " + bits + ", must be in (0, " + ECC_MAX_BITS + "]");
        }
        if (x == null || y == null) {
            throw new IllegalArgumentException("X and Y coordinates cannot be null");
        }
        this.bits = bits;
        this.x = Arrays.copyOf(x, ECC_MAX_LEN);
        this.y = Arrays.copyOf(y, ECC_MAX_LEN);
    }

    // ========================================================================
    // Getters and Setters
    // ========================================================================

    public int getBits() {
        return bits;
    }

    public void setBits(int bits) {
        if (bits <= 0 || bits > ECC_MAX_BITS) {
            throw new IllegalArgumentException("Invalid bits: " + bits);
        }
        this.bits = bits;
    }

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

    // ========================================================================
    // Utility Methods
    // ========================================================================

    /**
     * 获取有效的X坐标数据（去除前导零）
     *
     * @return 有效的X坐标数据
     */
    public byte[] getEffectiveX() {
        if (x == null) {
            return null;
        }
        int len = (bits + 7) / 8;
        return Arrays.copyOf(x, len);
    }

    /**
     * 获取有效的Y坐标数据（去除前导零）
     *
     * @return 有效的Y坐标数据
     */
    public byte[] getEffectiveY() {
        if (y == null) {
            return null;
        }
        int len = (bits + 7) / 8;
        return Arrays.copyOf(y, len);
    }

    @Override
    public String toString() {
        return "ECCPublicKey{" +
                "bits=" + bits +
                ", x=" + bytesToHex(getEffectiveX()) +
                ", y=" + bytesToHex(getEffectiveY()) +
                '}';
    }

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        int limit = Math.min(bytes.length, 16);  // 只显示前16字节
        for (int i = 0; i < limit; i++) {
            sb.append(String.format("%02X", bytes[i]));
        }
        if (bytes.length > limit) {
            sb.append("...(").append(bytes.length).append(" bytes)");
        }
        return sb.toString();
    }
}
