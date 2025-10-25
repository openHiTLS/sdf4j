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
 * ECC私钥
 * ECC Private Key (ECCrefPrivateKey)
 *
 * <p>对应C结构体: ECCrefPrivateKey_st
 * <p>定义于GM/T 0018-2023 5.6节
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
public class ECCPrivateKey {

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
     * 私钥值 K (最大64字节)
     * Private key value
     */
    private byte[] k;

    /**
     * 默认构造函数
     */
    public ECCPrivateKey() {
        this.k = new byte[ECC_MAX_LEN];
    }

    /**
     * 构造函数
     *
     * @param bits 密钥位数
     * @param k    私钥值
     */
    public ECCPrivateKey(int bits, byte[] k) {
        if (bits <= 0 || bits > ECC_MAX_BITS) {
            throw new IllegalArgumentException("Invalid bits: " + bits);
        }
        if (k == null) {
            throw new IllegalArgumentException("Private key value cannot be null");
        }
        this.bits = bits;
        this.k = Arrays.copyOf(k, ECC_MAX_LEN);
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

    public byte[] getK() {
        return k != null ? Arrays.copyOf(k, k.length) : null;
    }

    public void setK(byte[] k) {
        if (k == null) {
            throw new IllegalArgumentException("Private key value cannot be null");
        }
        this.k = Arrays.copyOf(k, ECC_MAX_LEN);
    }

    /**
     * 获取有效的私钥数据
     *
     * @return 有效的私钥数据
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
