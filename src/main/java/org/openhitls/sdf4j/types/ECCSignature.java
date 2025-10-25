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
 * ECC签名
 * ECC Signature (ECCSignature)
 *
 * <p>对应C结构体: ECCSignature_st
 * <p>定义于GM/T 0018-2023 5.8节
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
public class ECCSignature {

    /**
     * 最大字节数
     */
    public static final int ECC_MAX_LEN = 64;

    /**
     * 签名r值 (最大64字节)
     * Signature r value
     */
    private byte[] r;

    /**
     * 签名s值 (最大64字节)
     * Signature s value
     */
    private byte[] s;

    /**
     * 默认构造函数
     */
    public ECCSignature() {
        this.r = new byte[ECC_MAX_LEN];
        this.s = new byte[ECC_MAX_LEN];
    }

    /**
     * 构造函数
     *
     * @param r 签名r值
     * @param s 签名s值
     */
    public ECCSignature(byte[] r, byte[] s) {
        if (r == null || s == null) {
            throw new IllegalArgumentException("Signature r and s cannot be null");
        }
        this.r = Arrays.copyOf(r, ECC_MAX_LEN);
        this.s = Arrays.copyOf(s, ECC_MAX_LEN);
    }

    // ========================================================================
    // Getters and Setters
    // ========================================================================

    public byte[] getR() {
        return r != null ? Arrays.copyOf(r, r.length) : null;
    }

    public void setR(byte[] r) {
        if (r == null) {
            throw new IllegalArgumentException("Signature r cannot be null");
        }
        this.r = Arrays.copyOf(r, ECC_MAX_LEN);
    }

    public byte[] getS() {
        return s != null ? Arrays.copyOf(s, s.length) : null;
    }

    public void setS(byte[] s) {
        if (s == null) {
            throw new IllegalArgumentException("Signature s cannot be null");
        }
        this.s = Arrays.copyOf(s, ECC_MAX_LEN);
    }

    @Override
    public String toString() {
        return "ECCSignature{" +
                "r=" + bytesToHex(r, 16) +
                ", s=" + bytesToHex(s, 16) +
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
