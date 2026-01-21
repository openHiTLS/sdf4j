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

package org.openhitls.sdf4j.jce.key;

import java.security.PublicKey;
import java.util.Arrays;

/**
 * SM2 Public Key implementation
 */
public class SM2PublicKey implements PublicKey {

    private static final long serialVersionUID = 1L;
    private static final String ALGORITHM = "SM2";

    private final byte[] x;
    private final byte[] y;

    public SM2PublicKey(byte[] x, byte[] y) {
        if (x == null || x.length != 32 || y == null || y.length != 32) {
            throw new IllegalArgumentException("X and Y must be 32 bytes each");
        }
        this.x = x.clone();
        this.y = y.clone();
    }

    /**
     * Create from combined bytes (X || Y, 64 bytes)
     */
    public SM2PublicKey(byte[] combined) {
        if (combined == null || combined.length != 64) {
            throw new IllegalArgumentException("Combined key must be 64 bytes");
        }
        this.x = Arrays.copyOfRange(combined, 0, 32);
        this.y = Arrays.copyOfRange(combined, 32, 64);
    }

    @Override
    public String getAlgorithm() {
        return ALGORITHM;
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        byte[] encoded = new byte[64];
        System.arraycopy(x, 0, encoded, 0, 32);
        System.arraycopy(y, 0, encoded, 32, 32);
        return encoded;
    }

    public byte[] getX() {
        return x.clone();
    }

    public byte[] getY() {
        return y.clone();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof SM2PublicKey)) return false;
        SM2PublicKey other = (SM2PublicKey) obj;
        return Arrays.equals(x, other.x) && Arrays.equals(y, other.y);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(x) * 31 + Arrays.hashCode(y);
    }
}
