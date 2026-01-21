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

import java.security.MessageDigest;
import java.security.PrivateKey;
import java.util.Arrays;

/**
 * SM2 Private Key implementation
 */
public class SM2PrivateKey implements PrivateKey {

    private static final long serialVersionUID = 1L;
    private static final String ALGORITHM = "SM2";

    private final byte[] keyBytes;

    public SM2PrivateKey(byte[] keyBytes) {
        if (keyBytes == null || keyBytes.length != 32) {
            throw new IllegalArgumentException("Key must be 32 bytes");
        }
        this.keyBytes = keyBytes.clone();
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
        return keyBytes.clone();
    }

    public byte[] getKeyBytes() {
        return keyBytes.clone();
    }

    /**
     * Clear the key material
     */
    public void destroy() {
        Arrays.fill(keyBytes, (byte) 0);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof SM2PrivateKey)) return false;
        SM2PrivateKey other = (SM2PrivateKey) obj;
        // Use constant-time comparison to prevent timing attacks
        return MessageDigest.isEqual(keyBytes, other.keyBytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(keyBytes);
    }

    @Override
    public String toString() {
        return "SM2PrivateKey [key=****]";
    }
}
