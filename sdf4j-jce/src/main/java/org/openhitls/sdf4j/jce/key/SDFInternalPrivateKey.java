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

import java.security.PrivateKey;
import java.util.Arrays;

/**
 * SM2 Internal Private Key — references a key stored inside the SDF device by index.
 *
 * <p>The actual private key material never leaves the device.
 * An optional password is used to call {@code SDF_GetPrivateKeyAccessRight}
 * before private key operations.
 *
 * <p>Usage:
 * <pre>{@code
 * SDFInternalPrivateKey key = new SDFInternalPrivateKey(1, "password".toCharArray(), KeyUsage.SIGN);
 * Signature sig = Signature.getInstance("SM3withSM2", "SDF");
 * sig.initSign(key);
 * }</pre>
 */
public class SDFInternalPrivateKey implements PrivateKey {

    private static final long serialVersionUID = 1L;
    private static final String ALGORITHM = "SM2";

    /** Key usage type. */
    public enum KeyUsage {
        /** Signing key pair (index maps to sign key slot). */
        SIGN,
        /** Encryption key pair (index maps to enc key slot). */
        ENCRYPT
    }

    private final int keyIndex;
    private char[] password;
    private final KeyUsage usage;

    /**
     * Construct an internal private key reference.
     *
     * @param keyIndex device key index
     * @param password access password (nullable if device doesn't require it)
     * @param usage    key usage type (SIGN or ENCRYPT)
     */
    public SDFInternalPrivateKey(int keyIndex, char[] password, KeyUsage usage) {
        if (keyIndex < 0) {
            throw new IllegalArgumentException("keyIndex must be non-negative");
        }
        if (usage == null) {
            throw new IllegalArgumentException("usage must not be null");
        }
        this.keyIndex = keyIndex;
        this.password = password != null ? password.clone() : null;
        this.usage = usage;
    }

    /**
     * Convenience constructor defaulting to SIGN usage.
     */
    public SDFInternalPrivateKey(int keyIndex, char[] password) {
        this(keyIndex, password, KeyUsage.SIGN);
    }

    public int getKeyIndex() {
        return keyIndex;
    }

    public char[] getPassword() {
        return password != null ? password.clone() : null;
    }

    public KeyUsage getUsage() {
        return usage;
    }

    @Override
    public String getAlgorithm() {
        return ALGORITHM;
    }

    /**
     * Internal keys cannot be exported — returns {@code "SDF_INTERNAL"}.
     */
    @Override
    public String getFormat() {
        return "SDF_INTERNAL";
    }

    /**
     * Internal keys cannot be exported — always returns {@code null}.
     */
    @Override
    public byte[] getEncoded() {
        return null;
    }

    /**
     * Clear password material.
     */
    public void destroy() {
        if (password != null) {
            Arrays.fill(password, '\0');
            password = null;
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof SDFInternalPrivateKey)) return false;
        SDFInternalPrivateKey other = (SDFInternalPrivateKey) obj;
        return keyIndex == other.keyIndex && usage == other.usage;
    }

    @Override
    public int hashCode() {
        return 31 * keyIndex + usage.hashCode();
    }

    @Override
    public String toString() {
        return "SDFInternalPrivateKey{index=" + keyIndex + ", usage=" + usage + "}";
    }
}
