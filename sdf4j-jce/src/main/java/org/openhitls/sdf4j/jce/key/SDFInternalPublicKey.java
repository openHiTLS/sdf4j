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
 * SM2 Internal Public Key — references a public key stored inside the SDF device by index.
 *
 * <p>The actual public key coordinates (x, y) can be lazily loaded from the device
 * via {@code SDF_ExportSignPublicKey_ECC} or {@code SDF_ExportEncPublicKey_ECC}
 * when needed (e.g., for SM2 Z-value calculation).
 *
 * <p>Usage:
 * <pre>{@code
 * SDFInternalPublicKey key = new SDFInternalPublicKey(1, KeyUsage.SIGN);
 * Signature sig = Signature.getInstance("SM3withSM2", "SDF");
 * sig.initVerify(key);
 * }</pre>
 */
public class SDFInternalPublicKey implements PublicKey {

    private static final long serialVersionUID = 1L;
    private static final String ALGORITHM = "SM2";

    private final int keyIndex;
    private final SDFInternalPrivateKey.KeyUsage usage;

    /** Lazily loaded public key coordinates. */
    private byte[] x;
    private byte[] y;

    /**
     * Construct an internal public key reference.
     *
     * @param keyIndex device key index
     * @param usage    key usage type (SIGN or ENCRYPT)
     */
    public SDFInternalPublicKey(int keyIndex, SDFInternalPrivateKey.KeyUsage usage) {
        if (keyIndex < 0) {
            throw new IllegalArgumentException("keyIndex must be non-negative");
        }
        if (usage == null) {
            throw new IllegalArgumentException("usage must not be null");
        }
        this.keyIndex = keyIndex;
        this.usage = usage;
    }

    /**
     * Convenience constructor defaulting to SIGN usage.
     */
    public SDFInternalPublicKey(int keyIndex) {
        this(keyIndex, SDFInternalPrivateKey.KeyUsage.SIGN);
    }

    public int getKeyIndex() {
        return keyIndex;
    }

    public SDFInternalPrivateKey.KeyUsage getUsage() {
        return usage;
    }

    /**
     * Check if the public key coordinates have been loaded from the device.
     */
    public boolean isLoaded() {
        return x != null && y != null;
    }

    /**
     * Set the public key coordinates (called after exporting from device).
     *
     * @param x 32-byte X coordinate
     * @param y 32-byte Y coordinate
     */
    public void setCoordinates(byte[] x, byte[] y) {
        if (x == null || x.length != 32 || y == null || y.length != 32) {
            throw new IllegalArgumentException("X and Y must be 32 bytes each");
        }
        this.x = x.clone();
        this.y = y.clone();
    }

    /**
     * Get X coordinate. Must call {@link #setCoordinates} first.
     */
    public byte[] getX() {
        if (x == null) {
            throw new IllegalStateException("Public key coordinates not loaded. Export from device first.");
        }
        return x.clone();
    }

    /**
     * Get Y coordinate. Must call {@link #setCoordinates} first.
     */
    public byte[] getY() {
        if (y == null) {
            throw new IllegalStateException("Public key coordinates not loaded. Export from device first.");
        }
        return y.clone();
    }

    @Override
    public String getAlgorithm() {
        return ALGORITHM;
    }

    @Override
    public String getFormat() {
        return "SDF_INTERNAL";
    }

    /**
     * Returns the encoded public key (X || Y, 64 bytes) if coordinates are loaded,
     * otherwise returns {@code null}.
     */
    @Override
    public byte[] getEncoded() {
        if (x == null || y == null) {
            return null;
        }
        byte[] encoded = new byte[64];
        System.arraycopy(x, 0, encoded, 0, 32);
        System.arraycopy(y, 0, encoded, 32, 32);
        return encoded;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof SDFInternalPublicKey)) return false;
        SDFInternalPublicKey other = (SDFInternalPublicKey) obj;
        return keyIndex == other.keyIndex && usage == other.usage;
    }

    @Override
    public int hashCode() {
        return 31 * keyIndex + usage.hashCode();
    }

    @Override
    public String toString() {
        return "SDFInternalPublicKey{index=" + keyIndex + ", usage=" + usage
                + ", loaded=" + isLoaded() + "}";
    }
}
