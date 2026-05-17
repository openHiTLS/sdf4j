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

import java.util.Arrays;
import javax.crypto.SecretKey;

/**
 * SM4 Internal Symmetric Key — references an internal KEK-protected key in the SDF device.
 *
 * <p>For SM4 Internal mode, the key is managed via KEK (Key Encryption Key):
 * <ul>
 *   <li>Generate session key wrapped by KEK: {@code SDF_GenerateKeyWithKEK}</li>
 *   <li>Import session key wrapped by KEK: {@code SDF_ImportKeyWithKEK}</li>
 * </ul>
 *
 * <p>Usage:
 * <pre>{@code
 * // Create an internal key referencing KEK at index 4
 * SDFInternalSymmetricKey key = new SDFInternalSymmetricKey(4, "password".toCharArray());
 * Cipher cipher = Cipher.getInstance("SM4/CBC/NoPadding", "SDF");
 * cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
 * }</pre>
 */
public class SDFInternalSymmetricKey implements SecretKey {

    private static final long serialVersionUID = 1L;
    private static final String ALGORITHM = "SM4";

    private final int kekIndex;
    private char[] password;
    /** KEK-encrypted session key blob returned by SDF_GenerateKeyWithKEK; required for decryption. */
    private byte[] encryptedKeyBlob;

    /**
     * Construct an internal symmetric key reference.
     *
     * @param kekIndex KEK index in the device
     * @param password access password for KEK (nullable)
     */
    public SDFInternalSymmetricKey(int kekIndex, char[] password) {
        if (kekIndex < 0) {
            throw new IllegalArgumentException("kekIndex must be non-negative");
        }
        this.kekIndex = kekIndex;
        this.password = password != null ? password.clone() : null;
    }

    public int getKekIndex() {
        return kekIndex;
    }

    public char[] getPassword() {
        return password != null ? password.clone() : null;
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
     * Returns the KEK-encrypted session key blob set during encryption.
     * The blob must be passed to the decryption side so it can call
     * {@code SDF_ImportKeyWithKEK} to recover the same session key.
     *
     * @return cloned blob bytes, or {@code null} if not yet set
     */
    public byte[] getEncryptedKeyBlob() {
        return encryptedKeyBlob != null ? encryptedKeyBlob.clone() : null;
    }

    /**
     * Stores the KEK-encrypted session key blob produced by {@code SDF_GenerateKeyWithKEK}.
     *
     * @param blob the encrypted key blob (all bytes of the GenerateKeyWithKEK result
     *             except the trailing 8-byte key handle)
     */
    public void setEncryptedKeyBlob(byte[] blob) {
        this.encryptedKeyBlob = blob != null ? blob.clone() : null;
    }

    /**
     * Returns {@code true} if an encrypted key blob has been stored.
     */
    public boolean hasEncryptedKeyBlob() {
        return encryptedKeyBlob != null;
    }

    /**
     * Clear password material and key blob.
     */
    public void destroy() {
        if (password != null) {
            Arrays.fill(password, '\0');
            password = null;
        }
        if (encryptedKeyBlob != null) {
            Arrays.fill(encryptedKeyBlob, (byte) 0);
            encryptedKeyBlob = null;
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof SDFInternalSymmetricKey)) return false;
        SDFInternalSymmetricKey other = (SDFInternalSymmetricKey) obj;
        return kekIndex == other.kekIndex;
    }

    @Override
    public int hashCode() {
        return kekIndex;
    }

    @Override
    public String toString() {
        return "SDFInternalSymmetricKey{kekIndex=" + kekIndex + "}";
    }
}
