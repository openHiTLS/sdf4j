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


/**
 * Key Encryption Result
 *
 * <p>Contains encrypted key data and key handle
 *
 * <p>Used as return value for key generation and import operations
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
public class KeyEncryptionResult {
    private byte[] encryptedKey;
    private long keyHandle;

    /**
     * Constructor
     */
    public KeyEncryptionResult() {
    }

    /**
     * Constructor
     *
     * @param encryptedKey Encrypted key data
     * @param keyHandle Key handle
     */
    public KeyEncryptionResult(byte[] encryptedKey, long keyHandle) {
        this.encryptedKey = encryptedKey;
        this.keyHandle = keyHandle;
    }

    /**
     * Get encrypted key data
     *
     * @return Encrypted key data
     */
    public byte[] getEncryptedKey() {
        return encryptedKey;
    }

    /**
     * Get key handle
     *
     * @return Key handle
     */
    public long getKeyHandle() {
        return keyHandle;
    }
}
