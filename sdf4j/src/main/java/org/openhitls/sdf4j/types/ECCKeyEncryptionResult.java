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


public class ECCKeyEncryptionResult {
    private ECCCipher eccCipher;
    private long keyHandle;

    /**
     * Constructor
     */
    public ECCKeyEncryptionResult() {
    }

    /**
     * Constructor
     *
     * @param eccCipher ECC encrypted key data
     * @param keyHandle Key handle
     */
    public ECCKeyEncryptionResult(ECCCipher eccCipher, long keyHandle) {
        this.eccCipher = eccCipher;
        this.keyHandle = keyHandle;
    }

    /**
     * Get encrypted key data
     *
     * @return ECC encrypted key data
     */
    public ECCCipher getEccCipher() {
        return eccCipher;
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
