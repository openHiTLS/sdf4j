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
 * 密钥协商结果
 * Key Agreement Result
 *
 * <p>包含协商句柄、公钥和临时公钥
 * <p>Contains agreement handle, public key and temporary public key
 *
 */
public class KeyAgreementResult {
    private long agreementHandle;
    private ECCPublicKey publicKey;
    private ECCPublicKey tmpPublicKey;

    public KeyAgreementResult() {
    }

    public KeyAgreementResult(long agreementHandle, ECCPublicKey publicKey, ECCPublicKey tmpPublicKey) {
        this.agreementHandle = agreementHandle;
        this.publicKey = publicKey;
        this.tmpPublicKey = tmpPublicKey;
    }

    public long getAgreementHandle() {
        return agreementHandle;
    }

    /**
     * Get public key
     */
    public ECCPublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Get temporary public key
     */
    public ECCPublicKey getTmpPublicKey() {
        return tmpPublicKey;
    }
}
