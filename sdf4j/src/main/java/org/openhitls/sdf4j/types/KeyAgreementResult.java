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
 * <p>Contains the output of an SM2 key agreement operation, including the agreement handle,
 * the party's ECC public key, and the temporary ECC public key used in the agreement protocol.
 *
 * <p>Returned by {@link org.openhitls.sdf4j.SDF#SDF_GenerateAgreementDataWithECC}
 * (sponsor side) and {@link org.openhitls.sdf4j.SDF#SDF_GenerateAgreementDataAndKeyWithECC}
 * (responder side).
 *
 * <p><b>Usage in Two-Party Key Agreement</b>
 * <ol>
 *   <li>Sponsor calls {@code SDF_GenerateAgreementDataWithECC} to get sponsor's result</li>
 *   <li>Sponsor sends its public key and temporary public key to responder</li>
 *   <li>Responder calls {@code SDF_GenerateAgreementDataAndKeyWithECC} to get responder's result
 *       and compute the session key in one step</li>
 *   <li>Responder sends its public key and temporary public key back to sponsor</li>
 *   <li>Sponsor calls {@code SDF_GenerateKeyWithECC} with responder's data to compute the session key</li>
 * </ol>
 *
 * @author OpenHitls Team
 * @since 1.0.0
 * @see org.openhitls.sdf4j.SDF#SDF_GenerateAgreementDataWithECC
 * @see org.openhitls.sdf4j.SDF#SDF_GenerateAgreementDataAndKeyWithECC
 * @see org.openhitls.sdf4j.SDF#SDF_GenerateKeyWithECC
 */
public class KeyAgreementResult {

    /**
     * Agreement handle (used by sponsor to compute session key via
     * {@link org.openhitls.sdf4j.SDF#SDF_GenerateKeyWithECC})
     */
    private long agreementHandle;

    /**
     * Party's ECC public key
     */
    private ECCPublicKey publicKey;

    /**
     * Party's temporary ECC public key (ephemeral key for this agreement session)
     */
    private ECCPublicKey tmpPublicKey;

    /**
     * Default constructor.
     */
    public KeyAgreementResult() {
    }

    /**
     * Parameterized constructor.
     *
     * @param agreementHandle agreement handle or session key handle
     * @param publicKey       party's ECC public key
     * @param tmpPublicKey    party's temporary ECC public key
     */
    public KeyAgreementResult(long agreementHandle, ECCPublicKey publicKey, ECCPublicKey tmpPublicKey) {
        this.agreementHandle = agreementHandle;
        this.publicKey = publicKey;
        this.tmpPublicKey = tmpPublicKey;
    }

    /**
     * Get agreement handle.
     *
     * @return agreement handle
     */
    public long getAgreementHandle() {
        return agreementHandle;
    }

    /**
     * Get party's ECC public key.
     *
     * @return ECC public key of this party
     */
    public ECCPublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Get party's temporary ECC public key.
     *
     * <p>This is the ephemeral key generated specifically for this agreement session.
     *
     * @return temporary ECC public key
     */
    public ECCPublicKey getTmpPublicKey() {
        return tmpPublicKey;
    }
}
