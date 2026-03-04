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
 * ECC Key Encryption Result
 *
 * <p>Contains the result of an ECC-based session key generation operation,
 * including the ECC-encrypted key data ({@link ECCCipher}) and the session key handle
 * for use in subsequent cryptographic operations.
 *
 * <p>Returned by {@link org.openhitls.sdf4j.SDF#SDF_GenerateKeyWithIPK_ECC}
 * and {@link org.openhitls.sdf4j.SDF#SDF_GenerateKeyWithEPK_ECC}.
 *
 * <p>The {@code eccCipher} can be transmitted to the receiving party, who can then
 * recover the session key using {@link org.openhitls.sdf4j.SDF#SDF_ImportKeyWithISK_ECC}.
 *
 * @author OpenHitls Team
 * @since 1.0.0
 * @see org.openhitls.sdf4j.SDF#SDF_GenerateKeyWithIPK_ECC
 * @see org.openhitls.sdf4j.SDF#SDF_GenerateKeyWithEPK_ECC
 * @see org.openhitls.sdf4j.SDF#SDF_ImportKeyWithISK_ECC
 */
public class ECCKeyEncryptionResult {

    /**
     * ECC-encrypted session key data
     */
    private ECCCipher eccCipher;

    /**
     * Session key handle for cryptographic operations
     */
    private long keyHandle;

    /**
     * Default constructor.
     */
    public ECCKeyEncryptionResult() {
    }

    /**
     * Parameterized constructor.
     *
     * @param eccCipher ECC-encrypted key data
     * @param keyHandle session key handle
     */
    public ECCKeyEncryptionResult(ECCCipher eccCipher, long keyHandle) {
        this.eccCipher = eccCipher;
        this.keyHandle = keyHandle;
    }

    /**
     * Get ECC-encrypted key data.
     *
     * <p>This cipher should be transmitted to the receiving party for key recovery
     * via {@link org.openhitls.sdf4j.SDF#SDF_ImportKeyWithISK_ECC}.
     *
     * @return ECC-encrypted key data
     */
    public ECCCipher getEccCipher() {
        return eccCipher;
    }

    /**
     * Get session key handle.
     *
     * <p>This handle can be used directly for symmetric encryption/decryption
     * operations such as {@link org.openhitls.sdf4j.SDF#SDF_Encrypt} and
     * {@link org.openhitls.sdf4j.SDF#SDF_Decrypt}.
     *
     * @return session key handle
     */
    public long getKeyHandle() {
        return keyHandle;
    }
}
