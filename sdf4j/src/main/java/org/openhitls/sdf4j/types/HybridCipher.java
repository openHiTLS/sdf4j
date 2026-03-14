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

import java.util.Arrays;

/**
 * Hybrid Cipher Structure (HybridCipher)
 *
 * <p>Represents the ciphertext produced by a hybrid (post-quantum + classical) key encapsulation
 * operation. This structure combines a post-quantum ciphertext component (ML-KEM) with a
 * classical ECC ciphertext component (SM2), along with the resulting session key handle.
 *
 * <p>Typically returned by {@link org.openhitls.sdf4j.SDF#SDF_GenerateKeyWithEPK_Hybrid}
 * and consumed by {@link org.openhitls.sdf4j.SDF#SDF_ImportKeyWithISK_Hybrid}.
 *
 * <p><b>Structure Layout</b>
 * <ul>
 *   <li>{@code ctM} - Post-quantum ciphertext (e.g., ML-KEM ciphertext), length specified by {@code l1}</li>
 *   <li>{@code ctS} - Classical ECC ciphertext ({@link ECCCipher}, e.g., SM2 encryption result)</li>
 *   <li>{@code uiAlgID} - Algorithm identifier for the hybrid scheme</li>
 *   <li>{@code keyHandle} - Session key handle for subsequent symmetric operations</li>
 * </ul>
 *
 * @author OpenHitls Team
 * @since 1.0.0
 * @see org.openhitls.sdf4j.SDF#SDF_GenerateKeyWithEPK_Hybrid
 * @see org.openhitls.sdf4j.SDF#SDF_ImportKeyWithISK_Hybrid
 */
public class HybridCipher {

    /**
     * Post-quantum ciphertext length (bytes)
     */
    private long l1;

    /**
     * Post-quantum ciphertext data (e.g., ML-KEM ciphertext)
     */
    private byte[] ctM;

    /**
     * Algorithm identifier for the hybrid encryption scheme
     *
     * @see org.openhitls.sdf4j.constants.AlgorithmID#SGD_HYBRID_ENV_SM2_MLKEM_512
     */
    private long uiAlgID;

    /**
     * Classical ECC ciphertext component (e.g., SM2 encryption result)
     */
    private ECCCipher ctS;

    /**
     * Session key handle, usable for subsequent symmetric encryption/decryption operations
     */
    private long keyHandle;

    /**
     * Default constructor.
     */
    public HybridCipher() {
    }

    /**
     * Parameterized constructor used by JNI layer for efficient object creation.
     *
     * @param l1        post-quantum ciphertext length (bytes)
     * @param ctM       post-quantum ciphertext data (e.g., ML-KEM ciphertext)
     * @param uiAlgID   algorithm identifier for the hybrid scheme
     * @param ctS       classical ECC ciphertext component
     * @param keyHandle session key handle
     * @throws IllegalArgumentException if ctM or ctS is null, or l1 is invalid
     */
    public HybridCipher(long l1, byte[] ctM, long uiAlgID, ECCCipher ctS, long keyHandle) {
        if (ctM == null || ctS == null) {
            throw new IllegalArgumentException("input cannot be null");
        }
        if (l1 < 0 || l1 > ctM.length) {
            throw new IllegalArgumentException("pqc cipher is invalid");
        }
        this.l1 = l1;
        this.ctM = ctM;
        this.uiAlgID = uiAlgID;
        this.ctS = ctS;
        this.keyHandle = keyHandle;
    }

    /**
     * Get post-quantum ciphertext length.
     *
     * @return post-quantum ciphertext length in bytes
     */
    public long getL1() {
        return l1;
    }

    /**
     * Set post-quantum ciphertext length.
     *
     * @param l1 post-quantum ciphertext length in bytes
     * @throws IllegalArgumentException if l1 is negative or exceeds ctM length
     */
    public void setL1(long l1) {
        if (l1 < 0) {
            throw new IllegalArgumentException("Ciphertext length cannot be negative");
        }
        if (ctM != null && l1 > ctM.length) {
            throw new IllegalArgumentException("len cannot exceed data length");
        }
        this.l1 = l1;
    }

    /**
     * Get post-quantum ciphertext data.
     *
     * <p>Returns a direct reference to the internal array. Callers should not modify the returned value.
     *
     * @return post-quantum ciphertext byte array (e.g., ML-KEM ciphertext)
     */
    public byte[] getCtM() {
        return ctM;
    }

    /**
     * Set post-quantum ciphertext data.
     *
     * @param ctM post-quantum ciphertext byte array
     * @throws IllegalArgumentException if ctM is null or length is inconsistent with l1
     */
    public void setCtM(byte[] ctM) {
        if (ctM == null || this.l1 > ctM.length) {
            throw new IllegalArgumentException("cipher value is invalid");
        }
        this.ctM = ctM;
    }

    /**
     * Get algorithm identifier for the hybrid encryption scheme.
     *
     * @return algorithm identifier
     * @see org.openhitls.sdf4j.constants.AlgorithmID#SGD_HYBRID_ENV_SM2_MLKEM_512
     */
    public long getUiAlgID() {
        return uiAlgID;
    }

    /**
     * Set algorithm identifier for the hybrid encryption scheme.
     *
     * @param uiAlgID algorithm identifier
     */
    public void setUiAlgID(long uiAlgID) {
        this.uiAlgID = uiAlgID;
    }

    /**
     * Get classical ECC ciphertext component.
     *
     * @return ECC ciphertext structure (e.g., SM2 encryption result)
     */
    public ECCCipher getCtS() {
        return ctS;
    }

    /**
     * Set classical ECC ciphertext component.
     *
     * @param ctS ECC ciphertext structure
     * @throws IllegalArgumentException if ctS is null
     */
    public void setCtS(ECCCipher ctS) {
        if (ctS == null) {
            throw new IllegalArgumentException("cipher value cannot be null");
        }
        this.ctS = ctS;
    }

    /**
     * Get session key handle.
     *
     * <p>The key handle can be used for subsequent symmetric encryption/decryption
     * operations via {@link org.openhitls.sdf4j.SDF#SDF_Encrypt} and
     * {@link org.openhitls.sdf4j.SDF#SDF_Decrypt}.
     *
     * @return session key handle
     */
    public long getKeyHandle() {
        return keyHandle;
    }

    /**
     * Set session key handle.
     *
     * @param keyHandle session key handle
     */
    public void setKeyHandle(long keyHandle) {
        this.keyHandle = keyHandle;
    }
}
