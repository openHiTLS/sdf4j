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
 * Hybrid Signature Structure (HybridSignature)
 *
 * <p>Represents a composite signature produced by combining a classical ECC signature (e.g., SM2)
 * with a post-quantum signature (e.g., ML-DSA). Both signature components must verify
 * successfully for the overall verification to pass.
 *
 * <p>Typically returned by {@link org.openhitls.sdf4j.SDF#SDF_InternalSign_Composite}
 * and consumed by {@link org.openhitls.sdf4j.SDF#SDF_ExternalVerify_Composite}.
 *
 * <p><b>Structure Layout</b>
 * <ul>
 *   <li>{@code sigS} - Classical ECC signature component ({@link ECCSignature})</li>
 *   <li>{@code sigM} - Post-quantum signature data (e.g., ML-DSA signature), length specified by {@code l}</li>
 * </ul>
 *
 * @author OpenHitls Team
 * @since 1.0.0
 * @see org.openhitls.sdf4j.SDF#SDF_InternalSign_Composite
 * @see org.openhitls.sdf4j.SDF#SDF_ExternalVerify_Composite
 */
public class HybridSignature {

    /**
     * Classical ECC signature component (e.g., SM2 signature with r and s values)
     */
    private ECCSignature sigS;

    /**
     * Post-quantum signature length (bytes)
     */
    private int l;

    /**
     * Post-quantum signature data (e.g., ML-DSA signature value)
     */
    private byte[] sigM;

    /**
     * Default constructor.
     */
    public HybridSignature() {
    }

    /**
     * Parameterized constructor used by JNI layer for efficient object creation.
     *
     * @param sigS classical ECC signature component
     * @param l    post-quantum signature data length (bytes)
     * @param sigM post-quantum signature data
     * @throws IllegalArgumentException if sigS or sigM is null, or l is invalid
     */
    public HybridSignature(ECCSignature sigS, int l, byte[] sigM) {
        if (sigM == null || sigS == null) {
            throw new IllegalArgumentException("input cannot be null");
        }
        if (l < 0 || l > sigM.length) {
            throw new IllegalArgumentException("pqc signature value is invalid");
        }
        this.sigS = sigS;
        this.l = l;
        this.sigM = sigM;
    }

    /**
     * Get classical ECC signature component.
     *
     * @return ECC signature containing r and s values
     */
    public ECCSignature getSigS() {
        return sigS;
    }

    /**
     * Set classical ECC signature component.
     *
     * @param sigS ECC signature
     * @throws IllegalArgumentException if sigS is null
     */
    public void setSigS(ECCSignature sigS) {
        if (sigS == null) {
            throw new IllegalArgumentException("ECC signature cannot be null");
        }
        this.sigS = sigS;
    }

    /**
     * Get post-quantum signature data.
     *
     * <p>Returns a direct reference to the internal array. Callers should not modify the returned value.
     *
     * @return post-quantum signature byte array (e.g., ML-DSA signature)
     */
    public byte[] getSigM() {
        return sigM;
    }

    /**
     * Set post-quantum signature data.
     *
     * @param sigM post-quantum signature byte array
     * @throws IllegalArgumentException if sigM is null or length is inconsistent with l
     */
    public void setSigM(byte[] sigM) {
        if (sigM == null || this.l > sigM.length) {
            throw new IllegalArgumentException("signature value is invalid");
        }
        this.sigM = sigM;
    }

    /**
     * Get post-quantum signature data length.
     *
     * @return signature data length in bytes
     */
    public int getL() {
        return l;
    }

    /**
     * Set post-quantum signature data length.
     *
     * @param l signature data length in bytes
     */
    public void setL(int l) {
        if (l < 0) {
            throw new IllegalArgumentException("signature len is invalid");
        }
        if (sigM != null && l > sigM.length) {
            throw new IllegalArgumentException("signature len cannot exceed data length");
        }
        this.l = l;
    }
}
