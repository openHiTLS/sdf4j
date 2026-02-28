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
 */
public class HybridSignature {

    private ECCSignature sigS;
    private int l;
    private byte[] sigM;

    public HybridSignature() {
    }

    /**
     * Parameterized constructor used by JNI layer for efficient object creation.
     *
     * @param sigS ECC signature
     * @param l    signature M length
     * @param sigM signature M data
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

    public ECCSignature getSigS() {
        return sigS;
    }

    public void setSigS(ECCSignature sigS) {
        if (sigS == null) {
            throw new IllegalArgumentException("ECC signature cannot be null");
        }
        this.sigS = sigS;
    }

    public byte[] getSigM() {
        return sigM;
    }

    public void setSigM(byte[] sigM) {
        if (sigM == null || this.l > sigM.length) {
            throw new IllegalArgumentException("signature value is invalid");
        }
        this.sigM = sigM;
    }

    public int getL() {
        return l;
    }

    public void setL(int l) {
        this.l = l;
    }
}
