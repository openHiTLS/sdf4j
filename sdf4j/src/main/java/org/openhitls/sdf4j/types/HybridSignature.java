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
        if (sigM == null) {
            throw new IllegalArgumentException("signature value cannot be null");
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
