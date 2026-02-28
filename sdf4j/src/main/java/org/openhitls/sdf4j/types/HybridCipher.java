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
 */
public class HybridCipher {

    private long l1;
    private byte[] ctM;
    private long uiAlgID;
    private ECCCipher ctS;
    private long keyHandle;

    public HybridCipher() {
    }

    /**
     * Parameterized constructor used by JNI layer for efficient object creation.
     *
     * @param l1        ciphertext M length
     * @param ctM       ciphertext M data
     * @param uiAlgID   algorithm ID
     * @param ctS       ECC cipher structure
     * @param keyHandle key handle
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

    public long getL1() {
        return l1;
    }

    public void setL1(long l1) {
        if (l1 < 0) {
            throw new IllegalArgumentException("Ciphertext length cannot be negative");
        }
        if (ctM != null && l1 > ctM.length) {
            throw new IllegalArgumentException("len cannot exceed data length");
        }
        this.l1 = l1;
    }

    public byte[] getCtM() {
        return ctM;
    }

    public void setCtM(byte[] ctM) {
        if (ctM == null || this.l1 > ctM.length) {
            throw new IllegalArgumentException("cipher value is invalid");
        }
        this.ctM = ctM;
    }

    public long getUiAlgID() {
        return uiAlgID;
    }

    public void setUiAlgID(long uiAlgID) {
        this.uiAlgID = uiAlgID;
    }

    public ECCCipher getCtS() {
        return ctS;
    }

    public void setCtS(ECCCipher ctS) {
        if (ctS == null) {
            throw new IllegalArgumentException("cipher value cannot be null");
        }
        this.ctS = ctS;
    }

    public long getKeyHandle() {
        return keyHandle;
    }

    public void setKeyHandle(long keyHandle) {
        this.keyHandle = keyHandle;
    }
}
