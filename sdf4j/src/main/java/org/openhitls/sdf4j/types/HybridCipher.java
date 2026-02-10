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
 * 混合加密数据结构
 * Hybrid Cipher Structure (HybridCipher)
 */
public class HybridCipher {

    public static final int HYBRIDENCref_MAX_LEN = 1576;
    private long l1;
    private byte[] ctM;
    private long uiAlgID;
    private ECCCipher ctS;
    private long keyHandle;

    public HybridCipher() {
    }

    public long getL1() {
        return l1;
    }

    public void setL1(long l1) {
        this.l1 = l1;
    }

    public byte[] getCtM() {
        return ctM;
    }

    public void setCtM(byte[] ctM) {
        if (ctM == null) {
            throw new IllegalArgumentException("cipher value cannot be null");
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
        this.ctS = ctS;
    }

    public long getKeyHandle() {
        return keyHandle;
    }

    public void setKeyHandle(long keyHandle) {
        this.keyHandle = keyHandle;
    }
}
