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
     * 构造函数
     * Constructor
     */
    public ECCKeyEncryptionResult() {
    }

    
    /**
     * 构造函数
     * Constructor
     *
     * @param eccCipher ECC加密的密钥数据 / ECC encrypted key data
     * @param keyHandle 密钥句柄 / Key handle
     */
    public ECCKeyEncryptionResult(ECCCipher eccCipher, long keyHandle) {
        this.eccCipher = eccCipher;
        this.keyHandle = keyHandle;
    }

    /**
     * 获取ECC加密的密钥数据
     * Get encrypted key data
     *
     * @return ECC加密的密钥数据 / ECC encrypted key data
     */
    public ECCCipher getEccCipher() {
        return eccCipher;
    }

    /**
     * 获取密钥句柄
     * Get key handle
     *
     * @return 密钥句柄 / Key handle
     */
    public long getKeyHandle() {
        return keyHandle;
    }
}
