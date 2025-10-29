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
 * 密钥加密结果
 * Key Encryption Result
 *
 * <p>包含加密后的密钥数据和密钥句柄
 * <p>Contains encrypted key data and key handle
 *
 * <p>用于密钥生成和导入操作的返回结果
 * <p>Used as return value for key generation and import operations
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
public class KeyEncryptionResult {
    private byte[] encryptedKey;
    private long keyHandle;

    /**
     * 构造函数
     * Constructor
     */
    public KeyEncryptionResult() {
    }

    /**
     * 构造函数
     * Constructor
     *
     * @param encryptedKey 加密的密钥数据 / Encrypted key data
     * @param keyHandle 密钥句柄 / Key handle
     */
    public KeyEncryptionResult(byte[] encryptedKey, long keyHandle) {
        this.encryptedKey = encryptedKey;
        this.keyHandle = keyHandle;
    }

    /**
     * 获取加密的密钥数据
     * Get encrypted key data
     *
     * @return 加密的密钥数据 / Encrypted key data
     */
    public byte[] getEncryptedKey() {
        return encryptedKey;
    }

    /**
     * 设置加密的密钥数据
     * Set encrypted key data
     *
     * @param encryptedKey 加密的密钥数据 / Encrypted key data
     */
    public void setEncryptedKey(byte[] encryptedKey) {
        this.encryptedKey = encryptedKey;
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

    /**
     * 设置密钥句柄
     * Set key handle
     *
     * @param keyHandle 密钥句柄 / Key handle
     */
    public void setKeyHandle(long keyHandle) {
        this.keyHandle = keyHandle;
    }

    @Override
    public String toString() {
        return "KeyEncryptionResult{" +
                "encryptedKeyLength=" + (encryptedKey != null ? encryptedKey.length : 0) +
                ", keyHandle=" + keyHandle +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyEncryptionResult that = (KeyEncryptionResult) o;
        return keyHandle == that.keyHandle && Arrays.equals(encryptedKey, that.encryptedKey);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(encryptedKey);
        result = 31 * result + (int) (keyHandle ^ (keyHandle >>> 32));
        return result;
    }
}
