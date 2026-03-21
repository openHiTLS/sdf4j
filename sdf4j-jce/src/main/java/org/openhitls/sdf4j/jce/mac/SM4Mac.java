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

package org.openhitls.sdf4j.jce.mac;

import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

import org.openhitls.sdf4j.jce.SDFJceNative;
import java.util.Arrays;

/**
 * SM4-MAC (CBC-MAC) implementation
 */
public final class SM4Mac extends MacSpi {

    private static final int MAC_LENGTH = 16; // SM4 block size
    private static final int KEY_LENGTH = 16;
    private static final int IV_LENGTH = 16;

    private long sessionHandle;
    private byte[] key;
    private byte[] iv;
    private ByteArrayOutputStream buffer;

    public SM4Mac() {
        this.sessionHandle = SDFJceNative.openSession();
        if (sessionHandle == 0) {
            throw new IllegalStateException("Failed to open SDF session");
        }
        this.buffer = new ByteArrayOutputStream();
        this.iv = new byte[IV_LENGTH]; // Default zero IV
    }

    private void releaseSession() {
        if (sessionHandle != 0) {
            long h = sessionHandle;
            sessionHandle = 0;
            SDFJceNative.closeSession(h);
        }
    }

    @Override
    protected int engineGetMacLength() {
        return MAC_LENGTH;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        // Clean up existing key before re-initializing
        cleanupKey();

        if (!(key instanceof SecretKey)) {
            throw new InvalidKeyException("Key must be a SecretKey");
        }

        this.key = key.getEncoded();
        if (this.key == null || this.key.length != KEY_LENGTH) {
            throw new InvalidKeyException("SM4-MAC key must be 16 bytes");
        }

        if (params != null) {
            if (params instanceof IvParameterSpec) {
                byte[] paramIv = ((IvParameterSpec) params).getIV();
                if (paramIv.length != IV_LENGTH) {
                    throw new InvalidAlgorithmParameterException("IV must be 16 bytes");
                }
                this.iv = paramIv;
            } else {
                throw new InvalidAlgorithmParameterException("Unsupported parameter type");
            }
        } else {
            this.iv = new byte[IV_LENGTH];
        }

        buffer.reset();
    }

    @Override
    protected void engineUpdate(byte input) {
        buffer.write(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        buffer.write(input, offset, len);
    }

    @Override
    protected byte[] engineDoFinal() {
        byte[] data = buffer.toByteArray();
        buffer.reset();
        return SDFJceNative.sm4Mac(sessionHandle, key, iv, data);
    }

    @Override
    protected void engineReset() {
        buffer.reset();
    }

    /**
     * Clean up sensitive key material
     */
    private void cleanupKey() {
        if (key != null) {
            Arrays.fill(key, (byte) 0);
            key = null;
        }
        if (iv != null && iv.length == IV_LENGTH) {
            // Only clear IV if we own it (not externally provided via params)
            // For simplicity, we clear it here as it's typically not sensitive
        }
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            cleanupKey();
            releaseSession();
        } finally {
            super.finalize();
        }
    }
}
