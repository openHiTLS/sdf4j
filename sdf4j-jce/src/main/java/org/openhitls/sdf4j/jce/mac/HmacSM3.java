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
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

import org.openhitls.sdf4j.jce.SDFJceNative;
import java.util.Arrays;

/**
 * HMAC-SM3 implementation
 */
public final class HmacSM3 extends MacSpi {

    private static final int MAC_LENGTH = 32; // SM3 produces 256-bit hash

    private final long sessionHandle;
    private byte[] key;
    private ByteArrayOutputStream buffer;

    public HmacSM3() {
        this.sessionHandle = SDFJceNative.openSession();
        if (sessionHandle == 0) {
            throw new IllegalStateException("Failed to open SDF session");
        }
        this.buffer = new ByteArrayOutputStream();
    }

    @Override
    protected int engineGetMacLength() {
        return MAC_LENGTH;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params) throws InvalidKeyException, InvalidAlgorithmParameterException {
        // Clean up existing key before re-initializing
        cleanupKey();

        if (!(key instanceof SecretKey)) {
            throw new InvalidKeyException("Key must be a SecretKey");
        }
        this.key = key.getEncoded();
        if (this.key == null) {
            throw new InvalidKeyException("Key encoding is null");
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
        return SDFJceNative.hmacSm3(sessionHandle, key, data);
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
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            cleanupKey();
            if (sessionHandle != 0) {
                SDFJceNative.closeSession(sessionHandle);
            }
        } finally {
            super.finalize();
        }
    }
}
