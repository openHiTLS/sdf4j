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

package org.openhitls.sdf4j.jce.digest;

import java.security.MessageDigestSpi;

import org.openhitls.sdf4j.jce.SDFJceNative;

/**
 * SM3 MessageDigest implementation
 */
public final class SM3MessageDigest extends MessageDigestSpi {

    private static final int DIGEST_LENGTH = 32;

    private final long sessionHandle;
    private long ctx = 0;
    private boolean initialized = false;

    public SM3MessageDigest() {
        this.sessionHandle = SDFJceNative.openSession();
        if (sessionHandle == 0) {
            throw new IllegalStateException("Failed to open SDF session");
        }
    }

    @Override
    protected int engineGetDigestLength() {
        return DIGEST_LENGTH;
    }

    @Override
    protected void engineReset() {
        cleanupContext();
    }

    @Override
    protected void engineUpdate(byte input) {
        engineUpdate(new byte[]{input}, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        if (input == null) {
            throw new IllegalArgumentException("input is null");
        }
        if (offset < 0 || len < 0 || offset + len > input.length) {
            throw new IllegalArgumentException("Invalid offset/len");
        }
        if (!initialized) {
            ctx = SDFJceNative.sm3Init(sessionHandle);
            initialized = true;
        }
        if (len > 0) {
            SDFJceNative.sm3Update(ctx, input, offset, len);
        }
    }

    @Override
    protected byte[] engineDigest() {
        if (!initialized) {
            // Empty input
            return SDFJceNative.sm3Digest(sessionHandle, new byte[0]);
        }
        byte[] result = SDFJceNative.sm3Final(ctx);
        SDFJceNative.sm3Free(ctx);
        ctx = 0;
        initialized = false;
        return result;
    }

    @Override
    protected int engineDigest(byte[] buf, int offset, int len) {
        byte[] digest = engineDigest();
        if (offset < 0 || len < 0 || offset + digest.length > buf.length) {
            throw new IllegalArgumentException("Buffer too small or invalid offset");
        }
        System.arraycopy(digest, 0, buf, offset, digest.length);
        return digest.length;
    }

    /**
     * Cleanup native context safely
     */
    private void cleanupContext() {
        if (ctx != 0) {
            SDFJceNative.sm3Free(ctx);
            ctx = 0;
            initialized = false;
        }
    }

    /**
     * Cleanup when object is garbage collected
     */
    @Override
    protected void finalize() throws Throwable {
        try {
            cleanupContext();
            if (sessionHandle != 0) {
                SDFJceNative.closeSession(sessionHandle);
            }
        } finally {
            super.finalize();
        }
    }
}
