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

package org.openhitls.sdf4j.jce.random;

import java.security.SecureRandomSpi;

import org.openhitls.sdf4j.jce.native_.SDFJceNative;

/**
 * SecureRandom implementation using SDF hardware random number generator
 */
public final class SDFSecureRandom extends SecureRandomSpi {

    private static final long serialVersionUID = 1L;

    public SDFSecureRandom() {
    }

    @Override
    protected void engineSetSeed(byte[] seed) {
        // SDF hardware RNG doesn't need seeding
    }

    @Override
    protected void engineNextBytes(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return;
        }
        byte[] random = SDFJceNative.generateRandom(bytes.length);
        System.arraycopy(random, 0, bytes, 0, bytes.length);
    }

    @Override
    protected byte[] engineGenerateSeed(int numBytes) {
        if (numBytes <= 0) {
            return new byte[0];
        }
        return SDFJceNative.generateRandom(numBytes);
    }
}
