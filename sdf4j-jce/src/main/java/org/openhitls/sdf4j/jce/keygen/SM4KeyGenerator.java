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

package org.openhitls.sdf4j.jce.keygen;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

import org.openhitls.sdf4j.jce.native_.SDFJceNative;

/**
 * SM4 KeyGenerator implementation
 */
public final class SM4KeyGenerator extends KeyGeneratorSpi {

    private static final int KEY_SIZE = 128; // 128 bits = 16 bytes
    private SecureRandom random;

    public SM4KeyGenerator() {
    }

    @Override
    protected void engineInit(SecureRandom random) {
        this.random = random;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        this.random = random;
    }

    @Override
    protected void engineInit(int keysize, SecureRandom random) {
        if (keysize != KEY_SIZE) {
            throw new InvalidParameterException("SM4 key size must be 128 bits");
        }
        this.random = random;
    }

    @Override
    protected SecretKey engineGenerateKey() {
        byte[] keyBytes = SDFJceNative.generateSm4Key();
        return new SecretKeySpec(keyBytes, "SM4");
    }
}
