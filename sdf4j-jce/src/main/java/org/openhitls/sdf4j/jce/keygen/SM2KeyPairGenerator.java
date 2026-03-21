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
import java.util.Arrays;
import java.security.spec.AlgorithmParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;

import org.openhitls.sdf4j.jce.key.SM2PrivateKey;
import org.openhitls.sdf4j.jce.key.SM2PublicKey;
import org.openhitls.sdf4j.jce.SDFJceNative;

/**
 * SM2 KeyPairGenerator implementation
 */
public final class SM2KeyPairGenerator extends KeyPairGeneratorSpi {

    private long sessionHandle;
    private SecureRandom random;

    public SM2KeyPairGenerator() {
        this.sessionHandle = SDFJceNative.openSession();
        if (sessionHandle == 0) {
            throw new IllegalStateException("Failed to open SDF session");
        }
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        if (keysize != 256) {
            throw new InvalidParameterException("SM2 key size must be 256 bits");
        }
        this.random = random;
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        this.random = random;
    }

    @Override
    public KeyPair generateKeyPair() {
        // Returns byte[96]: privateKey(32) || publicKeyX(32) || publicKeyY(32)
        byte[] keyData = SDFJceNative.sm2GenerateKeyPair(sessionHandle);

        byte[] privateKeyBytes = new byte[32];
        byte[] publicKeyX = new byte[32];
        byte[] publicKeyY = new byte[32];

        try {
            System.arraycopy(keyData, 0, privateKeyBytes, 0, 32);
            System.arraycopy(keyData, 32, publicKeyX, 0, 32);
            System.arraycopy(keyData, 64, publicKeyY, 0, 32);
        } finally {
            // Zero out the raw key material immediately after copying
            Arrays.fill(keyData, (byte) 0);
        }

        SM2PrivateKey privateKey = new SM2PrivateKey(privateKeyBytes);
        SM2PublicKey publicKey = new SM2PublicKey(publicKeyX, publicKeyY);

        return new KeyPair(publicKey, privateKey);
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            if (sessionHandle != 0) {
                SDFJceNative.closeSession(sessionHandle);
            }
        } finally {
            super.finalize();
        }
    }
}
