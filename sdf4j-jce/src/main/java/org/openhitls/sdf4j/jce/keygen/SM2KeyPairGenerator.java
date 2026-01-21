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

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

import org.openhitls.sdf4j.jce.key.SM2PrivateKey;
import org.openhitls.sdf4j.jce.key.SM2PublicKey;
import org.openhitls.sdf4j.jce.native_.SDFJceNative;

/**
 * SM2 KeyPairGenerator implementation
 */
public final class SM2KeyPairGenerator extends KeyPairGeneratorSpi {

    private SecureRandom random;

    public SM2KeyPairGenerator() {
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
        byte[] keyData = SDFJceNative.sm2GenerateKeyPair();

        byte[] privateKeyBytes = new byte[32];
        byte[] publicKeyX = new byte[32];
        byte[] publicKeyY = new byte[32];

        System.arraycopy(keyData, 0, privateKeyBytes, 0, 32);
        System.arraycopy(keyData, 32, publicKeyX, 0, 32);
        System.arraycopy(keyData, 64, publicKeyY, 0, 32);

        SM2PrivateKey privateKey = new SM2PrivateKey(privateKeyBytes);
        SM2PublicKey publicKey = new SM2PublicKey(publicKeyX, publicKeyY);

        return new KeyPair(publicKey, privateKey);
    }
}
