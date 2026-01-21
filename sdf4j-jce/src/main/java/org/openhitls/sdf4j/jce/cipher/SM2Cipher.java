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

package org.openhitls.sdf4j.jce.cipher;

import javax.crypto.*;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

import org.openhitls.sdf4j.jce.key.SM2PrivateKey;
import org.openhitls.sdf4j.jce.key.SM2PublicKey;
import org.openhitls.sdf4j.jce.native_.SDFJceNative;

/**
 * SM2 Cipher implementation for asymmetric encryption/decryption
 */
public final class SM2Cipher extends CipherSpi {

    private SM2PublicKey publicKey;
    private SM2PrivateKey privateKey;
    private int opmode;
    private ByteArrayOutputStream buffer;

    public SM2Cipher() {
        this.buffer = new ByteArrayOutputStream();
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (!"ECB".equalsIgnoreCase(mode) && !"NONE".equalsIgnoreCase(mode)) {
            throw new NoSuchAlgorithmException("SM2 only supports ECB/NONE mode");
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!"NoPadding".equalsIgnoreCase(padding) && !"PKCS1Padding".equalsIgnoreCase(padding)) {
            throw new NoSuchPaddingException("SM2 only supports NoPadding");
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return 0; // SM2 is not a block cipher
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        if (opmode == Cipher.ENCRYPT_MODE) {
            // SM2 ciphertext: C1_X(32) + C1_Y(32) + C3(32) + C2(plaintext length) = 96 + plaintext
            return inputLen + 96;
        } else {
            // Plaintext is ciphertext - 96 bytes overhead
            return Math.max(0, inputLen - 96);
        }
    }

    @Override
    protected byte[] engineGetIV() {
        return null; // SM2 doesn't use IV
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        this.opmode = opmode;
        this.buffer.reset();

        if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
            if (!(key instanceof SM2PublicKey)) {
                throw new InvalidKeyException("SM2 encryption requires SM2PublicKey");
            }
            this.publicKey = (SM2PublicKey) key;
            this.privateKey = null;
        } else if (opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE) {
            if (!(key instanceof SM2PrivateKey)) {
                throw new InvalidKeyException("SM2 decryption requires SM2PrivateKey");
            }
            this.privateKey = (SM2PrivateKey) key;
            this.publicKey = null;
        } else {
            throw new InvalidKeyException("Unknown opmode: " + opmode);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(opmode, key, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(opmode, key, random);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        if (input != null && inputLen > 0) {
            buffer.write(input, inputOffset, inputLen);
        }
        return new byte[0];
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        engineUpdate(input, inputOffset, inputLen);
        return 0;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        if (input != null && inputLen > 0) {
            buffer.write(input, inputOffset, inputLen);
        }

        byte[] data = buffer.toByteArray();
        buffer.reset();

        if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
            if (publicKey == null) {
                throw new IllegalStateException("Public key not set");
            }
            return SDFJceNative.sm2Encrypt(publicKey.getX(), publicKey.getY(), data);
        } else {
            if (privateKey == null) {
                throw new IllegalStateException("Private key not set");
            }
            return SDFJceNative.sm2Decrypt(privateKey.getKeyBytes(), data);
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] result = engineDoFinal(input, inputOffset, inputLen);
        if (output.length - outputOffset < result.length) {
            throw new ShortBufferException("Output buffer too small");
        }
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }

    @Override
    protected byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException {
        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            throw new InvalidKeyException("Key does not support encoding");
        }
        try {
            return engineDoFinal(encoded, 0, encoded.length);
        } catch (BadPaddingException e) {
            throw new InvalidKeyException("Wrap failed", e);
        }
    }

    @Override
    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType)
            throws InvalidKeyException, NoSuchAlgorithmException {
        try {
            byte[] keyBytes = engineDoFinal(wrappedKey, 0, wrappedKey.length);
            if (wrappedKeyType == Cipher.SECRET_KEY) {
                return new javax.crypto.spec.SecretKeySpec(keyBytes, wrappedKeyAlgorithm);
            } else {
                throw new NoSuchAlgorithmException("Unsupported wrapped key type");
            }
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new InvalidKeyException("Unwrap failed", e);
        }
    }
}
