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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.openhitls.sdf4j.jce.key.SM2PrivateKey;
import org.openhitls.sdf4j.jce.key.SM2PublicKey;
import org.openhitls.sdf4j.jce.key.SDFInternalPrivateKey;
import org.openhitls.sdf4j.jce.key.SDFInternalPublicKey;
import org.openhitls.sdf4j.jce.SDFJceNative;

/**
 * SM2 Cipher implementation for asymmetric encryption/decryption.
 *
 * Supports both External and Internal key modes:
 * <ul>
 *   <li><b>External</b>: Use {@link SM2PublicKey}/{@link SM2PrivateKey} — key material
 *       provided by the application.</li>
 *   <li><b>Internal</b>: Use {@link SDFInternalPublicKey}/{@link SDFInternalPrivateKey} — key stays
 *       in the device, calls {@code SDF_InternalEncrypt_ECC}/{@code SDF_InternalDecrypt_ECC}.
 *       Password-based access rights are handled automatically.</li>
 * </ul>
 *
 * Ciphertext format: 0x04 || C1_X(32) || C1_Y(32) || C3(32) || C2(var)
 */
public final class SM2Cipher extends CipherSpi {

    /** SGD_SM2_3 algorithm ID for SM2 encryption. */
    private static final int SGD_SM2_3 = 0x00020800;

    private long sessionHandle;
    private SM2PublicKey publicKey;
    private SM2PrivateKey privateKey;
    private SDFInternalPublicKey internalPublicKey;
    private SDFInternalPrivateKey internalPrivateKey;
    private int opmode;
    private boolean useInternalKey;
    private ByteArrayOutputStream buffer;
    private int acquiredAccessKeyIndex = -1;

    public SM2Cipher() {
        this.sessionHandle = SDFJceNative.openSession();
        if (sessionHandle == 0) {
            throw new IllegalStateException("Failed to open SDF session");
        }
        this.buffer = new ByteArrayOutputStream();
    }

    private void cleanup() {
        if (acquiredAccessKeyIndex != -1) {
            try {
                SDFJceNative.releasePrivateKeyAccessRight(sessionHandle, acquiredAccessKeyIndex);
            } catch (Exception ignored) {}
            acquiredAccessKeyIndex = -1;
        }
        publicKey = null;
        privateKey = null;
        internalPublicKey = null;
        internalPrivateKey = null;
        if (buffer != null) {
            buffer.reset();
        }
    }

    private void releaseSession() {
        cleanup();
        if (sessionHandle != 0) {
            long h = sessionHandle;
            sessionHandle = 0;
            SDFJceNative.closeSession(h);
        }
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (!"ECB".equalsIgnoreCase(mode) && !"NONE".equalsIgnoreCase(mode)) {
            throw new NoSuchAlgorithmException("SM2 only supports ECB/NONE mode");
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!"NoPadding".equalsIgnoreCase(padding)) {
            throw new NoSuchPaddingException("SM2 only supports NoPadding");
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return 0;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        if (opmode == Cipher.ENCRYPT_MODE) {
            return inputLen + 97;
        } else {
            return Math.max(0, inputLen - 97);
        }
    }

    @Override
    protected byte[] engineGetIV() {
        return null;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        cleanup();
        this.opmode = opmode;

        if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
            if (key instanceof SDFInternalPublicKey) {
                this.internalPublicKey = (SDFInternalPublicKey) key;
                this.publicKey = null;
                this.useInternalKey = true;
            } else if (key instanceof SM2PublicKey) {
                this.publicKey = (SM2PublicKey) key;
                this.internalPublicKey = null;
                this.useInternalKey = false;
            } else {
                throw new InvalidKeyException("SM2 encryption requires SM2PublicKey or SDFInternalPublicKey");
            }
            this.privateKey = null;
            this.internalPrivateKey = null;
        } else if (opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE) {
            if (key instanceof SDFInternalPrivateKey) {
                this.internalPrivateKey = (SDFInternalPrivateKey) key;
                this.privateKey = null;
                this.useInternalKey = true;
                // Auto-acquire access right
                acquirePrivateKeyAccessRight(this.internalPrivateKey);
            } else if (key instanceof SM2PrivateKey) {
                this.privateKey = (SM2PrivateKey) key;
                this.internalPrivateKey = null;
                this.useInternalKey = false;
            } else {
                throw new InvalidKeyException("SM2 decryption requires SM2PrivateKey or SDFInternalPrivateKey");
            }
            this.publicKey = null;
            this.internalPublicKey = null;
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
            if (inputOffset < 0 || inputLen < 0 || inputOffset + inputLen > input.length) {
                throw new IllegalArgumentException("Invalid inputOffset/inputLen");
            }
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
            if (inputOffset < 0 || inputLen < 0 || inputOffset + inputLen > input.length) {
                throw new IllegalArgumentException("Invalid inputOffset/inputLen");
            }
            buffer.write(input, inputOffset, inputLen);
        }

        byte[] data = buffer.toByteArray();
        buffer.reset();

        if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
            if (useInternalKey) {
                if (internalPublicKey == null) {
                    throw new IllegalStateException("Internal public key not set");
                }
                return SDFJceNative.sm2InternalEncrypt(
                    sessionHandle, internalPublicKey.getKeyIndex(), data);
            } else {
                if (publicKey == null) {
                    throw new IllegalStateException("Public key not set");
                }
                return SDFJceNative.sm2Encrypt(sessionHandle, publicKey.getX(), publicKey.getY(), data);
            }
        } else {
            if (useInternalKey) {
                if (internalPrivateKey == null) {
                    throw new IllegalStateException("Internal private key not set");
                }
                return SDFJceNative.sm2InternalDecrypt(
                    sessionHandle, internalPrivateKey.getKeyIndex(), SGD_SM2_3, data);
            } else {
                if (privateKey == null) {
                    throw new IllegalStateException("Private key not set");
                }
                return SDFJceNative.sm2Decrypt(sessionHandle, privateKey.getKeyBytes(), data);
            }
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

    /**
     * Auto-acquire private key access right for Internal key.
     */
    private void acquirePrivateKeyAccessRight(SDFInternalPrivateKey key) throws InvalidKeyException {
        char[] pwd = key.getPassword();
        if (pwd != null) {
            byte[] pwdBytes = new byte[pwd.length];
            for (int i = 0; i < pwd.length; i++) {
                pwdBytes[i] = (byte) pwd[i];
            }
            try {
                SDFJceNative.getPrivateKeyAccessRight(sessionHandle, key.getKeyIndex(), pwdBytes);
                this.acquiredAccessKeyIndex = key.getKeyIndex();
            } catch (Exception e) {
                throw new InvalidKeyException("Failed to acquire private key access right: " + e.getMessage(), e);
            } finally {
                java.util.Arrays.fill(pwdBytes, (byte) 0);
                java.util.Arrays.fill(pwd, '\0');
            }
        }
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            releaseSession();
        } finally {
            super.finalize();
        }
    }
}
