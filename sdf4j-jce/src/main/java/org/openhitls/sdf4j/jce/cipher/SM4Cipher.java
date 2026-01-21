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
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

import org.openhitls.sdf4j.jce.native_.SDFJceNative;

/**
 * SM4 Cipher implementation
 */
public class SM4Cipher extends CipherSpi {

    protected static final int MODE_ECB = 0;
    protected static final int MODE_CBC = 1;
    protected static final int MODE_CTR = 2;
    protected static final int MODE_GCM = 3;

    protected static final int BLOCK_SIZE = 16;
    protected static final int KEY_SIZE = 16;

    protected static final int PADDING_NONE = 0;
    protected static final int PADDING_PKCS5 = 1;

    protected int cipherMode = MODE_CBC;
    protected int paddingMode = PADDING_NONE;
    protected int opmode;
    protected byte[] key;
    protected byte[] iv;
    protected long ctx = 0;
    protected ByteArrayOutputStream buffer;

    public SM4Cipher() {
        this.cipherMode = MODE_CBC;
    }

    protected SM4Cipher(int mode) {
        this.cipherMode = mode;
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if ("ECB".equalsIgnoreCase(mode)) {
            this.cipherMode = MODE_ECB;
        } else if ("CBC".equalsIgnoreCase(mode)) {
            this.cipherMode = MODE_CBC;
        } else if ("CTR".equalsIgnoreCase(mode)) {
            this.cipherMode = MODE_CTR;
        } else if ("GCM".equalsIgnoreCase(mode)) {
            // GCM mode is not yet fully implemented in native layer
            throw new NoSuchAlgorithmException("GCM mode not yet supported");
        } else {
            throw new NoSuchAlgorithmException("Unsupported mode: " + mode);
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if ("NoPadding".equalsIgnoreCase(padding)) {
            this.paddingMode = PADDING_NONE;
        } else if ("PKCS5Padding".equalsIgnoreCase(padding) || "PKCS7Padding".equalsIgnoreCase(padding)) {
            this.paddingMode = PADDING_PKCS5;
        } else {
            throw new NoSuchPaddingException("Unsupported padding: " + padding);
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return BLOCK_SIZE;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        if (opmode == Cipher.ENCRYPT_MODE) {
            if (paddingMode == PADDING_PKCS5) {
                // With padding, output is always aligned to block size plus one block
                return ((inputLen / BLOCK_SIZE) + 1) * BLOCK_SIZE;
            }
            // CTR/GCM modes don't change size; ECB/CBC with NoPadding return same size
            return inputLen;
        } else {
            // Decryption: output size is at most input size (padding removed)
            return inputLen;
        }
    }

    @Override
    protected byte[] engineGetIV() {
        return iv != null ? iv.clone() : null;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        try {
            engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException(e.getMessage());
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.opmode = opmode;
        this.key = key.getEncoded();

        if (this.key == null || this.key.length != KEY_SIZE) {
            throw new InvalidKeyException("Key must be 16 bytes");
        }

        if (params != null) {
            if (params instanceof IvParameterSpec) {
                this.iv = ((IvParameterSpec) params).getIV();
            } else {
                throw new InvalidAlgorithmParameterException("Unsupported parameter type");
            }
        } else if (cipherMode != MODE_ECB) {
            // Generate random IV for non-ECB modes
            this.iv = new byte[BLOCK_SIZE];
            SecureRandom rng = (random != null) ? random : new SecureRandom();
            rng.nextBytes(this.iv);
        }

        buffer = new ByteArrayOutputStream();
        ctx = 0;
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        AlgorithmParameterSpec spec = null;
        if (params != null) {
            try {
                spec = params.getParameterSpec(IvParameterSpec.class);
            } catch (Exception e) {
                throw new InvalidAlgorithmParameterException("Could not get IvParameterSpec from AlgorithmParameters");
            }
        }
        engineInit(opmode, key, spec, random);
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

        if (opmode == Cipher.ENCRYPT_MODE) {
            // Apply padding for encryption
            if (paddingMode == PADDING_PKCS5) {
                data = addPkcs5Padding(data);
            } else if (cipherMode != MODE_CTR && cipherMode != MODE_GCM) {
                // ECB and CBC require block-aligned data when no padding
                if (data.length % BLOCK_SIZE != 0) {
                    throw new IllegalBlockSizeException(
                        "Data length must be multiple of " + BLOCK_SIZE + " bytes with NoPadding");
                }
            }
            return SDFJceNative.sm4Encrypt(cipherMode, key, iv, data, null);
        } else {
            // Decrypt first
            byte[] decrypted = SDFJceNative.sm4Decrypt(cipherMode, key, iv, data, null, null);

            // Remove padding for decryption
            if (paddingMode == PADDING_PKCS5) {
                return removePkcs5Padding(decrypted);
            }
            return decrypted;
        }
    }

    /**
     * Add PKCS#5/PKCS#7 padding to data
     */
    private byte[] addPkcs5Padding(byte[] data) {
        int paddingLen = BLOCK_SIZE - (data.length % BLOCK_SIZE);
        byte[] padded = new byte[data.length + paddingLen];
        System.arraycopy(data, 0, padded, 0, data.length);
        for (int i = data.length; i < padded.length; i++) {
            padded[i] = (byte) paddingLen;
        }
        return padded;
    }

    /**
     * Remove PKCS#5/PKCS#7 padding from data
     */
    private byte[] removePkcs5Padding(byte[] data) throws BadPaddingException {
        if (data == null || data.length == 0) {
            throw new BadPaddingException("Empty data");
        }
        if (data.length % BLOCK_SIZE != 0) {
            throw new BadPaddingException("Data length not block aligned");
        }

        int paddingLen = data[data.length - 1] & 0xFF;
        if (paddingLen < 1 || paddingLen > BLOCK_SIZE) {
            throw new BadPaddingException("Invalid padding length: " + paddingLen);
        }

        // Verify all padding bytes are correct
        for (int i = data.length - paddingLen; i < data.length; i++) {
            if ((data[i] & 0xFF) != paddingLen) {
                throw new BadPaddingException("Invalid PKCS5 padding");
            }
        }

        byte[] unpadded = new byte[data.length - paddingLen];
        System.arraycopy(data, 0, unpadded, 0, unpadded.length);
        return unpadded;
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

    // Inner classes for specific modes
    public static class ECB extends SM4Cipher {
        public ECB() {
            super(MODE_ECB);
        }
    }

    public static class ECB_PKCS5 extends SM4Cipher {
        public ECB_PKCS5() {
            super(MODE_ECB);
            this.paddingMode = PADDING_PKCS5;
        }
    }

    public static class CBC extends SM4Cipher {
        public CBC() {
            super(MODE_CBC);
        }
    }

    public static class CBC_PKCS5 extends SM4Cipher {
        public CBC_PKCS5() {
            super(MODE_CBC);
            this.paddingMode = PADDING_PKCS5;
        }
    }

    public static class CTR extends SM4Cipher {
        public CTR() {
            super(MODE_CTR);
        }
    }

    // Note: GCM mode is not yet fully implemented in native layer
    // Uncomment when AEAD support is added
    // public static class GCM extends SM4Cipher {
    //     public GCM() {
    //         super(MODE_GCM);
    //     }
    // }
}
