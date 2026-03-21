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
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

import org.openhitls.sdf4j.jce.SDFJceNative;
import java.util.Arrays;

/**
 * SM4 Cipher implementation with true streaming support.
 *
 * <p>For ECB/CBC modes, uses SDF multi-packet APIs
 * (EncryptInit/Update/Final) for true streaming.
 *
 * <p>For GCM/CCM (AEAD) modes, buffers data then uses single-packet
 * SDF_AuthEnc/SDF_AuthDec APIs. GCM tag is appended to ciphertext
 * per JCE convention (doFinal returns ciphertext || tag).
 */
public class SM4Cipher extends CipherSpi {

    protected static final int MODE_ECB = 0;
    protected static final int MODE_CBC = 1;
    protected static final int MODE_GCM = 2;
    protected static final int MODE_CCM = 3;

    protected static final int BLOCK_SIZE = 16;
    protected static final int KEY_SIZE = 16;
    protected static final int DEFAULT_GCM_TAG_BITS = 128;

    protected static final int PADDING_NONE = 0;
    protected static final int PADDING_PKCS5 = 1;

    protected long sessionHandle;
    protected int cipherMode = MODE_CBC;
    protected int paddingMode = PADDING_NONE;
    protected int opmode;
    protected byte[] key;
    protected byte[] iv;
    protected long ctx = 0;

    // GCM specific fields
    protected int gcmTagLenBits = DEFAULT_GCM_TAG_BITS;
    protected ByteArrayOutputStream aadBuffer;

    // Buffer for incomplete blocks (streaming) or all data (GCM)
    protected ByteArrayOutputStream buffer;

    public SM4Cipher() {
        this.sessionHandle = SDFJceNative.openSession();
        if (sessionHandle == 0) {
            throw new IllegalStateException("Failed to open SDF session");
        }
        this.cipherMode = MODE_CBC;
    }

    protected SM4Cipher(int mode) {
        this.sessionHandle = SDFJceNative.openSession();
        if (sessionHandle == 0) {
            throw new IllegalStateException("Failed to open SDF session");
        }
        this.cipherMode = mode;
    }

    protected void releaseSession() {
        if (sessionHandle != 0) {
            long h = sessionHandle;
            sessionHandle = 0;
            SDFJceNative.closeSession(h);
        }
    }

    private boolean isAeadMode() {
        return cipherMode == MODE_GCM || cipherMode == MODE_CCM;
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if ("ECB".equalsIgnoreCase(mode)) {
            this.cipherMode = MODE_ECB;
        } else if ("CBC".equalsIgnoreCase(mode)) {
            this.cipherMode = MODE_CBC;
        } else if ("GCM".equalsIgnoreCase(mode)) {
            this.cipherMode = MODE_GCM;
        } else if ("CCM".equalsIgnoreCase(mode)) {
            this.cipherMode = MODE_CCM;
        } else {
            throw new NoSuchAlgorithmException("Unsupported mode: " + mode);
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if ("NoPadding".equalsIgnoreCase(padding)) {
            this.paddingMode = PADDING_NONE;
        } else if ("PKCS5Padding".equalsIgnoreCase(padding) || "PKCS7Padding".equalsIgnoreCase(padding)) {
            if (isAeadMode()) {
                throw new NoSuchPaddingException("AEAD modes do not support padding");
            }
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
        int totalLen = inputLen + (buffer != null ? buffer.size() : 0);
        if (isAeadMode()) {
            int tagBytes = gcmTagLenBits / 8;
            if (opmode == Cipher.ENCRYPT_MODE) {
                return totalLen + tagBytes;
            } else {
                return Math.max(0, totalLen - tagBytes);
            }
        }
        if (opmode == Cipher.ENCRYPT_MODE) {
            if (paddingMode == PADDING_PKCS5) {
                return ((totalLen / BLOCK_SIZE) + 1) * BLOCK_SIZE;
            }
            return totalLen;
        } else {
            return totalLen;
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
        // Clean up any existing sensitive data before re-initializing
        cleanup();

        this.opmode = opmode;
        this.key = key.getEncoded();

        if (this.key == null || this.key.length != KEY_SIZE) {
            throw new InvalidKeyException("Key must be 16 bytes");
        }

        // Parse parameters
        if (params != null) {
            if (params instanceof GCMParameterSpec) {
                if (!isAeadMode()) {
                    throw new InvalidAlgorithmParameterException("GCMParameterSpec only valid for GCM/CCM modes");
                }
                GCMParameterSpec gcmSpec = (GCMParameterSpec) params;
                this.iv = gcmSpec.getIV();
                this.gcmTagLenBits = gcmSpec.getTLen();
            } else if (params instanceof IvParameterSpec) {
                this.iv = ((IvParameterSpec) params).getIV();
            } else {
                throw new InvalidAlgorithmParameterException("Unsupported parameter type");
            }
        } else if (cipherMode != MODE_ECB) {
            if (opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE) {
                throw new InvalidAlgorithmParameterException("IV required for decryption");
            }
            this.iv = new byte[BLOCK_SIZE];
            SecureRandom rng = (random != null) ? random : new SecureRandom();
            rng.nextBytes(this.iv);
        }

        buffer = new ByteArrayOutputStream();
        aadBuffer = new ByteArrayOutputStream();

        // For non-AEAD modes, initialize streaming context immediately
        if (!isAeadMode()) {
            initStreamingContext();
        }
    }

    /**
     * Initialize the native streaming context (EncryptInit/DecryptInit).
     */
    private void initStreamingContext() {
        if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
            ctx = SDFJceNative.sm4EncryptInit(sessionHandle, cipherMode, key, iv);
        } else {
            ctx = SDFJceNative.sm4DecryptInit(sessionHandle, cipherMode, key, iv);
        }
        if (ctx == 0) {
            throw new IllegalStateException("Failed to initialize SM4 streaming context");
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        AlgorithmParameterSpec spec = null;
        if (params != null) {
            try {
                // Try GCMParameterSpec first for AEAD modes
                if (isAeadMode()) {
                    spec = params.getParameterSpec(GCMParameterSpec.class);
                } else {
                    spec = params.getParameterSpec(IvParameterSpec.class);
                }
            } catch (Exception e) {
                throw new InvalidAlgorithmParameterException("Could not get parameter spec from AlgorithmParameters");
            }
        }
        engineInit(opmode, key, spec, random);
    }

    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len) {
        if (!isAeadMode()) {
            throw new IllegalStateException("AAD only supported in AEAD modes (GCM/CCM)");
        }
        if (src != null && len > 0) {
            aadBuffer.write(src, offset, len);
        }
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        if (input == null || inputLen <= 0) {
            return new byte[0];
        }
        if (inputOffset < 0 || inputLen < 0 || inputOffset + inputLen > input.length) {
            throw new IllegalArgumentException("Invalid inputOffset/inputLen");
        }

        if (isAeadMode()) {
            buffer.write(input, inputOffset, inputLen);
            return new byte[0];
        }

        if (ctx == 0) {
            throw new IllegalStateException("Cipher not initialized");
        }

        if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
            return encryptUpdate(input, inputOffset, inputLen);
        } else {
            return decryptUpdate(input, inputOffset, inputLen);
        }
    }

    /**
     * Streaming encrypt update.
     * For PKCS5 padding: buffer incomplete blocks, send only complete blocks.
     * For NoPadding: send all data directly.
     */
    private byte[] encryptUpdate(byte[] input, int inputOffset, int inputLen) {
        if (paddingMode == PADDING_PKCS5) {
            // Buffer the data, only send complete blocks to native
            buffer.write(input, inputOffset, inputLen);
            byte[] buffered = buffer.toByteArray();
            int completeLen = (buffered.length / BLOCK_SIZE) * BLOCK_SIZE;
            if (completeLen == 0) {
                return new byte[0];
            }
            // Keep the remainder in buffer
            buffer.reset();
            if (buffered.length > completeLen) {
                buffer.write(buffered, completeLen, buffered.length - completeLen);
            }
            return SDFJceNative.sm4EncryptUpdate(ctx, buffered, 0, completeLen);
        } else {
            // NoPadding: send directly
            return SDFJceNative.sm4EncryptUpdate(ctx, input, inputOffset, inputLen);
        }
    }

    /**
     * Streaming decrypt update.
     * For PKCS5 padding: buffer data, send complete blocks but hold back the last block
     * (last block may contain padding, must wait for doFinal to strip).
     * For NoPadding: send all data directly.
     */
    private byte[] decryptUpdate(byte[] input, int inputOffset, int inputLen) {
        if (paddingMode == PADDING_PKCS5) {
            buffer.write(input, inputOffset, inputLen);
            byte[] buffered = buffer.toByteArray();
            // Hold back at least one block for doFinal to strip padding
            int sendLen = ((buffered.length - BLOCK_SIZE) / BLOCK_SIZE) * BLOCK_SIZE;
            if (sendLen <= 0) {
                return new byte[0];
            }
            buffer.reset();
            buffer.write(buffered, sendLen, buffered.length - sendLen);
            return SDFJceNative.sm4DecryptUpdate(ctx, buffered, 0, sendLen);
        } else {
            return SDFJceNative.sm4DecryptUpdate(ctx, input, inputOffset, inputLen);
        }
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException {
        byte[] result = engineUpdate(input, inputOffset, inputLen);
        if (result == null || result.length == 0) {
            return 0;
        }
        if (output.length - outputOffset < result.length) {
            throw new ShortBufferException("Output buffer too small");
        }
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        if (input != null && inputLen > 0) {
            buffer.write(input, inputOffset, inputLen);
        }

        if (isAeadMode()) {
            return doFinalAead();
        } else {
            return doFinalStreaming();
        }
    }

    /**
     * GCM/CCM final: one-shot processing with buffered data.
     */
    private byte[] doFinalAead() throws IllegalBlockSizeException, BadPaddingException {
        byte[] data = buffer.toByteArray();
        byte[] aad = aadBuffer.toByteArray();
        buffer.reset();
        aadBuffer.reset();

        int tagBytes = gcmTagLenBits / 8;

        if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
            if (data.length == 0) {
                throw new IllegalBlockSizeException("SM4 GCM/CCM does not support empty plaintext");
            }
            // sm4AuthEnc returns ciphertext || tag directly
            byte[] result = SDFJceNative.sm4AuthEnc(sessionHandle, cipherMode, key, iv,
                    aad.length > 0 ? aad : null, data);
            if (result == null) {
                throw new IllegalBlockSizeException("AuthEnc returned null");
            }
            return result;
        } else {
            // Decrypt: input is ciphertext || tag
            if (data.length < tagBytes) {
                throw new BadPaddingException("Input too short for GCM tag");
            }
            byte[] ciphertext = new byte[data.length - tagBytes];
            byte[] tag = new byte[tagBytes];
            System.arraycopy(data, 0, ciphertext, 0, ciphertext.length);
            System.arraycopy(data, ciphertext.length, tag, 0, tagBytes);

            byte[] plaintext = SDFJceNative.sm4AuthDec(sessionHandle, cipherMode, key, iv,
                    aad.length > 0 ? aad : null, tag, ciphertext);
            if (plaintext == null) {
                throw new AEADBadTagException("GCM authentication failed");
            }
            return plaintext;
        }
    }

    /**
     * ECB/CBC streaming final.
     */
    private byte[] doFinalStreaming() throws IllegalBlockSizeException, BadPaddingException {
        if (ctx == 0) {
            throw new IllegalStateException("Cipher not initialized");
        }

        ByteArrayOutputStream result = new ByteArrayOutputStream();
        try {
            byte[] remaining = buffer.toByteArray();
            buffer.reset();

            if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
                if (paddingMode == PADDING_PKCS5) {
                    remaining = addPkcs5Padding(remaining);
                } else if (remaining.length > 0 && remaining.length % BLOCK_SIZE != 0) {
                    throw new IllegalBlockSizeException(
                            "Data length must be multiple of " + BLOCK_SIZE + " bytes with NoPadding");
                }

                if (remaining.length > 0) {
                    byte[] encrypted = SDFJceNative.sm4EncryptUpdate(ctx, remaining, 0, remaining.length);
                    if (encrypted != null && encrypted.length > 0) {
                        result.write(encrypted, 0, encrypted.length);
                    }
                }

                byte[] finalOutput = SDFJceNative.sm4EncryptFinal(ctx);
                if (finalOutput != null && finalOutput.length > 0) {
                    result.write(finalOutput, 0, finalOutput.length);
                }
                return result.toByteArray();

            } else {
                if (remaining.length > 0) {
                    byte[] decrypted = SDFJceNative.sm4DecryptUpdate(ctx, remaining, 0, remaining.length);
                    if (decrypted != null && decrypted.length > 0) {
                        result.write(decrypted, 0, decrypted.length);
                    }
                }

                byte[] finalOutput = SDFJceNative.sm4DecryptFinal(ctx);
                if (finalOutput != null && finalOutput.length > 0) {
                    result.write(finalOutput, 0, finalOutput.length);
                }

                byte[] output = result.toByteArray();
                if (paddingMode == PADDING_PKCS5) {
                    return removePkcs5Padding(output);
                }
                return output;
            }
        } finally {
            SDFJceNative.sm4Free(ctx);
            ctx = 0;
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

    /**
     * Clean up sensitive data (key, IV, context)
     */
    protected void cleanup() {
        if (key != null) {
            Arrays.fill(key, (byte) 0);
            key = null;
        }
        if (iv != null) {
            Arrays.fill(iv, (byte) 0);
            iv = null;
        }
        if (ctx != 0) {
            SDFJceNative.sm4Free(ctx);
            ctx = 0;
        }
        if (buffer != null) {
            buffer.reset();
        }
        if (aadBuffer != null) {
            aadBuffer.reset();
        }
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            cleanup();
            releaseSession();
        } finally {
            super.finalize();
        }
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

    public static class GCM extends SM4Cipher {
        public GCM() {
            super(MODE_GCM);
        }
    }
}
