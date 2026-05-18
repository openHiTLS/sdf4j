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

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.openhitls.sdf4j.jce.SDFJceNative;
import org.openhitls.sdf4j.jce.key.SDFInternalSymmetricKey;
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

    // GM/T 0018 SDF algorithm IDs — passed to SDF_GenerateKeyWithKEK / SDF_ImportKeyWithKEK
    // as uiAlgID to indicate the mode in which the generated session key will be used.
    private static final int SGD_SM4_ECB = 0x00000401;
    private static final int SGD_SM4_CBC = 0x00000402;

    protected long sessionHandle;
    protected int cipherMode = MODE_CBC;
    protected int paddingMode = PADDING_NONE;
    protected int opmode;
    protected byte[] key;
    protected byte[] iv;
    protected long ctx = 0;

    // Internal (KEK) mode fields
    protected boolean useInternalKey = false;
    protected SDFInternalSymmetricKey internalKey;
    protected long internalKeyHandle = 0;
    private boolean generatedInternalKeyForCipher = false;

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

    private boolean isEncryptingOperation() {
        return opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE;
    }

    private boolean isDecryptingOperation() {
        return opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE;
    }

    private void ensureSupportedOpmode() {
        if (!isEncryptingOperation() && !isDecryptingOperation()) {
            throw new IllegalStateException("Unsupported opmode: " + opmode);
        }
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
            if (isEncryptingOperation()) {
                return totalLen + tagBytes;
            } else if (isDecryptingOperation()) {
                return Math.max(0, totalLen - tagBytes);
            }
            throw new IllegalStateException("Unsupported opmode: " + opmode);
        }
        if (isEncryptingOperation()) {
            if (paddingMode == PADDING_PKCS5) {
                return ((totalLen / BLOCK_SIZE) + 1) * BLOCK_SIZE;
            }
            return totalLen;
        } else if (isDecryptingOperation()) {
            return totalLen;
        }
        throw new IllegalStateException("Unsupported opmode: " + opmode);
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
        ensureSupportedOpmode();

        // Detect Internal (KEK) key vs External key
        if (key instanceof SDFInternalSymmetricKey) {
            this.internalKey = (SDFInternalSymmetricKey) key;
            this.useInternalKey = true;
            this.key = null;  // no raw key material
        } else {
            this.key = key.getEncoded();
            if (this.key == null || this.key.length != KEY_SIZE) {
                throw new InvalidKeyException("Key must be 16 bytes");
            }
            this.useInternalKey = false;
            this.internalKey = null;
        }

        // Parse parameters
        if (params != null) {
            if (params instanceof GCMParameterSpec) {
                if (!isAeadMode()) {
                    throw new InvalidAlgorithmParameterException("GCMParameterSpec only valid for GCM/CCM modes");
                }
                GCMParameterSpec gcmSpec = (GCMParameterSpec) params;
                if (gcmSpec.getTLen() != DEFAULT_GCM_TAG_BITS) {
                    throw new InvalidAlgorithmParameterException(
                            "Only 128-bit tag length is supported, got " + gcmSpec.getTLen() + " bits");
                }
                this.iv = gcmSpec.getIV();
                this.gcmTagLenBits = gcmSpec.getTLen();
            } else if (params instanceof IvParameterSpec) {
                this.iv = ((IvParameterSpec) params).getIV();
            } else {
                throw new InvalidAlgorithmParameterException("Unsupported parameter type");
            }
        } else if (cipherMode != MODE_ECB) {
            throw new InvalidAlgorithmParameterException("IV required for non-ECB mode");
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
        if (useInternalKey) {
            initInternalStreamingContext();
        } else {
            initRawKeyStreamingContext();
        }
        if (ctx == 0) {
            throw new IllegalStateException("Failed to initialize SM4 streaming context");
        }
    }

    /**
     * Reset the native streaming context to the state established by the last init call.
     */
    private void resetStreamingContext() {
        if (useInternalKey) {
            resetInternalStreamingContext();
        } else {
            initRawKeyStreamingContext();
        }
        if (ctx == 0) {
            throw new IllegalStateException("Failed to reset SM4 streaming context");
        }
    }

    private void initRawKeyStreamingContext() {
        if (isEncryptingOperation()) {
            ctx = SDFJceNative.sm4EncryptInit(sessionHandle, cipherMode, key, iv);
        } else if (isDecryptingOperation()) {
            ctx = SDFJceNative.sm4DecryptInit(sessionHandle, cipherMode, key, iv);
        } else {
            throw new IllegalStateException("Unsupported opmode: " + opmode);
        }
    }

    /**
     * Returns the GM/T 0018 SDF algorithm ID that corresponds to the current {@link #cipherMode}.
     *
     * <p>This ID is passed as {@code uiAlgID} to {@code SDF_GenerateKeyWithKEK} and
     * {@code SDF_ImportKeyWithKEK}, telling the device which mode the generated session key
     * will be used for. It is <em>not</em> the algorithm of the KEK itself.
     *
     * <p>GCM and CCM are not defined as distinct algorithm IDs in GM/T 0018; the SDF device
     * internally treats them as CBC-family keys. CBC is used as the fallback.
     */
    private int getSdfAlgId() {
        switch (cipherMode) {
            case MODE_ECB: return SGD_SM4_ECB;
            case MODE_CBC: return SGD_SM4_CBC;
            default:       return SGD_SM4_CBC; // GCM/CCM: no distinct SDF ID, fall back to CBC
        }
    }

    private void acquireKekAccessRight() {
        char[] pwd = internalKey.getPassword();
        if (pwd == null) {
            return;
        }
        byte[] pwdBytes = new byte[pwd.length];
        for (int i = 0; i < pwd.length; i++) {
            pwdBytes[i] = (byte) pwd[i];
        }
        try {
            SDFJceNative.getKEKAccessRight(sessionHandle, internalKey.getKekIndex(), pwdBytes);
        } finally {
            Arrays.fill(pwdBytes, (byte) 0);
            Arrays.fill(pwd, '\0');
        }
    }

    /**
     * Initialize streaming context using an Internal (KEK-protected) key.
     *
     * <p><b>Encrypt path</b>: calls {@code SDF_GenerateKeyWithKEK} to produce a new random
     * session key wrapped by the KEK. The encrypted key blob (all bytes except the trailing
     * 8-byte key handle) is stored back into {@link #internalKey} so the caller can hand it
     * to the decryption side.
     *
     * <p><b>Decrypt path</b>: reads the blob previously stored in {@link #internalKey} and
     * calls {@code SDF_ImportKeyWithKEK} to recover the same session key handle.
     */
    private void initInternalStreamingContext() {
        acquireKekAccessRight();

        try {
            if (isEncryptingOperation()) {
                // Generate a new random session key wrapped by the KEK.
                byte[] result = SDFJceNative.sm4GenerateKeyWithKEK(
                    sessionHandle, KEY_SIZE * 8, getSdfAlgId(), internalKey.getKekIndex());
                if (result == null || result.length < 8) {
                    throw new IllegalStateException("Failed to generate key with KEK");
                }
                // Save the encrypted key blob (everything except the trailing 8-byte handle)
                // so the decryption side can call ImportKeyWithKEK to recover the same key.
                byte[] blob = Arrays.copyOf(result, result.length - 8);
                internalKey.setEncryptedKeyBlob(blob);

                this.internalKeyHandle = extractKeyHandle(result);
                ctx = SDFJceNative.sm4EncryptInitWithKeyHandle(
                    sessionHandle, internalKeyHandle, cipherMode, iv);
            } else if (isDecryptingOperation()) {
                // Recover the session key from the blob produced during encryption.
                byte[] blob = internalKey.getEncryptedKeyBlob();
                if (blob == null) {
                    throw new IllegalStateException(
                        "No encrypted key blob found in SDFInternalSymmetricKey. " +
                        "For decryption, setEncryptedKeyBlob() must be called with the blob " +
                        "that was saved during the corresponding encryption operation.");
                }
                long keyHandle = SDFJceNative.sm4ImportKeyWithKEK(
                    sessionHandle, getSdfAlgId(), internalKey.getKekIndex(), blob);
                if (keyHandle == 0) {
                    throw new IllegalStateException("Failed to import key with KEK");
                }
                this.internalKeyHandle = keyHandle;
                ctx = SDFJceNative.sm4DecryptInitWithKeyHandle(
                    sessionHandle, internalKeyHandle, cipherMode, iv);
            } else {
                throw new IllegalStateException("Unsupported opmode: " + opmode);
            }

            if (ctx == 0) {
                throw new IllegalStateException("Failed to initialize SM4 streaming context with key handle");
            }
        } catch (Throwable t) {
            if (internalKeyHandle != 0) {
                try {
                    SDFJceNative.destroyKey(sessionHandle, internalKeyHandle);
                } catch (Exception ignored) {}
                internalKeyHandle = 0;
            }
            throw t;
        }
    }

    private void initInternalAeadKeyHandle() {
        acquireKekAccessRight();

        try {
            if (isEncryptingOperation()) {
                if (generatedInternalKeyForCipher) {
                    byte[] blob = internalKey.getEncryptedKeyBlob();
                    if (blob == null) {
                        throw new IllegalStateException("No encrypted key blob found for SM4 internal AEAD reset");
                    }
                    long keyHandle = SDFJceNative.sm4ImportKeyWithKEK(
                        sessionHandle, getSdfAlgId(), internalKey.getKekIndex(), blob);
                    if (keyHandle == 0) {
                        throw new IllegalStateException("Failed to import key with KEK");
                    }
                    this.internalKeyHandle = keyHandle;
                    return;
                }

                byte[] result = SDFJceNative.sm4GenerateKeyWithKEK(
                    sessionHandle, KEY_SIZE * 8, getSdfAlgId(), internalKey.getKekIndex());
                if (result == null || result.length < 8) {
                    throw new IllegalStateException("Failed to generate key with KEK");
                }
                byte[] blob = Arrays.copyOf(result, result.length - 8);
                internalKey.setEncryptedKeyBlob(blob);
                this.internalKeyHandle = extractKeyHandle(result);
                this.generatedInternalKeyForCipher = true;
            } else if (isDecryptingOperation()) {
                byte[] blob = internalKey.getEncryptedKeyBlob();
                if (blob == null) {
                    throw new IllegalStateException(
                        "No encrypted key blob found in SDFInternalSymmetricKey. " +
                        "For decryption, setEncryptedKeyBlob() must be called with the blob " +
                        "that was saved during the corresponding encryption operation.");
                }
                long keyHandle = SDFJceNative.sm4ImportKeyWithKEK(
                    sessionHandle, getSdfAlgId(), internalKey.getKekIndex(), blob);
                if (keyHandle == 0) {
                    throw new IllegalStateException("Failed to import key with KEK");
                }
                this.internalKeyHandle = keyHandle;
            } else {
                throw new IllegalStateException("Unsupported opmode: " + opmode);
            }
        } catch (Throwable t) {
            destroyDetachedInternalKey();
            throw t;
        }
    }

    /**
     * Reset an Internal (KEK-protected) stream without generating a new wrapped key blob.
     *
     * <p>JCE requires a successful doFinal to return the Cipher to the previous init state.
     * For internal encryption that means reusing the session key generated at init time,
     * not calling GenerateKeyWithKEK again and overwriting the blob the caller needs.
     */
    private void resetInternalStreamingContext() {
        byte[] blob = internalKey.getEncryptedKeyBlob();
        if (blob == null) {
            throw new IllegalStateException("No encrypted key blob found for SM4 internal key reset");
        }

        try {
            long keyHandle = SDFJceNative.sm4ImportKeyWithKEK(
                sessionHandle, getSdfAlgId(), internalKey.getKekIndex(), blob);
            if (keyHandle == 0) {
                throw new IllegalStateException("Failed to import key with KEK");
            }
            this.internalKeyHandle = keyHandle;
            if (isEncryptingOperation()) {
                ctx = SDFJceNative.sm4EncryptInitWithKeyHandle(
                    sessionHandle, internalKeyHandle, cipherMode, iv);
            } else if (isDecryptingOperation()) {
                ctx = SDFJceNative.sm4DecryptInitWithKeyHandle(
                    sessionHandle, internalKeyHandle, cipherMode, iv);
            } else {
                throw new IllegalStateException("Unsupported opmode: " + opmode);
            }
            if (ctx == 0) {
                throw new IllegalStateException("Failed to reset SM4 streaming context with key handle");
            }
        } catch (Throwable t) {
            destroyDetachedInternalKey();
            throw t;
        }
    }

    private void freeStreamingContext() {
        if (ctx != 0) {
            SDFJceNative.sm4Free(ctx);
            ctx = 0;
            internalKeyHandle = 0;
        }
    }

    private void destroyDetachedInternalKey() {
        if (internalKeyHandle != 0) {
            try {
                SDFJceNative.destroyKey(sessionHandle, internalKeyHandle);
            } catch (Exception ignored) { }
            internalKeyHandle = 0;
        }
    }

    /**
     * Extracts the 64-bit key handle from the last 8 bytes of an SDF key result array
     * (big-endian encoding).
     */
    private static long extractKeyHandle(byte[] result) {
        long kh = 0;
        int offset = result.length - 8;
        for (int i = 0; i < 8; i++) {
            kh = (kh << 8) | (result[offset + i] & 0xFFL);
        }
        return kh;
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

        if (isEncryptingOperation()) {
            return encryptUpdate(input, inputOffset, inputLen);
        } else if (isDecryptingOperation()) {
            return decryptUpdate(input, inputOffset, inputLen);
        }
        throw new IllegalStateException("Unsupported opmode: " + opmode);
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

        if (isEncryptingOperation()) {
            if (data.length == 0) {
                throw new IllegalBlockSizeException("SM4 GCM/CCM does not support empty plaintext");
            }
            byte[] result;
            if (useInternalKey) {
                initInternalAeadKeyHandle();
                try {
                    result = SDFJceNative.sm4AuthEncWithKeyHandle(sessionHandle, internalKeyHandle,
                            cipherMode, iv, aad.length > 0 ? aad : null, data);
                } finally {
                    destroyDetachedInternalKey();
                }
            } else {
                // sm4AuthEnc returns ciphertext || tag directly
                result = SDFJceNative.sm4AuthEnc(sessionHandle, cipherMode, key, iv,
                        aad.length > 0 ? aad : null, data);
            }
            if (result == null) {
                throw new IllegalBlockSizeException("AuthEnc returned null");
            }
            return result;
        } else if (isDecryptingOperation()) {
            // Decrypt: input is ciphertext || tag
            if (data.length < tagBytes) {
                throw new BadPaddingException("Input too short for GCM tag");
            }
            byte[] ciphertext = new byte[data.length - tagBytes];
            byte[] tag = new byte[tagBytes];
            System.arraycopy(data, 0, ciphertext, 0, ciphertext.length);
            System.arraycopy(data, ciphertext.length, tag, 0, tagBytes);
            byte[] plaintext;
            if (useInternalKey) {
                initInternalAeadKeyHandle();
                try {
                    plaintext = SDFJceNative.sm4AuthDecWithKeyHandle(sessionHandle, internalKeyHandle,
                            cipherMode, iv, aad.length > 0 ? aad : null, tag, ciphertext);
                } finally {
                    destroyDetachedInternalKey();
                }
            } else {
                plaintext = SDFJceNative.sm4AuthDec(sessionHandle, cipherMode, key, iv,
                        aad.length > 0 ? aad : null, tag, ciphertext);
            }
            if (plaintext == null) {
                throw new AEADBadTagException("GCM authentication failed");
            }
            return plaintext;
        }
        throw new IllegalStateException("Unsupported opmode: " + opmode);
    }

    /**
     * ECB/CBC streaming final.
     */
    private byte[] doFinalStreaming() throws IllegalBlockSizeException, BadPaddingException {
        if (ctx == 0) {
            throw new IllegalStateException("Cipher not initialized");
        }

        ByteArrayOutputStream result = new ByteArrayOutputStream();
        boolean success = false;
        try {
            byte[] remaining = buffer.toByteArray();
            buffer.reset();

            byte[] output;
            if (isEncryptingOperation()) {
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
                output = result.toByteArray();

            } else if (isDecryptingOperation()) {
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

                output = result.toByteArray();
                if (paddingMode == PADDING_PKCS5) {
                    output = removePkcs5Padding(output);
                }
            } else {
                throw new IllegalStateException("Unsupported opmode: " + opmode);
            }
            success = true;
            return output;
        } finally {
            freeStreamingContext();
            if (success) {
                resetStreamingContext();
            }
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
     * Remove PKCS#5/PKCS#7 padding from data (constant-time).
     */
    private byte[] removePkcs5Padding(byte[] data) throws BadPaddingException {
        if (data == null || data.length == 0) {
            throw new BadPaddingException("Empty data");
        }
        if (data.length % BLOCK_SIZE != 0) {
            throw new BadPaddingException("Data length not block aligned");
        }
        int paddingLen = data[data.length - 1] & 0xFF;
        int invalid = 0;
        invalid |= (paddingLen - 1) >> 31;
        invalid |= (BLOCK_SIZE - paddingLen) >> 31;

        for (int i = 1; i <= BLOCK_SIZE; i++) {
            int b = data[data.length - i] & 0xFF;
            int mask = ~((paddingLen - i) >> 31);
            invalid |= mask & (b ^ paddingLen);
        }
        if (invalid != 0) {
            throw new BadPaddingException("Invalid PKCS5 padding");
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
        freeStreamingContext();
        destroyDetachedInternalKey();
        internalKey = null;
        useInternalKey = false;
        generatedInternalKeyForCipher = false;
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
