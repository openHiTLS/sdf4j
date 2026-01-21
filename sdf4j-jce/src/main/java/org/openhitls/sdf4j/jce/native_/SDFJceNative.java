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

package org.openhitls.sdf4j.jce.native_;

/**
 * SDF JCE Native methods
 * All cryptographic operations are performed in native code for optimal performance.
 */
public final class SDFJceNative {

    static {
        NativeLoader.load();
    }

    private SDFJceNative() {
    }

    // ==================== Initialization ====================

    /**
     * Initialize the JCE engine
     *
     * @param libraryPath SDF library path
     * @param poolSize    Session pool size
     */
    public static native void init(String libraryPath, int poolSize);

    /**
     * Shutdown the JCE engine
     */
    public static native void shutdown();

    /**
     * Check if initialized
     *
     * @return true if initialized
     */
    public static native boolean isInitialized();

    /**
     * Get session pool statistics
     *
     * @return [total, available]
     */
    public static native int[] getPoolStats();

    // ==================== SM3 Hash ====================

    /**
     * SM3 one-shot digest
     *
     * @param data Input data
     * @return 32-byte hash
     */
    public static native byte[] sm3Digest(byte[] data);

    /**
     * SM3 streaming init
     *
     * @return Context handle
     */
    public static native long sm3Init();

    /**
     * SM3 streaming update
     *
     * @param ctx    Context handle
     * @param data   Input data
     * @param offset Offset in data
     * @param len    Length to process
     */
    public static native void sm3Update(long ctx, byte[] data, int offset, int len);

    /**
     * SM3 streaming final
     *
     * @param ctx Context handle
     * @return 32-byte hash
     */
    public static native byte[] sm3Final(long ctx);

    /**
     * SM3 free context (for exception cleanup)
     *
     * @param ctx Context handle
     */
    public static native void sm3Free(long ctx);

    // ==================== SM4 Symmetric Encryption ====================

    /**
     * SM4 one-shot encrypt
     *
     * @param mode Cipher mode (0=ECB, 1=CBC, 2=CTR, 3=GCM)
     * @param key  16-byte key
     * @param iv   IV (null for ECB)
     * @param data Plaintext
     * @param aad  AAD (for GCM/CCM only)
     * @return Ciphertext
     */
    public static native byte[] sm4Encrypt(int mode, byte[] key, byte[] iv, byte[] data, byte[] aad);

    /**
     * SM4 one-shot decrypt
     *
     * @param mode       Cipher mode
     * @param key        16-byte key
     * @param iv         IV
     * @param ciphertext Ciphertext
     * @param aad        AAD (for GCM/CCM only)
     * @param tag        Authentication tag (for GCM/CCM only)
     * @return Plaintext
     */
    public static native byte[] sm4Decrypt(int mode, byte[] key, byte[] iv, byte[] ciphertext, byte[] aad, byte[] tag);

    /**
     * SM4 streaming encrypt init
     *
     * @param mode Cipher mode
     * @param key  16-byte key
     * @param iv   IV
     * @return Context handle
     */
    public static native long sm4EncryptInit(int mode, byte[] key, byte[] iv);

    /**
     * SM4 streaming encrypt update
     *
     * @param ctx    Context handle
     * @param data   Input data
     * @param offset Offset
     * @param len    Length
     * @return Output data
     */
    public static native byte[] sm4EncryptUpdate(long ctx, byte[] data, int offset, int len);

    /**
     * SM4 streaming encrypt final
     *
     * @param ctx Context handle
     * @return Final output
     */
    public static native byte[] sm4EncryptFinal(long ctx);

    /**
     * SM4 streaming decrypt init
     */
    public static native long sm4DecryptInit(int mode, byte[] key, byte[] iv);

    /**
     * SM4 streaming decrypt update
     */
    public static native byte[] sm4DecryptUpdate(long ctx, byte[] data, int offset, int len);

    /**
     * SM4 streaming decrypt final
     */
    public static native byte[] sm4DecryptFinal(long ctx);

    /**
     * SM4 free context
     */
    public static native void sm4Free(long ctx);

    // ==================== SM2 Asymmetric ====================

    /**
     * Generate SM2 key pair
     *
     * @return [privateKey(32), publicKeyX(32), publicKeyY(32)]
     */
    public static native byte[] sm2GenerateKeyPair();

    /**
     * SM2 sign with external private key
     *
     * @param privateKey 32-byte private key
     * @param data       Data to sign (should be SM3 hash with Z value)
     * @return 64-byte signature (r||s)
     */
    public static native byte[] sm2Sign(byte[] privateKey, byte[] data);

    /**
     * SM2 sign with internal key index
     *
     * @param keyIndex Key index
     * @param data     Data to sign
     * @param pin      PIN for key access (can be null if already authorized)
     * @return 64-byte signature
     */
    public static native byte[] sm2SignWithIndex(int keyIndex, byte[] data, byte[] pin);

    /**
     * SM2 verify with external public key
     *
     * @param publicKeyX 32-byte X coordinate
     * @param publicKeyY 32-byte Y coordinate
     * @param data       Original data
     * @param signature  64-byte signature
     * @return true if valid
     */
    public static native boolean sm2Verify(byte[] publicKeyX, byte[] publicKeyY, byte[] data, byte[] signature);

    /**
     * SM2 verify with internal key index
     *
     * @param keyIndex  Key index
     * @param data      Original data
     * @param signature 64-byte signature
     * @return true if valid
     */
    public static native boolean sm2VerifyWithIndex(int keyIndex, byte[] data, byte[] signature);

    /**
     * SM2 encrypt with external public key
     *
     * @param publicKeyX 32-byte X coordinate
     * @param publicKeyY 32-byte Y coordinate
     * @param plaintext  Data to encrypt
     * @return Ciphertext (C1||C3||C2 format)
     */
    public static native byte[] sm2Encrypt(byte[] publicKeyX, byte[] publicKeyY, byte[] plaintext);

    /**
     * SM2 decrypt with external private key
     *
     * @param privateKey 32-byte private key
     * @param ciphertext Ciphertext (C1||C3||C2 format)
     * @return Plaintext
     */
    public static native byte[] sm2Decrypt(byte[] privateKey, byte[] ciphertext);

    /**
     * SM2 decrypt with internal key index
     *
     * @param keyIndex   Key index
     * @param ciphertext Ciphertext
     * @param pin        PIN for key access
     * @return Plaintext
     */
    public static native byte[] sm2DecryptWithIndex(int keyIndex, byte[] ciphertext, byte[] pin);

    // ==================== MAC ====================

    /**
     * SM4-MAC
     *
     * @param key  16-byte key
     * @param iv   IV
     * @param data Data
     * @return MAC value
     */
    public static native byte[] sm4Mac(byte[] key, byte[] iv, byte[] data);

    /**
     * HMAC-SM3
     *
     * @param key  Key
     * @param data Data
     * @return HMAC value
     */
    public static native byte[] hmacSm3(byte[] key, byte[] data);

    // ==================== Random ====================

    /**
     * Generate random bytes
     *
     * @param length Number of bytes
     * @return Random bytes
     */
    public static native byte[] generateRandom(int length);

    // ==================== Key Management ====================

    /**
     * Export public key from device
     *
     * @param keyIndex Key index
     * @param keyType  0=SIGN, 1=ENCRYPT
     * @return Public key bytes (X||Y, 64 bytes)
     */
    public static native byte[] exportPublicKey(int keyIndex, int keyType);

    /**
     * Generate SM4 key using device RNG
     *
     * @return 16-byte key
     */
    public static native byte[] generateSm4Key();
}
