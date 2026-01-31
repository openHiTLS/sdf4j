/*
 * Copyright (c) 2025 OpenHitls
 * SDF4J is licensed under Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

package org.openhitls.sdf4j.jce;

/**
 * SDF JCE Native methods
 *
 * <p>All methods require a sessionHandle parameter obtained from {@link #openSession()}.</p>
 *
 * <p>Usage:</p>
 * <pre>
 * long sessionHandle = SDFJceNative.openSession();
 * try {
 *     long ctx = SDFJceNative.sm4EncryptInit(sessionHandle, mode, key, iv);
 *     byte[] encrypted = SDFJceNative.sm4EncryptUpdate(ctx, data, 0, data.length);
 *     byte[] finalBlock = SDFJceNative.sm4EncryptFinal(ctx);
 * } finally {
 *     SDFJceNative.closeSession(sessionHandle);
 * }
 * </pre>
 */
public final class SDFJceNative {

    static {
        NativeLoader.load();
    }

    private SDFJceNative() {
    }

    // ==================== Session Management ====================

    /**
     * Open a new SDF session.
     * @return session handle, or 0 if failed
     */
    public static native long openSession();

    /**
     * Close an SDF session.
     * @param sessionHandle the session handle to close
     */
    public static native void closeSession(long sessionHandle);

    // ==================== SM3 Hash ====================

    /**
     * SM3 one-shot digest
     *
     * @param sessionHandle Session handle from {@link #openSession()}
     * @param data Input data
     * @return 32-byte hash
     */
    public static native byte[] sm3Digest(long sessionHandle, byte[] data);

    /**
     * SM3 streaming init
     *
     * @param sessionHandle Session handle from {@link #openSession()}
     * @return Context handle
     */
    public static native long sm3Init(long sessionHandle);

    /**
     * SM3 streaming update
     *
     * @param ctx   Context handle from {@link #sm3Init(long)}
     * @param data  Input data
     * @param offset Offset in data
     * @param len   Length to process
     */
    public static native void sm3Update(long ctx, byte[] data, int offset, int len);

    /**
     * SM3 streaming final
     *
     * @param ctx Context handle from {@link #sm3Init(long)}
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
     * SM4 authenticated encryption (GCM/CCM)
     *
     * @param sessionHandle Session handle from {@link #openSession()}
     * @param mode Cipher mode (3=GCM, 4=CCM)
     * @param key  16-byte key
     * @param iv   IV/Nonce
     * @param aad  Additional authenticated data (can be null)
     * @param data Plaintext
     * @return byte[] ciphertext || tag
     */
    public static native byte[] sm4AuthEnc(long sessionHandle, int mode, byte[] key, byte[] iv, byte[] aad, byte[] data);

    /**
     * SM4 authenticated decryption (GCM/CCM)
     *
     * @param sessionHandle Session handle from {@link #openSession()}
     * @param mode Cipher mode (3=GCM, 4=CCM)
     * @param key  16-byte key
     * @param iv   IV/Nonce
     * @param aad  Additional authenticated data (can be null)
     * @param tag  Authentication tag
     * @param ciphertext Ciphertext
     * @return Plaintext
     */
    public static native byte[] sm4AuthDec(long sessionHandle, int mode, byte[] key, byte[] iv, byte[] aad, byte[] tag, byte[] ciphertext);

    /**
     * SM4 streaming encrypt init
     *
     * @param sessionHandle Session handle from {@link #openSession()}
     * @param mode Cipher mode
     * @param key  16-byte key
     * @param iv   IV
     * @return Context handle
     */
    public static native long sm4EncryptInit(long sessionHandle, int mode, byte[] key, byte[] iv);

    /**
     * SM4 streaming encrypt update
     *
     * @param ctx   Context handle
     * @param data  Input data
     * @param offset Offset
     * @param len   Length
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
     *
     * @param sessionHandle Session handle from {@link #openSession()}
     * @param mode Cipher mode
     * @param key  16-byte key
     * @param iv   IV
     * @return Context handle
     */
    public static native long sm4DecryptInit(long sessionHandle, int mode, byte[] key, byte[] iv);

    /**
     * SM4 streaming decrypt update
     *
     * @param ctx   Context handle
     * @param data  Input data
     * @param offset Offset
     * @param len   Length
     * @return Output data
     */
    public static native byte[] sm4DecryptUpdate(long ctx, byte[] data, int offset, int len);

    /**
     * SM4 streaming decrypt final
     *
     * @param ctx Context handle
     * @return Final output
     */
    public static native byte[] sm4DecryptFinal(long ctx);

    /**
     * SM4 free context
     *
     * @param ctx Context handle
     */
    public static native void sm4Free(long ctx);

    // ==================== SM2 Asymmetric ====================

    /**
     * Generate SM2 key pair
     *
     * @param sessionHandle Session handle from {@link #openSession()}
     * @return [privateKey(32), publicKeyX(32), publicKeyY(32)]
     */
    public static native byte[] sm2GenerateKeyPair(long sessionHandle);

    /**
     * SM2 sign with external private key
     *
     * @param sessionHandle Session handle from {@link #openSession()}
     * @param privateKey 32-byte private key
     * @param data       Data to sign (should be SM3 hash with Z value)
     * @return 64-byte signature (r||s)
     */
    public static native byte[] sm2Sign(long sessionHandle, byte[] privateKey, byte[] data);

    /**
     * SM2 verify with external public key
     *
     * @param sessionHandle Session handle from {@link #openSession()}
     * @param publicKeyX 32-byte X coordinate
     * @param publicKeyY 32-byte Y coordinate
     * @param data       Original data
     * @param signature  64-byte signature
     * @return true if valid
     */
    public static native boolean sm2Verify(long sessionHandle, byte[] publicKeyX, byte[] publicKeyY, byte[] data, byte[] signature);

    /**
     * SM2 encrypt with external public key
     *
     * @param sessionHandle Session handle from {@link #openSession()}
     * @param publicKeyX 32-byte X coordinate
     * @param publicKeyY 32-byte Y coordinate
     * @param plaintext  Data to encrypt
     * @return Ciphertext (C1||C3||C2 format)
     */
    public static native byte[] sm2Encrypt(long sessionHandle, byte[] publicKeyX, byte[] publicKeyY, byte[] plaintext);

    /**
     * SM2 decrypt with external private key
     *
     * @param sessionHandle Session handle from {@link #openSession()}
     * @param privateKey 32-byte private key
     * @param ciphertext Ciphertext (C1||C3||C2 format)
     * @return Plaintext
     */
    public static native byte[] sm2Decrypt(long sessionHandle, byte[] privateKey, byte[] ciphertext);

    // ==================== MAC ====================

    /**
     * SM4-MAC
     *
     * @param sessionHandle Session handle from {@link #openSession()}
     * @param key  16-byte key
     * @param iv   IV
     * @param data Data
     * @return MAC value
     */
    public static native byte[] sm4Mac(long sessionHandle, byte[] key, byte[] iv, byte[] data);

    /**
     * HMAC-SM3
     *
     * @param sessionHandle Session handle from {@link #openSession()}
     * @param key  Key
     * @param data Data
     * @return HMAC value
     */
    public static native byte[] hmacSm3(long sessionHandle, byte[] key, byte[] data);

    // ==================== Random ====================

    /**
     * Generate random bytes
     *
     * @param sessionHandle Session handle from {@link #openSession()}
     * @param length Number of bytes
     * @return Random bytes
     */
    public static native byte[] generateRandom(long sessionHandle, int length);

    // ==================== Key Management ====================

    /**
     * Generate SM4 key using device RNG
     *
     * @param sessionHandle Session handle from {@link #openSession()}
     * @return 16-byte key
     */
    public static native byte[] generateSm4Key(long sessionHandle);
}
