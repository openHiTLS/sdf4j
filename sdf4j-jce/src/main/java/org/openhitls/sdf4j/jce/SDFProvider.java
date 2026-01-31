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

package org.openhitls.sdf4j.jce;

import java.security.Provider;

/**
 * SDF JCE Provider
 * <p>
 * Provides Chinese cryptographic algorithms (SM2, SM3, SM4) through
 * the standard Java Cryptography Extension (JCE) interface.
 * <p>
 * SDF library is automatically initialized via the {@code SDF_LIBRARY_PATH}
 * environment variable when the native library is loaded.
 * <p>
 * Usage:
 * <pre>
 * // Set environment variable before running:
 * // export SDF_LIBRARY_PATH=/path/to/libsdf.so
 *
 * SDFProvider provider = new SDFProvider();
 * Security.addProvider(provider);
 *
 * // Use JCE APIs
 * MessageDigest md = MessageDigest.getInstance("SM3", "SDF");
 * Cipher cipher = Cipher.getInstance("SM4/CBC/NoPadding", "SDF");
 * Signature sig = Signature.getInstance("SM3withSM2", "SDF");
 * </pre>
 */
public final class SDFProvider extends Provider {

    private static final long serialVersionUID = 1L;

    public static final String PROVIDER_NAME = "SDF";
    public static final double VERSION = 1.0;
    public static final String INFO = "SDF4J JCE Provider (GM/T 0018-2023)";

    /**
     * Create provider and register algorithms.
     * SDF library is automatically initialized via SDF_LIBRARY_PATH environment variable.
     */
    public SDFProvider() {
        super(PROVIDER_NAME, VERSION, INFO);
        registerAlgorithms();
        // Trigger native library loading, which auto-initializes SDF via SDF_LIBRARY_PATH
        ensureNativeLoaded();
    }

    /**
     * Create provider with SDF library path (backward compatibility).
     * <p>
     * Note: The libraryPath parameter is ignored. SDF library is now initialized
     * automatically via the SDF_LIBRARY_PATH environment variable.
     *
     * @param libraryPath ignored, use SDF_LIBRARY_PATH environment variable instead
     */
    public SDFProvider(String libraryPath) {
        this();
    }

    /**
     * Ensure native library is loaded, triggering JNI_OnLoad initialization.
     */
    private void ensureNativeLoaded() {
        // Accessing SDFJceNative triggers its static initializer (NativeLoader.load()),
        // which loads the native library and calls JNI_OnLoad
        NativeLoader.load();
    }

    /**
     * Shutdown the provider and release resources.
     * Resources are automatically released when JVM unloads the native library
     * via JNI_OnUnload.
     */
    public void shutdown() {
        NativeLoader.unload();
    }

    /**
     * Check if SDF is initialized (SDF_LIBRARY_PATH was set and library loaded successfully)
     */
    public boolean isInitialized() {
        try {
            return NativeLoader.isLoaded();
        } catch (Exception e) {
            return false;
        }
    }

    private void registerAlgorithms() {
        // MessageDigest
        put("MessageDigest.SM3", "org.openhitls.sdf4j.jce.digest.SM3MessageDigest");
        put("Alg.Alias.MessageDigest.1.2.156.10197.1.401", "SM3");

        // Cipher - SM4 Symmetric
        put("Cipher.SM4", "org.openhitls.sdf4j.jce.cipher.SM4Cipher");
        put("Cipher.SM4/ECB/NoPadding", "org.openhitls.sdf4j.jce.cipher.SM4Cipher$ECB");
        put("Cipher.SM4/ECB/PKCS5Padding", "org.openhitls.sdf4j.jce.cipher.SM4Cipher$ECB_PKCS5");
        put("Cipher.SM4/CBC/NoPadding", "org.openhitls.sdf4j.jce.cipher.SM4Cipher$CBC");
        put("Cipher.SM4/CBC/PKCS5Padding", "org.openhitls.sdf4j.jce.cipher.SM4Cipher$CBC_PKCS5");
        put("Cipher.SM4/GCM/NoPadding", "org.openhitls.sdf4j.jce.cipher.SM4Cipher$GCM");
        put("Alg.Alias.Cipher.SM4/ECB/PKCS7Padding", "SM4/ECB/PKCS5Padding");
        put("Alg.Alias.Cipher.SM4/CBC/PKCS7Padding", "SM4/CBC/PKCS5Padding");
        put("Alg.Alias.Cipher.1.2.156.10197.1.104", "SM4");

        // Cipher - SM2 Asymmetric
        put("Cipher.SM2", "org.openhitls.sdf4j.jce.cipher.SM2Cipher");
        put("Alg.Alias.Cipher.1.2.156.10197.1.301.1", "SM2");

        // Signature
        put("Signature.SM3withSM2", "org.openhitls.sdf4j.jce.signature.SM2Signature");
        put("Alg.Alias.Signature.1.2.156.10197.1.501", "SM3withSM2");

        // KeyPairGenerator
        put("KeyPairGenerator.SM2", "org.openhitls.sdf4j.jce.keygen.SM2KeyPairGenerator");
        put("Alg.Alias.KeyPairGenerator.1.2.156.10197.1.301", "SM2");

        // KeyGenerator
        put("KeyGenerator.SM4", "org.openhitls.sdf4j.jce.keygen.SM4KeyGenerator");

        // SecureRandom
        put("SecureRandom.SDF", "org.openhitls.sdf4j.jce.random.SDFSecureRandom");

        // Mac
        put("Mac.HmacSM3", "org.openhitls.sdf4j.jce.mac.HmacSM3");
        put("Mac.SM4-MAC", "org.openhitls.sdf4j.jce.mac.SM4Mac");
        put("Alg.Alias.Mac.SM4MAC", "SM4-MAC");
    }
}
