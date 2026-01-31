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

package org.openhitls.sdf4j.jce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.openhitls.sdf4j.jce.key.SM2PublicKey;

/**
 * SM2 algorithm parameter specification.
 * Used to specify the user ID and public key for SM2 signature operations.
 *
 * According to GM/T 0009-2012, the Z value is calculated as:
 * Z = SM3(ENTLA || IDA || a || b || xG || yG || xA || yA)
 *
 * Where:
 * - ENTLA is the bit length of IDA (2 bytes, big-endian)
 * - IDA is the user identifier (default: "1234567812345678")
 * - a, b, xG, yG are SM2 curve parameters
 * - xA, yA are the public key coordinates
 */
public class SM2ParameterSpec implements AlgorithmParameterSpec {

    /**
     * Default user ID as specified in GM/T 0009-2012
     */
    public static final byte[] DEFAULT_USER_ID =
        "1234567812345678".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    private final byte[] userId;
    private final SM2PublicKey publicKey;

    /**
     * Create with default user ID and specified public key
     *
     * @param publicKey the SM2 public key (required for Z value calculation)
     */
    public SM2ParameterSpec(SM2PublicKey publicKey) {
        this(DEFAULT_USER_ID, publicKey);
    }

    /**
     * Create with specified user ID and public key
     *
     * @param userId    the user identifier
     * @param publicKey the SM2 public key (required for Z value calculation)
     */
    public SM2ParameterSpec(byte[] userId, SM2PublicKey publicKey) {
        if (userId == null || userId.length == 0) {
            throw new IllegalArgumentException("User ID cannot be null or empty");
        }
        if (userId.length > 8191) {
            throw new IllegalArgumentException("User ID too long (max 8191 bytes)");
        }
        if (publicKey == null) {
            throw new IllegalArgumentException("Public key cannot be null");
        }
        this.userId = userId;
        this.publicKey = publicKey;
    }

    /**
     * Get the user identifier
     *
     * @return a copy of the user ID bytes
     */
    public byte[] getUserId() {
        return userId;
    }

    /**
     * Get the public key
     *
     * @return the SM2 public key
     */
    public SM2PublicKey getPublicKey() {
        return publicKey;
    }
}
