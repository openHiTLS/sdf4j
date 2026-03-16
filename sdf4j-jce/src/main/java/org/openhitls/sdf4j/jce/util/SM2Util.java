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

package org.openhitls.sdf4j.jce.util;

import org.openhitls.sdf4j.jce.SDFJceNative;

/**
 * SM2 utility class for Z value calculation according to GM/T 0009-2012.
 *
 * Z = SM3(ENTLA || IDA || a || b || xG || yG || xA || yA)
 */
public final class SM2Util {

    private SM2Util() {
    }

    /**
     * SM2 curve parameter 'a' (256 bits)
     * a = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC
     */
    private static final byte[] SM2_PARAM_A = hexToBytes(
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC");

    /**
     * SM2 curve parameter 'b' (256 bits)
     * b = 28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93
     */
    private static final byte[] SM2_PARAM_B = hexToBytes(
        "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93");

    /**
     * SM2 base point G x-coordinate (256 bits)
     * xG = 32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7
     */
    private static final byte[] SM2_PARAM_XG = hexToBytes(
        "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7");

    /**
     * SM2 base point G y-coordinate (256 bits)
     * yG = BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0
     */
    private static final byte[] SM2_PARAM_YG = hexToBytes(
        "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0");

    /**
     * Calculate Z value according to GM/T 0009-2012
     *
     * Z = SM3(ENTLA || IDA || a || b || xG || yG || xA || yA)
     *
     * @param sessionHandle Session handle from {@link org.openhitls.sdf4j.jce.SDFJceNative#openSession()}
     * @param userId   user identifier (IDA)
     * @param publicX  public key x-coordinate (xA, 32 bytes)
     * @param publicY  public key y-coordinate (yA, 32 bytes)
     * @return 32-byte Z value
     */
    public static byte[] calculateZ(long sessionHandle, byte[] userId, byte[] publicX, byte[] publicY) {
        if (userId == null || userId.length == 0) {
            throw new IllegalArgumentException("User ID cannot be null or empty");
        }
        if (publicX == null || publicX.length != 32) {
            throw new IllegalArgumentException("Public key X must be 32 bytes");
        }
        if (publicY == null || publicY.length != 32) {
            throw new IllegalArgumentException("Public key Y must be 32 bytes");
        }

        // ENTLA = bit length of IDA (2 bytes, big-endian)
        int entla = userId.length * 8;
        byte[] entlaBytes = new byte[2];
        entlaBytes[0] = (byte) ((entla >> 8) & 0xFF);
        entlaBytes[1] = (byte) (entla & 0xFF);

        // Concatenate: ENTLA || IDA || a || b || xG || yG || xA || yA
        // Total: 2 + userId.length + 32 + 32 + 32 + 32 + 32 + 32 = 194 + userId.length
        int totalLen = 2 + userId.length + 32 * 6;
        byte[] data = new byte[totalLen];

        int offset = 0;

        // ENTLA (2 bytes)
        System.arraycopy(entlaBytes, 0, data, offset, 2);
        offset += 2;

        // IDA
        System.arraycopy(userId, 0, data, offset, userId.length);
        offset += userId.length;

        // a (32 bytes)
        System.arraycopy(SM2_PARAM_A, 0, data, offset, 32);
        offset += 32;

        // b (32 bytes)
        System.arraycopy(SM2_PARAM_B, 0, data, offset, 32);
        offset += 32;

        // xG (32 bytes)
        System.arraycopy(SM2_PARAM_XG, 0, data, offset, 32);
        offset += 32;

        // yG (32 bytes)
        System.arraycopy(SM2_PARAM_YG, 0, data, offset, 32);
        offset += 32;

        // xA (32 bytes)
        System.arraycopy(publicX, 0, data, offset, 32);
        offset += 32;

        // yA (32 bytes)
        System.arraycopy(publicY, 0, data, offset, 32);

        // Z = SM3(data)
        return SDFJceNative.sm3Digest(sessionHandle, data);
    }

    /**
     * Calculate the message hash e = SM3(Z || M) for SM2 signature
     *
     * @param sessionHandle Session handle from {@link org.openhitls.sdf4j.jce.SDFJceNative#openSession()}
     * @param z       the Z value (32 bytes)
     * @param message the message to sign
     * @return 32-byte hash value e
     */
    public static byte[] calculateE(long sessionHandle, byte[] z, byte[] message) {
        if (z == null || z.length != 32) {
            throw new IllegalArgumentException("Z value must be 32 bytes");
        }
        if (message == null) {
            message = new byte[0];
        }

        byte[] data = new byte[z.length + message.length];
        System.arraycopy(z, 0, data, 0, z.length);
        System.arraycopy(message, 0, data, z.length, message.length);

        return SDFJceNative.sm3Digest(sessionHandle, data);
    }

    /**
     * Convert hex string to byte array
     */
    private static byte[] hexToBytes(String hex) {
        if (hex == null || hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Invalid hex string");
        }
        byte[] data = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
