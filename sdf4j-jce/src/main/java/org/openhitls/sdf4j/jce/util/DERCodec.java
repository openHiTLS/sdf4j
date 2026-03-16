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

package org.openhitls.sdf4j.jce.util;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;

/**
 * DER (Distinguished Encoding Rules) 编解码工具类
 *
 * 用于 SM2 签名格式转换：
 * - RAW 格式: r||s (64 bytes)
 * - DER 格式: SEQUENCE { INTEGER r, INTEGER s }
 */
public final class DERCodec {

    private DERCodec() {
    }

    /**
     * 将 RAW 格式签名 (r||s, 64 bytes) 转换为 DER 编码格式
     *
     * @param rawSignature 64 字节的 r||s 格式签名
     * @return DER 编码的签名
     * @throws IllegalArgumentException 如果签名格式无效
     */
    public static byte[] rawToDer(byte[] rawSignature) {
        if (rawSignature == null || rawSignature.length != 64) {
            throw new IllegalArgumentException("Raw signature must be 64 bytes (r||s)");
        }

        byte[] rBytes = new byte[32];
        byte[] sBytes = new byte[32];
        System.arraycopy(rawSignature, 0, rBytes, 0, 32);
        System.arraycopy(rawSignature, 32, sBytes, 0, 32);

        BigInteger r = new BigInteger(1, rBytes);
        BigInteger s = new BigInteger(1, sBytes);

        return encodeDerSignature(r, s);
    }

    /**
     * 将 DER 编码的签名转换为 RAW 格式 (r||s, 64 bytes)
     *
     * @param derSignature DER 编码的签名
     * @return 64 字节的 r||s 格式签名
     * @throws IllegalArgumentException 如果 DER 格式无效
     */
    public static byte[] derToRaw(byte[] derSignature) {
        if (derSignature == null || derSignature.length < 8) {
            throw new IllegalArgumentException("Invalid DER signature");
        }

        try {
            DerInputStream in = new DerInputStream(derSignature);

            // SEQUENCE tag
            if (in.readTag() != 0x30) {
                throw new IllegalArgumentException("Not a DER SEQUENCE");
            }
            int length = in.readLength();
            if (in.available() < length) {
                throw new IllegalArgumentException("DER length mismatch");
            }

            // INTEGER r
            if (in.readTag() != 0x02) {
                throw new IllegalArgumentException("Expected INTEGER for r");
            }
            int rLength = in.readLength();
            byte[] rBytes = in.readBytes(rLength);

            // INTEGER s
            if (in.readTag() != 0x02) {
                throw new IllegalArgumentException("Expected INTEGER for s");
            }
            int sLength = in.readLength();
            byte[] sBytes = in.readBytes(sLength);
            if (in.available() != 0) {
                throw new IllegalArgumentException("Trailing bytes in DER signature");
            }

            // 转换为 32 字节固定长度
            byte[] raw = new byte[64];
            copyToFixedBuffer(rBytes, raw, 0);
            copyToFixedBuffer(sBytes, raw, 32);

            return raw;
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid DER signature format", e);
        }
    }

    private static byte[] encodeDerSignature(BigInteger r, BigInteger s) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // 编码 r
        byte[] rEncoded = encodeInteger(r);
        // 编码 s
        byte[] sEncoded = encodeInteger(s);

        // SEQUENCE 长度
        int totalLength = rEncoded.length + sEncoded.length;

        // SEQUENCE tag + length
        out.write(0x30);
        encodeLength(out, totalLength);
        out.write(rEncoded, 0, rEncoded.length);
        out.write(sEncoded, 0, sEncoded.length);

        return out.toByteArray();
    }

    private static byte[] encodeInteger(BigInteger value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        byte[] bytes = value.toByteArray();

        // 去掉前导零（如果有符号位问题需要处理）
        if (bytes[0] == 0 && bytes.length > 1) {
            byte[] tmp = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, tmp, 0, tmp.length);
            bytes = tmp;
        }

        // 如果最高位是 1，需要添加前导零（表示正数）
        if ((bytes[0] & 0x80) != 0) {
            out.write(0x02);
            encodeLength(out, bytes.length + 1);
            out.write(0x00);
            out.write(bytes, 0, bytes.length);
        } else {
            out.write(0x02);
            encodeLength(out, bytes.length);
            out.write(bytes, 0, bytes.length);
        }

        return out.toByteArray();
    }

    private static void encodeLength(ByteArrayOutputStream out, int length) {
        if (length < 128) {
            out.write(length);
        } else if (length < 256) {
            out.write(0x81);
            out.write(length);
        } else {
            out.write(0x82);
            out.write((length >> 8) & 0xFF);
            out.write(length & 0xFF);
        }
    }

    private static void copyToFixedBuffer(byte[] src, byte[] dest, int offset) {
        int srcLen = src.length;
        int fixedLen = 32;

        if (srcLen > fixedLen) {
            // 因为interger的编码在高bit=0的时候会增加00, 可能导致编码长度是33
            if (src[0] == 0 && srcLen == fixedLen + 1) {
                System.arraycopy(src, 1, dest, offset, fixedLen);
            } else {
                throw new IllegalArgumentException("Integer value too large for " + fixedLen + " bytes");
            }
        } else {
            // 前导零填充
            int padLen = fixedLen - srcLen;
            for (int i = 0; i < padLen; i++) {
                dest[offset + i] = 0;
            }
            System.arraycopy(src, 0, dest, offset + padLen, srcLen);
        }
    }

    private static class DerInputStream {
        private final byte[] data;
        private int pos;

        DerInputStream(byte[] data) {
            this.data = data;
            this.pos = 0;
        }

        int readTag() {
            return data[pos++] & 0xFF;
        }

        int readLength() {
            int len = data[pos++] & 0xFF;
            if ((len & 0x80) == 0) {
                return len;
            }
            int numBytes = len & 0x7F;
            if (numBytes > 2) {
                throw new IllegalArgumentException("DER length too large");
            }
            len = 0;
            for (int i = 0; i < numBytes; i++) {
                len = (len << 8) | (data[pos++] & 0xFF);
            }
            return len;
        }

        byte[] readBytes(int length) {
            byte[] bytes = new byte[length];
            System.arraycopy(data, pos, bytes, 0, length);
            pos += length;
            return bytes;
        }

        int available() {
            return data.length - pos;
        }
    }
}
