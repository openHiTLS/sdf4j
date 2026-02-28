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

package org.openhitls.sdf4j.types;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * ECCSignature 测试类
 * 验证ECCSignature修改后的行为
 */
public class ECCSignatureTest {

    @Test
    public void testConstructorWithSM2SignatureLength() {
        // SM2签名通常是32字节
        byte[] r = new byte[32];
        byte[] s = new byte[32];

        // 填充测试数据
        for (int i = 0; i < 32; i++) {
            r[i] = (byte)(i + 1);
            s[i] = (byte)(i + 33);
        }

        ECCSignature signature = new ECCSignature(r, s);

        // 验证返回的数组长度应该是32字节，而不是强制填充到64字节
        byte[] rResult = signature.getR();
        byte[] sResult = signature.getS();

        assertEquals("R component should be 32 bytes", 32, rResult.length);
        assertEquals("S component should be 32 bytes", 32, sResult.length);

        // 验证数据内容正确
        for (int i = 0; i < 32; i++) {
            assertEquals("R data at index " + i, (byte)(i + 1), rResult[i]);
            assertEquals("S data at index " + i, (byte)(i + 33), sResult[i]);
        }
    }

    @Test
    public void testSettersWithSM2Length() {
        ECCSignature signature = new ECCSignature();

        byte[] r = new byte[32];
        byte[] s = new byte[32];

        for (int i = 0; i < 32; i++) {
            r[i] = (byte)(0x10 + i);
            s[i] = (byte)(0x50 + i);
        }

        signature.setR(r);
        signature.setS(s);

        byte[] rResult = signature.getR();
        byte[] sResult = signature.getS();

        // 验证长度保持为32字节
        assertEquals("R should maintain original length", 32, rResult.length);
        assertEquals("S should maintain original length", 32, sResult.length);

        // 验证数据内容
        for (int i = 0; i < 32; i++) {
            assertEquals((byte)(0x10 + i), rResult[i]);
            assertEquals((byte)(0x50 + i), sResult[i]);
        }
    }
}