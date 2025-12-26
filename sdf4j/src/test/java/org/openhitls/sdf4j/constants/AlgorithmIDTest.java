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

package org.openhitls.sdf4j.constants;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * AlgorithmID类单元测试
 */
public class AlgorithmIDTest {

    @Test
    public void testSymmetricAlgorithms() {
        // 对称算法的高16位应为0x0000
        assertTrue(AlgorithmID.isSymmetricAlgorithm(AlgorithmID.SGD_SM4_ECB));
        assertTrue(AlgorithmID.isSymmetricAlgorithm(AlgorithmID.SGD_SM4_CBC));
        assertTrue(AlgorithmID.isSymmetricAlgorithm(AlgorithmID.SGD_SM1_ECB));

        // 非对称算法的高16位不是0x0000
        assertFalse(AlgorithmID.isSymmetricAlgorithm(AlgorithmID.SGD_SM2_1));

        // 注意：SGD_SM3虽然是杂凑算法，但由于高16位是0x0000，
        // isSymmetricAlgorithm会返回true。这是设计上的限制。
        // 应该使用isHashAlgorithm来判断杂凑算法
    }

    @Test
    public void testAsymmetricAlgorithms() {
        assertTrue(AlgorithmID.isAsymmetricAlgorithm(AlgorithmID.SGD_SM2_1));
        assertTrue(AlgorithmID.isAsymmetricAlgorithm(AlgorithmID.SGD_SM2_3));
        assertTrue(AlgorithmID.isAsymmetricAlgorithm(AlgorithmID.SGD_RSA));

        assertFalse(AlgorithmID.isAsymmetricAlgorithm(AlgorithmID.SGD_SM4_ECB));
        assertFalse(AlgorithmID.isAsymmetricAlgorithm(AlgorithmID.SGD_SM3));
    }

    @Test
    public void testHashAlgorithms() {
        assertTrue(AlgorithmID.isHashAlgorithm(AlgorithmID.SGD_SM3));
        assertTrue(AlgorithmID.isHashAlgorithm(AlgorithmID.SGD_SHA1));
        assertTrue(AlgorithmID.isHashAlgorithm(AlgorithmID.SGD_SHA256));

        assertFalse(AlgorithmID.isHashAlgorithm(AlgorithmID.SGD_SM4_ECB));
        assertFalse(AlgorithmID.isHashAlgorithm(AlgorithmID.SGD_SM2_1));
    }

    @Test
    public void testAlgorithmNames() {
        String sm4EcbName = AlgorithmID.getAlgorithmName(AlgorithmID.SGD_SM4_ECB);
        assertNotNull(sm4EcbName);
        assertTrue(sm4EcbName.contains("SM4"));

        String sm2Name = AlgorithmID.getAlgorithmName(AlgorithmID.SGD_SM2_1);
        assertNotNull(sm2Name);
        assertTrue(sm2Name.contains("SM2"));

        String sm3Name = AlgorithmID.getAlgorithmName(AlgorithmID.SGD_SM3);
        assertNotNull(sm3Name);
        assertTrue(sm3Name.contains("SM3"));

        // 测试未知算法
        String unknownName = AlgorithmID.getAlgorithmName(0x99999999);
        assertTrue(unknownName.contains("未知") || unknownName.contains("Unknown"));
    }

    @Test
    public void testAlgorithmIDValues() {
        // 验证算法ID常量的值
        assertEquals(0x00000401, AlgorithmID.SGD_SM4_ECB);
        assertEquals(0x00000402, AlgorithmID.SGD_SM4_CBC);
        assertEquals(0x00020200, AlgorithmID.SGD_SM2_1);
        assertEquals(0x00020800, AlgorithmID.SGD_SM2_3);
        assertEquals(0x00000001, AlgorithmID.SGD_SM3);
    }

    @Test
    public void testAlgorithmCategories() {
        // 测试对称算法分类
        assertTrue("SM4-ECB应该是对称算法",
                   AlgorithmID.isSymmetricAlgorithm(AlgorithmID.SGD_SM4_ECB));

        // 测试非对称算法分类
        assertTrue("SM2应该是非对称算法",
                   AlgorithmID.isAsymmetricAlgorithm(AlgorithmID.SGD_SM2_1));

        // 测试杂凑算法分类
        assertTrue("SM3应该是杂凑算法",
                   AlgorithmID.isHashAlgorithm(AlgorithmID.SGD_SM3));
    }
}
