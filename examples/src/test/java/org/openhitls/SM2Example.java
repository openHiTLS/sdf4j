/*
 * Copyright (c) 2025 OpenHitls
 * SDF4J is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

package org.openhitls;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.openhitls.sdf4j.*;
import org.openhitls.sdf4j.constants.AlgorithmID;
import org.openhitls.sdf4j.types.*;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

/**
 * SM2 数字签名与加密测试
 */
public class SM2Example {

    private static final int ECC_KEY_BITS = 256;

    private SDF sdf;
    private long deviceHandle;
    private long sessionHandle;

    @Before
    public void setUp() throws SDFException {
        sdf = new SDF();
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);
    }

    @After
    public void tearDown() throws SDFException {
        if (sdf != null) {
            if (sessionHandle != 0) {
                sdf.SDF_CloseSession(sessionHandle);
            }
            if (deviceHandle != 0) {
                sdf.SDF_CloseDevice(deviceHandle);
            }
        }
    }

    @Test
    public void testExternalSign() throws SDFException {

        Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
        ECCPublicKey publicKey = (ECCPublicKey) keyPair[0];
        ECCPrivateKey privateKey = (ECCPrivateKey) keyPair[1];

        assertNotNull("公钥不能为空", publicKey);
        assertNotNull("私钥不能为空", privateKey);

        String message = "Hello SM2 Sign Test";
        byte[] data = message.getBytes(StandardCharsets.UTF_8);

        sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
        sdf.SDF_HashUpdate(sessionHandle, data);
        byte[] hash = sdf.SDF_HashFinal(sessionHandle);

        assertNotNull("SM3哈希结果不能为空", hash);

        ECCSignature signature = sdf.SDF_ExternalSign_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, privateKey, hash);
        assertNotNull("签名结果不能为空", signature);

        sdf.SDF_ExternalVerify_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, publicKey, hash, signature);
    }

    @Test
    public void testExternalEncrypt() throws SDFException {

        Object[] keyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
        ECCPublicKey publicKey = (ECCPublicKey) keyPair[0];
        ECCPrivateKey privateKey = (ECCPrivateKey) keyPair[1];

        String plaintext = "Hello SM2 Encrypt Test";
        byte[] data = plaintext.getBytes(StandardCharsets.UTF_8);

        ECCCipher encrypted = sdf.SDF_ExternalEncrypt_ECC(sessionHandle, AlgorithmID.SGD_SM2_3, publicKey, data);
        assertNotNull("加密结果不能为空", encrypted);

        byte[] decrypted = sdf.SDF_ExternalDecrypt_ECC(sessionHandle, AlgorithmID.SGD_SM2_3, privateKey, encrypted);
        assertNotNull("解密结果不能为空", decrypted);

        String decryptedText = new String(decrypted, StandardCharsets.UTF_8);
        assertEquals("解密结果与原文不一致", plaintext, decryptedText);
    }
}
