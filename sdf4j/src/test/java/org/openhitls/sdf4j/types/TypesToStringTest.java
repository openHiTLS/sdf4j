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
import org.openhitls.sdf4j.constants.AlgorithmID;

import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * Test class for toString() methods in types package
 *
 * <p>Verifies that:
 * <ul>
 *   <li>All types have working toString() methods</li>
 *   <li>toString() output contains expected class name and key fields</li>
 *   <li>Private keys have sensitive data redacted</li>
 *   <li>Output format is consistent and readable</li>
 * </ul>
 */
public class TypesToStringTest {

    @Test
    public void testECCCipherToStringTest() {
        byte[] x = new byte[]{0x01, 0x02, 0x03};
        byte[] y = new byte[]{0x04, 0x05, 0x06};
        byte[] m = new byte[]{0x07, 0x08};
        byte[] c = new byte[]{0x09, 0x0A, 0x0B, 0x0C};
        ECCCipher cipher = new ECCCipher(x, y, m, 4, c);

        String expected = "ECCCipher{x=010203, y=040506, m=0708, L=4, c.length=4}";
        assertEquals("ECCCipher toString output should match exactly", expected, cipher.toString());
    }

    @Test
    public void testECCSignatureToStringTest() {
        byte[] r = new byte[]{0x01, 0x02, 0x03};
        byte[] s = new byte[]{0x04, 0x05, 0x06};
        ECCSignature sig = new ECCSignature(r, s);

        String expected = "ECCSignature{r=010203, s=040506}";
        assertEquals("ECCSignature toString output should match exactly", expected, sig.toString());
    }

    @Test
    public void testECCPublicKeyToStringTest() {
        // ECCPublicKey uses getEffectiveX/Y which returns full-length (bits/8) arrays
        byte[] x = new byte[32];
        byte[] y = new byte[32];
        x[0] = 0x01;
        y[0] = 0x02;
        ECCPublicKey key = new ECCPublicKey(256, x, y);

        String expected = "ECCPublicKey{bits=256, x=0100000000000000000000000000000000000000000000000000000000000000, " +
                         "y=0200000000000000000000000000000000000000000000000000000000000000}";
        assertEquals("ECCPublicKey toString output should match exactly", expected, key.toString());
    }

    @Test
    public void testECCPrivateKeyToStringTest() {
        byte[] k = new byte[]{(byte) 0xAB, (byte) 0xCD, (byte) 0xEF};
        ECCPrivateKey key = new ECCPrivateKey(256, k);

        String expected = "ECCPrivateKey{bits=256, k=[REDACTED]}";
        assertEquals("ECCPrivateKey toString output should match exactly", expected, key.toString());
    }

    @Test
    public void testRSAPublicKeyToStringTest() {
        // RSAPublicKey uses getEffectiveM/E which returns full-length arrays
        byte[] m = new byte[256];  // 2048 bits = 256 bytes
        byte[] e = new byte[256];
        m[0] = 0x01;
        m[1] = 0x02;
        m[2] = 0x03;
        e[0] = 0x01;
        e[1] = 0x00;
        e[2] = 0x01;
        RSAPublicKey key = new RSAPublicKey(2048, m, e);

        StringBuilder zeros = new StringBuilder();
        for (int i = 0; i < 253; i++) zeros.append("00");
        String expected = "RSAPublicKey{bits=2048, m=010203" + zeros + ", e=010001" + zeros + "}";
        assertEquals("RSAPublicKey toString output should match exactly", expected, key.toString());
    }

    @Test
    public void testRSAPrivateKeyToStringTest() {
        byte[] m = new byte[]{0x01, 0x02, 0x03};
        byte[] e = new byte[]{0x01, 0x00, 0x01};
        byte[] d = new byte[32];
        byte[][] prime = {new byte[16], new byte[16]};
        byte[][] pexp = {new byte[16], new byte[16]};
        byte[] coef = new byte[16];
        RSAPrivateKey key = new RSAPrivateKey(2048, m, e, d, prime, pexp, coef);

        String expected = "RSAPrivateKey{bits=2048, m=010203, e=010001, d=[REDACTED], prime=[REDACTED], pexp=[REDACTED], coef=[REDACTED]}";
        assertEquals("RSAPrivateKey toString output should match exactly", expected, key.toString());
    }

    @Test
    public void testHybridCipherToStringTest() {
        byte[] ctM = new byte[]{(byte) 0xAB, (byte) 0xCD};
        byte[] x = new byte[]{0x01};
        byte[] y = new byte[]{0x02};
        byte[] m = new byte[]{0x03};
        byte[] c = new byte[]{0x04};
        ECCCipher ctS = new ECCCipher(x, y, m, 1, c);
        HybridCipher cipher = new HybridCipher(2, ctM, 0x80000001L, ctS, 0x12345678L);

        String expected = "HybridCipher{l1=2, ctM=ABCD, uiAlgID=0x80000001, ctS=ECCCipher{x=01, y=02, m=03, L=1, c.length=1}, keyHandlePresent=true}";
        assertEquals("HybridCipher toString output should match exactly", expected, cipher.toString());
    }

    @Test
    public void testHybridSignatureToStringTest() {
        byte[] r = new byte[]{(byte) 0xAA};
        byte[] s = new byte[]{(byte) 0xBB};
        ECCSignature sigS = new ECCSignature(r, s);
        byte[] sigM = new byte[]{(byte) 0xCC, (byte) 0xDD};
        HybridSignature sig = new HybridSignature(sigS, 2, sigM);

        String expected = "HybridSignature{sigS=ECCSignature{r=AA, s=BB}, l=2, sigM=CCDD}";
        assertEquals("HybridSignature toString output should match exactly", expected, sig.toString());
    }

    @Test
    public void testKeyEncryptionResultToStringTest() {
        byte[] encryptedKey = new byte[]{(byte) 0xAB, (byte) 0xCD, (byte) 0xEF};
        KeyEncryptionResult result = new KeyEncryptionResult(encryptedKey, 0x12345678L);

        String expected = "KeyEncryptionResult{keyHandlePresent=true, encryptedKey.length=3}";
        assertEquals("KeyEncryptionResult toString output should match exactly", expected, result.toString());
    }

    @Test
    public void testECCKeyEncryptionResultToStringTest() {
        byte[] x = new byte[]{0x01};
        byte[] y = new byte[]{0x02};
        byte[] m = new byte[]{0x03};
        byte[] c = new byte[]{0x04};
        ECCCipher eccCipher = new ECCCipher(x, y, m, 1, c);
        ECCKeyEncryptionResult result = new ECCKeyEncryptionResult(eccCipher, 0x12345678L);

        String expected = "ECCKeyEncryptionResult{keyHandlePresent=true, eccCipher=ECCCipher{x=01, y=02, m=03, L=1, c.length=1}}";
        assertEquals("ECCKeyEncryptionResult toString output should match exactly", expected, result.toString());
    }

    @Test
    public void testKeyAgreementResultToStringTest() {
        // ECCPublicKey uses getEffectiveX/Y which returns full-length arrays
        byte[] x = new byte[32];
        byte[] y = new byte[32];
        x[0] = 0x01;
        y[0] = 0x02;
        ECCPublicKey publicKey = new ECCPublicKey(256, x, y);
        ECCPublicKey tmpPublicKey = new ECCPublicKey(256, x, y);
        KeyAgreementResult result = new KeyAgreementResult(0x12345678L, publicKey, tmpPublicKey);

        StringBuilder zeros = new StringBuilder();
        for (int i = 0; i < 31; i++) zeros.append("00");
        String xy = "01" + zeros;
        String expected = "KeyAgreementResult{agreementHandle=0x12345678, publicKey=ECCPublicKey{bits=256, x=" + xy +
                         ", y=02" + zeros + "}, tmpPublicKey=ECCPublicKey{bits=256, x=" + xy + ", y=02" + zeros + "}}";
        assertEquals("KeyAgreementResult toString output should match exactly", expected, result.toString());
    }

    @Test
    public void testDeviceInfoToStringTest() {
        DeviceInfo info = new DeviceInfo("Issuer","Device","SN001",10,20,new long[]{100L, 200L}, 0xFL, 0x1L, 4096
        );

        String result = info.toString();
        // DeviceInfo使用单引号包裹字符串值
        assertTrue("DeviceInfo should contain issuerName with quotes", result.contains("issuerName='Issuer'"));
        assertTrue("DeviceInfo should contain deviceName with quotes", result.contains("deviceName='Device'"));
        assertTrue("DeviceInfo should contain deviceSerial with quotes", result.contains("deviceSerial='SN001'"));
        assertTrue("DeviceInfo should contain bufferSize", result.contains("bufferSize=4096"));
    }
}
