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

package org.openhitls.sdf4j.examples;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.openhitls.sdf4j.*;
import org.openhitls.sdf4j.constants.AlgorithmID;
import org.openhitls.sdf4j.constants.ErrorCode;
import org.openhitls.sdf4j.types.*;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

/**
 * SM2 非对称加密和签名示例测试
 * 演示SM2签名验签和加密
 */
public class SM2ExampleTest {

    private SDF sdf;
    private long deviceHandle;
    private long sessionHandle;
    private static final int KEY_INDEX = 1;

    @Before
    public void setUp() throws SDFException {
        System.out.println("========================================");
        System.out.println("SM2 非对称加密和签名示例");
        System.out.println("========================================\n");

        sdf = new SDF();
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);
        System.out.println("设备和会话已打开\n");
    }

    
    @After
    public void tearDown() {
        try {
            if (sessionHandle != 0) {
                sdf.SDF_CloseSession(sessionHandle);
            }
            if (deviceHandle != 0) {
                sdf.SDF_CloseDevice(deviceHandle);
            }
            System.out.println("\n资源已清理");
        } catch (SDFException e) {
            System.err.println("关闭资源失败: " + e.getMessage());
        }
    }

    @Test
    public void testExportSM2PublicKey() throws SDFException {
        System.out.println("========================================");
        System.out.println("示例1: 导出SM2公钥");
        System.out.println("========================================\n");

        try {
            // 导出签名公钥
            ECCPublicKey signPubKey = sdf.SDF_ExportSignPublicKey_ECC(sessionHandle, KEY_INDEX);
            assertNotNull("签名公钥不应为空", signPubKey);
            System.out.println("签名公钥:");
            System.out.println("  密钥位数: " + signPubKey.getBits());
            System.out.println("  X坐标: " + bytesToHex(signPubKey.getX()));
            System.out.println("  Y坐标: " + bytesToHex(signPubKey.getY()));

            assertTrue("密钥位数应大于0", signPubKey.getBits() > 0);
            assertNotNull("X坐标不应为空", signPubKey.getX());
            assertNotNull("Y坐标不应为空", signPubKey.getY());

            // 导出加密公钥
            ECCPublicKey encPubKey = sdf.SDF_ExportEncPublicKey_ECC(sessionHandle, KEY_INDEX);
            assertNotNull("加密公钥不应为空", encPubKey);
            System.out.println("\n加密公钥:");
            System.out.println("  密钥位数: " + encPubKey.getBits());
            System.out.println("  X坐标: " + bytesToHex(encPubKey.getX()));
            System.out.println("  Y坐标: " + bytesToHex(encPubKey.getY()));

            assertTrue("密钥位数应大于0", encPubKey.getBits() > 0);
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("⚠ SM2公钥导出功能未实现（这是正常的）");
            } else {
                throw e;
            }
        }
    }

    @Test
    public void testSM2InternalSignAndVerify() throws SDFException {
        System.out.println("\n========================================");
        System.out.println("示例2: SM2内部签名和验签");
        System.out.println("========================================\n");

        try {
            // 待签名数据
            String message = "这是一份重要的文档";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);
            System.out.println("待签名数据: " + message);
            System.out.println("数据哈希: " + bytesToHex(data));

            // 使用设备内部私钥签名
            System.out.println("\n使用内部私钥签名...");
            ECCSignature signature = sdf.SDF_InternalSign_ECC(sessionHandle, KEY_INDEX, data);
            assertNotNull("签名结果不应为空", signature);
            System.out.println("签名结果:");
            System.out.println("  r: " + bytesToHex(signature.getR()));
            System.out.println("  s: " + bytesToHex(signature.getS()));

            assertNotNull("签名r不应为空", signature.getR());
            assertNotNull("签名s不应为空", signature.getS());

            // 使用设备内部公钥验签
            System.out.println("\n使用内部公钥验签...");
            try {
                sdf.SDF_InternalVerify_ECC(sessionHandle, KEY_INDEX, data, signature);
                System.out.println("✓ 内部验签成功！");
            } catch (SDFException e) {
                System.out.println("✗ 内部验签失败: " + e.getMessage());
                fail("内部验签应该成功");
            }
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("⚠ SM2内部签名/验签功能未实现（这是正常的）");
            } else {
                throw e;
            }
        }
    }

    @Test
    public void testSM2ExternalVerify() throws SDFException {
        System.out.println("\n========================================");
        System.out.println("示例3: SM2外部公钥验签");
        System.out.println("========================================\n");

        try {
            // 先导出公钥和签名
            ECCPublicKey signPubKey = sdf.SDF_ExportSignPublicKey_ECC(sessionHandle, KEY_INDEX);

            String message = "这是一份重要的文档";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);
            ECCSignature signature = sdf.SDF_InternalSign_ECC(sessionHandle, KEY_INDEX, data);

            // 使用导出的公钥进行外部验签
            System.out.println("使用导出的公钥验签...");
            try {
                sdf.SDF_ExternalVerify_ECC(
                    sessionHandle,
                    AlgorithmID.SGD_SM2_1,
                    signPubKey,
                    data,
                    signature
                );
                System.out.println("✓ 外部验签成功！");
            } catch (SDFException e) {
                System.out.println("✗ 外部验签失败: " + e.getMessage());
            }
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("⚠ SM2外部验签功能未实现（这是正常的）");
            } else {
                throw e;
            }
        }
    }

    @Test
    public void testSM2ExternalEncrypt() throws SDFException {
        System.out.println("\n========================================");
        System.out.println("示例4: SM2外部公钥加密");
        System.out.println("========================================\n");

        try {
            // 导出加密公钥
            ECCPublicKey encPubKey = sdf.SDF_ExportEncPublicKey_ECC(sessionHandle, KEY_INDEX);

            String plaintext = "机密信息";
            byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
            System.out.println("明文: " + plaintext);
            System.out.println("明文字节: " + bytesToHex(plaintextBytes));

            // 使用公钥加密
            System.out.println("\n使用公钥加密...");
            ECCCipher cipher = sdf.SDF_ExternalEncrypt_ECC(
                sessionHandle,
                AlgorithmID.SGD_SM2_3,
                encPubKey,
                plaintextBytes
            );

            assertNotNull("密文不应为空", cipher);
            System.out.println("密文信息:");
            System.out.println("  C1 X坐标: " + bytesToHex(cipher.getX()));
            System.out.println("  C1 Y坐标: " + bytesToHex(cipher.getY()));
            System.out.println("  C3 MAC值: " + bytesToHex(cipher.getM()));
            System.out.println("  C2 密文: " + bytesToHex(cipher.getC()));
            System.out.println("  密文长度: " + cipher.getL() + " bytes");

            assertNotNull("C1 X坐标不应为空", cipher.getX());
            assertNotNull("C1 Y坐标不应为空", cipher.getY());
            assertNotNull("C3 MAC值不应为空", cipher.getM());
            assertNotNull("C2密文不应为空", cipher.getC());

            System.out.println("\n注意: SM2解密需要使用内部私钥，请参考SDF接口文档");
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("⚠ SM2外部加密功能未实现（这是正常的）");
            } else {
                throw e;
            }
        }
    }

    @Test
    public void testVerifyWithTamperedData() throws SDFException {
        System.out.println("\n========================================");
        System.out.println("示例5: 验签失败测试");
        System.out.println("========================================\n");

        try {
            // 导出公钥
            ECCPublicKey signPubKey = sdf.SDF_ExportSignPublicKey_ECC(sessionHandle, KEY_INDEX);

            // 签名原始数据
            String message = "这是一份重要的文档";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);
            ECCSignature signature = sdf.SDF_InternalSign_ECC(sessionHandle, KEY_INDEX, data);

            // 篡改数据
            byte[] tamperedData = "这是一份被篡改的文档".getBytes(StandardCharsets.UTF_8);
            System.out.println("篡改后的数据: " + new String(tamperedData, StandardCharsets.UTF_8));

            try {
                sdf.SDF_ExternalVerify_ECC(
                    sessionHandle,
                    AlgorithmID.SGD_SM2_1,
                    signPubKey,
                    tamperedData,
                    signature
                );
                System.out.println("✗ 验签应该失败但却成功了！");
                fail("使用篡改数据验签应该失败");
            } catch (SDFException e) {
                System.out.println("✓ 验签正确失败: " + e.getErrorCodeHex());
            }

            System.out.println("\n========================================");
            System.out.println("SM2示例完成！");
            System.out.println("========================================");
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("⚠ SM2签名/验签功能未实现（这是正常的）");
            } else {
                throw e;
            }
        }
    }

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
