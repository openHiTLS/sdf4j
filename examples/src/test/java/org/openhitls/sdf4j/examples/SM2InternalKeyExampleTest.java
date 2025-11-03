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
 * SM2 内部密钥示例测试
 * 演示使用设备内部密钥进行SM2签名验签和加密解密操作
 *
 * 内部密钥是指存储在密码设备内部的密钥，通过密钥索引访问
 */
public class SM2InternalKeyExampleTest {

    private SDF sdf;
    private long deviceHandle;
    private long sessionHandle;
    private static final int SIGN_KEY_INDEX = 10;  // 签名密钥索引
    private static final int ENC_KEY_INDEX = 10;   // 加密密钥索引

    @Before
    public void setUp() throws SDFException {
        System.out.println("========================================");
        System.out.println("SM2 内部密钥示例测试");
        System.out.println("========================================\n");

        sdf = new SDF();
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);
        System.out.println("✓ 设备和会话已打开\n");
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
            System.out.println("\n✓ 资源已清理");
            System.out.println("========================================\n");
        } catch (SDFException e) {
            System.err.println("✗ 关闭资源失败: " + e.getMessage());
        }
    }

    @Test
    public void testExportInternalPublicKey() throws SDFException {
        System.out.println("----------------------------------------");
        System.out.println("测试1: 导出内部密钥的公钥部分");
        System.out.println("----------------------------------------\n");

        try {
            // 导出签名公钥
            System.out.println("导出签名公钥 (密钥索引: " + SIGN_KEY_INDEX + ")");
            ECCPublicKey signPubKey = sdf.SDF_ExportSignPublicKey_ECC(sessionHandle, SIGN_KEY_INDEX);
            assertNotNull("签名公钥不应为空", signPubKey);

            System.out.println("签名公钥信息:");
            System.out.println("  密钥位数: " + signPubKey.getBits() + " bits");
            System.out.println("  X 坐标长度: " + signPubKey.getX().length + " bytes");
            System.out.println("  Y 坐标长度: " + signPubKey.getY().length + " bytes");
            System.out.println("  X: " + bytesToHex(signPubKey.getX()));
            System.out.println("  Y: " + bytesToHex(signPubKey.getY()));

            assertTrue("密钥位数应大于0", signPubKey.getBits() > 0);
            assertNotNull("X坐标不应为空", signPubKey.getX());
            assertNotNull("Y坐标不应为空", signPubKey.getY());

            // 导出加密公钥
            System.out.println("\n导出加密公钥 (密钥索引: " + ENC_KEY_INDEX + ")");
            ECCPublicKey encPubKey = sdf.SDF_ExportEncPublicKey_ECC(sessionHandle, ENC_KEY_INDEX);
            assertNotNull("加密公钥不应为空", encPubKey);

            System.out.println("加密公钥信息:");
            System.out.println("  密钥位数: " + encPubKey.getBits() + " bits");
            System.out.println("  X 坐标长度: " + encPubKey.getX().length + " bytes");
            System.out.println("  Y 坐标长度: " + encPubKey.getY().length + " bytes");

            assertTrue("密钥位数应大于0", encPubKey.getBits() > 0);

            System.out.println("\n✓ 公钥导出成功");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("⚠ 内部公钥导出功能未实现（这是正常的）");
            } else if (e.getErrorCode() == ErrorCode.SDR_KEYNOTEXIST) {
                System.out.println("⚠ 设备中不存在指定索引的密钥");
            } else {
                throw e;
            }
        }
    }

    @Test
    public void testInternalSignAndVerify() throws SDFException {
        System.out.println("----------------------------------------");
        System.out.println("测试2: 内部密钥签名和验签");
        System.out.println("----------------------------------------\n");

        try {
            // 待签名数据
            String message = "这是需要签名的重要文档内容";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);

            System.out.println("待签名数据: \"" + message + "\"");
            System.out.println("数据长度: " + data.length + " bytes");
            System.out.println("数据十六进制: " + bytesToHex(data));

            // 先对数据进行SM3哈希（SM2签名通常需要先哈希）
            System.out.println("\n先计算SM3哈希值");
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data);
            byte[] hashedData = sdf.SDF_HashFinal(sessionHandle);
            System.out.println("SM3哈希值: " + bytesToHex(hashedData));
            System.out.println("哈希长度: " + hashedData.length + " bytes");

            // 步骤1: 使用设备内部私钥签名（签名哈希值）
            System.out.println("\n步骤1: 使用内部私钥签名哈希值 (密钥索引: " + SIGN_KEY_INDEX + ")");
            ECCSignature signature = sdf.SDF_InternalSign_ECC(sessionHandle, SIGN_KEY_INDEX, hashedData);
            assertNotNull("签名结果不应为空", signature);

            System.out.println("签名成功:");
            System.out.println("  r 分量长度: " + signature.getR().length + " bytes");
            System.out.println("  s 分量长度: " + signature.getS().length + " bytes");
            System.out.println("  r: " + bytesToHex(signature.getR()));
            System.out.println("  s: " + bytesToHex(signature.getS()));

            assertNotNull("签名r分量不应为空", signature.getR());
            assertNotNull("签名s分量不应为空", signature.getS());
            assertTrue("签名r分量长度应大于0", signature.getR().length > 0);
            assertTrue("签名s分量长度应大于0", signature.getS().length > 0);

            // 步骤2: 使用设备内部公钥验签（验签哈希值）
            System.out.println("\n步骤2: 使用内部公钥验签哈希值 (密钥索引: " + SIGN_KEY_INDEX + ")");
            sdf.SDF_InternalVerify_ECC(sessionHandle, SIGN_KEY_INDEX, hashedData, signature);
            System.out.println("✓ 内部验签成功 - 签名有效!");

            // 步骤3: 验证修改数据后验签会失败
            System.out.println("\n步骤3: 验证数据完整性检测");
            byte[] tamperedData = (message + "被篡改").getBytes(StandardCharsets.UTF_8);
            System.out.println("篡改后的数据: \"" + new String(tamperedData, StandardCharsets.UTF_8) + "\"");

            // 计算篡改数据的哈希
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, tamperedData);
            byte[] tamperedHash = sdf.SDF_HashFinal(sessionHandle);

            try {
                sdf.SDF_InternalVerify_ECC(sessionHandle, SIGN_KEY_INDEX, tamperedHash, signature);
                fail("使用篡改数据验签应该失败");
            } catch (SDFException e) {
                System.out.println("✓ 篡改数据验签正确失败: " + e.getErrorCodeHex());
            }

            System.out.println("\n✓ 内部签名验签测试完成");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("⚠ SM2内部签名/验签功能未实现（这是正常的）");
            } else if (e.getErrorCode() == ErrorCode.SDR_KEYNOTEXIST) {
                System.out.println("⚠ 设备中不存在指定索引的密钥");
            } else {
                throw e;
            }
        }
    }

    @Test
    public void testInternalEncryptDecrypt() throws SDFException {
        System.out.println("----------------------------------------");
        System.out.println("测试3: 使用内部密钥进行加密和解密");
        System.out.println("----------------------------------------\n");

        try {
            // 步骤1: 导出内部加密公钥
            System.out.println("步骤1: 导出内部加密公钥 (密钥索引: " + ENC_KEY_INDEX + ")");
            ECCPublicKey encPubKey = sdf.SDF_ExportEncPublicKey_ECC(sessionHandle, ENC_KEY_INDEX);
            assertNotNull("加密公钥不应为空", encPubKey);
            System.out.println("✓ 加密公钥导出成功 (密钥位数: " + encPubKey.getBits() + ")");

            // 步骤2: 使用公钥加密数据
            String plaintext = "这是需要加密的机密信息";
            byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

            System.out.println("\n步骤2: 使用导出的公钥作为外部公钥加密数据");
            System.out.println("明文: \"" + plaintext + "\"");
            System.out.println("明文长度: " + plaintextBytes.length + " bytes");
            System.out.println("明文十六进制: " + bytesToHex(plaintextBytes));

            // 注意：SDF标准没有定义内部密钥加密接口，只能使用导出的公钥作为外部公钥加密
            ECCCipher cipher = sdf.SDF_ExternalEncrypt_ECC(
                sessionHandle,
                AlgorithmID.SGD_SM2_3,
                encPubKey,
                plaintextBytes
            );

            assertNotNull("密文不应为空", cipher);
            System.out.println("\n加密成功:");
            System.out.println("  密文结构 (SM2加密结果 C1||C3||C2):");
            System.out.println("    C1 X 坐标: " + bytesToHex(cipher.getX()));
            System.out.println("    C1 Y 坐标: " + bytesToHex(cipher.getY()));
            System.out.println("    C3 (MAC): " + bytesToHex(cipher.getM()));
            System.out.println("    C2 (密文): " + bytesToHex(cipher.getC()));
            System.out.println("    密文长度: " + cipher.getL() + " bytes");

            assertNotNull("C1 X坐标不应为空", cipher.getX());
            assertNotNull("C1 Y坐标不应为空", cipher.getY());
            assertNotNull("C3 MAC值不应为空", cipher.getM());
            assertNotNull("C2密文不应为空", cipher.getC());
            assertEquals("密文长度应与明文相同", plaintextBytes.length, cipher.getL());

            System.out.println("\n说明: 使用内部密钥解密需要设备支持相应接口");
            System.out.println("     标准的GM/T 0018没有定义内部私钥解密接口");
            System.out.println("     通常通过密钥协商或导入会话密钥的方式实现");

            System.out.println("\n✓ 加密测试完成");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("⚠ 内部密钥加密功能未实现（这是正常的）");
            } else if (e.getErrorCode() == ErrorCode.SDR_KEYNOTEXIST) {
                System.out.println("⚠ 设备中不存在指定索引的密钥");
            } else {
                throw e;
            }
        }
    }

    @Test
    public void testInternalKeyUsageScenario() throws SDFException {
        System.out.println("----------------------------------------");
        System.out.println("测试4: 内部密钥典型应用场景");
        System.out.println("----------------------------------------\n");

        try {
            System.out.println("场景: 数字签名保证文档完整性和身份认证\n");

            // 模拟多个文档签名
            String[] documents = {
                "合同文件 - 甲乙双方协议",
                "财务报表 - 2024年度",
                "技术方案 - 系统架构设计"
            };

            for (int i = 0; i < documents.length; i++) {
                System.out.println((i + 1) + ". 签名文档: \"" + documents[i] + "\"");
                byte[] docData = documents[i].getBytes(StandardCharsets.UTF_8);

                // 先计算文档的SM3哈希
                sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
                sdf.SDF_HashUpdate(sessionHandle, docData);
                byte[] docHash = sdf.SDF_HashFinal(sessionHandle);

                // 签名哈希值
                ECCSignature signature = sdf.SDF_InternalSign_ECC(sessionHandle, SIGN_KEY_INDEX, docHash);
                System.out.println("   签名: r=" + bytesToHex(signature.getR()).substring(0, 16) + "...");

                // 验签哈希值
                sdf.SDF_InternalVerify_ECC(sessionHandle, SIGN_KEY_INDEX, docHash, signature);
                System.out.println("   ✓ 验签通过\n");
            }

            System.out.println("✓ 典型场景测试完成");
            System.out.println("\n内部密钥优势:");
            System.out.println("  • 私钥永不离开安全设备");
            System.out.println("  • 硬件级别的密钥保护");
            System.out.println("  • 符合商密合规要求");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("⚠ 功能未实现");
            } else if (e.getErrorCode() == ErrorCode.SDR_KEYNOTEXIST) {
                System.out.println("⚠ 密钥不存在");
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
