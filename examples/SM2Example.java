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

import org.openhitls.sdf4j.*;
import org.openhitls.sdf4j.constants.AlgorithmID;
import org.openhitls.sdf4j.types.*;
import java.nio.charset.StandardCharsets;

/**
 * SM2 非对称加密和签名示例
 * 演示SM2签名验签和加密
 *
 * 编译: javac -cp .:target/sdf4j-1.0.0-SNAPSHOT.jar examples/SM2Example.java
 * 运行: java -cp .:target/sdf4j-1.0.0-SNAPSHOT.jar -Djava.library.path=target/native SM2Example
 */
public class SM2Example {

    public static void main(String[] args) {
        System.out.println("========================================");
        System.out.println("SM2 非对称加密和签名示例");
        System.out.println("========================================\n");

        SDF sdf = new SDF();
        long deviceHandle = 0;
        long sessionHandle = 0;

        try {
            // 打开设备和会话
            deviceHandle = sdf.SDF_OpenDevice();
            sessionHandle = sdf.SDF_OpenSession(deviceHandle);
            System.out.println("设备和会话已打开\n");

            // 密钥索引（需要根据实际设备配置）
            int keyIndex = 1;

            // ====================================
            // 示例1: 导出SM2公钥
            // ====================================
            System.out.println("========================================");
            System.out.println("示例1: 导出SM2公钥");
            System.out.println("========================================\n");

            // 导出签名公钥
            ECCPublicKey signPubKey = sdf.SDF_ExportSignPublicKey_ECC(sessionHandle, keyIndex);
            System.out.println("签名公钥:");
            System.out.println("  密钥位数: " + signPubKey.getBits());
            System.out.println("  X坐标: " + bytesToHex(signPubKey.getX()));
            System.out.println("  Y坐标: " + bytesToHex(signPubKey.getY()));

            // 导出加密公钥
            ECCPublicKey encPubKey = sdf.SDF_ExportEncPublicKey_ECC(sessionHandle, keyIndex);
            System.out.println("\n加密公钥:");
            System.out.println("  密钥位数: " + encPubKey.getBits());
            System.out.println("  X坐标: " + bytesToHex(encPubKey.getX()));
            System.out.println("  Y坐标: " + bytesToHex(encPubKey.getY()));

            // ====================================
            // 示例2: SM2内部签名和验签
            // ====================================
            System.out.println("\n========================================");
            System.out.println("示例2: SM2内部签名和验签");
            System.out.println("========================================\n");

            // 待签名数据
            String message = "这是一份重要的文档";
            byte[] data = message.getBytes(StandardCharsets.UTF_8);
            System.out.println("待签名数据: " + message);
            System.out.println("数据哈希: " + bytesToHex(data));

            // 使用设备内部私钥签名
            System.out.println("\n使用内部私钥签名...");
            ECCSignature signature = sdf.SDF_InternalSign_ECC(sessionHandle, keyIndex, data);
            System.out.println("签名结果:");
            System.out.println("  r: " + bytesToHex(signature.getR()));
            System.out.println("  s: " + bytesToHex(signature.getS()));

            // 使用设备内部公钥验签
            System.out.println("\n使用内部公钥验签...");
            try {
                sdf.SDF_InternalVerify_ECC(sessionHandle, keyIndex, data, signature);
                System.out.println("✓ 内部验签成功！");
            } catch (SDFException e) {
                System.out.println("✗ 内部验签失败: " + e.getMessage());
            }

            // ====================================
            // 示例3: SM2外部公钥验签
            // ====================================
            System.out.println("\n========================================");
            System.out.println("示例3: SM2外部公钥验签");
            System.out.println("========================================\n");

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

            // ====================================
            // 示例4: SM2外部公钥加密
            // ====================================
            System.out.println("\n========================================");
            System.out.println("示例4: SM2外部公钥加密");
            System.out.println("========================================\n");

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

            System.out.println("密文信息:");
            System.out.println("  C1 X坐标: " + bytesToHex(cipher.getX()));
            System.out.println("  C1 Y坐标: " + bytesToHex(cipher.getY()));
            System.out.println("  C3 MAC值: " + bytesToHex(cipher.getM()));
            System.out.println("  C2 密文: " + bytesToHex(cipher.getC()));
            System.out.println("  密文长度: " + cipher.getL() + " bytes");

            System.out.println("\n注意: SM2解密需要使用内部私钥，请参考SDF接口文档");

            // ====================================
            // 示例5: 验签失败测试
            // ====================================
            System.out.println("\n========================================");
            System.out.println("示例5: 验签失败测试");
            System.out.println("========================================\n");

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
            } catch (SDFException e) {
                System.out.println("✓ 验签正确失败: " + e.getErrorCodeHex());
            }

            System.out.println("\n========================================");
            System.out.println("SM2示例完成！");
            System.out.println("========================================");

        } catch (SDFException e) {
            System.err.println("\n错误: " + e.getErrorCodeHex() + " - " + e.getMessage());
            e.printStackTrace();
        } finally {
            // 关闭会话和设备
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
