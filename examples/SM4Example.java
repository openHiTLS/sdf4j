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
import java.nio.charset.StandardCharsets;

/**
 * SM4 对称加密示例
 * 演示SM4-ECB和SM4-CBC加解密
 *
 * 编译: javac -cp .:target/sdf4j-1.0.0-SNAPSHOT.jar examples/SM4Example.java
 * 运行: java -cp .:target/sdf4j-1.0.0-SNAPSHOT.jar -Djava.library.path=target/native SM4Example
 */
public class SM4Example {

    public static void main(String[] args) {
        System.out.println("========================================");
        System.out.println("SM4 对称加密示例");
        System.out.println("========================================\n");

        SDF sdf = new SDF();
        long deviceHandle = 0;
        long sessionHandle = 0;

        try {
            // 打开设备和会话
            deviceHandle = sdf.SDF_OpenDevice();
            sessionHandle = sdf.SDF_OpenSession(deviceHandle);
            System.out.println("设备和会话已打开\n");

            // 准备明文数据
            String plaintext = "Hello SDF4J! 测试SM4加密";
            byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
            System.out.println("明文: " + plaintext);
            System.out.println("明文字节: " + bytesToHex(plaintextBytes));
            System.out.println("明文长度: " + plaintextBytes.length + " bytes\n");

            // 注意：实际使用中需要先生成或导入密钥
            // 这里假设keyHandle是有效的密钥句柄
            // 在真实环境中，需要调用相应的密钥生成或导入函数
            long keyHandle = 0; // 需要替换为实际的密钥句柄

            // ====================================
            // 示例1: SM4-ECB加密解密
            // ====================================
            System.out.println("========================================");
            System.out.println("示例1: SM4-ECB模式");
            System.out.println("========================================");

            if (keyHandle != 0) {
                // ECB模式加密
                System.out.println("\n加密...");
                byte[] ciphertext = sdf.SDF_Encrypt(
                    sessionHandle,
                    keyHandle,
                    AlgorithmID.SGD_SM4_ECB,
                    null,  // ECB模式不需要IV
                    plaintextBytes
                );
                System.out.println("密文: " + bytesToHex(ciphertext));
                System.out.println("密文长度: " + ciphertext.length + " bytes");

                // ECB模式解密
                System.out.println("\n解密...");
                byte[] decrypted = sdf.SDF_Decrypt(
                    sessionHandle,
                    keyHandle,
                    AlgorithmID.SGD_SM4_ECB,
                    null,
                    ciphertext
                );
                String decryptedText = new String(decrypted, StandardCharsets.UTF_8);
                System.out.println("解密结果: " + decryptedText);

                // 验证
                if (plaintext.equals(decryptedText)) {
                    System.out.println("✓ SM4-ECB加解密验证成功！");
                } else {
                    System.out.println("✗ SM4-ECB加解密验证失败！");
                }
            } else {
                System.out.println("注意：需要先生成或导入SM4密钥");
                System.out.println("密钥生成示例：");
                System.out.println("  // 生成会话密钥");
                System.out.println("  keyHandle = sdf.SDF_GenerateKeyWith_KEK(...);");
            }

            // ====================================
            // 示例2: SM4-CBC加密解密
            // ====================================
            System.out.println("\n========================================");
            System.out.println("示例2: SM4-CBC模式");
            System.out.println("========================================");

            if (keyHandle != 0) {
                // 生成随机IV
                byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 16);
                System.out.println("\n初始向量IV: " + bytesToHex(iv));

                // CBC模式加密
                System.out.println("\n加密...");
                byte[] ciphertext = sdf.SDF_Encrypt(
                    sessionHandle,
                    keyHandle,
                    AlgorithmID.SGD_SM4_CBC,
                    iv,
                    plaintextBytes
                );
                System.out.println("密文: " + bytesToHex(ciphertext));

                // CBC模式解密
                System.out.println("\n解密...");
                byte[] decrypted = sdf.SDF_Decrypt(
                    sessionHandle,
                    keyHandle,
                    AlgorithmID.SGD_SM4_CBC,
                    iv,
                    ciphertext
                );
                String decryptedText = new String(decrypted, StandardCharsets.UTF_8);
                System.out.println("解密结果: " + decryptedText);

                // 验证
                if (plaintext.equals(decryptedText)) {
                    System.out.println("✓ SM4-CBC加解密验证成功！");
                } else {
                    System.out.println("✗ SM4-CBC加解密验证失败！");
                }
            }

            // ====================================
            // 示例3: SM4-MAC计算
            // ====================================
            System.out.println("\n========================================");
            System.out.println("示例3: SM4-MAC消息认证码");
            System.out.println("========================================");

            if (keyHandle != 0) {
                byte[] data = "Message to authenticate".getBytes(StandardCharsets.UTF_8);
                System.out.println("\n待认证消息: " + new String(data, StandardCharsets.UTF_8));

                // 计算MAC
                byte[] mac = sdf.SDF_CalculateMAC(
                    sessionHandle,
                    keyHandle,
                    AlgorithmID.SGD_SM4_MAC,
                    null,
                    data
                );
                System.out.println("MAC值: " + bytesToHex(mac));
                System.out.println("MAC长度: " + mac.length + " bytes");
                System.out.println("✓ MAC计算成功！");
            }

            System.out.println("\n========================================");
            System.out.println("SM4示例完成！");
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
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
