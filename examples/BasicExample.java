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
import org.openhitls.sdf4j.types.*;

/**
 * SDF4J 基础示例
 * 演示设备打开、会话管理和基本操作
 *
 * 编译: javac -cp .:target/sdf4j-1.0.0-SNAPSHOT.jar examples/BasicExample.java
 * 运行: java -cp .:target/sdf4j-1.0.0-SNAPSHOT.jar -Djava.library.path=target/native BasicExample
 */
public class BasicExample {

    public static void main(String[] args) {
        System.out.println("========================================");
        System.out.println("SDF4J 基础示例");
        System.out.println("========================================\n");

        SDF sdf = new SDF();
        long deviceHandle = 0;
        long sessionHandle = 0;

        try {
            // 1. 打开设备
            System.out.println("1. 打开设备...");
            deviceHandle = sdf.SDF_OpenDevice();
            System.out.println("   设备句柄: " + deviceHandle);
            System.out.println("   ✓ 设备打开成功\n");

            // 2. 打开会话
            System.out.println("2. 打开会话...");
            sessionHandle = sdf.SDF_OpenSession(deviceHandle);
            System.out.println("   会话句柄: " + sessionHandle);
            System.out.println("   ✓ 会话打开成功\n");

            // 3. 获取设备信息
            System.out.println("3. 获取设备信息...");
            DeviceInfo info = sdf.SDF_GetDeviceInfo(sessionHandle);
            System.out.println("   厂商名称: " + info.getIssuerName());
            System.out.println("   设备型号: " + info.getDeviceName());
            System.out.println("   设备序列号: " + info.getDeviceSerial());
            System.out.println("   设备版本: 0x" + Long.toHexString(info.getDeviceVersion()));
            System.out.println("   标准版本: 0x" + Long.toHexString(info.getStandardVersion()));
            System.out.println("   缓冲区大小: " + info.getBufferSize() + " bytes");
            System.out.println("   ✓ 设备信息获取成功\n");

            // 4. 生成随机数
            System.out.println("4. 生成随机数...");
            byte[] random16 = sdf.SDF_GenerateRandom(sessionHandle, 16);
            System.out.println("   16字节随机数: " + bytesToHex(random16));

            byte[] random32 = sdf.SDF_GenerateRandom(sessionHandle, 32);
            System.out.println("   32字节随机数: " + bytesToHex(random32));
            System.out.println("   ✓ 随机数生成成功\n");

            // 5. 测试多会话
            System.out.println("5. 测试多会话...");
            long session2 = sdf.SDF_OpenSession(deviceHandle);
            System.out.println("   第二个会话句柄: " + session2);

            // 在第二个会话中生成随机数
            byte[] random = sdf.SDF_GenerateRandom(session2, 16);
            System.out.println("   第二个会话中的随机数: " + bytesToHex(random));

            // 关闭第二个会话
            sdf.SDF_CloseSession(session2);
            System.out.println("   ✓ 多会话测试成功\n");

            System.out.println("========================================");
            System.out.println("所有操作完成！");
            System.out.println("========================================");

        } catch (SDFException e) {
            System.err.println("\n错误: " + e.getErrorCodeHex() + " - " + e.getMessage());
            e.printStackTrace();
        } finally {
            // 6. 关闭会话和设备
            try {
                if (sessionHandle != 0) {
                    System.out.println("\n关闭会话...");
                    sdf.SDF_CloseSession(sessionHandle);
                }
                if (deviceHandle != 0) {
                    System.out.println("关闭设备...");
                    sdf.SDF_CloseDevice(deviceHandle);
                }
                System.out.println("✓ 资源清理完成");
            } catch (SDFException e) {
                System.err.println("关闭资源失败: " + e.getMessage());
            }
        }
    }

    /**
     * 字节数组转十六进制字符串
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
