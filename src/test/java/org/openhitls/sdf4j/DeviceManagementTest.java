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

package org.openhitls.sdf4j;

import org.junit.Test;
import org.openhitls.sdf4j.types.DeviceInfo;

import static org.junit.Assert.*;

/**
 * 设备管理功能测试
 */
public class DeviceManagementTest extends BaseSDFTest {

    @Test
    public void testOpenAndCloseDevice() {
        requireDevice();

        assertNotEquals("设备句柄不应为0", 0, deviceHandle);
        printTestInfo("设备打开和关闭测试");
        System.out.println("设备句柄: " + deviceHandle);
    }

    @Test
    public void testOpenAndCloseSession() {
        requireDevice();

        assertNotEquals("会话句柄不应为0", 0, sessionHandle);
        printTestInfo("会话打开和关闭测试");
        System.out.println("会话句柄: " + sessionHandle);
    }

    @Test
    public void testGetDeviceInfo() throws SDFException {
        requireDevice();
        printTestInfo("获取设备信息测试");

        DeviceInfo info = sdf.SDF_GetDeviceInfo(sessionHandle);
        assertNotNull("设备信息不应为null", info);

        System.out.println("设备厂商: " + info.getIssuerName());
        System.out.println("设备型号: " + info.getDeviceName());
        System.out.println("设备序列号: " + info.getDeviceSerial());
        System.out.println("设备版本: 0x" + Long.toHexString(info.getDeviceVersion()));
        System.out.println("标准版本: 0x" + Long.toHexString(info.getStandardVersion()));
        System.out.println("缓冲区大小: " + info.getBufferSize());

        assertNotNull("设备厂商名称不应为null", info.getIssuerName());
        assertNotNull("设备型号不应为null", info.getDeviceName());
    }

    @Test
    public void testGenerateRandom() throws SDFException {
        requireDevice();
        printTestInfo("生成随机数测试");

        // 生成16字节随机数
        byte[] random16 = sdf.SDF_GenerateRandom(sessionHandle, 16);
        assertNotNull("随机数不应为null", random16);
        assertEquals("随机数长度应为16", 16, random16.length);
        System.out.println("16字节随机数: " + bytesToHex(random16));

        // 生成32字节随机数
        byte[] random32 = sdf.SDF_GenerateRandom(sessionHandle, 32);
        assertNotNull("随机数不应为null", random32);
        assertEquals("随机数长度应为32", 32, random32.length);
        System.out.println("32字节随机数: " + bytesToHex(random32));

        // 验证两次生成的随机数不同
        assertFalse("两次生成的随机数应该不同",
                    bytesToHex(random16).equals(bytesToHex(random32).substring(0, 32)));
    }

    @Test
    public void testGenerateRandomDifferent() throws SDFException {
        requireDevice();
        printTestInfo("验证随机数唯一性测试");

        byte[] random1 = sdf.SDF_GenerateRandom(sessionHandle, 32);
        byte[] random2 = sdf.SDF_GenerateRandom(sessionHandle, 32);

        assertFalse("两次生成的随机数应该不同", bytesToHex(random1).equals(bytesToHex(random2)));
        System.out.println("随机数1: " + bytesToHex(random1));
        System.out.println("随机数2: " + bytesToHex(random2));
    }

    @Test
    public void testMultipleSessions() throws SDFException {
        requireDevice();
        printTestInfo("多会话测试");

        // 创建第二个会话
        long session2 = sdf.SDF_OpenSession(deviceHandle);
        assertNotEquals("第二个会话句柄不应为0", 0, session2);
        assertNotEquals("两个会话句柄应该不同", sessionHandle, session2);

        System.out.println("第一个会话: " + sessionHandle);
        System.out.println("第二个会话: " + session2);

        // 关闭第二个会话
        sdf.SDF_CloseSession(session2);
        System.out.println("成功关闭第二个会话");
    }

    @Test(expected = SDFException.class)
    public void testInvalidSessionHandle() throws SDFException {
        requireDevice();
        printTestInfo("无效会话句柄测试");

        // 使用无效的会话句柄应该抛出异常
        sdf.SDF_GenerateRandom(99999, 16);
    }
}
