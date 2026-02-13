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

import org.junit.After;
import org.junit.Before;
import org.junit.Assume;

/**
 * SDF测试基类
 *
 * 提供测试的基础设施和通用方法
 */
public abstract class BaseSDFTest {

    protected SDF sdf;
    protected long deviceHandle;
    protected long sessionHandle;
    protected boolean deviceAvailable;

    @Before
    public void setUp() throws Exception {
        deviceAvailable = false;

        try {
            sdf = new SDF();
            // 尝试打开设备
            deviceHandle = sdf.SDF_OpenDevice();
            sessionHandle = sdf.SDF_OpenSession(deviceHandle);
            deviceAvailable = true;
        } catch (UnsatisfiedLinkError e) {
            System.out.println("SDF库未加载，跳过需要设备的测试: " + e.getMessage());
        } catch (SDFException e) {
            System.out.println("SDF设备不可用，跳过需要设备的测试: " + e.getMessage());
        }
    }

    @After
    public void tearDown() throws Exception {
        if (deviceAvailable && sdf != null) {
            try {
                if (sessionHandle != 0) {
                    sdf.SDF_CloseSession(sessionHandle);
                }
                if (deviceHandle != 0) {
                    sdf.SDF_CloseDevice(deviceHandle);
                }
            } catch (SDFException e) {
                System.err.println("关闭设备失败: " + e.getMessage());
            }
        }
    }

    /**
     * 要求设备可用，如果设备不可用则跳过测试
     */
    protected void requireDevice() {
        Assume.assumeTrue("需要SDF设备才能运行此测试", deviceAvailable);
    }

    /**
     * 字节数组转十六进制字符串
     */
    protected String bytesToHex(byte[] bytes) {
        if (bytes == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * 十六进制字符串转字节数组
     */
    protected byte[] hexToBytes(String hex) {
        if (hex == null || hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Invalid hex string");
        }
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
