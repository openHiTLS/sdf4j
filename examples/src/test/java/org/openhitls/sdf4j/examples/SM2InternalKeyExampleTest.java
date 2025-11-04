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
 * SM2 内部密钥签名验签测试
 * 演示使用设备内部密钥进行SM2签名和验签操作
 */
public class SM2InternalKeyExampleTest {

    private SDF sdf;
    private long deviceHandle;
    private long sessionHandle;
    private TestConfig config;
    private int keyIndex;
    private String keyPassword;

    @Before
    public void setUp() throws SDFException {
        config = TestConfig.getInstance();
        keyIndex = config.getSM2InternalKeyIndex();
        keyPassword = config.getSM2KeyAccessPassword();

        System.out.println("Test Configuration:");
        System.out.println("  Environment: " + config.getEnvironmentName());
        System.out.println("  Key Index: " + keyIndex);
        System.out.println("  Key Password: " + keyPassword);
        System.out.println();

        sdf = new SDF();
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);
    }

    @After
    public void tearDown() throws SDFException {
        if (sessionHandle != 0) {
            sdf.SDF_CloseSession(sessionHandle);
        }
        if (deviceHandle != 0) {
            sdf.SDF_CloseDevice(deviceHandle);
        }
    }

    /**
     * 测试1: SM2内部密钥签名和验签
     */
    @Test
    public void testSignAndVerify() throws SDFException {
        boolean accessRightObtained = false;
        try {
            // 获取内部密钥访问权限
            try {
                sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, keyIndex, keyPassword);
                accessRightObtained = true;
                System.out.println("成功获取密钥访问权限");
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("设备不需要获取密钥访问权限");
                } else {
                    throw e;
                }
            }

            // 待签名数据
            byte[] data = "重要文档内容".getBytes(StandardCharsets.UTF_8);

            // 计算SM3哈希
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data);
            byte[] hash = sdf.SDF_HashFinal(sessionHandle);

            // 使用内部密钥签名
            ECCSignature signature = sdf.SDF_InternalSign_ECC(sessionHandle, keyIndex, hash);
            assertNotNull("签名不应为空", signature);
            assertNotNull("签名r分量不应为空", signature.getR());
            assertNotNull("签名s分量不应为空", signature.getS());

            // 使用内部密钥验签
            sdf.SDF_InternalVerify_ECC(sessionHandle, keyIndex, hash, signature);

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("设备不支持内部密钥签名/验签功能");
            } else if (e.getErrorCode() == ErrorCode.SDR_KEYNOTEXIST) {
                System.out.println("设备中不存在指定索引的密钥");
            } else {
                throw e;
            }
        } finally {
            // 释放密钥访问权限
            if (accessRightObtained) {
                try {
                    sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, keyIndex);
                    System.out.println("已释放密钥访问权限");
                } catch (SDFException e) {
                    System.out.println("释放密钥访问权限失败: " + e.getMessage());
                }
            }
        }
    }

    /**
     * 测试2: 验证签名的完整性检测
     */
    @Test
    public void testVerifyWithTamperedData() throws SDFException {
        boolean accessRightObtained = false;
        try {
            // 获取内部密钥访问权限
            try {
                sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, keyIndex, keyPassword);
                accessRightObtained = true;
                System.out.println("成功获取密钥访问权限");
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("设备不需要获取密钥访问权限");
                } else {
                    throw e;
                }
            }

            // 原始数据签名
            byte[] data = "原始数据".getBytes(StandardCharsets.UTF_8);
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, data);
            byte[] hash = sdf.SDF_HashFinal(sessionHandle);

            ECCSignature signature = sdf.SDF_InternalSign_ECC(sessionHandle, keyIndex, hash);

            // 篡改数据后验签应失败
            byte[] tamperedData = "篡改数据".getBytes(StandardCharsets.UTF_8);
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, tamperedData);
            byte[] tamperedHash = sdf.SDF_HashFinal(sessionHandle);

            try {
                sdf.SDF_InternalVerify_ECC(sessionHandle, keyIndex, tamperedHash, signature);
                fail("篡改数据验签应该失败");
            } catch (SDFException e) {
                // 验签失败是预期行为
                assertTrue("应该是验签失败错误", e.getErrorCode() != ErrorCode.SDR_OK);
            }

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT
                    || e.getErrorCode() == ErrorCode.SDR_KEYNOTEXIST) {
                // 跳过不支持的功能
            } else {
                throw e;
            }
        } finally {
            // 释放密钥访问权限
            if (accessRightObtained) {
                try {
                    sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, keyIndex);
                    System.out.println("已释放密钥访问权限");
                } catch (SDFException e) {
                    System.out.println("释放密钥访问权限失败: " + e.getMessage());
                }
            }
        }
    }

}
