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
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.openhitls.sdf4j.*;
import org.openhitls.sdf4j.constants.ErrorCode;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

/**
 * 6.7节 用户文件操作类函数测试
 * User File Operation Functions Test (GM/T 0018-2023 Section 6.7)
 *
 * 本测试文件包含以下函数的测试用例：
 * This file contains test cases for the following functions:
 * - SDF_CreateFile (6.7.2) - 创建文件
 * - SDF_ReadFile (6.7.3) - 读取文件
 * - SDF_WriteFile (6.7.4) - 写文件
 * - SDF_DeleteFile (6.7.5) - 删除文件
 */
public class FileOperationTest {

    private SDF sdf;
    private long deviceHandle;
    private long sessionHandle;

    // 测试文件名前缀
    private static final String TEST_FILE_PREFIX = "sdf4j_test_";

    @Before
    public void setUp() throws SDFException {
        sdf = new SDF();
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);
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
        } catch (SDFException e) {
            System.err.println("关闭资源失败: " + e.getMessage());
        }
    }

    /**
     * 6.7.2 创建文件测试
     * SDF_CreateFile(hSessionHandle, pucFileName, uiNameLen, uiFileSize)
     */
    @Test
    public void testCreateFile() throws SDFException {
        String fileName = TEST_FILE_PREFIX + "create.dat";
        int fileSize = 256;

        try {

            sdf.SDF_CreateFile(sessionHandle, fileName, fileSize);


            // 清理：删除测试文件
            try {
                sdf.SDF_DeleteFile(sessionHandle, fileName);
            } catch (SDFException e) {
                // 忽略删除失败
            }
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SDF_CreateFile 功能未实现");
                Assume.assumeTrue("SDF_CreateFile 功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        }
    }

    /**
     * 6.7.3 读取文件测试
     * SDF_ReadFile(hSessionHandle, pucFileName, uiNameLen, uiOffset, puiFileLength, pucBuffer)
     */
    @Test
    public void testReadFile() throws SDFException {
        String fileName = TEST_FILE_PREFIX + "read.dat";
        int fileSize = 128;
        int offset = 0;
        int readLength = 16;

        try {
            // 先创建并写入测试文件
            sdf.SDF_CreateFile(sessionHandle, fileName, fileSize);

            byte[] testData = "Hello SDF4J File Operation Test!".getBytes(StandardCharsets.UTF_8);
            sdf.SDF_WriteFile(sessionHandle, fileName, 0, testData);

            // 读取文件

            byte[] readData = sdf.SDF_ReadFile(sessionHandle, fileName, offset, readLength);

            assertNotNull("读取数据不应为空", readData);
            assertTrue("读取数据长度应大于0", readData.length > 0);

            // 清理：删除测试文件
            try {
                sdf.SDF_DeleteFile(sessionHandle, fileName);
            } catch (SDFException e) {
                // 忽略删除失败
            }
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SDF_ReadFile 功能未实现");
                Assume.assumeTrue("SDF_ReadFile 功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        }
    }

    /**
     * 6.7.4 写文件测试
     * SDF_WriteFile(hSessionHandle, pucFileName, uiNameLen, uiOffset, uiFileLength, pucBuffer)
     */
    @Test
    public void testWriteFile() throws SDFException {
        String fileName = TEST_FILE_PREFIX + "write.dat";
        int fileSize = 256;
        int offset = 0;
        String dataStr = "SDF4J Write File Test Data!";
        byte[] data = dataStr.getBytes(StandardCharsets.UTF_8);

        try {
            // 先创建测试文件
            sdf.SDF_CreateFile(sessionHandle, fileName, fileSize);

            // 写入文件
            sdf.SDF_WriteFile(sessionHandle, fileName, offset, data);
            // 清理：删除测试文件
            try {
                sdf.SDF_DeleteFile(sessionHandle, fileName);
            } catch (SDFException e) {
                // 忽略删除失败
            }
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SDF_WriteFile 功能未实现");
                Assume.assumeTrue("SDF_WriteFile 功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        }
    }

    /**
     * 6.7.5 删除文件测试
     * SDF_DeleteFile(hSessionHandle, pucFileName, uiNameLen)
     */
    @Test
    public void testDeleteFile() throws SDFException {
        String fileName = TEST_FILE_PREFIX + "delete.dat";
        int fileSize = 64;

        try {
            // 先创建测试文件
            sdf.SDF_CreateFile(sessionHandle, fileName, fileSize);

            // 删除文件
            sdf.SDF_DeleteFile(sessionHandle, fileName);


        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] SDF_DeleteFile 功能未实现");
                Assume.assumeTrue("SDF_DeleteFile 功能未实现", false);
            } else {
                System.out.println(e.getMessage());
                throw e;
            }
        }
    }

    /**
     * 完整文件操作流程测试
     * 创建 -> 写入 -> 读取验证 -> 删除
     */
    @Test
    public void testCompleteFileOperation() throws SDFException {
        String fileName = TEST_FILE_PREFIX + "complete.dat";
        int fileSize = 512;

        try {
            // 步骤1: 创建文件
            sdf.SDF_CreateFile(sessionHandle, fileName, fileSize);

            // 步骤2: 写入数据
            String originalText = "This is a test data for file operations. 包含中文测试数据.";
            byte[] writeData = originalText.getBytes(StandardCharsets.UTF_8);
            sdf.SDF_WriteFile(sessionHandle, fileName, 0, writeData);

            // 步骤3: 读取数据验证
            byte[] readData = sdf.SDF_ReadFile(sessionHandle, fileName, 0, writeData.length);

            // 验证写入和读取数据一致
            assertArrayEquals("读取数据应与写入数据一致", writeData, readData);
            String readText = new String(readData, StandardCharsets.UTF_8);
            assertEquals("读取文本应与写入文本一致", originalText, readText);

            // 步骤4: 删除文件
            sdf.SDF_DeleteFile(sessionHandle, fileName);

            // 步骤5: 验证文件已删除（再次读取应失败）
            try {
                sdf.SDF_ReadFile(sessionHandle, fileName, 0, 16);
                fail("删除后文件应该无法读取");
            } catch (SDFException e) {
                // Expected - file should not exist after deletion
            }


        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 文件操作功能未实现");
                Assume.assumeTrue("文件操作功能未实现", false);
            } else {
                // 清理：尝试删除测试文件
                try {
                    sdf.SDF_DeleteFile(sessionHandle, fileName);
                } catch (Exception ignored) {
                }
                System.out.println(e.getMessage());
                throw e;
            }
        }
    }

    /**
     * 多次写入读取测试
     * 测试分块写入和读取
     */
    @Test
    public void testMultipleReadWrite() throws SDFException {
        String fileName = TEST_FILE_PREFIX + "multiple.dat";
        int fileSize = 512;

        try {
            // 创建文件
            sdf.SDF_CreateFile(sessionHandle, fileName, fileSize);

            // 分三次写入不同位置的数据
            String[] testData = {
                "First block of data. 第一块数据。",
                "Second block! 第二块！",
                "Third block 123. 第三块123。"
            };

            int offset = 0;
            for (int i = 0; i < testData.length; i++) {
                byte[] data = testData[i].getBytes(StandardCharsets.UTF_8);
                sdf.SDF_WriteFile(sessionHandle, fileName, offset, data);
                offset += data.length;
            }

            // 读取完整数据验证
            byte[] readData = sdf.SDF_ReadFile(sessionHandle, fileName, 0, offset);
            String readText = new String(readData, StandardCharsets.UTF_8);

            // 验证
            String expectedText = testData[0] + testData[1] + testData[2];
            assertEquals("读取数据应与写入数据一致", expectedText, readText);

            // 清理
            sdf.SDF_DeleteFile(sessionHandle, fileName);

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("[跳过] 文件操作功能未实现");
                Assume.assumeTrue("文件操作功能未实现", false);
            } else {
                // 清理
                try {
                    sdf.SDF_DeleteFile(sessionHandle, fileName);
                } catch (Exception ignored) {
                }
                System.out.println(e.getMessage());
                throw e;
            }
        }
    }

    // ========================================================================
    // 辅助方法
    // ========================================================================

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
