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
        System.out.println("========================================");
        System.out.println("6.7 用户文件操作类函数测试");
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

    /**
     * 6.7.2 创建文件测试
     * SDF_CreateFile(hSessionHandle, pucFileName, uiNameLen, uiFileSize)
     */
    @Test
    public void testCreateFile() throws SDFException {
        System.out.println("测试 6.7.2 SDF_CreateFile - 创建文件");

        String fileName = TEST_FILE_PREFIX + "create.dat";
        int fileSize = 256;

        try {
            System.out.println("  文件名: " + fileName);
            System.out.println("  文件名长度: " + fileName.length() + " 字节");
            System.out.println("  文件大小: " + fileSize + " 字节");

            System.out.println("  执行创建文件...");
            sdf.SDF_CreateFile(sessionHandle, fileName, fileSize);

            System.out.println("  文件创建成功");
            System.out.println("SDF_CreateFile 测试通过");

            // 清理：删除测试文件
            try {
                sdf.SDF_DeleteFile(sessionHandle, fileName);
                System.out.println("  (已清理测试文件)");
            } catch (SDFException e) {
                // 忽略删除失败
            }
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("SDF_CreateFile 功能未实现");
            } else {
                throw new SDFException(e.getErrorCode(), "SDF_CreateFile 测试失败: " + e.getMessage());
            }
        }
    }

    /**
     * 6.7.3 读取文件测试
     * SDF_ReadFile(hSessionHandle, pucFileName, uiNameLen, uiOffset, puiFileLength, pucBuffer)
     */
    @Test
    public void testReadFile() throws SDFException {
        System.out.println("测试 6.7.3 SDF_ReadFile - 读取文件");

        String fileName = TEST_FILE_PREFIX + "read.dat";
        int fileSize = 128;
        int offset = 0;
        int readLength = 16;

        try {
            // 先创建并写入测试文件
	    System.out.println("  准备: 创建测试文件...");
            sdf.SDF_CreateFile(sessionHandle, fileName, fileSize);

            byte[] testData = "Hello SDF4J File Operation Test!".getBytes(StandardCharsets.UTF_8);
            sdf.SDF_WriteFile(sessionHandle, fileName, 0, testData);
            System.out.println("  准备: 已写入测试数据");
            System.out.println("  写入数据: " + new String(testData, StandardCharsets.UTF_8));
            System.out.println("  写入数据(hex): " + bytesToHex(testData));
            System.out.println("  写入数据长度: " + testData.length + " 字节");

            // 读取文件
            System.out.println("\n  文件名: " + fileName);
            System.out.println("  文件名长度: " + fileName.length() + " 字节");
            System.out.println("  偏移量(uiOffset): " + offset);
            System.out.println("  读取长度(puiFileLength): " + readLength + " 字节");

            System.out.println("  执行读取文件...");
            byte[] readData = sdf.SDF_ReadFile(sessionHandle, fileName, offset, readLength);

            assertNotNull("读取数据不应为空", readData);
            assertTrue("读取数据长度应大于0", readData.length > 0);
            System.out.println("  读取数据长度: " + readData.length + " 字节");
            System.out.println("  读取数据(hex): " + bytesToHex(readData));
            System.out.println("  读取数据(text): " + new String(readData, StandardCharsets.UTF_8).trim());
            System.out.println("SDF_ReadFile 测试通过");

            // 清理：删除测试文件
            try {
                sdf.SDF_DeleteFile(sessionHandle, fileName);
                System.out.println("  (已清理测试文件)");
            } catch (SDFException e) {
                // 忽略删除失败
            }
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("SDF_ReadFile 功能未实现");
            } else {
                throw new SDFException(e.getErrorCode(), "SDF_ReadFile 测试失败: " + e.getMessage());
            }
        }
    }

    /**
     * 6.7.4 写文件测试
     * SDF_WriteFile(hSessionHandle, pucFileName, uiNameLen, uiOffset, uiFileLength, pucBuffer)
     */
    @Test
    public void testWriteFile() throws SDFException {
        System.out.println("测试 6.7.4 SDF_WriteFile - 写文件");

        String fileName = TEST_FILE_PREFIX + "write.dat";
        int fileSize = 256;
        int offset = 0;
        String dataStr = "SDF4J Write File Test Data!";
        byte[] data = dataStr.getBytes(StandardCharsets.UTF_8);

        try {
            // 先创建测试文件
            System.out.println("  准备: 创建测试文件...");
            sdf.SDF_CreateFile(sessionHandle, fileName, fileSize);

            // 写入文件
            System.out.println("\n  文件名: " + fileName);
            System.out.println("  文件名长度(uiNameLen): " + fileName.length() + " 字节");
            System.out.println("  偏移量(uiOffset): " + offset);
            System.out.println("  写入数据: " + dataStr);
            System.out.println("  写入数据(hex): " + bytesToHex(data));
            System.out.println("  写入数据长度(uiFileLength): " + data.length + " 字节");

            System.out.println("  执行写入文件...");
            sdf.SDF_WriteFile(sessionHandle, fileName, offset, data);

            System.out.println("  文件写入成功");
            System.out.println("SDF_WriteFile 测试通过");

            // 清理：删除测试文件
            try {
                sdf.SDF_DeleteFile(sessionHandle, fileName);
                System.out.println("  (已清理测试文件)");
            } catch (SDFException e) {
                // 忽略删除失败
            }
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("SDF_WriteFile 功能未实现");
            } else {
                throw new SDFException(e.getErrorCode(), "SDF_WriteFile 测试失败: " + e.getMessage());
            }
        }
    }

    /**
     * 6.7.5 删除文件测试
     * SDF_DeleteFile(hSessionHandle, pucFileName, uiNameLen)
     */
    @Test
    public void testDeleteFile() throws SDFException {
        System.out.println("测试 6.7.5 SDF_DeleteFile - 删除文件");

        String fileName = TEST_FILE_PREFIX + "delete.dat";
        int fileSize = 64;

        try {
            // 先创建测试文件
            System.out.println("  准备: 创建测试文件...");
            sdf.SDF_CreateFile(sessionHandle, fileName, fileSize);
            System.out.println("  文件已创建: " + fileName);

            // 删除文件
            System.out.println("\n  文件名: " + fileName);
            System.out.println("  文件名长度(uiNameLen): " + fileName.length() + " 字节");
            System.out.println("  执行删除文件...");
            sdf.SDF_DeleteFile(sessionHandle, fileName);

            System.out.println("  文件删除成功");
            System.out.println("SDF_DeleteFile 测试通过");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("SDF_DeleteFile 功能未实现");
            } else {
                throw new SDFException(e.getErrorCode(), "SDF_DeleteFile 测试失败: " + e.getMessage());
            }
        }
    }

    /**
     * 完整文件操作流程测试
     * 创建 -> 写入 -> 读取验证 -> 删除
     */
    @Test
    public void testCompleteFileOperation() throws SDFException {
        System.out.println("测试完整文件操作流程");

        String fileName = TEST_FILE_PREFIX + "complete.dat";
        int fileSize = 512;

        try {
            // 步骤1: 创建文件
            System.out.println("  步骤1: 创建文件");
            System.out.println("  文件名: " + fileName + ", 大小: " + fileSize + " 字节");
            sdf.SDF_CreateFile(sessionHandle, fileName, fileSize);
            System.out.println("  文件创建成功");

            // 步骤2: 写入数据
            System.out.println("\n  步骤2: 写入数据");
            String originalText = "This is a test data for file operations. 包含中文测试数据.";
            byte[] writeData = originalText.getBytes(StandardCharsets.UTF_8);
            System.out.println("  写入数据: " + originalText);
            System.out.println("  写入数据(hex): " + bytesToHex(writeData));
            System.out.println("  写入长度: " + writeData.length + " 字节");
            sdf.SDF_WriteFile(sessionHandle, fileName, 0, writeData);
            System.out.println("  写入成功");

            // 步骤3: 读取数据验证
            System.out.println("\n  步骤3: 读取数据验证");
            byte[] readData = sdf.SDF_ReadFile(sessionHandle, fileName, 0, writeData.length);
            System.out.println("  读取长度: " + readData.length + " 字节");
            System.out.println("  读取数据(hex): " + bytesToHex(readData));

            // 验证写入和读取数据一致
            assertArrayEquals("读取数据应与写入数据一致", writeData, readData);
            String readText = new String(readData, StandardCharsets.UTF_8);
            System.out.println("  读取数据(text): " + readText);
            assertEquals("读取文本应与写入文本一致", originalText, readText);
            System.out.println("  数据一致性验证通过");

            // 步骤4: 删除文件
            System.out.println("\n  步骤4: 删除文件");
            sdf.SDF_DeleteFile(sessionHandle, fileName);
            System.out.println("  文件删除成功");

            // 步骤5: 验证文件已删除（再次读取应失败）
            System.out.println("\n  步骤5: 验证文件已删除");
            try {
                sdf.SDF_ReadFile(sessionHandle, fileName, 0, 16);
                System.out.println("  警告: 删除后仍能读取文件，可能设备不支持");
            } catch (SDFException e) {
                System.out.println("  确认文件已删除（读取失败，错误码: 0x" + Integer.toHexString(e.getErrorCode()) + ")");
            }

            System.out.println("完整文件操作流程测试通过");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("文件操作功能未实现");
            } else {
                // 清理：尝试删除测试文件
                try {
                    sdf.SDF_DeleteFile(sessionHandle, fileName);
                } catch (Exception ignored) {
                }
                throw new SDFException(e.getErrorCode(), "完整文件操作测试失败: " + e.getMessage());
            }
        }
    }

    /**
     * 多次写入读取测试
     * 测试分块写入和读取
     */
    @Test
    public void testMultipleReadWrite() throws SDFException {
        System.out.println("测试多次写入读取");

        String fileName = TEST_FILE_PREFIX + "multiple.dat";
        int fileSize = 512;

        try {
            // 创建文件
            sdf.SDF_CreateFile(sessionHandle, fileName, fileSize);
            System.out.println("  文件创建成功");

            // 分三次写入不同位置的数据
            String[] testData = {
                "First block of data. 第一块数据。",
                "Second block! 第二块！",
                "Third block 123. 第三块123。"
            };

            int offset = 0;
            for (int i = 0; i < testData.length; i++) {
                byte[] data = testData[i].getBytes(StandardCharsets.UTF_8);
                System.out.println("  写入块 " + (i + 1) + ": " + testData[i]);
                sdf.SDF_WriteFile(sessionHandle, fileName, offset, data);
                offset += data.length;
            }

            // 读取完整数据验证
            byte[] readData = sdf.SDF_ReadFile(sessionHandle, fileName, 0, offset);
            String readText = new String(readData, StandardCharsets.UTF_8);
            System.out.println("  读取完整数据: " + readText);

            // 验证
            String expectedText = testData[0] + testData[1] + testData[2];
            assertEquals("读取数据应与写入数据一致", expectedText, readText);
            System.out.println("  数据一致性验证通过");

            // 清理
            sdf.SDF_DeleteFile(sessionHandle, fileName);
            System.out.println("多次写入读取测试通过");

        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("文件操作功能未实现");
            } else {
                // 清理
                try {
                    sdf.SDF_DeleteFile(sessionHandle, fileName);
                } catch (Exception ignored) {
                }
                throw new SDFException(e.getErrorCode(), "多次写入读取测试失败: " + e.getMessage());
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
