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
import org.openhitls.sdf4j.constants.ErrorCode;

import static org.junit.Assert.*;

/**
 * SDFException类单元测试
 */
public class SDFExceptionTest {

    @Test
    public void testConstructorWithErrorCode() {
        SDFException e = new SDFException(ErrorCode.SDR_UNKNOWERR);
        assertEquals(ErrorCode.SDR_UNKNOWERR, e.getErrorCode());
        assertNotNull(e.getMessage());
    }

    @Test
    public void testConstructorWithErrorCodeAndMessage() {
        String customMessage = "Custom error message";
        SDFException e = new SDFException(ErrorCode.SDR_INARGERR, customMessage);
        assertEquals(ErrorCode.SDR_INARGERR, e.getErrorCode());
        assertEquals(customMessage, e.getMessage());
    }

    @Test
    public void testConstructorWithErrorCodeAndCause() {
        Exception cause = new RuntimeException("Root cause");
        SDFException e = new SDFException(ErrorCode.SDR_COMMFAIL, cause);
        assertEquals(ErrorCode.SDR_COMMFAIL, e.getErrorCode());
        assertEquals(cause, e.getCause());
    }

    @Test
    public void testConstructorWithErrorCodeMessageAndCause() {
        String customMessage = "Custom error with cause";
        Exception cause = new RuntimeException("Root cause");
        SDFException e = new SDFException(ErrorCode.SDR_HARDFAIL, customMessage, cause);

        assertEquals(ErrorCode.SDR_HARDFAIL, e.getErrorCode());
        assertEquals(customMessage, e.getMessage());
        assertEquals(cause, e.getCause());
    }

    @Test
    public void testGetErrorCodeHex() {
        SDFException e = new SDFException(ErrorCode.SDR_UNKNOWERR);
        assertEquals("0x01000001", e.getErrorCodeHex());

        SDFException e2 = new SDFException(ErrorCode.SDR_OK);
        assertEquals("0x00000000", e2.getErrorCodeHex());

        SDFException e3 = new SDFException(ErrorCode.SDR_INARGERR);
        assertEquals("0x0100001D", e3.getErrorCodeHex());
    }

    @Test
    public void testIsSuccess() {
        SDFException successException = new SDFException(ErrorCode.SDR_OK);
        assertTrue(successException.isSuccess());

        SDFException failureException = new SDFException(ErrorCode.SDR_UNKNOWERR);
        assertFalse(failureException.isSuccess());
    }

    @Test
    public void testToString() {
        SDFException e = new SDFException(ErrorCode.SDR_INARGERR, "Invalid argument");
        String str = e.toString();

        assertTrue(str.contains("SDFException"));
        assertTrue(str.contains("0x0100001D"));
        assertTrue(str.contains("Invalid argument"));
    }

    @Test
    public void testSerializable() {
        // 验证SDFException是可序列化的
        SDFException e = new SDFException(ErrorCode.SDR_UNKNOWERR);
        assertTrue(e instanceof java.io.Serializable);
    }
}
