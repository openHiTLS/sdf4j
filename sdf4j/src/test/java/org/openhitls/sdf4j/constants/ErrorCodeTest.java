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

package org.openhitls.sdf4j.constants;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * ErrorCode类单元测试
 */
public class ErrorCodeTest {

    @Test
    public void testSuccessCode() {
        assertEquals(0x00000000, ErrorCode.SDR_OK);
        assertTrue(ErrorCode.isSuccess(ErrorCode.SDR_OK));
        assertFalse(ErrorCode.isSuccess(ErrorCode.SDR_UNKNOWERR));
    }

    @Test
    public void testErrorMessages() {
        // 测试成功消息
        String okMsg = ErrorCode.getErrorMessage(ErrorCode.SDR_OK);
        assertNotNull(okMsg);
        assertTrue(okMsg.contains("成功") || okMsg.contains("success"));

        // 测试错误消息
        String unknownMsg = ErrorCode.getErrorMessage(ErrorCode.SDR_UNKNOWERR);
        assertNotNull(unknownMsg);
        assertFalse(unknownMsg.isEmpty());

        // 测试未知错误码
        String invalidMsg = ErrorCode.getErrorMessage(0x99999999);
        assertNotNull(invalidMsg);
        assertTrue(invalidMsg.contains("未知") || invalidMsg.contains("Unknown"));
    }

    @Test
    public void testAllDefinedErrorCodes() {
        // 测试所有定义的错误码都有对应的消息
        int[] errorCodes = {
            ErrorCode.SDR_OK,
            ErrorCode.SDR_UNKNOWERR,
            ErrorCode.SDR_NOTSUPPORT,
            ErrorCode.SDR_COMMFAIL,
            ErrorCode.SDR_HARDFAIL,
            ErrorCode.SDR_OPENDEVICE,
            ErrorCode.SDR_OPENSESSION,
            ErrorCode.SDR_ALGNOTSUPPORT,
            ErrorCode.SDR_KEYNOTEXIST,
            ErrorCode.SDR_INARGERR
        };

        for (int code : errorCodes) {
            String msg = ErrorCode.getErrorMessage(code);
            assertNotNull("错误码 0x" + Integer.toHexString(code) + " 应该有错误消息", msg);
            assertFalse("错误码 0x" + Integer.toHexString(code) + " 的错误消息不应为空", msg.isEmpty());
        }
    }

    @Test
    public void testErrorCodeConstants() {
        // 验证错误码常量的值
        assertEquals(0x00000000, ErrorCode.SDR_OK);
        assertEquals(0x01000001, ErrorCode.SDR_UNKNOWERR);
        assertEquals(0x01000002, ErrorCode.SDR_NOTSUPPORT);
        assertEquals(0x0100001D, ErrorCode.SDR_INARGERR);
    }
}
