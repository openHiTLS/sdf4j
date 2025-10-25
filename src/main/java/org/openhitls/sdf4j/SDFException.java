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

import org.openhitls.sdf4j.constants.ErrorCode;

/**
 * SDF异常类
 * SDF Exception
 *
 * <p>封装SDF接口调用过程中产生的错误，包含错误码和详细错误信息。
 * This exception wraps errors that occur during SDF interface calls,
 * including error code and detailed error message.
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
public class SDFException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * SDF错误码
     */
    private final int errorCode;

    /**
     * 构造函数 - 使用错误码
     *
     * @param errorCode SDF错误码
     */
    public SDFException(int errorCode) {
        super(ErrorCode.getErrorMessage(errorCode));
        this.errorCode = errorCode;
    }

    /**
     * 构造函数 - 使用错误码和自定义消息
     *
     * @param errorCode SDF错误码
     * @param message   自定义错误消息
     */
    public SDFException(int errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    /**
     * 构造函数 - 使用错误码和原因
     *
     * @param errorCode SDF错误码
     * @param cause     异常原因
     */
    public SDFException(int errorCode, Throwable cause) {
        super(ErrorCode.getErrorMessage(errorCode), cause);
        this.errorCode = errorCode;
    }

    /**
     * 构造函数 - 使用错误码、自定义消息和原因
     *
     * @param errorCode SDF错误码
     * @param message   自定义错误消息
     * @param cause     异常原因
     */
    public SDFException(int errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    /**
     * 获取SDF错误码
     *
     * @return SDF错误码
     */
    public int getErrorCode() {
        return errorCode;
    }

    /**
     * 获取十六进制格式的错误码字符串
     *
     * @return 十六进制错误码字符串（例如：0x01000001）
     */
    public String getErrorCodeHex() {
        return "0x" + String.format("%08X", errorCode);
    }

    /**
     * 判断是否为成功状态
     *
     * @return 如果错误码为SDR_OK返回true
     */
    public boolean isSuccess() {
        return ErrorCode.isSuccess(errorCode);
    }

    /**
     * 重写toString方法，提供更详细的异常信息
     *
     * @return 异常信息字符串
     */
    @Override
    public String toString() {
        return "SDFException{" +
                "errorCode=" + getErrorCodeHex() +
                ", message='" + getMessage() + '\'' +
                '}';
    }
}
