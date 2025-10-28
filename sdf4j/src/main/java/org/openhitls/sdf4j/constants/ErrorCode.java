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

/**
 * SDF错误码常量定义
 * SDF Error Code Constants (GM/T 0018-2023 Appendix A)
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
public final class ErrorCode {

    private ErrorCode() {
        // 禁止实例化
        throw new AssertionError("No ErrorCode instances for you!");
    }

    // ========================================================================
    // 标准错误码 (Standard Error Codes)
    // ========================================================================

    /**
     * 操作成功
     * Success
     */
    public static final int SDR_OK = 0x00000000;

    /**
     * 错误码基础值
     * Base value for error codes
     */
    public static final int SDR_BASE = 0x01000000;

    /**
     * 未知错误
     * Unknown error
     */
    public static final int SDR_UNKNOWERR = SDR_BASE + 0x00000001;

    /**
     * 不支持的接口调用
     * Unsupported interface
     */
    public static final int SDR_NOTSUPPORT = SDR_BASE + 0x00000002;

    /**
     * 与设备通信失败
     * Communication failure with device
     */
    public static final int SDR_COMMFAIL = SDR_BASE + 0x00000003;

    /**
     * 运算模块无响应
     * Hardware failure/no response from cryptographic module
     */
    public static final int SDR_HARDFAIL = SDR_BASE + 0x00000004;

    /**
     * 打开设备失败
     * Failed to open device
     */
    public static final int SDR_OPENDEVICE = SDR_BASE + 0x00000005;

    /**
     * 创建会话失败
     * Failed to open session
     */
    public static final int SDR_OPENSESSION = SDR_BASE + 0x00000006;

    /**
     * 无私钥使用权限
     * Private key access denied
     */
    public static final int SDR_PARDENY = SDR_BASE + 0x00000007;

    /**
     * 不存在的密钥调用
     * Key does not exist
     */
    public static final int SDR_KEYNOTEXIST = SDR_BASE + 0x00000008;

    /**
     * 不支持的算法调用
     * Algorithm not supported
     */
    public static final int SDR_ALGNOTSUPPORT = SDR_BASE + 0x00000009;

    /**
     * 不支持的算法模式调用
     * Algorithm mode not supported
     */
    public static final int SDR_ALGMODNOTSUPPORT = SDR_BASE + 0x0000000A;

    /**
     * 公钥运算失败
     * Public key operation error
     */
    public static final int SDR_PKOPERR = SDR_BASE + 0x0000000B;

    /**
     * 私钥运算失败
     * Private key operation error
     */
    public static final int SDR_SKOPERR = SDR_BASE + 0x0000000C;

    /**
     * 签名运算失败
     * Sign operation error
     */
    public static final int SDR_SIGNERR = SDR_BASE + 0x0000000D;

    /**
     * 验证签名失败
     * Verify operation error
     */
    public static final int SDR_VERIFYERR = SDR_BASE + 0x0000000E;

    /**
     * 对称算法运算失败
     * Symmetric operation error
     */
    public static final int SDR_SYMOPERR = SDR_BASE + 0x0000000F;

    /**
     * 多步运算步骤错误
     * Multi-step operation sequence error
     */
    public static final int SDR_STEPERR = SDR_BASE + 0x00000010;

    /**
     * 文件长度超出限制
     * File size error
     */
    public static final int SDR_FILESIZEERR = SDR_BASE + 0x00000011;

    /**
     * 指定的文件不存在
     * File does not exist
     */
    public static final int SDR_FILENOEXIST = SDR_BASE + 0x00000012;

    /**
     * 文件起始位置错误
     * File offset error
     */
    public static final int SDR_FILEOFSERR = SDR_BASE + 0x00000013;

    /**
     * 密钥类型错误
     * Key type error
     */
    public static final int SDR_KEYTYPEERR = SDR_BASE + 0x00000014;

    /**
     * 密钥错误
     * Key error
     */
    public static final int SDR_KEYERR = SDR_BASE + 0x00000015;

    /**
     * ECC加密数据错误
     * ECC encrypted data error
     */
    public static final int SDR_ENCDATAERR = SDR_BASE + 0x00000016;

    /**
     * 随机数产生失败
     * Random generation error
     */
    public static final int SDR_RANDERR = SDR_BASE + 0x00000017;

    /**
     * 私钥使用权限获取失败
     * Failed to get private key access right
     */
    public static final int SDR_PRKRERR = SDR_BASE + 0x00000018;

    /**
     * MAC运算失败
     * MAC operation error
     */
    public static final int SDR_MACERR = SDR_BASE + 0x00000019;

    /**
     * 指定文件已存在
     * File already exists
     */
    public static final int SDR_FILEEXISTS = SDR_BASE + 0x0000001A;

    /**
     * 文件写入失败
     * File write error
     */
    public static final int SDR_FILEWERR = SDR_BASE + 0x0000001B;

    /**
     * 存储空间不足
     * Insufficient buffer space
     */
    public static final int SDR_NOBUFFER = SDR_BASE + 0x0000001C;

    /**
     * 输入参数错误
     * Invalid input argument
     */
    public static final int SDR_INARGERR = SDR_BASE + 0x0000001D;

    /**
     * 输出参数错误
     * Invalid output argument
     */
    public static final int SDR_OUTARGERR = SDR_BASE + 0x0000001E;

    /**
     * 用户标识错误
     * User ID error
     */
    public static final int SDR_USERIDERR = SDR_BASE + 0x0000001F;

    // ========================================================================
    // 工具方法 (Utility Methods)
    // ========================================================================

    /**
     * 获取错误信息描述
     *
     * @param errorCode 错误码
     * @return 错误信息字符串
     */
    public static String getErrorMessage(int errorCode) {
        switch (errorCode) {
            case SDR_OK:
                return "操作成功 (Success)";
            case SDR_UNKNOWERR:
                return "未知错误 (Unknown error)";
            case SDR_NOTSUPPORT:
                return "不支持的接口调用 (Unsupported interface)";
            case SDR_COMMFAIL:
                return "与设备通信失败 (Communication failure)";
            case SDR_HARDFAIL:
                return "运算模块无响应 (Hardware failure)";
            case SDR_OPENDEVICE:
                return "打开设备失败 (Failed to open device)";
            case SDR_OPENSESSION:
                return "创建会话失败 (Failed to open session)";
            case SDR_PARDENY:
                return "无私钥使用权限 (Private key access denied)";
            case SDR_KEYNOTEXIST:
                return "不存在的密钥调用 (Key does not exist)";
            case SDR_ALGNOTSUPPORT:
                return "不支持的算法调用 (Algorithm not supported)";
            case SDR_ALGMODNOTSUPPORT:
                return "不支持的算法模式调用 (Algorithm mode not supported)";
            case SDR_PKOPERR:
                return "公钥运算失败 (Public key operation error)";
            case SDR_SKOPERR:
                return "私钥运算失败 (Private key operation error)";
            case SDR_SIGNERR:
                return "签名运算失败 (Sign operation error)";
            case SDR_VERIFYERR:
                return "验证签名失败 (Verify operation error)";
            case SDR_SYMOPERR:
                return "对称算法运算失败 (Symmetric operation error)";
            case SDR_STEPERR:
                return "多步运算步骤错误 (Multi-step operation sequence error)";
            case SDR_FILESIZEERR:
                return "文件长度超出限制 (File size error)";
            case SDR_FILENOEXIST:
                return "指定的文件不存在 (File does not exist)";
            case SDR_FILEOFSERR:
                return "文件起始位置错误 (File offset error)";
            case SDR_KEYTYPEERR:
                return "密钥类型错误 (Key type error)";
            case SDR_KEYERR:
                return "密钥错误 (Key error)";
            case SDR_ENCDATAERR:
                return "ECC加密数据错误 (ECC encrypted data error)";
            case SDR_RANDERR:
                return "随机数产生失败 (Random generation error)";
            case SDR_PRKRERR:
                return "私钥使用权限获取失败 (Failed to get private key access right)";
            case SDR_MACERR:
                return "MAC运算失败 (MAC operation error)";
            case SDR_FILEEXISTS:
                return "指定文件已存在 (File already exists)";
            case SDR_FILEWERR:
                return "文件写入失败 (File write error)";
            case SDR_NOBUFFER:
                return "存储空间不足 (Insufficient buffer space)";
            case SDR_INARGERR:
                return "输入参数错误 (Invalid input argument)";
            case SDR_OUTARGERR:
                return "输出参数错误 (Invalid output argument)";
            case SDR_USERIDERR:
                return "用户标识错误 (User ID error)";
            default:
                return "未知错误码 (Unknown error code): 0x" + Integer.toHexString(errorCode).toUpperCase();
        }
    }

    /**
     * 判断是否为成功状态
     *
     * @param errorCode 错误码
     * @return 如果是成功状态返回true
     */
    public static boolean isSuccess(int errorCode) {
        return errorCode == SDR_OK;
    }

    /**
     * 判断是否为错误状态
     *
     * @param errorCode 错误码
     * @return 如果是错误状态返回true
     */
    public static boolean isError(int errorCode) {
        return errorCode != SDR_OK;
    }
}
