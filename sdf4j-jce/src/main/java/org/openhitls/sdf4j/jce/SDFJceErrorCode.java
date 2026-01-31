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

package org.openhitls.sdf4j.jce;

/**
 * SDF错误码常量定义 (GM/T 0018-2023 附录A)
 * SDF Error Code Constants (GM/T 0018-2023 Appendix A)
 *
 * <p>sdf4j-jce 自包含的错误码定义，不依赖 sdf4j 模块。
 * 错误码值与 GM/T 0018-2023 标准一致。</p>
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
public final class SDFJceErrorCode {

    private SDFJceErrorCode() {
        throw new AssertionError("No SDFJceErrorCode instances for you!");
    }

    // ========================================================================
    // 标准错误码 (Standard Error Codes)
    // ========================================================================

    /** 操作成功 (Success) */
    public static final int SDR_OK = 0x00000000;

    /** 错误码基础值 (Base value for error codes) */
    public static final int SDR_BASE = 0x01000000;

    /** 未知错误 (Unknown error) */
    public static final int SDR_UNKNOWERR = SDR_BASE + 0x00000001;

    /** 不支持的接口调用 (Unsupported interface) */
    public static final int SDR_NOTSUPPORT = SDR_BASE + 0x00000002;

    /** 与设备通信失败 (Communication failure with device) */
    public static final int SDR_COMMFAIL = SDR_BASE + 0x00000003;

    /** 运算模块无响应 (Hardware failure/no response from cryptographic module) */
    public static final int SDR_HARDFAIL = SDR_BASE + 0x00000004;

    /** 打开设备失败 (Failed to open device) */
    public static final int SDR_OPENDEVICE = SDR_BASE + 0x00000005;

    /** 创建会话失败 (Failed to open session) */
    public static final int SDR_OPENSESSION = SDR_BASE + 0x00000006;

    /** 无私钥使用权限 (Private key access denied) */
    public static final int SDR_PARDENY = SDR_BASE + 0x00000007;

    /** 不存在的密钥调用 (Key does not exist) */
    public static final int SDR_KEYNOTEXIST = SDR_BASE + 0x00000008;

    /** 不支持的算法调用 (Algorithm not supported) */
    public static final int SDR_ALGNOTSUPPORT = SDR_BASE + 0x00000009;

    /** 不支持的算法模式调用 (Algorithm mode not supported) */
    public static final int SDR_ALGMODNOTSUPPORT = SDR_BASE + 0x0000000A;

    /** 公钥运算失败 (Public key operation error) */
    public static final int SDR_PKOPERR = SDR_BASE + 0x0000000B;

    /** 私钥运算失败 (Private key operation error) */
    public static final int SDR_SKOPERR = SDR_BASE + 0x0000000C;

    /** 签名运算失败 (Sign operation error) */
    public static final int SDR_SIGNERR = SDR_BASE + 0x0000000D;

    /** 验证签名失败 (Verify operation error) */
    public static final int SDR_VERIFYERR = SDR_BASE + 0x0000000E;

    /** 对称算法运算失败 (Symmetric operation error) */
    public static final int SDR_SYMOPERR = SDR_BASE + 0x0000000F;

    /** 多步运算步骤错误 (Multi-step operation sequence error) */
    public static final int SDR_STEPERR = SDR_BASE + 0x00000010;

    /** 文件长度超出限制 (File size error) */
    public static final int SDR_FILESIZEERR = SDR_BASE + 0x00000011;

    /** 指定的文件不存在 (File does not exist) */
    public static final int SDR_FILENOEXIST = SDR_BASE + 0x00000012;

    /** 文件起始位置错误 (File offset error) */
    public static final int SDR_FILEOFSERR = SDR_BASE + 0x00000013;

    /** 密钥类型错误 (Key type error) */
    public static final int SDR_KEYTYPEERR = SDR_BASE + 0x00000014;

    /** 密钥错误 (Key error) */
    public static final int SDR_KEYERR = SDR_BASE + 0x00000015;

    /** ECC加密数据错误 (ECC encrypted data error) */
    public static final int SDR_ENCDATAERR = SDR_BASE + 0x00000016;

    /** 随机数产生失败 (Random generation error) */
    public static final int SDR_RANDERR = SDR_BASE + 0x00000017;

    /** 私钥使用权限获取失败 (Failed to get private key access right) */
    public static final int SDR_PRKRERR = SDR_BASE + 0x00000018;

    /** MAC运算失败 (MAC operation error) */
    public static final int SDR_MACERR = SDR_BASE + 0x00000019;

    /** 指定文件已存在 (File already exists) */
    public static final int SDR_FILEEXISTS = SDR_BASE + 0x0000001A;

    /** 文件写入失败 (File write error) */
    public static final int SDR_FILEWERR = SDR_BASE + 0x0000001B;

    /** 存储空间不足 (Insufficient buffer space) */
    public static final int SDR_NOBUFFER = SDR_BASE + 0x0000001C;

    /** 输入参数错误 (Invalid input argument) */
    public static final int SDR_INARGERR = SDR_BASE + 0x0000001D;

    /** 输出参数错误 (Invalid output argument) */
    public static final int SDR_OUTARGERR = SDR_BASE + 0x0000001E;

    /** 用户标识错误 (User ID error) */
    public static final int SDR_USERIDERR = SDR_BASE + 0x0000001F;

    /** 缓冲区长度不足 (Short buffer) */
    public static final int SDR_SHORT_BUFFER = SDR_BASE + 0x00000021;

    /** 自测试失败 (Self test error) */
    public static final int SDR_SELFTESTERR = SDR_BASE + 0x00000022;

    /** 设备繁忙 (Device busy) */
    public static final int SDR_BUSY = SDR_BASE + 0x10000001;

    /** 密码重复 (Duplicate password) */
    public static final int SDR_DUPLIPWD = SDR_BASE + 0x00A00001;
}
