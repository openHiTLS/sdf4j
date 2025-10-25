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

/**
 * SDF常量定义包
 * SDF Constants Definitions
 *
 * <h2>概述 / Overview</h2>
 * <p>
 * 本包包含SDF接口使用的所有常量定义，包括算法标识符、错误码等。
 * 这些常量严格遵循GM/T 0018-2023标准的定义。
 * </p>
 * <p>
 * This package contains all constant definitions used by SDF interfaces, including
 * algorithm identifiers and error codes. These constants strictly follow the
 * GM/T 0018-2023 standard definitions.
 * </p>
 *
 * <h2>主要类 / Main Classes</h2>
 *
 * <h3>{@link org.openhitls.sdf4j.constants.AlgorithmID} - 算法标识符</h3>
 * <p>
 * 定义了所有支持的密码算法标识符，包括：
 * </p>
 * <ul>
 *     <li><b>对称算法</b>: SM1, SM4, SM7, SSF33, AES (ECB/CBC/OFB/CFB/CTR/GCM模式)</li>
 *     <li><b>非对称算法</b>: RSA, SM2, SM9 (签名、验签、加密、解密、密钥交换)</li>
 *     <li><b>杂凑算法</b>: SM3, SHA-1, SHA-256, SHA-384, SHA-512, MD5</li>
 * </ul>
 * <p>
 * 使用示例：
 * </p>
 * <pre>{@code
 * // 使用SM4-ECB加密
 * int algID = AlgorithmID.SGD_SM4_ECB;
 * byte[] encrypted = sdf.SDF_Encrypt(sessionHandle, keyHandle, algID, null, plaintext);
 *
 * // 检查算法类型
 * if (AlgorithmID.isSymmetricAlgorithm(algID)) {
 *     System.out.println("这是对称算法");
 * }
 *
 * // 获取算法名称
 * String name = AlgorithmID.getAlgorithmName(algID);
 * System.out.println("算法: " + name);
 * }</pre>
 *
 * <h3>{@link org.openhitls.sdf4j.constants.ErrorCode} - 错误码</h3>
 * <p>
 * 定义了所有SDF接口可能返回的错误码，共31个。每个错误码都有对应的中英文说明。
 * </p>
 * <p>
 * 错误码分类：
 * </p>
 * <ul>
 *     <li><b>通用错误</b> (0x01000001-0x01000003): 未知错误、不支持、文件操作错误</li>
 *     <li><b>访问控制错误</b> (0x01000004-0x01000006): 权限错误、密码错误</li>
 *     <li><b>应用接口错误</b> (0x01000007-0x0100000E): 密钥格式、算法类型、句柄错误等</li>
 *     <li><b>设备管理错误</b> (0x0100000F-0x01000013): 设备状态、会话错误等</li>
 *     <li><b>密钥管理错误</b> (0x01000014-0x01000017): 密钥状态、用途错误等</li>
 *     <li><b>算法运算错误</b> (0x01000018-0x0100001E): 数据、参数、缓冲区错误等</li>
 *     <li><b>通信错误</b> (0x0100001F): 通信超时</li>
 * </ul>
 * <p>
 * 使用示例：
 * </p>
 * <pre>{@code
 * try {
 *     long deviceHandle = sdf.SDF_OpenDevice();
 * } catch (SDFException e) {
 *     int errorCode = e.getErrorCode();
 *     String errorMsg = ErrorCode.getErrorMessage(errorCode);
 *     System.err.println("错误: " + errorMsg);
 *
 *     // 检查特定错误
 *     if (errorCode == ErrorCode.SDR_STEPERR) {
 *         System.err.println("步骤错误，请检查调用顺序");
 *     }
 * }
 * }</pre>
 *
 * <h2>算法标识符编码规则 / Algorithm ID Encoding Rules</h2>
 * <p>
 * 算法标识符使用32位整数，编码规则如下：
 * </p>
 * <ul>
 *     <li>位31-24: 算法类别（对称0x00, 非对称0x02, 杂凑0x00等）</li>
 *     <li>位23-16: 算法类型（RSA=0x01, ECC=0x02, SM1=0x01等）</li>
 *     <li>位15-8: 算法模式（ECB=0x01, CBC=0x02等）</li>
 *     <li>位7-0: 填充方式或其他参数</li>
 * </ul>
 * <p>
 * 例如: {@code SGD_SM4_ECB = 0x00000401}
 * </p>
 * <ul>
 *     <li>0x00: 对称算法</li>
 *     <li>0x00: 保留</li>
 *     <li>0x04: SM4算法</li>
 *     <li>0x01: ECB模式</li>
 * </ul>
 *
 * <h2>错误码编码规则 / Error Code Encoding Rules</h2>
 * <p>
 * 错误码基于{@code SDR_BASE = 0x01000000}，所有错误码的高字节为0x01。
 * 错误码0x00000000表示成功（SDR_OK）。
 * </p>
 *
 * <h2>线程安全 / Thread Safety</h2>
 * <p>
 * 所有常量类都是线程安全的，可以在多线程环境中安全使用。
 * </p>
 *
 * @see org.openhitls.sdf4j.SDF
 * @see org.openhitls.sdf4j.SDFException
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
package org.openhitls.sdf4j.constants;
