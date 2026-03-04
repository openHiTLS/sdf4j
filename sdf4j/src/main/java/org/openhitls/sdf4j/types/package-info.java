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
 * SDF数据类型定义包
 * SDF Data Type Definitions
 *
 * <h2>概述 / Overview</h2>
 * <p>
 * 本包包含所有SDF接口使用的Java数据类型，这些类型对应于GM/T 0018-2023标准中定义的C语言结构体。
 * 每个Java类都提供了与C结构体之间的双向转换功能。
 * </p>
 * <p>
 * This package contains all Java data types used by SDF interfaces, corresponding to C language
 * structures defined in the GM/T 0018-2023 standard. Each Java class provides bidirectional
 * conversion with C structures.
 * </p>
 *
 * <h2>主要类型 / Main Types</h2>
 *
 * <h3>设备信息 / Device Information</h3>
 * <ul>
 *     <li>{@link org.openhitls.sdf4j.types.DeviceInfo} - 设备信息，包含厂商、型号、版本、能力等</li>
 * </ul>
 *
 * <h3>RSA密钥类型 / RSA Key Types</h3>
 * <ul>
 *     <li>{@link org.openhitls.sdf4j.types.RSAPublicKey} - RSA公钥（模数n和指数e）</li>
 *     <li>{@link org.openhitls.sdf4j.types.RSAPrivateKey} - RSA私钥（模数n、公钥指数e、私钥指数d）</li>
 * </ul>
 * <p>
 * RSA密钥支持最大4096位密钥长度。
 * </p>
 *
 * <h3>ECC密钥类型 / ECC Key Types</h3>
 * <ul>
 *     <li>{@link org.openhitls.sdf4j.types.ECCPublicKey} - ECC公钥（椭圆曲线点坐标x和y）</li>
 *     <li>{@link org.openhitls.sdf4j.types.ECCPrivateKey} - ECC私钥（私钥值d）</li>
 *     <li>{@link org.openhitls.sdf4j.types.ECCSignature} - ECC签名值（签名分量r和s）</li>
 *     <li>{@link org.openhitls.sdf4j.types.ECCCipher} - ECC加密密文（包含点坐标、MAC和密文数据）</li>
 * </ul>
 * <p>
 * ECC类型支持最大512位密钥长度，适用于SM2等国密算法。
 * </p>
 *
 * <h3>混合后量子类型 / Hybrid Post-Quantum Types</h3>
 * <ul>
 *     <li>{@link org.openhitls.sdf4j.types.HybridCipher} - Hybrid cipher combining PQC (ML-KEM) and classical (SM2) ciphertext</li>
 *     <li>{@link org.openhitls.sdf4j.types.HybridSignature} - Composite signature combining PQC (ML-DSA) and classical (SM2) signatures</li>
 * </ul>
 *
 * <h3>计算返回结果类型 / Operation Result Types</h3>
 * <ul>
 *     <li>{@link org.openhitls.sdf4j.types.KeyEncryptionResult} - RSA-based session key generation result (encrypted key + handle)</li>
 *     <li>{@link org.openhitls.sdf4j.types.ECCKeyEncryptionResult} - ECC-based session key generation result (cipher + handle)</li>
 *     <li>{@link org.openhitls.sdf4j.types.KeyAgreementResult} - Key agreement result (handle + public keys)</li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 *
 * <h3>获取并显示设备信息</h3>
 * <pre>{@code
 * SDF sdf = new SDF();
 * long deviceHandle = sdf.SDF_OpenDevice();
 * long sessionHandle = sdf.SDF_OpenSession(deviceHandle);
 *
 * DeviceInfo info = sdf.SDF_GetDeviceInfo(sessionHandle);
 * System.out.println("厂商: " + info.getIssuerName());
 * System.out.println("型号: " + info.getDeviceName());
 * System.out.println("序列号: " + info.getDeviceSerial());
 * System.out.println("版本: " + info.getDeviceVersion());
 *
 * sdf.SDF_CloseSession(sessionHandle);
 * sdf.SDF_CloseDevice(deviceHandle);
 * }</pre>
 *
 * <h3>导出ECC公钥</h3>
 * <pre>{@code
 * SDF sdf = new SDF();
 * long sessionHandle = ...;  // 已打开的会话
 *
 * // 导出签名公钥
 * ECCPublicKey pubKey = sdf.SDF_ExportSignPublicKey_ECC(sessionHandle, 1);
 * System.out.println("密钥位数: " + pubKey.getBits());
 * System.out.println("X坐标: " + bytesToHex(pubKey.getX()));
 * System.out.println("Y坐标: " + bytesToHex(pubKey.getY()));
 * }</pre>
 *
 * <h3>ECC签名和验签</h3>
 * <pre>{@code
 * SDF sdf = new SDF();
 * long sessionHandle = ...;
 * byte[] data = "Hello World".getBytes();
 *
 * // 内部私钥签名
 * ECCSignature signature = sdf.SDF_InternalSign_ECC(sessionHandle, 1, data);
 * System.out.println("签名r: " + bytesToHex(signature.getR()));
 * System.out.println("签名s: " + bytesToHex(signature.getS()));
 *
 * // 内部公钥验签
 * sdf.SDF_InternalVerify_ECC(sessionHandle, 1, data, signature);
 * System.out.println("验签成功");
 * }</pre>
 *
 * <h2>数据转换注意事项 / Data Conversion Notes</h2>
 * <ul>
 *     <li>所有字节数组在Java中使用{@code byte[]}表示，对应C中的{@code BYTE*}</li>
 *     <li>字符串字段会自动去除尾部的NULL字符</li>
 *     <li>数值类型严格按照标准定义的位数进行转换</li>
 *     <li>所有类型都是不可变的（immutable），线程安全</li>
 * </ul>
 *
 * <h2>内存管理 / Memory Management</h2>
 * <p>
 * Java对象的内存由JVM自动管理。在JNI层，所有临时分配的C内存都会被正确释放，
 * 不会造成内存泄漏。敏感数据（如私钥、密码）在使用后会被清零。
 * </p>
 *
 * @see org.openhitls.sdf4j.SDF
 * @see org.openhitls.sdf4j.constants.AlgorithmID
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
package org.openhitls.sdf4j.types;
