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
 * SDF4J - Java接口封装库，用于GM/T 0018-2023密码设备应用接口规范
 * SDF4J - Java wrapper library for GM/T 0018-2023 Cryptographic Device Application Interface Specification
 *
 * <h2>概述 / Overview</h2>
 * <p>
 * SDF4J是OpenHitls项目的子项目，提供符合中国国家密码管理局发布的《GM/T 0018-2023 密码设备应用接口规范》
 * 的Java语言封装。该规范定义了应用程序访问密码设备的标准接口，支持国密SM2、SM3、SM4等算法。
 * </p>
 * <p>
 * SDF4J is a subproject of OpenHitls that provides Java language bindings for the "GM/T 0018-2023
 * Cryptographic Device Application Interface Specification" published by China's State Cryptography
 * Administration. This specification defines standard interfaces for applications to access cryptographic
 * devices, supporting Chinese national cryptographic algorithms such as SM2, SM3, and SM4.
 * </p>
 *
 * <h2>主要功能 / Key Features</h2>
 * <ul>
 *     <li><b>设备管理</b> - 设备打开/关闭、会话管理、设备信息查询 / Device open/close, session management, device info query</li>
 *     <li><b>密钥管理</b> - RSA/ECC公钥导出、密钥句柄管理 / RSA/ECC public key export, key handle management</li>
 *     <li><b>非对称算法</b> - SM2/RSA签名验签、ECC加密 / SM2/RSA signature/verification, ECC encryption</li>
 *     <li><b>对称算法</b> - SM4/AES加解密、MAC计算 / SM4/AES encryption/decryption, MAC calculation</li>
 *     <li><b>杂凑算法</b> - SM3/SHA哈希计算 / SM3/SHA hash calculation</li>
 * </ul>
 *
 * <h2>快速开始 / Quick Start</h2>
 * <pre>{@code
 * // 1. 加载本地库
 * NativeLibraryLoader.loadLibrary();
 *
 * // 2. 创建SDF实例
 * SDF sdf = new SDF();
 *
 * // 3. 打开设备并创建会话
 * long deviceHandle = sdf.SDF_OpenDevice();
 * long sessionHandle = sdf.SDF_OpenSession(deviceHandle);
 *
 * // 4. 使用密码功能
 * DeviceInfo info = sdf.SDF_GetDeviceInfo(sessionHandle);
 * System.out.println("设备型号: " + info.getDeviceName());
 *
 * byte[] random = sdf.SDF_GenerateRandom(sessionHandle, 32);
 * System.out.println("随机数长度: " + random.length);
 *
 * // 5. 关闭会话和设备
 * sdf.SDF_CloseSession(sessionHandle);
 * sdf.SDF_CloseDevice(deviceHandle);
 * }</pre>
 *
 * <h2>依赖要求 / Dependencies</h2>
 * <ul>
 *     <li>Java 8 或更高版本 / Java 8 or higher</li>
 *     <li>SDF native library (libsdfx.so) - 符合GM/T 0018-2023标准的密码设备库</li>
 *     <li>libsdf4j-jni.so - JNI桥接库 / JNI bridge library</li>
 * </ul>
 *
 * <h2>配置 / Configuration</h2>
 * <p>
 * 可通过以下方式配置SDF库路径：
 * </p>
 * <ol>
 *     <li>Java系统属性: {@code -Dsdf4j.library.path=/path/to/libsdfx.so}</li>
 *     <li>配置文件: src/main/resources/sdf4j.properties</li>
 *     <li>环境变量: {@code SDF_LIBRARY_PATH}</li>
 *     <li>默认搜索路径: /usr/lib, /usr/local/lib</li>
 * </ol>
 *
 * <h2>线程安全 / Thread Safety</h2>
 * <p>
 * SDF接口的线程安全性取决于底层密码设备的实现。建议在多线程环境中：
 * </p>
 * <ul>
 *     <li>每个线程使用独立的会话句柄 / Each thread uses its own session handle</li>
 *     <li>对共享资源进行适当的同步 / Properly synchronize shared resources</li>
 *     <li>及时关闭不再使用的句柄 / Close handles when no longer needed</li>
 * </ul>
 *
 * <h2>异常处理 / Exception Handling</h2>
 * <p>
 * 所有SDF接口方法在发生错误时抛出{@link org.openhitls.sdf4j.SDFException}，
 * 异常中包含详细的错误码和错误消息。
 * </p>
 * <pre>{@code
 * try {
 *     long deviceHandle = sdf.SDF_OpenDevice();
 * } catch (SDFException e) {
 *     System.err.println("错误码: " + e.getErrorCodeHex());
 *     System.err.println("错误信息: " + e.getMessage());
 * }
 * }</pre>
 *
 * <h2>许可证 / License</h2>
 * <p>
 * SDF4J使用木兰宽松许可证第2版（Mulan PSL v2）
 * </p>
 *
 * @see org.openhitls.sdf4j.SDF
 * @see org.openhitls.sdf4j.SDFException
 * @see org.openhitls.sdf4j.constants.AlgorithmID
 * @see org.openhitls.sdf4j.constants.ErrorCode
 *
 * @author OpenHitls Team
 * @since 1.0.0
 * @version 1.0.0
 */
package org.openhitls.sdf4j;
