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
 * SDF内部实现包
 * SDF Internal Implementation
 *
 * <h2>概述 / Overview</h2>
 * <p>
 * 本包包含SDF4J的内部实现细节，包括本地库加载、JNI桥接等。
 * 该包中的类通常不需要应用程序直接使用。
 * </p>
 * <p>
 * This package contains internal implementation details of SDF4J, including native
 * library loading and JNI bridging. Classes in this package are typically not used
 * directly by applications.
 * </p>
 *
 * <h2>主要类 / Main Classes</h2>
 *
 * <h3>{@link org.openhitls.sdf4j.internal.NativeLibraryLoader} - 本地库加载器</h3>
 * <p>
 * 负责加载SDF本地库（libsdfx.so）和JNI桥接库（libsdf4j-jni.so）。
 * 支持多种配置方式：
 * </p>
 * <ol>
 *     <li><b>Java系统属性</b>: {@code -Dsdf4j.library.path=/path/to/libsdfx.so}</li>
 *     <li><b>配置文件</b>: src/main/resources/sdf4j.properties</li>
 *     <li><b>环境变量</b>: {@code SDF_LIBRARY_PATH}</li>
 *     <li><b>默认路径</b>: /usr/lib, /usr/local/lib, /lib</li>
 * </ol>
 *
 * <h2>库加载流程 / Library Loading Process</h2>
 * <ol>
 *     <li>首次使用SDF类时，静态初始化块自动调用{@code NativeLibraryLoader.loadLibrary()}</li>
 *     <li>加载器首先加载JNI桥接库（libsdf4j-jni.so）</li>
 *     <li>然后通过JNI调用动态加载SDF本地库（libsdfx.so）</li>
 *     <li>如果加载失败，抛出{@code UnsatisfiedLinkError}或{@code RuntimeException}</li>
 * </ol>
 *
 * <h2>平台支持 / Platform Support</h2>
 * <p>
 * 当前版本支持以下平台：
 * </p>
 * <ul>
 *     <li>Linux x86_64</li>
 *     <li>Linux aarch64</li>
 * </ul>
 * <p>
 * 库加载器会自动检测操作系统和架构，加载对应的本地库。
 * </p>
 *
 * <h2>调试 / Debugging</h2>
 * <p>
 * 可以通过设置配置属性启用调试模式：
 * </p>
 * <pre>
 * debug=true
 * </pre>
 * <p>
 * 调试模式下会输出详细的库加载日志。
 * </p>
 *
 * <h2>故障排除 / Troubleshooting</h2>
 *
 * <h3>UnsatisfiedLinkError</h3>
 * <p>
 * 如果遇到{@code UnsatisfiedLinkError}，请检查：
 * </p>
 * <ul>
 *     <li>JNI库（libsdf4j-jni.so）是否在java.library.path中</li>
 *     <li>JNI库的架构是否与JVM匹配（32位/64位）</li>
 *     <li>是否有足够的文件访问权限</li>
 * </ul>
 *
 * <h3>SDF库加载失败</h3>
 * <p>
 * 如果SDF库加载失败，请检查：
 * </p>
 * <ul>
 *     <li>SDF库文件（libsdfx.so）是否存在于配置的路径中</li>
 *     <li>SDF库的依赖库是否都已安装</li>
 *     <li>可以使用{@code ldd libsdfx.so}检查依赖</li>
 * </ul>
 *
 * <h2>安全注意事项 / Security Notes</h2>
 * <ul>
 *     <li>确保本地库来自可信来源，避免加载恶意库</li>
 *     <li>在生产环境中，建议将库安装到系统标准路径</li>
 *     <li>不要在不受信任的环境中使用用户指定的库路径</li>
 * </ul>
 *
 * <h2>使用示例 / Usage Example</h2>
 * <p>
 * 通常情况下，应用程序不需要直接使用本包中的类。SDF类会自动处理库加载：
 * </p>
 * <pre>{@code
 * // 库会自动加载
 * SDF sdf = new SDF();
 * }</pre>
 * <p>
 * 如果需要手动控制加载时机，可以显式调用：
 * </p>
 * <pre>{@code
 * // 在应用启动时预加载
 * try {
 *     NativeLibraryLoader.loadLibrary();
 *     System.out.println("SDF库加载成功");
 * } catch (Exception e) {
 *     System.err.println("SDF库加载失败: " + e.getMessage());
 * }
 * }</pre>
 *
 * @see org.openhitls.sdf4j.SDF
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
package org.openhitls.sdf4j.internal;
