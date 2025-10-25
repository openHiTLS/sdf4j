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

package org.openhitls.sdf4j.internal;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Properties;

/**
 * 本地库加载器
 * Native Library Loader
 *
 * <p>负责加载SDF4J的JNI桥接库和底层SDF库
 * <p>Responsible for loading SDF4J JNI bridge library and underlying SDF library
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
public class NativeLibraryLoader {

    private static final String SDF4J_LIBRARY_NAME = "sdf4j-jni";
    private static final String PROPERTIES_FILE = "sdf4j.properties";

    private static boolean loaded = false;
    private static final Object lock = new Object();

    /**
     * 加载本地库
     * 优先级: 系统属性 > 配置文件 > 环境变量
     *
     * @throws UnsatisfiedLinkError 如果加载失败
     */
    public static void loadLibrary() {
        synchronized (lock) {
            if (loaded) {
                return;
            }

            try {
                // 1. 加载JNI桥接库 (libsdf4j-jni.so)
                loadBridgeLibrary();

                // 2. 获取SDF库名称（必填）
                String libraryName = getLibraryName();
                if (libraryName == null || libraryName.trim().isEmpty()) {
                    throw new UnsatisfiedLinkError(
                        "SDF library name not configured. Please specify via:\n" +
                        "  1. System property: -Dsdf4j.library.name=<name>\n" +
                        "  2. Config file: library.name=<name> in src/main/resources/sdf4j.properties\n" +
                        "  3. Environment variable: SDF_LIBRARY_NAME=<name>");
                }

                // 3. 获取SDF库路径（可选）
                String libraryDir = getLibraryDir();

                // 4. 构造完整的库路径或库名
                String libraryPath = constructLibraryPath(libraryName, libraryDir);

                // 5. 在JNI层动态加载SDF库
                if (!nativeLoadSDFLibrary(libraryPath)) {
                    String errorMsg = (libraryDir == null)
                        ? "Failed to load SDF library '" + libraryName + "' from system default paths. " +
                          "Please install the library or specify path via -Dsdf4j.library.path"
                        : "Failed to load SDF library from: " + libraryPath;
                    throw new UnsatisfiedLinkError(errorMsg);
                }

                loaded = true;
            } catch (Exception e) {
                throw new UnsatisfiedLinkError("Failed to load native libraries: " + e.getMessage());
            }
        }
    }

    /**
     * 加载JNI桥接库
     */
    private static void loadBridgeLibrary() {
        try {
            // 尝试从java.library.path加载
            System.loadLibrary(SDF4J_LIBRARY_NAME);
        } catch (UnsatisfiedLinkError e) {
            // 如果失败，尝试从resources中提取并加载
            try {
                loadLibraryFromResources();
            } catch (IOException ex) {
                throw new UnsatisfiedLinkError("Failed to load bridge library: " + ex.getMessage());
            }
        }
    }

    /**
     * 从resources中提取并加载库
     */
    private static void loadLibraryFromResources() throws IOException {
        String platform = getPlatform();
        String libraryFileName = getLibraryFileName(SDF4J_LIBRARY_NAME);
        String resourcePath = "/native/" + platform + "/" + libraryFileName;

        // 尝试从classpath加载资源
        InputStream is = NativeLibraryLoader.class.getResourceAsStream(resourcePath);
        if (is == null) {
            throw new FileNotFoundException("Library not found in resources: " + resourcePath);
        }

        // 提取到临时目录
        Path tempDir = Files.createTempDirectory("sdf4j-native");
        Path tempLibrary = tempDir.resolve(libraryFileName);

        try {
            Files.copy(is, tempLibrary, StandardCopyOption.REPLACE_EXISTING);
            System.load(tempLibrary.toAbsolutePath().toString());
        } finally {
            is.close();
            // 注册删除钩子
            tempLibrary.toFile().deleteOnExit();
            tempDir.toFile().deleteOnExit();
        }
    }

    /**
     * 获取SDF库名称（必填）
     * 优先级: 系统属性 > 配置文件 > 环境变量
     */
    private static String getLibraryName() {
        // 优先级1: 系统属性 sdf4j.library.name
        String name = System.getProperty("sdf4j.library.name");
        if (name != null && !name.trim().isEmpty()) {
            return name.trim();
        }

        // 优先级2: 配置文件
        name = loadConfigProperty("library.name");
        if (name != null && !name.trim().isEmpty()) {
            return name.trim();
        }

        // 优先级3: 环境变量 SDF_LIBRARY_NAME
        name = System.getenv("SDF_LIBRARY_NAME");
        if (name != null && !name.trim().isEmpty()) {
            return name.trim();
        }

        // 没有配置，返回 null
        return null;
    }

    /**
     * 获取SDF库目录（可选）
     * 优先级: 系统属性 > 配置文件 > 环境变量
     */
    private static String getLibraryDir() {
        // 优先级1: 系统属性 sdf4j.library.path
        String path = System.getProperty("sdf4j.library.path");
        if (path != null && !path.trim().isEmpty()) {
            return path.trim();
        }

        // 优先级2: 配置文件
        path = loadConfigProperty("library.path");
        if (path != null && !path.trim().isEmpty()) {
            return path.trim();
        }

        // 优先级3: 环境变量 SDF_LIBRARY_PATH
        path = System.getenv("SDF_LIBRARY_PATH");
        if (path != null && !path.trim().isEmpty()) {
            return path.trim();
        }

        // 没有配置，返回 null（使用系统默认路径）
        return null;
    }

    /**
     * 构造库的完整路径
     * @param libraryName 库名称（不含前缀和后缀）
     * @param libraryDir 库目录（可选，null表示使用系统默认路径）
     * @return 完整的库路径或库名
     */
    private static String constructLibraryPath(String libraryName, String libraryDir) {
        if (libraryDir == null) {
            // 没有指定目录，返回库名，让系统在默认路径搜索
            return getLibraryFileName(libraryName);
        }

        // 指定了目录，构造完整路径
        String separator = File.separator;
        String libraryFileName = getLibraryFileName(libraryName);

        // 确保目录路径以分隔符结尾
        if (!libraryDir.endsWith(separator)) {
            libraryDir += separator;
        }

        return libraryDir + libraryFileName;
    }

    /**
     * 从配置文件加载指定属性
     * @param propertyName 属性名
     * @return 属性值，如果不存在返回 null
     */
    private static String loadConfigProperty(String propertyName) {
        try (InputStream is = NativeLibraryLoader.class.getClassLoader().getResourceAsStream(PROPERTIES_FILE)) {
            if (is != null) {
                Properties props = new Properties();
                props.load(is);
                return props.getProperty(propertyName);
            }
        } catch (IOException e) {
            // 配置文件不存在或读取失败，忽略
        }
        return null;
    }


    /**
     * 获取当前平台标识
     */
    private static String getPlatform() {
        String os = System.getProperty("os.name").toLowerCase();
        String arch = System.getProperty("os.arch").toLowerCase();

        String osName;
        if (os.contains("linux")) {
            osName = "linux";
        } else if (os.contains("win")) {
            osName = "windows";
        } else if (os.contains("mac")) {
            osName = "macos";
        } else {
            throw new UnsupportedOperationException("Unsupported OS: " + os);
        }

        String archName;
        if (arch.contains("amd64") || arch.contains("x86_64")) {
            archName = "x86_64";
        } else if (arch.contains("aarch64") || arch.contains("arm64")) {
            archName = "aarch64";
        } else {
            archName = arch;
        }

        return osName + "-" + archName;
    }

    /**
     * 获取库文件名（带平台特定的前缀和后缀）
     */
    private static String getLibraryFileName(String libraryName) {
        String os = System.getProperty("os.name").toLowerCase();

        if (os.contains("linux") || os.contains("unix")) {
            return "lib" + libraryName + ".so";
        } else if (os.contains("win")) {
            return libraryName + ".dll";
        } else if (os.contains("mac")) {
            return "lib" + libraryName + ".dylib";
        }

        throw new UnsupportedOperationException("Unsupported OS: " + os);
    }

    /**
     * Native方法：在JNI层动态加载SDF库
     * 此方法由JNI层实现，使用dlopen/LoadLibrary动态加载
     *
     * @param libraryPath SDF库路径
     * @return 加载成功返回true，否则返回false
     */
    private static native boolean nativeLoadSDFLibrary(String libraryPath);

    /**
     * 判断库是否已加载
     *
     * @return 如果已加载返回true
     */
    public static boolean isLoaded() {
        return loaded;
    }
}
