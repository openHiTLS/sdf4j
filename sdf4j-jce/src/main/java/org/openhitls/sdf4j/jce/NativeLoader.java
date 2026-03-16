/*
 * Copyright (c) 2025 OpenHitls
 * SDF4J is licensed under Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

package org.openhitls.sdf4j.jce;

import java.io.*;
import java.nio.file.*;
import java.util.Properties;

/**
 * Native library loader for SDF4J JCE
 *
 * <p>Library loading priority (for SDF platform library):</p>
 * <ol>
 *   <li>System property: sdf4j.library.name / sdf4j.library.path</li>
 *   <li>Config file: sdf4j-jce.properties</li>
 *   <li>Environment variable: SDF_LIBRARY_NAME / SDF_LIBRARY_PATH</li>
 * </ol>
 */
final class NativeLoader {

    private static final String LIBRARY_NAME = "sdf4j-jce";
    private static final String PROPERTIES_FILE = "sdf4j-jce.properties";
    private static volatile boolean loaded = false;

    private NativeLoader() {
    }

    /**
     * Load the native library and SDF platform library
     */
    public static synchronized void load() {
        if (loaded) {
            return;
        }

        try {
            // 1. Load JCE JNI bridge library (libsdf4j-jce.so)
            loadBridgeLibrary();

            // 2. Get SDF platform library path for initialization
            // Priority: system property > config file > environment variable
            String libraryPath = getSDFLibraryPath();

            // 3. Set library path and initialize SDF
            if (libraryPath != null && !libraryPath.isEmpty()) {
                setLibraryPath(libraryPath);
            }

            // 4. Initialize SDF (uses path from setLibraryPath or environment variable)
            // This will throw SDFJceException if initialization fails
            boolean initialized = initialize();
            if (!initialized) {
                throw new IllegalStateException("SDF initialization failed");
            }
            loaded = true;
        } catch (IOException e) {
            throw new UnsatisfiedLinkError(
                "Failed to load native library: " + e.getMessage());
        }
    }

    /**
     * Load the JCE JNI bridge library
     */
    private static void loadBridgeLibrary() throws IOException {
        try {
            // First try system library path
            System.loadLibrary(LIBRARY_NAME);
        } catch (UnsatisfiedLinkError e) {
            // Extract from JAR and load
            loadLibraryFromResources();
        }
    }

    /**
     * Extract native library from JAR to temp directory and load it
     */
    private static void loadLibraryFromResources() throws IOException {
        String platform = getPlatform();
        String libraryFileName = "lib" + LIBRARY_NAME + ".so";
        String resourcePath = "/native/" + platform + "/" + libraryFileName;

        try (InputStream is = NativeLoader.class.getResourceAsStream(resourcePath)) {
            if (is == null) {
                throw new FileNotFoundException(
                    "Native library not found in JAR: " + resourcePath);
            }

            Path baseDir = Paths.get(System.getProperty("java.io.tmpdir"), "sdf4j-jce-native");
            Files.createDirectories(baseDir);
            Path tempLib = baseDir.resolve(platform + "-" + libraryFileName);

            // Extract the library (always re-extract to ensure using latest version)
            Files.copy(is, tempLib, StandardCopyOption.REPLACE_EXISTING);

            // Load the extracted library
            System.load(tempLib.toAbsolutePath().toString());

            // Clean up on JVM exit
            tempLib.toFile().deleteOnExit();
        }
    }

    /**
     * Get SDF platform library path
     * Priority: system property > config file > environment variable
     *
     * Note: SDF_LIBRARY_PATH environment variable (full path) takes precedence over
     * config file's library.name setting
     *
     * @return library path, or null if not configured
     */
    private static String getSDFLibraryPath() {
        String path;
        String name;

        // Priority 1: System properties (sdf.library.* takes precedence over sdf4j.library.*)
        path = getFirstNonNullProperty("sdf.library.path", "sdf4j.library.path");
        name = getFirstNonNullProperty("sdf.library.name", "sdf4j.library.name");
        if (name != null && !name.trim().isEmpty()) {
            name = name.trim();
        }
        if (path != null && !path.trim().isEmpty()) {
            path = path.trim();
            return constructLibraryPath(name, path);
        }
        if (name != null) {
            return constructLibraryPath(name, null);
        }

        // Priority 1.5: Environment variable SDF_LIBRARY_PATH (full path, highest priority)
        // This takes precedence over config file because it's an explicit runtime override
        String envPath = System.getenv("SDF_LIBRARY_PATH");
        if (envPath != null && !envPath.trim().isEmpty()) {
            return constructLibraryPath(null, envPath.trim());
        }

        // Priority 2: Config file
        Properties props = loadConfigProperties();
        if (props != null) {
            path = props.getProperty("library.path");
            name = props.getProperty("library.name");
            // Only use config values if both are empty or have meaningful values
            if ((path == null || path.trim().isEmpty()) && (name == null || name.trim().isEmpty())) {
                // Config file has no meaningful values, skip to environment variables
            } else {
                if (name != null && !name.trim().isEmpty()) {
                    name = name.trim();
                }
                if (path != null && !path.trim().isEmpty()) {
                    path = path.trim();
                    return constructLibraryPath(name, path);
                }
                if (name != null) {
                    return constructLibraryPath(name, null);
                }
            }
        }

        // Priority 3: Environment variable SDF_LIBRARY_NAME (name only)
        name = System.getenv("SDF_LIBRARY_NAME");
        if (name != null && !name.trim().isEmpty()) {
            return constructLibraryPath(name.trim(), null);
        }

        return null;
    }

    /**
     * Get the first non-null system property from the given list of property names
     */
    private static String getFirstNonNullProperty(String... propertyNames) {
        for (String propertyName : propertyNames) {
            String value = System.getProperty(propertyName);
            if (value != null && !value.trim().isEmpty()) {
                return value.trim();
            }
        }
        return null;
    }

    /**
     * Construct library path from library name and optional directory
     *
     * @param libraryName the library name (without lib prefix and extension)
     * @param libraryDir the directory containing the library, or null for system default
     * @return full path to the library file
     */
    private static String constructLibraryPath(String libraryName, String libraryDir) {
        if (libraryName == null || libraryName.isEmpty()) {
            // If library.path already points to a file (contains .so/.dll/.dylib), use it directly
            if (libraryDir != null && (libraryDir.endsWith(".so") || libraryDir.endsWith(".dll") ||
                libraryDir.endsWith(".dylib"))) {
                return libraryDir;
            }
            return libraryDir;
        }

        String os = System.getProperty("os.name").toLowerCase();
        String libraryFileName;

        if (os.contains("linux") || os.contains("unix")) {
            libraryFileName = "lib" + libraryName + ".so";
        } else if (os.contains("win")) {
            libraryFileName = libraryName + ".dll";
        } else if (os.contains("mac")) {
            libraryFileName = "lib" + libraryName + ".dylib";
        } else {
            // Default to Linux naming
            libraryFileName = "lib" + libraryName + ".so";
        }

        // If directory is specified, combine with filename
        if (libraryDir != null && !libraryDir.isEmpty()) {
            String separator = libraryDir.endsWith("/") || libraryDir.endsWith("\\") ? "" : "/";
            return libraryDir + separator + libraryFileName;
        }

        // Just return the filename, system will search default paths
        return libraryFileName;
    }

    /**
     * Load configuration properties from sdf4j-jce.properties
     */
    private static Properties loadConfigProperties() {
        try (InputStream is = NativeLoader.class.getClassLoader().getResourceAsStream(PROPERTIES_FILE)) {
            if (is != null) {
                Properties props = new Properties();
                props.load(is);
                return props;
            }
        } catch (IOException e) {
            // Config file not found or error reading, ignore
        }
        return null;
    }

    /**
     * Set SDF library path for initialization
     * This native method stores the path for later use during initialize()
     *
     * @param path full path to the SDF platform library
     */
    private static native void setLibraryPath(String path);

    /**
     * Initialize SDF using the path set by setLibraryPath() or from environment variable
     *
     * @return true if initialization succeeded, false otherwise
     * @throws SDFJceException if SDF initialization fails
     */
    private static native boolean initialize();

    /**
     * Cleanup SDF resources (close session and device)
     */
    private static native void cleanup();

    /**
     * Check if library is loaded
     */
    public static boolean isLoaded() {
        return loaded;
    }

    /**
     * Unload the native library and cleanup SDF resources
     */
    public static synchronized void unload() {
        if (loaded) {
            cleanup();
            loaded = false;
        }
    }

    /**
     * Get platform identifier
     */
    private static String getPlatform() {
        String os = System.getProperty("os.name").toLowerCase();
        String arch = System.getProperty("os.arch").toLowerCase();

        String osName;
        if (os.contains("linux")) {
            osName = "linux";
        } else if (os.contains("mac") || os.contains("darwin")) {
            osName = "darwin";
        } else if (os.contains("windows")) {
            osName = "windows";
        } else {
            osName = "linux"; // Default to linux
        }

        String archName;
        if (arch.equals("amd64") || arch.equals("x86_64") || arch.equals("x64")) {
            archName = "x86_64";
        } else if (arch.equals("aarch64") || arch.equals("arm64")) {
            archName = "aarch64";
        } else {
            archName = arch;
        }

        return osName + "-" + archName;
    }
}
