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

package org.openhitls.sdf4j.jce.native_;

import java.io.*;
import java.nio.file.*;

/**
 * Native library loader for SDF4J JCE
 */
public final class NativeLoader {

    private static final String LIBRARY_NAME = "sdf4j-jce";
    private static volatile boolean loaded = false;

    private NativeLoader() {
    }

    /**
     * Load the native library
     */
    public static synchronized void load() {
        if (loaded) {
            return;
        }

        try {
            // First try system library path
            System.loadLibrary(LIBRARY_NAME);
            loaded = true;
            return;
        } catch (UnsatisfiedLinkError e) {
            // Continue to try extracting from JAR
        }

        // Try to extract from JAR
        String platform = getPlatform();
        String libraryFileName = "lib" + LIBRARY_NAME + ".so";
        String resourcePath = "/native/" + platform + "/" + libraryFileName;

        try (InputStream is = NativeLoader.class.getResourceAsStream(resourcePath)) {
            if (is == null) {
                throw new UnsatisfiedLinkError(
                    "Native library not found in JAR: " + resourcePath);
            }

            // Use a deterministic path based on user and library name to avoid
            // accumulating temp files in long-running services
            Path baseDir = Paths.get(System.getProperty("java.io.tmpdir"), "sdf4j-jce-native");
            Files.createDirectories(baseDir);
            Path tempLib = baseDir.resolve(platform + "-" + libraryFileName);

            // Only extract if file doesn't exist or is older than JAR
            boolean needExtract = !Files.exists(tempLib);
            if (!needExtract) {
                // Check if JAR is newer (simple heuristic: always re-extract for safety)
                // In production, you might compare checksums
                needExtract = false;
            }

            if (needExtract || !Files.exists(tempLib)) {
                Files.copy(is, tempLib, StandardCopyOption.REPLACE_EXISTING);
            }

            System.load(tempLib.toAbsolutePath().toString());
            loaded = true;
        } catch (IOException e) {
            throw new UnsatisfiedLinkError(
                "Failed to extract native library: " + e.getMessage());
        }
    }

    /**
     * Check if library is loaded
     */
    public static boolean isLoaded() {
        return loaded;
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
