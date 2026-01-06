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

package org.openhitls.sdf4j.examples;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Test configuration loader for SDF4J examples.
 * Loads configuration from test-config.properties file.
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
public class TestConfig {

    private static final String DEFAULT_CONFIG_FILE = "test-config.properties";

    private static TestConfig instance;
    private Properties properties;

    private TestConfig() {
        properties = new Properties();
        loadConfiguration();
    }

    /**
     * Get singleton instance of TestConfig
     * @return TestConfig instance
     */
    public static synchronized TestConfig getInstance() {
        if (instance == null) {
            instance = new TestConfig();
        }
        return instance;
    }

    /**
     * Load configuration from properties file
     */
    private void loadConfiguration() {
        try (InputStream input = getClass().getClassLoader().getResourceAsStream(DEFAULT_CONFIG_FILE)) {
            if (input == null) {
                System.err.println("ERROR: Configuration file not found: " + DEFAULT_CONFIG_FILE);
                System.err.println("Please create the configuration file at: examples/src/test/resources/" + DEFAULT_CONFIG_FILE);
                throw new RuntimeException("Configuration file not found: " + DEFAULT_CONFIG_FILE);
            }

            properties.load(input);
            System.out.println("Loaded configuration from: " + DEFAULT_CONFIG_FILE);

        } catch (IOException e) {
            System.err.println("ERROR: Failed to load configuration file: " + DEFAULT_CONFIG_FILE);
            throw new RuntimeException("Failed to load configuration file", e);
        }
    }

    /**
     * Get SM2 internal key index
     * @return key index
     */
    public int getSM2InternalKeyIndex() {
        return getInt("sm2.internal.key.index");
    }

    /**
     * Get SM2 key access password
     * @return password string, may be empty if no password is required
     */
    public String getSM2KeyAccessPassword() {
        String value = properties.getProperty("sm2.key.access.password");
        return value != null ? value.trim() : "";
    }

    /**
     * Get SM2 default user ID
     * @return user ID string
     */
    public String getSM2DefaultUserId() {
        return getString("sm2.default.user.id");
    }

    /**
     * Get SM4 internal key index (KEK index)
     * @return key index
     */
    public int getSM4InternalKeyIndex() {
        return getInt("sm4.internal.key.index");
    }

    /**
     * Get SM4 key access password (KEK password)
     * @return password string, may be empty if no password is required
     */
    public String getSM4KeyAccessPassword() {
        String value = properties.getProperty("sm4.key.access.password");
        return value != null ? value.trim() : "";
    }

    /**
     * Get environment name
     * @return environment name
     */
    public String getEnvironmentName() {
        return getString("environment.name");
    }

    /**
     * Get string property from configuration
     * @param key property key
     * @return property value
     * @throws RuntimeException if property not found
     */
    private String getString(String key) {
        String value = properties.getProperty(key);
        if (value == null || value.trim().isEmpty()) {
            throw new RuntimeException("Missing required configuration property: " + key);
        }
        return value.trim();
    }

    /**
     * Get integer property from configuration
     * @param key property key
     * @return property value as integer
     * @throws RuntimeException if property not found or invalid
     */
    private int getInt(String key) {
        String value = properties.getProperty(key);
        if (value == null || value.trim().isEmpty()) {
            throw new RuntimeException("Missing required configuration property: " + key);
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            throw new RuntimeException("Invalid integer value for " + key + ": " + value, e);
        }
    }

    /**
     * Get raw property value
     * @param key property key
     * @return property value or null
     */
    public String getProperty(String key) {
        return properties.getProperty(key);
    }

    /**
     * Get raw property value with default
     * @param key property key
     * @param defaultValue default value if key not found
     * @return property value
     */
    public String getProperty(String key, String defaultValue) {
        return properties.getProperty(key, defaultValue);
    }
}
