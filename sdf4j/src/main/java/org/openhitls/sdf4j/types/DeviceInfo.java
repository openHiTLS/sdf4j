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

package org.openhitls.sdf4j.types;

import java.util.Arrays;

/**
 * Device Information (DEVICEINFO)
 *
 * <p>Corresponds to C struct: DeviceInfo_st
 * <p>Defined in GM/T 0018-2023 Section 5.3
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
public class DeviceInfo {

    /**
     * Issuer name (40 bytes)
     */
    private String issuerName;

    /**
     * Device name (16 bytes)
     */
    private String deviceName;

    /**
     * Device serial number (16 bytes)
     */
    private String deviceSerial;

    /**
     * Device version
     */
    private long deviceVersion;

    /**
     * Standard version supported by device
     */
    private long standardVersion;

    /**
     * Asymmetric algorithm abilities
     */
    private long[] asymAlgAbility;

    /**
     * Symmetric algorithm ability
     */
    private long symAlgAbility;

    /**
     * Hash algorithm ability
     */
    private long hashAlgAbility;

    /**
     * Device buffer size
     */
    private long bufferSize;

    /**
     * Default constructor.
     */
    public DeviceInfo() {
    }

    /**
     * Parameterized constructor.
     *
     * @param issuerName      issuer name
     * @param deviceName      device name
     * @param deviceSerial    device serial number
     * @param deviceVersion   device version
     * @param standardVersion standard version
     * @param asymAlgAbility  asymmetric algorithm abilities
     * @param symAlgAbility   symmetric algorithm ability
     * @param hashAlgAbility  hash algorithm ability
     * @param bufferSize      buffer size
     */
    public DeviceInfo(String issuerName, String deviceName, String deviceSerial,
                      long deviceVersion, long standardVersion, long[] asymAlgAbility,
                      long symAlgAbility, long hashAlgAbility, long bufferSize) {
        if (issuerName == null || deviceName == null || deviceSerial == null || asymAlgAbility == null) {
            throw new IllegalArgumentException("null input");
        }
        this.issuerName = issuerName;
        this.deviceName = deviceName;
        this.deviceSerial = deviceSerial;
        this.deviceVersion = deviceVersion;
        this.standardVersion = standardVersion;
        this.asymAlgAbility = asymAlgAbility;
        this.symAlgAbility = symAlgAbility;
        this.hashAlgAbility = hashAlgAbility;
        this.bufferSize = bufferSize;
    }

    // ========================================================================
    // Getters and Setters
    // ========================================================================

    /**
     * Get issuer name.
     *
     * @return issuer name
     */
    public String getIssuerName() {
        return issuerName;
    }

    /**
     * Set issuer name.
     *
     * @param issuerName issuer name
     */
    public void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
    }

    /**
     * Get device name.
     *
     * @return device name
     */
    public String getDeviceName() {
        return deviceName;
    }

    /**
     * Set device name.
     *
     * @param deviceName device name
     */
    public void setDeviceName(String deviceName) {
        this.deviceName = deviceName;
    }

    /**
     * Get device serial number.
     *
     * @return device serial number
     */
    public String getDeviceSerial() {
        return deviceSerial;
    }

    /**
     * Set device serial number.
     *
     * @param deviceSerial device serial number
     */
    public void setDeviceSerial(String deviceSerial) {
        this.deviceSerial = deviceSerial;
    }

    /**
     * Get device version.
     *
     * @return device version number
     */
    public long getDeviceVersion() {
        return deviceVersion;
    }

    /**
     * Set device version.
     *
     * @param deviceVersion device version number
     */
    public void setDeviceVersion(long deviceVersion) {
        this.deviceVersion = deviceVersion;
    }

    /**
     * Get standard version supported by this device.
     *
     * @return standard version number
     */
    public long getStandardVersion() {
        return standardVersion;
    }

    /**
     * Set standard version.
     *
     * @param standardVersion standard version number
     */
    public void setStandardVersion(long standardVersion) {
        this.standardVersion = standardVersion;
    }

    /**
     * Get asymmetric algorithm abilities.
     *
     * <p>Returns a direct reference to the internal array. Callers should not modify the returned value.
     *
     * @return asymmetric algorithm ability flags
     */
    public long[] getAsymAlgAbility() {
        return asymAlgAbility;
    }

    /**
     * Set asymmetric algorithm abilities.
     *
     * @param asymAlgAbility asymmetric algorithm ability flags
     * @throws IllegalArgumentException if asymAlgAbility is null
     */
    public void setAsymAlgAbility(long[] asymAlgAbility) {
        if (asymAlgAbility == null) {
            throw new IllegalArgumentException("asymAlgAbility cannot be null");
        }
        this.asymAlgAbility = asymAlgAbility;
    }

    /**
     * Get symmetric algorithm ability flags.
     *
     * @return symmetric algorithm ability bitmask
     */
    public long getSymAlgAbility() {
        return symAlgAbility;
    }

    /**
     * Set symmetric algorithm ability flags.
     *
     * @param symAlgAbility symmetric algorithm ability bitmask
     */
    public void setSymAlgAbility(long symAlgAbility) {
        this.symAlgAbility = symAlgAbility;
    }

    /**
     * Get hash algorithm ability flags.
     *
     * @return hash algorithm ability bitmask
     */
    public long getHashAlgAbility() {
        return hashAlgAbility;
    }

    /**
     * Set hash algorithm ability flags.
     *
     * @param hashAlgAbility hash algorithm ability bitmask
     */
    public void setHashAlgAbility(long hashAlgAbility) {
        this.hashAlgAbility = hashAlgAbility;
    }

    /**
     * Get device buffer size.
     *
     * @return buffer size in bytes
     */
    public long getBufferSize() {
        return bufferSize;
    }

    /**
     * Set device buffer size.
     *
     * @param bufferSize buffer size in bytes
     */
    public void setBufferSize(long bufferSize) {
        this.bufferSize = bufferSize;
    }

    // ========================================================================
    // Object Methods
    // ========================================================================

    @Override
    public String toString() {
        return "DeviceInfo{" +
                "issuerName='" + issuerName + '\'' +
                ", deviceName='" + deviceName + '\'' +
                ", deviceSerial='" + deviceSerial + '\'' +
                ", deviceVersion=" + deviceVersion +
                ", standardVersion=" + standardVersion +
                ", asymAlgAbility=" + Arrays.toString(asymAlgAbility) +
                ", symAlgAbility=0x" + Long.toHexString(symAlgAbility) +
                ", hashAlgAbility=0x" + Long.toHexString(hashAlgAbility) +
                ", bufferSize=" + bufferSize +
                '}';
    }
}
