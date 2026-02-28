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
     * Asymmetric algorithm abilities (2 elements)
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

    public String getIssuerName() {
        return issuerName;
    }

    public void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
    }

    public String getDeviceName() {
        return deviceName;
    }

    public void setDeviceName(String deviceName) {
        this.deviceName = deviceName;
    }

    public String getDeviceSerial() {
        return deviceSerial;
    }

    public void setDeviceSerial(String deviceSerial) {
        this.deviceSerial = deviceSerial;
    }

    public long getDeviceVersion() {
        return deviceVersion;
    }

    public void setDeviceVersion(long deviceVersion) {
        this.deviceVersion = deviceVersion;
    }

    public long getStandardVersion() {
        return standardVersion;
    }

    public void setStandardVersion(long standardVersion) {
        this.standardVersion = standardVersion;
    }

    /**
     * Returns a direct reference to the internal array. Callers should not modify the returned value.
     */
    public long[] getAsymAlgAbility() {
        return asymAlgAbility;
    }

    public void setAsymAlgAbility(long[] asymAlgAbility) {
        if (asymAlgAbility == null) {
            throw new IllegalArgumentException("asymAlgAbility cannot be null");
        }
        this.asymAlgAbility = asymAlgAbility;
    }

    public long getSymAlgAbility() {
        return symAlgAbility;
    }

    public void setSymAlgAbility(long symAlgAbility) {
        this.symAlgAbility = symAlgAbility;
    }

    public long getHashAlgAbility() {
        return hashAlgAbility;
    }

    public void setHashAlgAbility(long hashAlgAbility) {
        this.hashAlgAbility = hashAlgAbility;
    }

    public long getBufferSize() {
        return bufferSize;
    }

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
