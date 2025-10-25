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
 * 设备信息
 * Device Information (DEVICEINFO)
 *
 * <p>对应C结构体: DeviceInfo_st
 * <p>定义于GM/T 0018-2023 5.3节
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
public class DeviceInfo {

    /**
     * 设备生产厂商名称 (40字节)
     * Issuer name (40 bytes)
     */
    private String issuerName;

    /**
     * 设备型号 (16字节)
     * Device name (16 bytes)
     */
    private String deviceName;

    /**
     * 设备序列号 (16字节)
     * Device serial number (16 bytes)
     */
    private String deviceSerial;

    /**
     * 设备版本号
     * Device version
     */
    private long deviceVersion;

    /**
     * 设备支持的接口规范版本号
     * Standard version supported by device
     */
    private long standardVersion;

    /**
     * 设备支持的非对称算法能力 (2个元素)
     * Asymmetric algorithm abilities (2 elements)
     */
    private long[] asymAlgAbility;

    /**
     * 设备支持的对称算法能力
     * Symmetric algorithm ability
     */
    private long symAlgAbility;

    /**
     * 设备支持的杂凑算法能力
     * Hash algorithm ability
     */
    private long hashAlgAbility;

    /**
     * 设备数据缓冲区大小
     * Device buffer size
     */
    private long bufferSize;

    /**
     * 默认构造函数
     */
    public DeviceInfo() {
        this.asymAlgAbility = new long[2];
    }

    /**
     * 完整构造函数
     *
     * @param issuerName      厂商名称
     * @param deviceName      设备型号
     * @param deviceSerial    设备序列号
     * @param deviceVersion   设备版本
     * @param standardVersion 标准版本
     * @param asymAlgAbility  非对称算法能力
     * @param symAlgAbility   对称算法能力
     * @param hashAlgAbility  杂凑算法能力
     * @param bufferSize      缓冲区大小
     */
    public DeviceInfo(String issuerName, String deviceName, String deviceSerial,
                      long deviceVersion, long standardVersion, long[] asymAlgAbility,
                      long symAlgAbility, long hashAlgAbility, long bufferSize) {
        this.issuerName = issuerName;
        this.deviceName = deviceName;
        this.deviceSerial = deviceSerial;
        this.deviceVersion = deviceVersion;
        this.standardVersion = standardVersion;
        this.asymAlgAbility = asymAlgAbility != null ? Arrays.copyOf(asymAlgAbility, 2) : new long[2];
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

    public long[] getAsymAlgAbility() {
        return asymAlgAbility != null ? Arrays.copyOf(asymAlgAbility, asymAlgAbility.length) : null;
    }

    public void setAsymAlgAbility(long[] asymAlgAbility) {
        this.asymAlgAbility = asymAlgAbility != null ? Arrays.copyOf(asymAlgAbility, 2) : new long[2];
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
