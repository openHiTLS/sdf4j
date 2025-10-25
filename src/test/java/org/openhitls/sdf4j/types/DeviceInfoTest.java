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

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * DeviceInfo类单元测试
 */
public class DeviceInfoTest {

    @Test
    public void testDefaultConstructor() {
        DeviceInfo info = new DeviceInfo();
        assertNotNull(info);
    }

    @Test
    public void testSettersAndGetters() {
        DeviceInfo info = new DeviceInfo();

        info.setIssuerName("TestVendor");
        assertEquals("TestVendor", info.getIssuerName());

        info.setDeviceName("TestDevice");
        assertEquals("TestDevice", info.getDeviceName());

        info.setDeviceSerial("SN12345678");
        assertEquals("SN12345678", info.getDeviceSerial());

        info.setDeviceVersion(0x01000000L);
        assertEquals(0x01000000L, info.getDeviceVersion());

        info.setStandardVersion(0x00020023L);
        assertEquals(0x00020023L, info.getStandardVersion());

        long[] asymAlg = {0x00020100L, 0x00010000L};
        info.setAsymAlgAbility(asymAlg);
        assertArrayEquals(asymAlg, info.getAsymAlgAbility());

        info.setSymAlgAbility(0x00000401L);
        assertEquals(0x00000401L, info.getSymAlgAbility());

        info.setHashAlgAbility(0x00000001L);
        assertEquals(0x00000001L, info.getHashAlgAbility());

        info.setBufferSize(4096L);
        assertEquals(4096L, info.getBufferSize());
    }

    @Test
    public void testToString() {
        DeviceInfo info = new DeviceInfo();
        info.setIssuerName("OpenHitls");
        info.setDeviceName("TestDevice");
        info.setDeviceSerial("SN001");

        String str = info.toString();
        assertNotNull(str);
        assertTrue(str.contains("OpenHitls"));
        assertTrue(str.contains("TestDevice"));
        assertTrue(str.contains("SN001"));
    }

    @Test
    public void testAsymAlgAbilityArray() {
        DeviceInfo info = new DeviceInfo();
        long[] asymAlg = {0x00020100L, 0x00010000L};
        info.setAsymAlgAbility(asymAlg);

        long[] retrieved = info.getAsymAlgAbility();
        assertNotNull(retrieved);
        assertEquals(2, retrieved.length);
        assertEquals(0x00020100L, retrieved[0]);
        assertEquals(0x00010000L, retrieved[1]);
    }
}
