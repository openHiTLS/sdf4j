/*
 * Copyright (c) 2025 OpenHitls
 * SDF4J is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

package org.openhitls;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.openhitls.sdf4j.*;
import org.openhitls.sdf4j.constants.AlgorithmID;
import org.openhitls.sdf4j.types.ECCKeyEncryptionResult;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

/**
 * SM3 哈希算法测试
 */
public class SM3Example {

    private static final int KEY_INDEX = 1;

    private SDF sdf;
    private long deviceHandle;
    private long sessionHandle;

    @Before
    public void setUp() throws SDFException {
        sdf = new SDF();
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);
    }

    @After
    public void tearDown() throws SDFException {
        if (sdf != null) {
            if (sessionHandle != 0) {
                sdf.SDF_CloseSession(sessionHandle);
            }
            if (deviceHandle != 0) {
                sdf.SDF_CloseDevice(deviceHandle);
            }
        }
    }

    @Test
    public void testSM3Hash() throws SDFException {

        String message = "Hello SM3 Test";
        byte[] data = message.getBytes(StandardCharsets.UTF_8);

        sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
        sdf.SDF_HashUpdate(sessionHandle, data);
        byte[] hash = sdf.SDF_HashFinal(sessionHandle);

        assertNotNull("SM3哈希结果不能为空", hash);
        assertEquals("SM3哈希长度应为32字节", 32, hash.length);
    }
}
