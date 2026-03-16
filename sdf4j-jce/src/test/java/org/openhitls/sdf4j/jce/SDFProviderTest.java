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

package org.openhitls.sdf4j.jce;

import org.junit.Test;
import static org.junit.Assert.*;

import java.security.*;

/**
 * Tests for SDFProvider registration (without SDF device)
 */
public class SDFProviderTest {

    @Test
    public void testProviderCreation() {
        SDFProvider provider = new SDFProvider();
        assertNotNull(provider);
        assertEquals("SDF", provider.getName());
        assertEquals(1.0, provider.getVersion(), 0.001);
        assertNotNull(provider.getInfo());
    }

    @Test
    public void testProviderRegistration() {
        SDFProvider provider = new SDFProvider();
        Security.addProvider(provider);

        try {
            Provider registered = Security.getProvider("SDF");
            assertNotNull("Provider should be registered", registered);
            assertEquals("SDF", registered.getName());
        } finally {
            Security.removeProvider("SDF");
        }
    }

    @Test
    public void testAlgorithmRegistration() {
        SDFProvider provider = new SDFProvider();
        Security.addProvider(provider);

        try {
            // Check MessageDigest
            assertNotNull("SM3 should be registered",
                    provider.getService("MessageDigest", "SM3"));

            // Check Cipher
            assertNotNull("SM4 should be registered",
                    provider.getService("Cipher", "SM4"));
            assertNotNull("SM4/CBC/NoPadding should be registered",
                    provider.getService("Cipher", "SM4/CBC/NoPadding"));
            assertNotNull("SM2 should be registered",
                    provider.getService("Cipher", "SM2"));

            // Check Signature
            assertNotNull("SM3withSM2 should be registered",
                    provider.getService("Signature", "SM3withSM2"));

            // Check KeyPairGenerator
            assertNotNull("SM2 KeyPairGenerator should be registered",
                    provider.getService("KeyPairGenerator", "SM2"));

            // Check KeyGenerator
            assertNotNull("SM4 KeyGenerator should be registered",
                    provider.getService("KeyGenerator", "SM4"));

            // Check SecureRandom
            assertNotNull("SDF SecureRandom should be registered",
                    provider.getService("SecureRandom", "SDF"));

            // Check Mac
            assertNotNull("HmacSM3 should be registered",
                    provider.getService("Mac", "HmacSM3"));
            assertNotNull("SM4-MAC should be registered",
                    provider.getService("Mac", "SM4-MAC"));

        } finally {
            Security.removeProvider("SDF");
        }
    }
}
