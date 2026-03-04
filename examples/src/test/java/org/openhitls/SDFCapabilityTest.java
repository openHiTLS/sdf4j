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

package org.openhitls;

import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.openhitls.sdf4j.*;
import org.openhitls.sdf4j.constants.AlgorithmID;
import org.openhitls.sdf4j.types.*;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * SDF Device Capability Detection Test
 *
 * <p>Automatically probes all GM/T 0018-2023 standard interfaces supported
 * by the connected SDF cryptographic device and outputs a capability report.
 *
 * <p>Usage: mvn test -pl examples -Dtest=SDFCapabilityTest
 */
public class SDFCapabilityTest {

    private static final int ECC_KEY_BITS = 256;
    private static final int RSA_KEY_BITS = 2048;
    private static final int KEY_INDEX = 1;
    private static final int KEK_INDEX = 1;

    private SDF sdf;
    private long deviceHandle;
    private long sessionHandle;

    @Before
    public void setUp() throws SDFException {
        try {
            sdf = new SDF();
            deviceHandle = sdf.SDF_OpenDevice();
            sessionHandle = sdf.SDF_OpenSession(deviceHandle);
        } catch (SDFException e) {
            Assume.assumeNoException("Require configured sdf device", e);
        }
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

    /**
     * Detects all supported SDF device capabilities and prints a report.
     */
    @Test
    public void testDetectCapabilities() {
        Map<String, Boolean> capabilities = new LinkedHashMap<>();

        // ==== 6.2 Device Management Functions ====
        capabilities.put("GetDeviceInfo", checkFunction(() ->
            sdf.SDF_GetDeviceInfo(sessionHandle)));
        capabilities.put("GenerateRandom", checkFunction(() ->
            sdf.SDF_GenerateRandom(sessionHandle, 16)));
        capabilities.put("GetPrivateKeyAccessRight", checkFunction(() ->
            sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, KEY_INDEX, "test")));
        capabilities.put("ReleasePrivateKeyAccessRight", checkFunction(() ->
            sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, KEY_INDEX)));
        capabilities.put("GetKEKAccessRight", checkFunction(() ->
            sdf.SDF_GetKEKAccessRight(sessionHandle, KEK_INDEX, "test")));
        capabilities.put("ReleaseKEKAccessRight", checkFunction(() ->
            sdf.SDF_ReleaseKEKAccessRight(sessionHandle, KEK_INDEX)));

        // ==== 6.3 Key Management Functions ====
        capabilities.put("ExportSignPublicKey_RSA", checkFunction(() ->
            sdf.SDF_ExportSignPublicKey_RSA(sessionHandle, KEY_INDEX)));
        capabilities.put("ExportEncPublicKey_RSA", checkFunction(() ->
            sdf.SDF_ExportEncPublicKey_RSA(sessionHandle, KEY_INDEX)));
        capabilities.put("ExportSignPublicKey_ECC", checkFunction(() ->
            sdf.SDF_ExportSignPublicKey_ECC(sessionHandle, KEY_INDEX)));
        capabilities.put("ExportEncPublicKey_ECC", checkFunction(() ->
            sdf.SDF_ExportEncPublicKey_ECC(sessionHandle, KEY_INDEX)));
        capabilities.put("GenerateKeyWithIPK_RSA", checkFunction(() -> {
            KeyEncryptionResult r = sdf.SDF_GenerateKeyWithIPK_RSA(sessionHandle, KEY_INDEX, 128);
            sdf.SDF_DestroyKey(sessionHandle, r.getKeyHandle());
        }));
        capabilities.put("GenerateKeyWithEPK_RSA", checkGenerateKeyWithEPK_RSA());
        capabilities.put("ImportKeyWithISK_RSA", checkFunction(() ->
            sdf.SDF_ImportKeyWithISK_RSA(sessionHandle, KEY_INDEX, new byte[256])));
        capabilities.put("GenerateKeyWithIPK_ECC", checkFunction(() -> {
            ECCKeyEncryptionResult r = sdf.SDF_GenerateKeyWithIPK_ECC(sessionHandle, KEY_INDEX, 128);
            sdf.SDF_DestroyKey(sessionHandle, r.getKeyHandle());
        }));
        capabilities.put("GenerateKeyWithEPK_ECC", checkGenerateKeyWithEPK_ECC());
        capabilities.put("ImportKeyWithISK_ECC", checkFunction(() ->
            sdf.SDF_ImportKeyWithISK_ECC(sessionHandle, KEY_INDEX, new ECCCipher())));
        capabilities.put("GenerateAgreementDataWithECC", checkFunction(() ->
            sdf.SDF_GenerateAgreementDataWithECC(sessionHandle, KEY_INDEX, 128, new byte[16])));
        capabilities.put("GenerateKeyWithKEK", checkFunction(() -> {
            KeyEncryptionResult r = sdf.SDF_GenerateKeyWithKEK(sessionHandle, 128, AlgorithmID.SGD_SM4_ECB, KEK_INDEX);
            sdf.SDF_DestroyKey(sessionHandle, r.getKeyHandle());
        }));
        capabilities.put("ImportKeyWithKEK", checkFunction(() ->
            sdf.SDF_ImportKeyWithKEK(sessionHandle, AlgorithmID.SGD_SM4_ECB, KEK_INDEX, new byte[16])));
        capabilities.put("ImportKey", checkFunction(() -> {
            long kh = sdf.SDF_ImportKey(sessionHandle, new byte[16]);
            sdf.SDF_DestroyKey(sessionHandle, kh);
        }));

        // ==== 6.4 Asymmetric Algorithm Functions ====
        // RSA operations
        capabilities.put("ExternalPublicKeyOperation_RSA", checkExternalRSA());
        capabilities.put("InternalPublicKeyOperation_RSA", checkFunction(() ->
            sdf.SDF_InternalPublicKeyOperation_RSA(sessionHandle, KEY_INDEX, new byte[256])));
        capabilities.put("InternalPrivateKeyOperation_RSA", checkFunction(() ->
            sdf.SDF_InternalPrivateKeyOperation_RSA(sessionHandle, KEY_INDEX, new byte[256])));
        // ECC sign/verify
        capabilities.put("ExternalSign_ECC", checkExternalSignECC());
        capabilities.put("ExternalVerify_ECC", checkExternalVerifyECC());
        capabilities.put("InternalSign_ECC", checkFunction(() ->
            sdf.SDF_InternalSign_ECC(sessionHandle, KEY_INDEX, new byte[32])));
        capabilities.put("InternalVerify_ECC", checkFunction(() ->
            sdf.SDF_InternalVerify_ECC(sessionHandle, KEY_INDEX, new byte[32], new ECCSignature())));
        // ECC encrypt/decrypt
        capabilities.put("ExternalEncrypt_ECC", checkExternalEncryptECC());
        capabilities.put("ExternalDecrypt_ECC", checkExternalDecryptECC());
        capabilities.put("InternalEncrypt_ECC", checkFunction(() ->
            sdf.SDF_InternalEncrypt_ECC(sessionHandle, KEY_INDEX, new byte[16])));
        capabilities.put("InternalDecrypt_ECC", checkFunction(() ->
            sdf.SDF_InternalDecrypt_ECC(sessionHandle, KEY_INDEX, AlgorithmID.SGD_SM2_3, new ECCCipher())));
        // Digital envelope exchange
        capabilities.put("ExchangeDigitEnvelopeBaseOnECC", checkFunction(() ->
            sdf.SDF_ExchangeDigitEnvelopeBaseOnECC(sessionHandle, KEY_INDEX,
                AlgorithmID.SGD_SM2_3, new ECCPublicKey(), new ECCCipher())));
        capabilities.put("ExchangeDigitEnvelopeBaseOnRSA", checkFunction(() ->
            sdf.SDF_ExchangeDigitEnvelopeBaseOnRSA(sessionHandle, KEY_INDEX,
                new RSAPublicKey(), new byte[256])));

        // ==== 6.5 Symmetric Algorithm Functions ====
        // Single-packet operations
        capabilities.put("Encrypt/Decrypt (SM4_ECB)", checkEncryptDecrypt());
        capabilities.put("CalculateMAC", checkCalculateMAC());
        capabilities.put("AuthEnc/AuthDec (SM4_GCM)", checkAuthEncDec());
        // Multi-packet operations
        capabilities.put("MultiPacketEncrypt", checkMultiPacketEncrypt());
        capabilities.put("MultiPacketDecrypt", checkMultiPacketDecrypt());
        capabilities.put("MultiPacketMAC", checkMultiPacketMAC());
        capabilities.put("MultiPacketAuthEnc", checkMultiPacketAuthEnc());
        capabilities.put("MultiPacketAuthDec", checkMultiPacketAuthDec());

        // ==== 6.6 Hash Operation Functions ====
        capabilities.put("Hash_SM3", checkFunction(() -> {
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, new byte[16]);
            sdf.SDF_HashFinal(sessionHandle);
        }));
        capabilities.put("HMAC", checkHMAC());

        // ==== 6.7 File Operation Functions ====
        capabilities.put("FileOperations", checkFileOperations());

        // ==== 6.8 Validation and Debug Functions ====
        capabilities.put("GenerateKeyPair_RSA", checkFunction(() ->
            sdf.SDF_GenerateKeyPair_RSA(sessionHandle, RSA_KEY_BITS)));
        capabilities.put("GenerateKeyPair_ECC", checkFunction(() ->
            sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS)));
        capabilities.put("ExternalPrivateKeyOperation_RSA", checkExternalPrivateRSA());
        capabilities.put("ExternalKeyEncrypt/Decrypt", checkExternalKeyEncryptDecrypt());
        capabilities.put("ExternalKeyMultiPacketEncrypt", checkExternalKeyMultiPacketEncrypt());
        capabilities.put("ExternalKeyHMACInit", checkFunction(() ->
            sdf.SDF_ExternalKeyHMACInit(sessionHandle, AlgorithmID.SGD_SM3, new byte[16])));

        // ==== Hybrid Algorithm Functions ====
        capabilities.put("ExportPublicKey_Hybrid", checkFunction(() ->
            sdf.SDF_ExportPublicKey_Hybrid(sessionHandle, KEY_INDEX)));
        capabilities.put("GenerateKeyWithEPK_Hybrid", checkFunction(() ->
            sdf.SDF_GenerateKeyWithEPK_Hybrid(sessionHandle, 0, new byte[64])));
        capabilities.put("InternalSign_Composite", checkFunction(() ->
            sdf.SDF_InternalSign_Composite(sessionHandle, KEY_INDEX, new byte[32])));
        capabilities.put("ExternalVerify_Composite", checkFunction(() ->
            sdf.SDF_ExternalVerify_Composite(sessionHandle, 0, new byte[64],
                new byte[32], new HybridSignature())));

        // Print the capability report
        printCapabilityReport(capabilities);
    }

    @FunctionalInterface
    private interface SDFAction {
        /**
         * Execute an SDF operation.
         *
         * @throws Exception if the operation fails
         */
        void run() throws Exception;
    }

    private boolean checkFunction(SDFAction action) {
        try {
            action.run();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkGenerateKeyWithEPK_RSA() {
        try {
            Object[] kp = sdf.SDF_GenerateKeyPair_RSA(sessionHandle, RSA_KEY_BITS);
            RSAPublicKey pub = (RSAPublicKey) kp[0];
            KeyEncryptionResult r = sdf.SDF_GenerateKeyWithEPK_RSA(sessionHandle, 128, pub);
            sdf.SDF_DestroyKey(sessionHandle, r.getKeyHandle());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkGenerateKeyWithEPK_ECC() {
        try {
            Object[] kp = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_3, ECC_KEY_BITS);
            ECCPublicKey pub = (ECCPublicKey) kp[0];
            ECCKeyEncryptionResult r = sdf.SDF_GenerateKeyWithEPK_ECC(sessionHandle, 128, AlgorithmID.SGD_SM2_3, pub);
            sdf.SDF_DestroyKey(sessionHandle, r.getKeyHandle());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkExternalRSA() {
        try {
            Object[] kp = sdf.SDF_GenerateKeyPair_RSA(sessionHandle, RSA_KEY_BITS);
            RSAPublicKey pub = (RSAPublicKey) kp[0];
            sdf.SDF_ExternalPublicKeyOperation_RSA(sessionHandle, pub, new byte[RSA_KEY_BITS / 8]);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkExternalPrivateRSA() {
        try {
            Object[] kp = sdf.SDF_GenerateKeyPair_RSA(sessionHandle, RSA_KEY_BITS);
            RSAPrivateKey priv = (RSAPrivateKey) kp[1];
            sdf.SDF_ExternalPrivateKeyOperation_RSA(sessionHandle, priv, new byte[RSA_KEY_BITS / 8]);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkExternalSignECC() {
        try {
            Object[] kp = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPrivateKey priv = (ECCPrivateKey) kp[1];
            sdf.SDF_ExternalSign_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, priv, new byte[32]);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkExternalVerifyECC() {
        try {
            Object[] kp = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, ECC_KEY_BITS);
            ECCPublicKey pub = (ECCPublicKey) kp[0];
            ECCPrivateKey priv = (ECCPrivateKey) kp[1];
            byte[] hash = new byte[32];
            ECCSignature sig = sdf.SDF_ExternalSign_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, priv, hash);
            sdf.SDF_ExternalVerify_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, pub, hash, sig);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkExternalEncryptECC() {
        try {
            Object[] kp = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_3, ECC_KEY_BITS);
            ECCPublicKey pub = (ECCPublicKey) kp[0];
            sdf.SDF_ExternalEncrypt_ECC(sessionHandle, AlgorithmID.SGD_SM2_3, pub, new byte[16]);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkExternalDecryptECC() {
        try {
            Object[] kp = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_3, ECC_KEY_BITS);
            ECCPublicKey pub = (ECCPublicKey) kp[0];
            ECCPrivateKey priv = (ECCPrivateKey) kp[1];
            ECCCipher cipher = sdf.SDF_ExternalEncrypt_ECC(sessionHandle, AlgorithmID.SGD_SM2_3, pub, new byte[16]);
            sdf.SDF_ExternalDecrypt_ECC(sessionHandle, AlgorithmID.SGD_SM2_3, priv, cipher);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkEncryptDecrypt() {
        try {
            long keyHandle = sdf.SDF_ImportKey(sessionHandle, new byte[16]);
            try {
                byte[] enc = sdf.SDF_Encrypt(sessionHandle, keyHandle,
                    AlgorithmID.SGD_SM4_ECB, null, new byte[16]);
                sdf.SDF_Decrypt(sessionHandle, keyHandle,
                    AlgorithmID.SGD_SM4_ECB, null, enc);
                return true;
            } finally {
                sdf.SDF_DestroyKey(sessionHandle, keyHandle);
            }
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkCalculateMAC() {
        try {
            long keyHandle = sdf.SDF_ImportKey(sessionHandle, new byte[16]);
            try {
                sdf.SDF_CalculateMAC(sessionHandle, keyHandle,
                    AlgorithmID.SGD_SM4_MAC, null, new byte[16]);
                return true;
            } finally {
                sdf.SDF_DestroyKey(sessionHandle, keyHandle);
            }
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkAuthEncDec() {
        try {
            long keyHandle = sdf.SDF_ImportKey(sessionHandle, new byte[16]);
            try {
                byte[][] result = sdf.SDF_AuthEnc(sessionHandle, keyHandle,
                    AlgorithmID.SGD_SM4_GCM, new byte[12], null, new byte[16]);
                byte[] ciphertext = result[0];
                byte[] tag = result[1];
                sdf.SDF_AuthDec(sessionHandle, keyHandle,
                    AlgorithmID.SGD_SM4_GCM, new byte[12], null, tag, ciphertext);
                return true;
            } finally {
                sdf.SDF_DestroyKey(sessionHandle, keyHandle);
            }
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkMultiPacketEncrypt() {
        try {
            long keyHandle = sdf.SDF_ImportKey(sessionHandle, new byte[16]);
            try {
                sdf.SDF_EncryptInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_ECB, null);
                sdf.SDF_EncryptUpdate(sessionHandle, new byte[16]);
                sdf.SDF_EncryptFinal(sessionHandle);
                return true;
            } finally {
                sdf.SDF_DestroyKey(sessionHandle, keyHandle);
            }
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkMultiPacketDecrypt() {
        try {
            long keyHandle = sdf.SDF_ImportKey(sessionHandle, new byte[16]);
            try {
                // Encrypt first to get valid ciphertext
                byte[] enc = sdf.SDF_Encrypt(sessionHandle, keyHandle,
                    AlgorithmID.SGD_SM4_ECB, null, new byte[16]);
                sdf.SDF_DecryptInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_ECB, null);
                sdf.SDF_DecryptUpdate(sessionHandle, enc);
                sdf.SDF_DecryptFinal(sessionHandle);
                return true;
            } finally {
                sdf.SDF_DestroyKey(sessionHandle, keyHandle);
            }
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkMultiPacketMAC() {
        try {
            long keyHandle = sdf.SDF_ImportKey(sessionHandle, new byte[16]);
            try {
                sdf.SDF_CalculateMACInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_MAC, null);
                sdf.SDF_CalculateMACUpdate(sessionHandle, new byte[16]);
                sdf.SDF_CalculateMACFinal(sessionHandle);
                return true;
            } finally {
                sdf.SDF_DestroyKey(sessionHandle, keyHandle);
            }
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkMultiPacketAuthEnc() {
        try {
            long keyHandle = sdf.SDF_ImportKey(sessionHandle, new byte[16]);
            try {
                sdf.SDF_AuthEncInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM,
                    new byte[12], null, 16);
                sdf.SDF_AuthEncUpdate(sessionHandle, new byte[16]);
                sdf.SDF_AuthEncFinal(sessionHandle, null);
                return true;
            } finally {
                sdf.SDF_DestroyKey(sessionHandle, keyHandle);
            }
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkMultiPacketAuthDec() {
        try {
            long keyHandle = sdf.SDF_ImportKey(sessionHandle, new byte[16]);
            try {
                // AuthEnc first to get valid ciphertext and tag
                byte[][] encResult = sdf.SDF_AuthEnc(sessionHandle, keyHandle,
                    AlgorithmID.SGD_SM4_GCM, new byte[12], null, new byte[16]);
                byte[] ciphertext = encResult[0];
                byte[] tag = encResult[1];
                sdf.SDF_AuthDecInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM,
                    new byte[12], null, tag, ciphertext.length);
                sdf.SDF_AuthDecUpdate(sessionHandle, ciphertext);
                sdf.SDF_AuthDecFinal(sessionHandle);
                return true;
            } finally {
                sdf.SDF_DestroyKey(sessionHandle, keyHandle);
            }
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkHMAC() {
        try {
            long keyHandle = sdf.SDF_ImportKey(sessionHandle, new byte[16]);
            try {
                sdf.SDF_HMACInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM3);
                sdf.SDF_HMACUpdate(sessionHandle, new byte[16]);
                sdf.SDF_HMACFinal(sessionHandle);
                return true;
            } finally {
                sdf.SDF_DestroyKey(sessionHandle, keyHandle);
            }
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkFileOperations() {
        String testFileName = "__sdf4j_cap_test__";
        try {
            sdf.SDF_CreateFile(sessionHandle, testFileName, 16);
            sdf.SDF_WriteFile(sessionHandle, testFileName, 0, new byte[16]);
            sdf.SDF_ReadFile(sessionHandle, testFileName, 0, 16);
            sdf.SDF_DeleteFile(sessionHandle, testFileName);
            return true;
        } catch (Exception e) {
            try {
                sdf.SDF_DeleteFile(sessionHandle, testFileName);
            } catch (Exception ignored) {
                // ignore cleanup errors
            }
            return false;
        }
    }

    private boolean checkExternalKeyEncryptDecrypt() {
        try {
            byte[] key = new byte[16];
            byte[] data = new byte[16];
            byte[] enc = sdf.SDF_ExternalKeyEncrypt(sessionHandle,
                AlgorithmID.SGD_SM4_ECB, key, null, data);
            sdf.SDF_ExternalKeyDecrypt(sessionHandle,
                AlgorithmID.SGD_SM4_ECB, key, null, enc);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkExternalKeyMultiPacketEncrypt() {
        try {
            byte[] key = new byte[16];
            sdf.SDF_ExternalKeyEncryptInit(sessionHandle,
                AlgorithmID.SGD_SM4_ECB, key, null);
            sdf.SDF_EncryptUpdate(sessionHandle, new byte[16]);
            sdf.SDF_EncryptFinal(sessionHandle);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private void printCapabilityReport(Map<String, Boolean> capabilities) {
        System.out.println();
        System.out.println("===========================================================");
        System.out.println("           SDF Device Capability Report");
        System.out.println("===========================================================");

        int supported = 0;
        int total = capabilities.size();

        for (Map.Entry<String, Boolean> entry : capabilities.entrySet()) {
            String name = entry.getKey();
            boolean ok = entry.getValue();
            if (ok) {
                supported++;
            }
            String status = ok ? "[OK] Supported" : "[--] Not Supported";
            System.out.printf("  %-40s %s%n", name, status);
        }

        System.out.println("-----------------------------------------------------------");
        System.out.printf("  Total: %d/%d capabilities supported%n", supported, total);
        System.out.println("===========================================================");
        System.out.println();
    }
}

