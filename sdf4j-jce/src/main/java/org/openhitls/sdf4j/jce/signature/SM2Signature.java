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

package org.openhitls.sdf4j.jce.signature;

import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

import org.openhitls.sdf4j.jce.key.SM2PrivateKey;
import org.openhitls.sdf4j.jce.key.SM2PublicKey;
import org.openhitls.sdf4j.jce.key.SDFInternalPrivateKey;
import org.openhitls.sdf4j.jce.key.SDFInternalPublicKey;
import org.openhitls.sdf4j.jce.SDFJceNative;
import org.openhitls.sdf4j.jce.spec.SM2ParameterSpec;
import org.openhitls.sdf4j.jce.util.SM2Util;
import org.openhitls.sdf4j.jce.util.DERCodec;

/**
 * SM2 Signature implementation (SM3withSM2)
 *
 * Supports both External and Internal key modes:
 * <ul>
 *   <li><b>External</b>: Use {@link SM2PrivateKey}/{@link SM2PublicKey} — key material
 *       provided by the application, calls {@code SDF_ExternalSign_ECC}/{@code SDF_ExternalVerify_ECC}.</li>
 *   <li><b>Internal</b>: Use {@link SDFInternalPrivateKey}/{@link SDFInternalPublicKey} — key stays
 *       in the device, calls {@code SDF_InternalSign_ECC}/{@code SDF_InternalVerify_ECC}.
 *       Password-based access rights are handled automatically.</li>
 * </ul>
 *
 * This implementation follows GM/T 0009-2012 standard for SM2 signature:
 * 1. Calculate Z = SM3(ENTLA || IDA || a || b || xG || yG || xA || yA)
 * 2. Calculate e = SM3(Z || M)
 * 3. Sign e using SM2 algorithm
 */
public final class SM2Signature extends SignatureSpi {

    private long sessionHandle;
    private SM2PrivateKey privateKey;
    private SM2PublicKey publicKey;
    private SDFInternalPrivateKey internalPrivateKey;
    private SDFInternalPublicKey internalPublicKey;
    private ByteArrayOutputStream data;
    private boolean forSigning;
    private boolean useInternalKey;
    private byte[] userId = SM2ParameterSpec.DEFAULT_USER_ID;

    public SM2Signature() {
        this.sessionHandle = SDFJceNative.openSession();
        if (sessionHandle == 0) {
            throw new IllegalStateException("Failed to open SDF session");
        }
        this.data = new ByteArrayOutputStream();
    }
    private void releaseSession() {
        if (sessionHandle != 0) {
            long h = sessionHandle;
            sessionHandle = 0;
            SDFJceNative.closeSession(h);
        }
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (publicKey instanceof SDFInternalPublicKey) {
            this.internalPublicKey = (SDFInternalPublicKey) publicKey;
            this.publicKey = null;
            this.useInternalKey = true;
            // Lazily load coordinates for Z value calculation
            ensureInternalPublicKeyLoaded(this.internalPublicKey);
        } else if (publicKey instanceof SM2PublicKey) {
            this.publicKey = (SM2PublicKey) publicKey;
            this.internalPublicKey = null;
            this.useInternalKey = false;
        } else {
            throw new InvalidKeyException("Key must be SM2PublicKey or SDFInternalPublicKey");
        }
        this.privateKey = null;
        this.internalPrivateKey = null;
        this.forSigning = false;
        this.data.reset();
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (privateKey instanceof SDFInternalPrivateKey) {
            this.internalPrivateKey = (SDFInternalPrivateKey) privateKey;
            this.privateKey = null;
            this.useInternalKey = true;
            // Auto-acquire access right
            acquirePrivateKeyAccessRight(this.internalPrivateKey);
            // Auto-export and cache public key for Z value calculation
            ensureInternalSignPublicKeyAvailable(this.internalPrivateKey);
        } else if (privateKey instanceof SM2PrivateKey) {
            this.privateKey = (SM2PrivateKey) privateKey;
            this.internalPrivateKey = null;
            this.useInternalKey = false;
        } else {
            throw new InvalidKeyException("Key must be SM2PrivateKey or SDFInternalPrivateKey");
        }
        // Note: Do NOT reset publicKey/internalPublicKey here — may have been set via setParameter()
        this.forSigning = true;
        this.data.reset();
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey, SecureRandom random) throws InvalidKeyException {
        engineInitSign(privateKey);
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        data.write(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        data.write(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (!forSigning) {
            throw new SignatureException("Not initialized for signing");
        }

        byte[] dataBytes = data.toByteArray();
        data.reset();

        if (useInternalKey) {
            return signInternal(dataBytes);
        } else {
            return signExternal(dataBytes);
        }
    }

    private byte[] signExternal(byte[] dataBytes) throws SignatureException {
        if (privateKey == null) {
            throw new SignatureException("Private key not set");
        }
        if (publicKey == null) {
            throw new SignatureException(
                "Public key required for SM2 signature. " +
                "Use setParameter(SM2ParameterSpec) to provide the public key before signing.");
        }

        // Calculate Z value according to GM/T 0009-2012
        byte[] z = SM2Util.calculateZ(sessionHandle, userId, publicKey.getX(), publicKey.getY());

        // Calculate e = SM3(Z || M)
        byte[] e = SM2Util.calculateE(sessionHandle, z, dataBytes);

        // Sign the hash e (returns r||s format, 64 bytes)
        byte[] rawSignature = SDFJceNative.sm2Sign(sessionHandle, privateKey.getKeyBytes(), e);
        return DERCodec.rawToDer(rawSignature);
    }

    private byte[] signInternal(byte[] dataBytes) throws SignatureException {
        if (internalPrivateKey == null) {
            throw new SignatureException("Internal private key not set");
        }

        // Get public key coordinates for Z value
        byte[] pubX, pubY;
        if (internalPublicKey != null && internalPublicKey.isLoaded()) {
            pubX = internalPublicKey.getX();
            pubY = internalPublicKey.getY();
        } else if (publicKey != null) {
            pubX = publicKey.getX();
            pubY = publicKey.getY();
        } else {
            throw new SignatureException(
                "Public key required for SM2 Z-value calculation. " +
                "This should have been auto-exported — check device connectivity.");
        }

        byte[] z = SM2Util.calculateZ(sessionHandle, userId, pubX, pubY);
        byte[] e = SM2Util.calculateE(sessionHandle, z, dataBytes);
        byte[] rawSignature = SDFJceNative.sm2InternalSign(
            sessionHandle, internalPrivateKey.getKeyIndex(), e);
        return DERCodec.rawToDer(rawSignature);
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (forSigning) {
            throw new SignatureException("Not initialized for verification");
        }

        byte[] dataBytes = data.toByteArray();
        data.reset();

        if (useInternalKey) {
            return verifyInternal(dataBytes, sigBytes);
        } else {
            return verifyExternal(dataBytes, sigBytes);
        }
    }

    private boolean verifyExternal(byte[] dataBytes, byte[] sigBytes) throws SignatureException {
        if (publicKey == null) {
            throw new SignatureException("Public key not set");
        }

        byte[] z = SM2Util.calculateZ(sessionHandle, userId, publicKey.getX(), publicKey.getY());

        // Calculate e = SM3(Z || M)
        byte[] e = SM2Util.calculateE(sessionHandle, z, dataBytes);

        // Convert signature to raw format (r||s, 64 bytes) from DER format
        byte[] rawSignature = DERCodec.derToRaw(sigBytes);

        // Verify the signature (expects r||s format, 64 bytes)
        return SDFJceNative.sm2Verify(sessionHandle, publicKey.getX(), publicKey.getY(), e, rawSignature);
    }

    private boolean verifyInternal(byte[] dataBytes, byte[] sigBytes) throws SignatureException {
        if (internalPublicKey == null) {
            throw new SignatureException("Internal public key not set");
        }

        // Use loaded coordinates for Z value
        byte[] pubX = internalPublicKey.getX();
        byte[] pubY = internalPublicKey.getY();

        byte[] z = SM2Util.calculateZ(sessionHandle, userId, pubX, pubY);
        byte[] e = SM2Util.calculateE(sessionHandle, z, dataBytes);
        byte[] rawSignature = DERCodec.derToRaw(sigBytes);
        return SDFJceNative.sm2InternalVerify(
            sessionHandle, internalPublicKey.getKeyIndex(), e, rawSignature);
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        if (params == null) {
            return;
        }

        if (params instanceof SM2ParameterSpec) {
            SM2ParameterSpec sm2Params = (SM2ParameterSpec) params;
            this.userId = sm2Params.getUserId();
            this.publicKey = sm2Params.getPublicKey();
        } else {
            throw new InvalidAlgorithmParameterException(
                "Parameters must be SM2ParameterSpec, got: " + params.getClass().getName());
        }
    }

    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new InvalidParameterException("Not supported");
    }

    @Override
    @Deprecated
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new InvalidParameterException("Not supported");
    }

    /**
     * Auto-acquire private key access right for Internal key.
     */
    private void acquirePrivateKeyAccessRight(SDFInternalPrivateKey key) throws InvalidKeyException {
        char[] pwd = key.getPassword();
        if (pwd != null) {
            byte[] pwdBytes = new byte[pwd.length];
            for (int i = 0; i < pwd.length; i++) {
                pwdBytes[i] = (byte) pwd[i];
            }
            try {
                SDFJceNative.getPrivateKeyAccessRight(sessionHandle, key.getKeyIndex(), pwdBytes);
            } catch (Exception e) {
                throw new InvalidKeyException("Failed to acquire private key access right: " + e.getMessage(), e);
            } finally {
                java.util.Arrays.fill(pwdBytes, (byte) 0);
                java.util.Arrays.fill(pwd, '\0');
            }
        }
    }

    /**
     * Ensure public key coordinates are available for Internal signing key.
     * Auto-exports from device if not yet loaded.
     */
    private void ensureInternalSignPublicKeyAvailable(SDFInternalPrivateKey privKey) throws InvalidKeyException {
        // If an explicit public key was set via setParameter(), use that
        if (publicKey != null) {
            return;
        }
        // If internalPublicKey is set and loaded, use that
        if (internalPublicKey != null && internalPublicKey.isLoaded()) {
            return;
        }

        // Auto-export sign public key from device
        try {
            byte[] pubKeyBytes;
            if (privKey.getUsage() == SDFInternalPrivateKey.KeyUsage.SIGN) {
                pubKeyBytes = SDFJceNative.exportSignPublicKeyECC(sessionHandle, privKey.getKeyIndex());
            } else {
                pubKeyBytes = SDFJceNative.exportEncPublicKeyECC(sessionHandle, privKey.getKeyIndex());
            }
            if (pubKeyBytes != null && pubKeyBytes.length == 64) {
                SDFInternalPublicKey iPub = new SDFInternalPublicKey(privKey.getKeyIndex(), privKey.getUsage());
                byte[] x = new byte[32], y = new byte[32];
                System.arraycopy(pubKeyBytes, 0, x, 0, 32);
                System.arraycopy(pubKeyBytes, 32, y, 0, 32);
                iPub.setCoordinates(x, y);
                this.internalPublicKey = iPub;
            }
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to export public key for Z-value calculation: " + e.getMessage(), e);
        }
    }

    /**
     * Ensure Internal public key coordinates are loaded from device.
     */
    private void ensureInternalPublicKeyLoaded(SDFInternalPublicKey key) throws InvalidKeyException {
        if (key.isLoaded()) {
            return;
        }
        try {
            byte[] pubKeyBytes;
            if (key.getUsage() == SDFInternalPrivateKey.KeyUsage.SIGN) {
                pubKeyBytes = SDFJceNative.exportSignPublicKeyECC(sessionHandle, key.getKeyIndex());
            } else {
                pubKeyBytes = SDFJceNative.exportEncPublicKeyECC(sessionHandle, key.getKeyIndex());
            }
            if (pubKeyBytes != null && pubKeyBytes.length == 64) {
                byte[] x = new byte[32], y = new byte[32];
                System.arraycopy(pubKeyBytes, 0, x, 0, 32);
                System.arraycopy(pubKeyBytes, 32, y, 0, 32);
                key.setCoordinates(x, y);
            } else {
                throw new InvalidKeyException("Failed to export public key from device");
            }
        } catch (InvalidKeyException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to load internal public key: " + e.getMessage(), e);
        }
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            releaseSession();
        } finally {
            super.finalize();
        }
    }
}
