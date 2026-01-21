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
import org.openhitls.sdf4j.jce.native_.SDFJceNative;
import org.openhitls.sdf4j.jce.spec.SM2ParameterSpec;
import org.openhitls.sdf4j.jce.util.SM2Util;

/**
 * SM2 Signature implementation (SM3withSM2)
 *
 * This implementation follows GM/T 0009-2012 standard for SM2 signature:
 * 1. Calculate Z = SM3(ENTLA || IDA || a || b || xG || yG || xA || yA)
 * 2. Calculate e = SM3(Z || M)
 * 3. Sign e using SM2 algorithm
 *
 * The public key is required for Z value calculation. It can be provided via:
 * - SM2ParameterSpec when calling setParameter()
 * - Directly when calling initVerify() with SM2PublicKey
 *
 * For signing, the public key must be set via SM2ParameterSpec before signing,
 * or the signature will fail.
 */
public final class SM2Signature extends SignatureSpi {

    private SM2PrivateKey privateKey;
    private SM2PublicKey publicKey;
    private ByteArrayOutputStream data;
    private boolean forSigning;
    private byte[] userId = SM2ParameterSpec.DEFAULT_USER_ID;

    public SM2Signature() {
        this.data = new ByteArrayOutputStream();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof SM2PublicKey)) {
            throw new InvalidKeyException("Key must be SM2PublicKey");
        }
        this.publicKey = (SM2PublicKey) publicKey;
        this.privateKey = null;
        this.forSigning = false;
        this.data.reset();
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof SM2PrivateKey)) {
            throw new InvalidKeyException("Key must be SM2PrivateKey");
        }
        this.privateKey = (SM2PrivateKey) privateKey;
        // Note: Do NOT reset publicKey here - it may have been set via setParameter()
        // and is required for Z value calculation during signing
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
        if (!forSigning || privateKey == null) {
            throw new SignatureException("Not initialized for signing");
        }

        if (publicKey == null) {
            throw new SignatureException(
                "Public key required for SM2 signature. " +
                "Use setParameter(SM2ParameterSpec) to provide the public key before signing.");
        }

        byte[] dataBytes = data.toByteArray();
        data.reset();

        // Calculate Z value according to GM/T 0009-2012
        byte[] z = SM2Util.calculateZ(userId, publicKey.getX(), publicKey.getY());

        // Calculate e = SM3(Z || M)
        byte[] e = SM2Util.calculateE(z, dataBytes);

        // Sign the hash e
        return SDFJceNative.sm2Sign(privateKey.getKeyBytes(), e);
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (forSigning || publicKey == null) {
            throw new SignatureException("Not initialized for verification");
        }

        byte[] dataBytes = data.toByteArray();
        data.reset();

        // Calculate Z value according to GM/T 0009-2012
        byte[] z = SM2Util.calculateZ(userId, publicKey.getX(), publicKey.getY());

        // Calculate e = SM3(Z || M)
        byte[] e = SM2Util.calculateE(z, dataBytes);

        // Verify the signature
        return SDFJceNative.sm2Verify(publicKey.getX(), publicKey.getY(), e, sigBytes);
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
}
