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

package org.openhitls.sdf4j.constants;

/**
 * 算法标识符常量定义
 * Algorithm Identifier Constants (GM/T 0018-2023)
 *
 * <p>算法标识符编码规则（32位）：
 * <ul>
 *   <li>高16位：算法类型</li>
 *   <li>低16位：算法模式或变体</li>
 * </ul>
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
public final class AlgorithmID {

    private AlgorithmID() {
        // 禁止实例化
        throw new AssertionError("No AlgorithmID instances for you!");
    }

    // ========================================================================
    // 对称算法 (Symmetric Algorithms)
    // ========================================================================

    /**
     * SM1 算法 ECB 模式
     * SM1 algorithm ECB mode
     */
    public static final int SGD_SM1_ECB = 0x00000101;

    /**
     * SM1 算法 CBC 模式
     * SM1 algorithm CBC mode
     */
    public static final int SGD_SM1_CBC = 0x00000102;

    /**
     * SM1 算法 CFB 模式
     * SM1 algorithm CFB mode
     */
    public static final int SGD_SM1_CFB = 0x00000104;

    /**
     * SM1 算法 OFB 模式
     * SM1 algorithm OFB mode
     */
    public static final int SGD_SM1_OFB = 0x00000108;

    /**
     * SM1 算法 MAC 模式
     * SM1 algorithm MAC mode
     */
    public static final int SGD_SM1_MAC = 0x00000110;

    /**
     * SSF33 算法 ECB 模式
     * SSF33 algorithm ECB mode
     */
    public static final int SGD_SSF33_ECB = 0x00000201;

    /**
     * SSF33 算法 CBC 模式
     * SSF33 algorithm CBC mode
     */
    public static final int SGD_SSF33_CBC = 0x00000202;

    /**
     * SSF33 算法 CFB 模式
     * SSF33 algorithm CFB mode
     */
    public static final int SGD_SSF33_CFB = 0x00000204;

    /**
     * SSF33 算法 OFB 模式
     * SSF33 algorithm OFB mode
     */
    public static final int SGD_SSF33_OFB = 0x00000208;

    /**
     * SSF33 算法 MAC 模式
     * SSF33 algorithm MAC mode
     */
    public static final int SGD_SSF33_MAC = 0x00000210;

    /**
     * SM4 算法 ECB 模式
     * SM4 algorithm ECB mode
     */
    public static final int SGD_SM4_ECB = 0x00000401;

    /**
     * SM4 算法 CBC 模式
     * SM4 algorithm CBC mode
     */
    public static final int SGD_SM4_CBC = 0x00000402;

    /**
     * SM4 算法 CFB 模式
     * SM4 algorithm CFB mode
     */
    public static final int SGD_SM4_CFB = 0x00000404;

    /**
     * SM4 算法 OFB 模式
     * SM4 algorithm OFB mode
     */
    public static final int SGD_SM4_OFB = 0x00000408;

    /**
     * SM4 算法 MAC 模式
     * SM4 algorithm MAC mode
     */
    public static final int SGD_SM4_MAC = 0x00000410;

    /**
     * SM4 算法 GCM 模式 (GM/T 0018-2023 新增)
     * SM4 algorithm GCM mode (added in GM/T 0018-2023)
     */
    public static final int SGD_SM4_GCM = 0x02000400;

    /**
     * SM4 算法 CCM 模式 (GM/T 0018-2023 新增)
     * SM4 algorithm CCM mode (added in GM/T 0018-2023)
     */
    public static final int SGD_SM4_CCM = 0x04000400;

    /**
     * SM4 算法 XTS 模式 (GM/T 0018-2023 新增)
     * SM4 algorithm XTS mode (added in GM/T 0018-2023)
     */
    public static final int SGD_SM4_XTS = 0x02000402;

    /**
     * SM4 算法 CTR 模式 (GM/T 0018-2023 新增)
     * SM4 algorithm CTR mode (added in GM/T 0018-2023)
     */
    public static final int SGD_SM4_CTR = 0x00000420;

    // ========================================================================
    // 非对称算法 (Asymmetric Algorithms)
    // ========================================================================

    /**
     * RSA 算法
     * RSA algorithm
     */
    public static final int SGD_RSA = 0x00010000;

    /**
     * SM2 椭圆曲线密码算法
     * SM2 elliptic curve cryptography algorithm
     */
    public static final int SGD_SM2 = 0x00020100;

    /**
     * SM2 椭圆曲线签名算法
     * SM2 elliptic curve sign algorithm
     */
    public static final int SGD_SM2_1 = 0x00020200;

    /**
     * SM2 椭圆曲线密钥交换协议
     * SM2 elliptic curve key exchange protocol
     */
    public static final int SGD_SM2_2 = 0x00020400;

    /**
     * SM2 椭圆曲线加密算法
     * SM2 elliptic curve encryption algorithm
     */
    public static final int SGD_SM2_3 = 0x00020800;

    // ========================================================================
    // 杂凑算法 (Hash Algorithms)
    // ========================================================================

    /**
     * SM3 密码杂凑算法
     * SM3 cryptographic hash algorithm
     */
    public static final int SGD_SM3 = 0x00000001;

    /**
     * SHA-1 杂凑算法
     * SHA-1 hash algorithm
     */
    public static final int SGD_SHA1 = 0x00000002;

    /**
     * SHA-224 杂凑算法
     * SHA-224 hash algorithm
     */
    public static final int SGD_SHA224 = 0x00000003;

    /**
     * SHA-256 杂凑算法
     * SHA-256 hash algorithm
     */
    public static final int SGD_SHA256 = 0x00000004;

    /**
     * SHA-384 杂凑算法
     * SHA-384 hash algorithm
     */
    public static final int SGD_SHA384 = 0x00000005;

    /**
     * SHA-512 杂凑算法
     * SHA-512 hash algorithm
     */
    public static final int SGD_SHA512 = 0x00000006;

    /**
     * SHA-512/224 杂凑算法
     * SHA-512/224 hash algorithm
     */
    public static final int SGD_SHA512_224 = 0x00000007;

    /**
     * SHA-512/256 杂凑算法
     * SHA-512/256 hash algorithm
     */
    public static final int SGD_SHA512_256 = 0x00000008;

    // ========================================================================
    // SM9 算法 (SM9 Algorithms)
    // ========================================================================

    /**
     * SM9 基于标识的签名算法
     * SM9 identity-based sign algorithm
     */
    public static final int SGD_SM9_1 = 0x00080100;

    /**
     * SM9 基于标识的密钥交换协议
     * SM9 identity-based key exchange protocol
     */
    public static final int SGD_SM9_2 = 0x00080200;

    /**
     * SM9 基于标识的加密算法
     * SM9 identity-based encryption algorithm
     */
    public static final int SGD_SM9_3 = 0x00080400;

    // 扩展算法id支持

    /**
     * SM2 椭圆曲线解密算法
     */
    public static final int SGD_SM2_DECRYPT = 0x00020801;

    /**
     * SM3 密码杂凑算法 HMAC
     */
    public static final int SGD_SM3_HMAC = 0x00100001;

    /**
     * Post-quantum hybrid algorithm
     */
    public static final int SGD_HYBRID = 0x00000FFF;

    /**
     * Hybrid envelope: SM2 + ML-KEM-512
     *
     * <p>Combines SM2 elliptic curve key encapsulation with ML-KEM-512
     * post-quantum key encapsulation mechanism.
     */
    public static final int SGD_HYBRID_ENV_SM2_MLKEM_512 = 0x80000000;

    /**
     * Hybrid envelope: SM2 + ML-KEM-768
     *
     * <p>Combines SM2 elliptic curve key encapsulation with ML-KEM-768
     * post-quantum key encapsulation mechanism.
     */
    public static final int SGD_HYBRID_ENV_SM2_MLKEM_768 = 0x80000001;

    /**
     * Hybrid envelope: SM2 + ML-KEM-1024
     *
     * <p>Combines SM2 elliptic curve key encapsulation with ML-KEM-1024
     * post-quantum key encapsulation mechanism.
     */
    public static final int SGD_HYBRID_ENV_SM2_MLKEM_1024 = 0x80000002;

    /**
     * Hybrid envelope: SM2 + POLAR-LAC-LIGHT
     *
     * <p>Combines SM2 elliptic curve key encapsulation with POLAR-LAC-LIGHT
     * lattice-based post-quantum key encapsulation mechanism.
     */
    public static final int SGD_HYBRID_ENV_SM2_POLAR_LAC_LIGHT = 0x80000003;

    /**
     * Composite signature: ML-DSA-44 + SM2
     *
     * <p>Combines ML-DSA-44 (NIST security level 2) post-quantum digital
     * signature with SM2 elliptic curve digital signature.
     */
    public static final int SGD_COMPOSITE_MLDSA44_SM2 = 0x80000004;

    /**
     * Composite signature: ML-DSA-65 + SM2
     *
     * <p>Combines ML-DSA-65 (NIST security level 3) post-quantum digital
     * signature with SM2 elliptic curve digital signature.
     */
    public static final int SGD_COMPOSITE_MLDSA65_SM2 = 0x80000005;

    /**
     * Composite signature: ML-DSA-87 + SM2
     *
     * <p>Combines ML-DSA-87 (NIST security level 5) post-quantum digital
     * signature with SM2 elliptic curve digital signature.
     */
    public static final int SGD_COMPOSITE_MLDSA87_SM2 = 0x80000006;

    // ========================================================================
    // 工具方法 (Utility Methods)
    // ========================================================================

    /**
     * 获取算法名称
     *
     * @param algorithmID 算法标识符
     * @return 算法名称字符串
     */
    public static String getAlgorithmName(int algorithmID) {
        switch (algorithmID) {
            // SM1
            case SGD_SM1_ECB:
                return "SM1-ECB";
            case SGD_SM1_CBC:
                return "SM1-CBC";
            case SGD_SM1_CFB:
                return "SM1-CFB";
            case SGD_SM1_OFB:
                return "SM1-OFB";
            case SGD_SM1_MAC:
                return "SM1-MAC";

            // SSF33
            case SGD_SSF33_ECB:
                return "SSF33-ECB";
            case SGD_SSF33_CBC:
                return "SSF33-CBC";
            case SGD_SSF33_CFB:
                return "SSF33-CFB";
            case SGD_SSF33_OFB:
                return "SSF33-OFB";
            case SGD_SSF33_MAC:
                return "SSF33-MAC";

            // SM4
            case SGD_SM4_ECB:
                return "SM4-ECB";
            case SGD_SM4_CBC:
                return "SM4-CBC";
            case SGD_SM4_CFB:
                return "SM4-CFB";
            case SGD_SM4_OFB:
                return "SM4-OFB";
            case SGD_SM4_MAC:
                return "SM4-MAC";
            case SGD_SM4_GCM:
                return "SM4-GCM";
            case SGD_SM4_CCM:
                return "SM4-CCM";
            case SGD_SM4_XTS:
                return "SM4-XTS";
            case SGD_SM4_CTR:
                return "SM4-CTR";

            // RSA
            case SGD_RSA:
                return "RSA";

            // SM2
            case SGD_SM2:
                return "SM2";
            case SGD_SM2_1:
                return "SM2-Sign";
            case SGD_SM2_2:
                return "SM2-KeyExchange";
            case SGD_SM2_3:
                return "SM2-Encrypt";

            // Hash
            case SGD_SM3:
                return "SM3";
            case SGD_SHA1:
                return "SHA1";
            case SGD_SHA224:
                return "SHA224";
            case SGD_SHA256:
                return "SHA256";
            case SGD_SHA384:
                return "SHA384";
            case SGD_SHA512:
                return "SHA512";
            case SGD_SHA512_224:
                return "SHA512/224";
            case SGD_SHA512_256:
                return "SHA512/256";

            // SM9
            case SGD_SM9_1:
                return "SM9-Sign";
            case SGD_SM9_2:
                return "SM9-KeyExchange";
            case SGD_SM9_3:
                return "SM9-Encrypt";

            // 扩展算法id支持
            case SGD_SM2_DECRYPT:
                return "SM2-Decrypt";
            case SGD_SM3_HMAC:
                return "SM3-HMAC";
            case SGD_HYBRID_ENV_SM2_MLKEM_512:
                return "HYBRID-ENV-SM2-MLKEM-512";
            case SGD_HYBRID_ENV_SM2_MLKEM_768:
                return "HYBRID-ENV-SM2-MLKEM-768";
            case SGD_HYBRID_ENV_SM2_MLKEM_1024:
                return "HYBRID-ENV-SM2-MLKEM-1024";
            case SGD_HYBRID_ENV_SM2_POLAR_LAC_LIGHT:
                return "HYBRID-ENV-SM2-POLAR-LAC-LIGHT";
            case SGD_COMPOSITE_MLDSA44_SM2:
                return "COMPOSITE-MLDSA44-SM2";
            case SGD_COMPOSITE_MLDSA65_SM2:
                return "COMPOSITE-MLDSA65-SM2";
            case SGD_COMPOSITE_MLDSA87_SM2:
                return "COMPOSITE-MLDSA87-SM2";
            default:
                return "Unknown(0x" + Integer.toHexString(algorithmID).toUpperCase() + ")";
        }
    }

    /**
     * 判断是否为对称算法
     *
     * @param algorithmID 算法标识符
     * @return 如果是对称算法返回true
     */
    public static boolean isSymmetricAlgorithm(int algorithmID) {
        int type = (algorithmID >> 16) & 0xFFFF;
        return type == 0x0000 || type == 0x0200;
    }

    /**
     * 判断是否为非对称算法
     *
     * @param algorithmID 算法标识符
     * @return 如果是非对称算法返回true
     */
    public static boolean isAsymmetricAlgorithm(int algorithmID) {
        int type = (algorithmID >> 16) & 0xFFFF;
        return type == 0x0001 || type == 0x0002 || type == 0x0008;
    }

    /**
     * 判断是否为杂凑算法
     *
     * @param algorithmID 算法标识符
     * @return 如果是杂凑算法返回true
     */
    public static boolean isHashAlgorithm(int algorithmID) {
        return algorithmID >= 0x00000001 && algorithmID <= 0x00000008;
    }
}
