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

package org.openhitls.sdf4j;

import org.openhitls.sdf4j.internal.NativeLibraryLoader;
import org.openhitls.sdf4j.types.*;

/**
 * SDF主接口类
 * SDF Main Interface (GM/T 0018-2023)
 *
 * <p>提供符合GM/T 0018-2023标准的密码设备应用接口
 * <p>Provides GM/T 0018-2023 compliant cryptographic device application interface
 *
 * <p>使用示例 / Usage Example:
 * <pre>{@code
 * // 加载本地库
 * NativeLibraryLoader.loadLibrary();
 *
 * // 创建SDF实例
 * SDF sdf = new SDF();
 *
 * // 打开设备
 * long deviceHandle = sdf.SDF_OpenDevice();
 *
 * // 打开会话
 * long sessionHandle = sdf.SDF_OpenSession(deviceHandle);
 *
 * // 获取设备信息
 * DeviceInfo info = sdf.SDF_GetDeviceInfo(sessionHandle);
 *
 * // 关闭会话和设备
 * sdf.SDF_CloseSession(sessionHandle);
 * sdf.SDF_CloseDevice(deviceHandle);
 * }</pre>
 *
 * @author OpenHitls Team
 * @since 1.0.0
 */
public class SDF {

    static {
        // 加载本地库
        NativeLibraryLoader.loadLibrary();
    }

    // ========================================================================
    // 6.2 设备管理类函数 (Device Management Functions)
    // ========================================================================

    /**
     * 6.2.2 打开设备
     * Open Device
     *
     * @return 设备句柄 / Device handle
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native long SDF_OpenDevice() throws SDFException;

    /**
     * 6.2.3 关闭设备
     * Close Device
     *
     * @param deviceHandle 设备句柄 / Device handle
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native void SDF_CloseDevice(long deviceHandle) throws SDFException;

    /**
     * 6.2.4 创建会话
     * Open Session
     *
     * @param deviceHandle 设备句柄 / Device handle
     * @return 会话句柄 / Session handle
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native long SDF_OpenSession(long deviceHandle) throws SDFException;

    /**
     * 6.2.5 关闭会话
     * Close Session
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native void SDF_CloseSession(long sessionHandle) throws SDFException;

    /**
     * 6.2.6 获取设备信息
     * Get Device Information
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @return 设备信息对象 / Device information object
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native DeviceInfo SDF_GetDeviceInfo(long sessionHandle) throws SDFException;

    /**
     * 6.2.7 产生随机数
     * Generate Random
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param length        随机数长度（字节）/ Random number length (bytes)
     * @return 随机数字节数组 / Random number byte array
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native byte[] SDF_GenerateRandom(long sessionHandle, int length) throws SDFException;

    /**
     * 6.2.8 获取私钥使用权限
     * Get Private Key Access Right
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyIndex      密钥索引号 / Key index
     * @param password      授权口令 / Authorization password
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native void SDF_GetPrivateKeyAccessRight(long sessionHandle, int keyIndex, String password)
            throws SDFException;

    /**
     * 6.2.9 释放私钥使用权限
     * Release Private Key Access Right
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyIndex      密钥索引号 / Key index
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native void SDF_ReleasePrivateKeyAccessRight(long sessionHandle, int keyIndex) throws SDFException;

    // ========================================================================
    // 6.3 密钥管理类函数 (Key Management Functions)
    // ========================================================================

    /**
     * 6.3.2 导出RSA签名公钥
     * Export RSA Sign Public Key
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyIndex      密钥索引号 / Key index
     * @return RSA公钥对象 / RSA public key object
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native RSAPublicKey SDF_ExportSignPublicKey_RSA(long sessionHandle, int keyIndex) throws SDFException;

    /**
     * 6.3.3 导出RSA加密公钥
     * Export RSA Encryption Public Key
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyIndex      密钥索引号 / Key index
     * @return RSA公钥对象 / RSA public key object
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native RSAPublicKey SDF_ExportEncPublicKey_RSA(long sessionHandle, int keyIndex) throws SDFException;

    /**
     * 6.3.7 导出ECC签名公钥
     * Export ECC Sign Public Key
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyIndex      密钥索引号 / Key index
     * @return ECC公钥对象 / ECC public key object
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native ECCPublicKey SDF_ExportSignPublicKey_ECC(long sessionHandle, int keyIndex) throws SDFException;

    /**
     * 6.3.8 导出ECC加密公钥
     * Export ECC Encryption Public Key
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyIndex      密钥索引号 / Key index
     * @return ECC公钥对象 / ECC public key object
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native ECCPublicKey SDF_ExportEncPublicKey_ECC(long sessionHandle, int keyIndex) throws SDFException;

    /**
     * 6.3.4 生成会话密钥并用内部RSA公钥加密输出
     * Generate Key With IPK RSA
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyIndex      内部公钥索引 / Internal public key index
     * @param keyBits       密钥长度（位）/ Key length in bits
     * @return 密钥加密结果（包含加密密钥和密钥句柄）/ Key encryption result
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native KeyEncryptionResult SDF_GenerateKeyWithIPK_RSA(
            long sessionHandle, int keyIndex, int keyBits) throws SDFException;

    /**
     * 6.3.5 生成会话密钥并用外部RSA公钥加密输出
     * Generate Key With EPK RSA
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyBits       密钥长度（位）/ Key length in bits
     * @param publicKey     外部RSA公钥 / External RSA public key
     * @return 密钥加密结果（包含加密密钥和密钥句柄）/ Key encryption result
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native KeyEncryptionResult SDF_GenerateKeyWithEPK_RSA(
            long sessionHandle, int keyBits, RSAPublicKey publicKey) throws SDFException;

    /**
     * 6.3.6 导入会话密钥并用内部RSA私钥解密
     * Import Key With ISK RSA
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyIndex      内部私钥索引 / Internal private key index
     * @param encryptedKey  加密的密钥数据 / Encrypted key data
     * @return 密钥句柄 / Key handle
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native long SDF_ImportKeyWithISK_RSA(
            long sessionHandle, int keyIndex, byte[] encryptedKey) throws SDFException;

    /**
     * 6.3.9 生成会话密钥并用内部ECC公钥加密输出
     * Generate Key With IPK ECC
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyIndex      内部公钥索引 / Internal public key index
     * @param keyBits       密钥长度（位）/ Key length in bits
     * @return ECC密钥密文和密钥句柄 / ECC cipher and key handle
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native KeyEncryptionResult SDF_GenerateKeyWithIPK_ECC(
            long sessionHandle, int keyIndex, int keyBits) throws SDFException;

    /**
     * 6.3.10 生成会话密钥并用外部ECC公钥加密输出
     * Generate Key With EPK ECC
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyBits       密钥长度（位）/ Key length in bits
     * @param algID         算法标识 / Algorithm ID
     * @param publicKey     外部ECC公钥 / External ECC public key
     * @return ECC密钥密文和密钥句柄 / ECC cipher and key handle
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native KeyEncryptionResult SDF_GenerateKeyWithEPK_ECC(
            long sessionHandle, int keyBits, int algID, ECCPublicKey publicKey) throws SDFException;

    /**
     * 6.3.11 导入会话密钥并用内部ECC私钥解密
     * Import Key With ISK ECC
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyIndex      内部私钥索引 / Internal private key index
     * @param cipher        ECC密文 / ECC cipher
     * @return 密钥句柄 / Key handle
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native long SDF_ImportKeyWithISK_ECC(
            long sessionHandle, int keyIndex, ECCCipher cipher) throws SDFException;

    /**
     * 6.3.12 生成密钥协商参数并输出
     * Generate Agreement Data With ECC
     *
     * @param sessionHandle     会话句柄 / Session handle
     * @param keyIndex          内部私钥索引 / Internal private key index
     * @param keyBits           密钥长度（位）/ Key length in bits
     * @param sponsorID         发起方ID / Sponsor ID
     * @param sponsorPublicKey  发起方公钥 / Sponsor public key
     * @param sponsorTmpPublicKey 发起方临时公钥 / Sponsor temporary public key
     * @return 协商句柄 / Agreement handle
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native long SDF_GenerateAgreementDataWithECC(
            long sessionHandle, int keyIndex, int keyBits,
            byte[] sponsorID, ECCPublicKey sponsorPublicKey,
            ECCPublicKey sponsorTmpPublicKey) throws SDFException;

    /**
     * 6.3.13 计算会话密钥
     * Generate Key With ECC
     *
     * @param sessionHandle       会话句柄 / Session handle
     * @param responseID          响应方ID / Response ID
     * @param responsePublicKey   响应方公钥 / Response public key
     * @param responseTmpPublicKey 响应方临时公钥 / Response temporary public key
     * @param agreementHandle     协商句柄 / Agreement handle
     * @return 密钥句柄 / Key handle
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native long SDF_GenerateKeyWithECC(
            long sessionHandle, byte[] responseID,
            ECCPublicKey responsePublicKey, ECCPublicKey responseTmpPublicKey,
            long agreementHandle) throws SDFException;

    /**
     * 6.3.14 产生协商数据并计算会话密钥
     * Generate Agreement Data And Key With ECC
     *
     * @param sessionHandle       会话句柄 / Session handle
     * @param keyIndex            内部私钥索引 / Internal private key index
     * @param keyBits             密钥长度（位）/ Key length in bits
     * @param responseID          响应方ID / Response ID
     * @param sponsorID           发起方ID / Sponsor ID
     * @param sponsorPublicKey    发起方公钥 / Sponsor public key
     * @param sponsorTmpPublicKey 发起方临时公钥 / Sponsor temporary public key
     * @param responsePublicKey   响应方公钥 / Response public key
     * @param responseTmpPublicKey 响应方临时公钥 / Response temporary public key
     * @return 密钥句柄 / Key handle
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native long SDF_GenerateAgreementDataAndKeyWithECC(
            long sessionHandle, int keyIndex, int keyBits,
            byte[] responseID, byte[] sponsorID,
            ECCPublicKey sponsorPublicKey, ECCPublicKey sponsorTmpPublicKey,
            ECCPublicKey responsePublicKey, ECCPublicKey responseTmpPublicKey) throws SDFException;

    /**
     * 6.3.15 生成会话密钥并用密钥加密密钥加密输出
     * Generate Key With KEK
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyBits       密钥长度（位）/ Key length in bits
     * @param algID         算法标识 / Algorithm ID
     * @param kekIndex      密钥加密密钥索引 / KEK index
     * @return 密钥加密结果（包含加密密钥和密钥句柄）/ Key encryption result
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native KeyEncryptionResult SDF_GenerateKeyWithKEK(
            long sessionHandle, int keyBits, int algID, int kekIndex) throws SDFException;

    /**
     * 6.3.16 导入会话密钥并用密钥加密密钥解密
     * Import Key With KEK
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param algID         算法标识 / Algorithm ID
     * @param kekIndex      密钥加密密钥索引 / KEK index
     * @param encryptedKey  加密的密钥数据 / Encrypted key data
     * @return 密钥句柄 / Key handle
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native long SDF_ImportKeyWithKEK(
            long sessionHandle, int algID, int kekIndex, byte[] encryptedKey) throws SDFException;

    /**
     * 6.3.17 销毁会话密钥
     * Destroy Key
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyHandle     密钥句柄 / Key handle
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native void SDF_DestroyKey(long sessionHandle, long keyHandle) throws SDFException;

    // ========================================================================
    // 6.4 非对称算法运算类函数 (Asymmetric Algorithm Functions)
    // ========================================================================

    /**
     * 6.4.2 外部公钥RSA运算
     * External Public Key Operation RSA
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param publicKey     RSA公钥 / RSA public key
     * @param dataInput     输入数据 / Input data
     * @return 输出数据 / Output data
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native byte[] SDF_ExternalPublicKeyOperation_RSA(
            long sessionHandle, RSAPublicKey publicKey, byte[] dataInput) throws SDFException;

    /**
     * 6.4.3 内部公钥RSA运算
     * Internal Public Key Operation RSA
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyIndex      公钥索引号 / Public key index
     * @param dataInput     输入数据 / Input data
     * @return 输出数据 / Output data
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native byte[] SDF_InternalPublicKeyOperation_RSA(
            long sessionHandle, int keyIndex, byte[] dataInput) throws SDFException;

    /**
     * 6.4.4 内部私钥RSA运算
     * Internal Private Key Operation RSA
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyIndex      私钥索引号 / Private key index
     * @param dataInput     输入数据 / Input data
     * @return 输出数据 / Output data
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native byte[] SDF_InternalPrivateKeyOperation_RSA(
            long sessionHandle, int keyIndex, byte[] dataInput) throws SDFException;

    /**
     * 6.4.6 内部私钥ECC签名
     * Internal Sign ECC
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyIndex      私钥索引号 / Private key index
     * @param data          待签名数据 / Data to be signed
     * @return ECC签名对象 / ECC signature object
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native ECCSignature SDF_InternalSign_ECC(long sessionHandle, int keyIndex, byte[] data)
            throws SDFException;

    /**
     * 6.4.7 内部公钥ECC验证
     * Internal Verify ECC
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyIndex      公钥索引号 / Public key index
     * @param data          原始数据 / Original data
     * @param signature     ECC签名 / ECC signature
     * @throws SDFException 如果操作失败或验证失败 / if operation fails or verification fails
     */
    public native void SDF_InternalVerify_ECC(long sessionHandle, int keyIndex, byte[] data, ECCSignature signature)
            throws SDFException;

    /**
     * 6.4.5 外部公钥ECC验证
     * External Verify ECC
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param algID         算法标识 / Algorithm ID
     * @param publicKey     ECC公钥 / ECC public key
     * @param data          原始数据 / Original data
     * @param signature     ECC签名 / ECC signature
     * @throws SDFException 如果操作失败或验证失败 / if operation fails or verification fails
     */
    public native void SDF_ExternalVerify_ECC(long sessionHandle, int algID, ECCPublicKey publicKey,
                                               byte[] data, ECCSignature signature) throws SDFException;

    /**
     * 6.4.8 外部公钥ECC加密
     * External Encrypt ECC
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param algID         算法标识 / Algorithm ID
     * @param publicKey     ECC公钥 / ECC public key
     * @param data          待加密数据 / Data to be encrypted
     * @return ECC密文对象 / ECC cipher object
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native ECCCipher SDF_ExternalEncrypt_ECC(long sessionHandle, int algID, ECCPublicKey publicKey, byte[] data)
            throws SDFException;

    /**
     * 6.4.9 内部公钥ECC加密
     * Internal Encrypt ECC
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyIndex      内部加密公钥索引号 / Internal encryption public key index
     * @param data          待加密数据 / Data to be encrypted
     * @return ECC密文对象 / ECC cipher object
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native ECCCipher SDF_InternalEncrypt_ECC(long sessionHandle, int keyIndex, byte[] data)
            throws SDFException;

    /**
     * 6.4.10 内部私钥ECC解密
     * Internal Decrypt ECC
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyIndex      内部加密私钥索引号 / Internal encryption private key index
     * @param eccKeyType    私钥使用类型（算法ID，如SGD_SM2_1等）/ Private key usage type (algorithm ID)
     * @param cipher        ECC密文 / ECC cipher
     * @return 明文数据 / Decrypted data
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native byte[] SDF_InternalDecrypt_ECC(long sessionHandle, int keyIndex, int eccKeyType, ECCCipher cipher)
            throws SDFException;

    // ========================================================================
    // 6.5 对称算法运算类函数 (Symmetric Algorithm Functions)
    // ========================================================================

    /**
     * 6.5.2 单包对称加密
     * Encrypt
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyHandle     密钥句柄 / Key handle
     * @param algID         算法标识 / Algorithm ID
     * @param iv            初始向量（可为null）/ Initialization vector (can be null)
     * @param data          待加密数据 / Data to be encrypted
     * @return 密文数据 / Encrypted data
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native byte[] SDF_Encrypt(long sessionHandle, long keyHandle, int algID, byte[] iv, byte[] data)
            throws SDFException;

    /**
     * 6.5.3 单包对称解密
     * Decrypt
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyHandle     密钥句柄 / Key handle
     * @param algID         算法标识 / Algorithm ID
     * @param iv            初始向量（可为null）/ Initialization vector (can be null)
     * @param encData       密文数据 / Encrypted data
     * @return 明文数据 / Decrypted data
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native byte[] SDF_Decrypt(long sessionHandle, long keyHandle, int algID, byte[] iv, byte[] encData)
            throws SDFException;

    /**
     * 6.5.4 计算单包MAC
     * Calculate MAC
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyHandle     密钥句柄 / Key handle
     * @param algID         算法标识 / Algorithm ID
     * @param iv            初始向量（可为null）/ Initialization vector (can be null)
     * @param data          待计算MAC的数据 / Data for MAC calculation
     * @return MAC值 / MAC value
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native byte[] SDF_CalculateMAC(long sessionHandle, long keyHandle, int algID, byte[] iv, byte[] data)
            throws SDFException;

    /**
     * 6.5.5 单包可鉴别加密
     * Authenticated Encryption
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyHandle     密钥句柄 / Key handle
     * @param algID         算法标识 / Algorithm ID
     * @param iv            初始向量 / Initialization vector
     * @param aad           附加认证数据 / Additional authenticated data
     * @param data          待加密数据 / Data to be encrypted
     * @return 包含密文和认证标签的结果数组 / Result containing ciphertext and auth tag
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native byte[][] SDF_AuthEnc(long sessionHandle, long keyHandle, int algID,
                                       byte[] iv, byte[] aad, byte[] data) throws SDFException;

    /**
     * 6.5.6 单包可鉴别解密
     * Authenticated Decryption
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyHandle     密钥句柄 / Key handle
     * @param algID         算法标识 / Algorithm ID
     * @param iv            初始向量 / Initialization vector
     * @param aad           附加认证数据 / Additional authenticated data
     * @param authTag       认证标签 / Authentication tag
     * @param encData       密文数据 / Encrypted data
     * @return 明文数据 / Decrypted data
     * @throws SDFException 如果操作失败或认证失败 / if operation fails or auth fails
     */
    public native byte[] SDF_AuthDec(long sessionHandle, long keyHandle, int algID,
                                     byte[] iv, byte[] aad, byte[] authTag, byte[] encData) throws SDFException;

    /**
     * 6.5.7 多包对称加密初始化
     * Encrypt Init
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyHandle     密钥句柄 / Key handle
     * @param algID         算法标识 / Algorithm ID
     * @param iv            初始向量 / Initialization vector
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native void SDF_EncryptInit(long sessionHandle, long keyHandle, int algID, byte[] iv)
            throws SDFException;

    /**
     * 6.5.8 多包对称加密
     * Encrypt Update
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param data          待加密数据 / Data to be encrypted
     * @return 密文数据 / Encrypted data
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native byte[] SDF_EncryptUpdate(long sessionHandle, byte[] data) throws SDFException;

    /**
     * 6.5.9 多包对称加密结束
     * Encrypt Final
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @return 最后的密文数据 / Final encrypted data
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native byte[] SDF_EncryptFinal(long sessionHandle) throws SDFException;

    /**
     * 6.5.10 多包对称解密初始化
     * Decrypt Init
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyHandle     密钥句柄 / Key handle
     * @param algID         算法标识 / Algorithm ID
     * @param iv            初始向量 / Initialization vector
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native void SDF_DecryptInit(long sessionHandle, long keyHandle, int algID, byte[] iv)
            throws SDFException;

    /**
     * 6.5.11 多包对称解密
     * Decrypt Update
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param encData       密文数据 / Encrypted data
     * @return 明文数据 / Decrypted data
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native byte[] SDF_DecryptUpdate(long sessionHandle, byte[] encData) throws SDFException;

    /**
     * 6.5.12 多包对称解密结束
     * Decrypt Final
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @return 最后的明文数据 / Final decrypted data
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native byte[] SDF_DecryptFinal(long sessionHandle) throws SDFException;

    /**
     * 6.5.13 多包MAC初始化
     * Calculate MAC Init
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyHandle     密钥句柄 / Key handle
     * @param algID         算法标识 / Algorithm ID
     * @param iv            初始向量 / Initialization vector
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native void SDF_CalculateMACInit(long sessionHandle, long keyHandle, int algID, byte[] iv)
            throws SDFException;

    /**
     * 6.5.14 多包MAC计算
     * Calculate MAC Update
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param data          数据 / Data
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native void SDF_CalculateMACUpdate(long sessionHandle, byte[] data) throws SDFException;

    /**
     * 6.5.15 多包MAC结束
     * Calculate MAC Final
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @return MAC值 / MAC value
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native byte[] SDF_CalculateMACFinal(long sessionHandle) throws SDFException;

    /**
     * 6.5.16 多包可鉴别加密初始化
     * Auth Encrypt Init
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyHandle     密钥句柄 / Key handle
     * @param algID         算法标识 / Algorithm ID
     * @param iv            初始向量 / Initialization vector
     * @param aad           附加认证数据 / Additional authenticated data
     * @param dataLength    待加密数据总长度 / Total data length
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native void SDF_AuthEncInit(long sessionHandle, long keyHandle, int algID,
                                       byte[] iv, byte[] aad, int dataLength) throws SDFException;

    /**
     * 6.5.17 多包可鉴别加密
     * Auth Encrypt Update
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param data          待加密数据 / Data to be encrypted
     * @return 密文数据 / Encrypted data
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native byte[] SDF_AuthEncUpdate(long sessionHandle, byte[] data) throws SDFException;

    /**
     * 6.5.18 多包可鉴别加密结束
     * Auth Encrypt Final
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param pucEncData    加密数据缓冲区 / Encrypted data buffer
     * @return 包含最后密文和认证标签的结果数组 / Result containing final ciphertext and auth tag
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native byte[][] SDF_AuthEncFinal(long sessionHandle, byte[] pucEncData) throws SDFException;

    /**
     * 6.5.19 多包可鉴别解密初始化
     * Auth Decrypt Init
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyHandle     密钥句柄 / Key handle
     * @param algID         算法标识 / Algorithm ID
     * @param iv            初始向量 / Initialization vector
     * @param aad           附加认证数据 / Additional authenticated data
     * @param authTag       认证标签 / Authentication tag
     * @param dataLength    待解密数据总长度 / Total data length
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native void SDF_AuthDecInit(long sessionHandle, long keyHandle, int algID,
                                       byte[] iv, byte[] aad, byte[] authTag, int dataLength) throws SDFException;

    /**
     * 6.5.20 多包可鉴别解密
     * Auth Decrypt Update
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param encData       密文数据 / Encrypted data
     * @return 明文数据 / Decrypted data
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native byte[] SDF_AuthDecUpdate(long sessionHandle, byte[] encData) throws SDFException;

    /**
     * 6.5.21 多包可鉴别解密结束
     * Auth Decrypt Final
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @return 最后的明文数据 / Final decrypted data
     * @throws SDFException 如果操作失败或认证失败 / if operation fails or auth fails
     */
    public native byte[] SDF_AuthDecFinal(long sessionHandle) throws SDFException;

    // ========================================================================
    // 6.6 杂凑运算类函数 (Hash Operation Functions)
    // ========================================================================

    /**
     * 6.6.2 带密钥的杂凑运算初始化
     * HMAC Init
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyHandle     密钥句柄 / Key handle
     * @param algID         算法标识 / Algorithm ID
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native void SDF_HMACInit(long sessionHandle, long keyHandle, int algID) throws SDFException;

    /**
     * 6.6.3 带密钥的多包杂凑运算
     * HMAC Update
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param data          数据 / Data
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native void SDF_HMACUpdate(long sessionHandle, byte[] data) throws SDFException;

    /**
     * 6.6.4 带密钥的杂凑运算结束
     * HMAC Final
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @return HMAC值 / HMAC value
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native byte[] SDF_HMACFinal(long sessionHandle) throws SDFException;

    /**
     * 6.6.5 杂凑运算初始化
     * Hash Init
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param algID         算法标识 / Algorithm ID
     * @param publicKey     ECC公钥（用于SM3，可为null）/ ECC public key (for SM3, can be null)
     * @param id            用户ID（用于SM3，可为null）/ User ID (for SM3, can be null)
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native void SDF_HashInit(long sessionHandle, int algID, ECCPublicKey publicKey, byte[] id)
            throws SDFException;

    /**
     * 6.6.6 多包杂凑运算
     * Hash Update
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param data          数据 / Data
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native void SDF_HashUpdate(long sessionHandle, byte[] data) throws SDFException;

    /**
     * 6.6.7 杂凑运算结束
     * Hash Final
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @return 杂凑值 / Hash value
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native byte[] SDF_HashFinal(long sessionHandle) throws SDFException;

    // ========================================================================
    // 6.7 用户文件操作类函数 (User File Operation Functions)
    // ========================================================================

    /**
     * 6.7.2 创建文件
     * Create File
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param fileName      文件名 / File name
     * @param fileSize      文件大小（字节）/ File size in bytes
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native void SDF_CreateFile(long sessionHandle, String fileName, int fileSize) throws SDFException;

    /**
     * 6.7.3 读取文件
     * Read File
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param fileName      文件名 / File name
     * @param offset        读取偏移量 / Read offset
     * @param length        读取长度 / Read length
     * @return 文件数据 / File data
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native byte[] SDF_ReadFile(long sessionHandle, String fileName, int offset, int length)
            throws SDFException;

    /**
     * 6.7.4 写文件
     * Write File
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param fileName      文件名 / File name
     * @param offset        写入偏移量 / Write offset
     * @param data          写入数据 / Data to write
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native void SDF_WriteFile(long sessionHandle, String fileName, int offset, byte[] data)
            throws SDFException;

    /**
     * 6.7.5 删除文件
     * Delete File
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param fileName      文件名 / File name
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native void SDF_DeleteFile(long sessionHandle, String fileName) throws SDFException;

    // ========================================================================
    // 6.8 验证调试类函数 (Validation and Debug Functions)
    // ========================================================================

    /**
     * 6.8.2 产生RSA非对称密钥对并输出
     * Generate Key Pair RSA
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param keyBits       密钥长度（位）/ Key length in bits
     * @return 包含公钥和私钥的数组 / Array containing public key and private key
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native Object[] SDF_GenerateKeyPair_RSA(long sessionHandle, int keyBits) throws SDFException;

    /**
     * 6.8.3 产生ECC非对称密钥对并输出
     * Generate Key Pair ECC
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param algID         算法标识 / Algorithm ID
     * @param keyBits       密钥长度（位）/ Key length in bits
     * @return 包含公钥和私钥的数组 / Array containing public key and private key
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native Object[] SDF_GenerateKeyPair_ECC(long sessionHandle, int algID, int keyBits) throws SDFException;

    /**
     * 6.8.4 外部私钥RSA运算
     * External Private Key Operation RSA
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param privateKey    RSA私钥 / RSA private key
     * @param dataInput     输入数据 / Input data
     * @return 输出数据 / Output data
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native byte[] SDF_ExternalPrivateKeyOperation_RSA(
            long sessionHandle, RSAPrivateKey privateKey, byte[] dataInput) throws SDFException;

    /**
     * 6.8.5 外部私钥ECC签名
     * External Sign ECC
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param algID         算法标识 / Algorithm ID
     * @param privateKey    ECC私钥 / ECC private key
     * @param data          待签名数据 / Data to be signed
     * @return ECC签名对象 / ECC signature object
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native ECCSignature SDF_ExternalSign_ECC(
            long sessionHandle, int algID, ECCPrivateKey privateKey, byte[] data) throws SDFException;

    /**
     * 6.8.6 外部私钥ECC解密
     * External Decrypt ECC
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param algID         算法标识 / Algorithm ID
     * @param privateKey    ECC私钥 / ECC private key
     * @param cipher        ECC密文 / ECC cipher
     * @return 明文数据 / Decrypted data
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native byte[] SDF_ExternalDecrypt_ECC(
            long sessionHandle, int algID, ECCPrivateKey privateKey, ECCCipher cipher) throws SDFException;

    /**
     * 6.8.9 外部密钥单包对称加密
     * External Key Encrypt
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param algID         算法标识 / Algorithm ID
     * @param key           对称密钥 / Symmetric key
     * @param iv            初始向量 / Initialization vector
     * @param data          待加密数据 / Data to be encrypted
     * @return 密文数据 / Encrypted data
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native byte[] SDF_ExternalKeyEncrypt(
            long sessionHandle, int algID, byte[] key, byte[] iv, byte[] data) throws SDFException;

    /**
     * 6.8.10 外部密钥单包对称解密
     * External Key Decrypt
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param algID         算法标识 / Algorithm ID
     * @param key           对称密钥 / Symmetric key
     * @param iv            初始向量 / Initialization vector
     * @param encData       密文数据 / Encrypted data
     * @return 明文数据 / Decrypted data
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native byte[] SDF_ExternalKeyDecrypt(
            long sessionHandle, int algID, byte[] key, byte[] iv, byte[] encData) throws SDFException;

    /**
     * 6.8.11 外部密钥多包对称加密初始化
     * External Key Encrypt Init
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param algID         算法标识 / Algorithm ID
     * @param key           对称密钥 / Symmetric key
     * @param iv            初始向量 / Initialization vector
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native void SDF_ExternalKeyEncryptInit(
            long sessionHandle, int algID, byte[] key, byte[] iv) throws SDFException;

    /**
     * 6.8.12 外部密钥多包对称解密初始化
     * External Key Decrypt Init
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param algID         算法标识 / Algorithm ID
     * @param key           对称密钥 / Symmetric key
     * @param iv            初始向量 / Initialization vector
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native void SDF_ExternalKeyDecryptInit(
            long sessionHandle, int algID, byte[] key, byte[] iv) throws SDFException;

    /**
     * 6.8.13 带外部密钥的杂凑运算初始化
     * External Key HMAC Init
     *
     * @param sessionHandle 会话句柄 / Session handle
     * @param algID         算法标识 / Algorithm ID
     * @param key           HMAC密钥 / HMAC key
     * @throws SDFException 如果操作失败 / if operation fails
     */
    public native void SDF_ExternalKeyHMACInit(
            long sessionHandle, int algID, byte[] key) throws SDFException;

    // ========================================================================
    // 工具方法 (Utility Methods)
    // ========================================================================

    /**
     * 获取SDF4J版本信息
     *
     * @return 版本字符串
     */
    public static String getVersion() {
        return "SDF4J 1.0.0-SNAPSHOT (OpenHitls)";
    }

    // ========================================================================
    // 日志管理 (Logging Management)
    // ========================================================================

    /**
     * 当前的日志回调实例（默认使用DefaultSDFLogger）
     */
    private static volatile SDFLogger loggerInstance = new DefaultSDFLogger();

    /**
     * 设置日志回调
     * Set Logger Callback
     *
     * <p>设置用于接收Native层日志的回调实例。
     * 默认使用DefaultSDFLogger输出到System.out。
     * <p>Sets the callback instance for receiving native layer logs.
     * Defaults to DefaultSDFLogger which outputs to System.out.
     *
     * @param logger 日志回调实例，传入null将使用默认实现
     *               Logger callback instance, passing null will use default implementation
     */
    public static void setLogger(SDFLogger logger) {
        if (logger == null) {
            loggerInstance = new DefaultSDFLogger();
        } else {
            loggerInstance = logger;
        }
        // 通知Native层更新日志回调
        setNativeLogger(loggerInstance);
    }

    /**
     * 获取当前的日志回调实例
     * Get Current Logger Instance
     *
     * @return 当前的日志回调实例
     *         Current logger callback instance
     */
    public static SDFLogger getLogger() {
        return loggerInstance;
    }

    /**
     * 启用/禁用文件日志
     * Enable/Disable File Logging
     *
     * @param enable true启用文件日志，false禁用文件日志
     *               true to enable file logging, false to disable
     */
    public static native void setFileLoggingEnabled(boolean enable);

    /**
     * 启用/禁用Java回调日志
     * Enable/Disable Java Callback Logging
     *
     * @param enable true启用Java回调日志，false禁用Java回调日志
     *               true to enable Java callback logging, false to disable
     */
    public static native void setJavaLoggingEnabled(boolean enable);

    /**
     * Native方法：设置Java日志回调对象
     * Native method: Set Java logger callback object
     *
     * @param logger 日志回调对象
     *               Logger callback object
     */
    private static native void setNativeLogger(SDFLogger logger);

    static {
        // 默认启用Java回调日志，禁用文件日志
        // 使用try-catch避免在native库未加载时出错
        try {
            setNativeLogger(loggerInstance);
            setJavaLoggingEnabled(true);
            setFileLoggingEnabled(true);  // 同时保留文件日志
        } catch (UnsatisfiedLinkError e) {
            // Native库尚未加载，忽略
        }
    }
}
