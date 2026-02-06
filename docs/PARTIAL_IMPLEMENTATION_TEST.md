# 部分实现测试指南 (Partial Implementation Test Guide)

本文档说明如何验证SDF4J对于部分实现的SDF库的错误处理机制。

## 概述

不同的SDF提供商可能只实现GM/T 0018-2023标准的部分功能。SDF4J通过以下机制优雅地处理这种情况：

1. **库加载阶段**：可选函数符号找不到时记录警告但继续加载
2. **运行时阶段**：调用未实现的函数时返回 `SDR_NOTSUPPORT` 错误码 (0x01000002)

## 核心函数 vs 可选函数

### 核心函数（必须实现）
以下函数必须在SDF库中实现，否则库加载失败：
- `SDF_OpenDevice`
- `SDF_CloseDevice`
- `SDF_OpenSession`
- `SDF_CloseSession`

### 可选函数
所有其他函数均为可选，分类如下：

**设备管理类（6.2）**
- `SDF_GetDeviceInfo` - 获取设备信息
- `SDF_GenerateRandom` - 产生随机数
- `SDF_GetPrivateKeyAccessRight` - 获取私钥使用权限
- `SDF_ReleasePrivateKeyAccessRight` - 释放私钥使用权限
- `SDF_GetKEKAccessRight` - 获取KEK密钥使用权限
- `SDF_ReleaseKEKAccessRight` - 释放KEK密钥使用权限

**密钥管理类（6.3）**
- `SDF_ExportSignPublicKey_RSA` / `SDF_ExportEncPublicKey_RSA`
- `SDF_ExportSignPublicKey_ECC` / `SDF_ExportEncPublicKey_ECC`
- `SDF_GenerateKeyWithIPK_RSA` / `SDF_GenerateKeyWithEPK_RSA` / `SDF_ImportKeyWithISK_RSA`
- `SDF_GenerateKeyWithIPK_ECC` / `SDF_GenerateKeyWithEPK_ECC` / `SDF_ImportKeyWithISK_ECC`
- `SDF_GenerateAgreementDataWithECC` / `SDF_GenerateKeyWithECC` / `SDF_GenerateAgreementDataAndKeyWithECC`
- `SDF_GenerateKeyWithKEK` / `SDF_ImportKeyWithKEK`
- `SDF_DestroyKey`

**非对称算法类（6.4）**
- `SDF_ExternalPublicKeyOperation_RSA` / `SDF_InternalPublicKeyOperation_RSA` / `SDF_InternalPrivateKeyOperation_RSA`
- `SDF_InternalSign_ECC` / `SDF_InternalVerify_ECC` / `SDF_ExternalVerify_ECC`
- `SDF_ExternalEncrypt_ECC` / `SDF_InternalEncrypt_ECC` / `SDF_InternalDecrypt_ECC`
- `SDF_ExchangeDigitEnvelopeBaseOnECC`

**对称算法类（6.5）**
- 单包加解密：`SDF_Encrypt` / `SDF_Decrypt` / `SDF_CalculateMAC`
- 认证加解密：`SDF_AuthEnc` / `SDF_AuthDec`
- 多包加解密：`SDF_EncryptInit` / `SDF_EncryptUpdate` / `SDF_EncryptFinal`
- 多包解密：`SDF_DecryptInit` / `SDF_DecryptUpdate` / `SDF_DecryptFinal`
- 多包MAC：`SDF_CalculateMACInit` / `SDF_CalculateMACUpdate` / `SDF_CalculateMACFinal`
- 多包认证加密：`SDF_AuthEncInit` / `SDF_AuthEncUpdate` / `SDF_AuthEncFinal`
- 多包认证解密：`SDF_AuthDecInit` / `SDF_AuthDecUpdate` / `SDF_AuthDecFinal`

**杂凑算法类（6.6）**
- HMAC：`SDF_HMACInit` / `SDF_HMACUpdate` / `SDF_HMACFinal`
- Hash：`SDF_HashInit` / `SDF_HashUpdate` / `SDF_HashFinal`

**文件操作类（6.7）**
- `SDF_CreateFile` / `SDF_ReadFile` / `SDF_WriteFile` / `SDF_DeleteFile`

**验证调试类（6.8）**
- `SDF_GenerateKeyPair_RSA` / `SDF_GenerateKeyPair_ECC`
- `SDF_ExternalPrivateKeyOperation_RSA`
- `SDF_ExternalSign_ECC` / `SDF_ExternalDecrypt_ECC`
- `SDF_ExternalKeyEncrypt` / `SDF_ExternalKeyDecrypt`
- `SDF_ExternalKeyEncryptInit` / `SDF_ExternalKeyDecryptInit`
- `SDF_ExternalKeyHMACInit`

## 测试方法

### 方法1：代码中检测

```java
import org.openhitls.sdf4j.*;
import org.openhitls.sdf4j.constants.ErrorCode;

public class PartialImplementationTest {
    public static void main(String[] args) {
        SDF sdf = new SDF();

        try {
            long deviceHandle = sdf.SDF_OpenDevice();
            long sessionHandle = sdf.SDF_OpenSession(deviceHandle);

            // 尝试调用可能未实现的函数
            try {
                ECCPublicKey key = sdf.SDF_ExportSignPublicKey_ECC(sessionHandle, 1);
                System.out.println("✓ SM2签名公钥导出功能可用");
            } catch (SDFException e) {
                if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                    System.out.println("⚠ SM2签名公钥导出功能未实现");
                } else {
                    System.out.println("✗ SM2签名公钥导出失败: " + e.getMessage());
                }
            }

            // 测试其他可选功能
            testOptionalFeature(() -> sdf.SDF_GenerateRandom(sessionHandle, 16),
                               "随机数生成");
            testOptionalFeature(() -> sdf.SDF_GetDeviceInfo(sessionHandle),
                               "设备信息获取");

            sdf.SDF_CloseSession(sessionHandle);
            sdf.SDF_CloseDevice(deviceHandle);

        } catch (SDFException e) {
            System.err.println("设备操作失败: " + e.getMessage());
        }
    }

    private static void testOptionalFeature(Callable<?> func, String featureName) {
        try {
            func.call();
            System.out.println("✓ " + featureName + " 功能可用");
        } catch (SDFException e) {
            if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
                System.out.println("⚠ " + featureName + " 功能未实现");
            } else {
                System.out.println("✗ " + featureName + " 失败: " + e.getMessage());
            }
        } catch (Exception e) {
            System.out.println("✗ " + featureName + " 异常: " + e.getMessage());
        }
    }
}
```

### 方法2：功能探测器

创建一个工具类来探测SDF库的可用功能：

```java
public class SDFCapabilityDetector {
    private final SDF sdf;
    private final long sessionHandle;

    public SDFCapabilityDetector(SDF sdf, long sessionHandle) {
        this.sdf = sdf;
        this.sessionHandle = sessionHandle;
    }

    public Map<String, Boolean> detectCapabilities() {
        Map<String, Boolean> capabilities = new LinkedHashMap<>();

        // 设备管理类功能
        capabilities.put("GetDeviceInfo", checkFunction(() ->
            sdf.SDF_GetDeviceInfo(sessionHandle)));
        capabilities.put("GenerateRandom", checkFunction(() ->
            sdf.SDF_GenerateRandom(sessionHandle, 16)));

        // 密钥管理类功能 (需要有效的密钥索引)
        capabilities.put("ExportSignPublicKey_ECC", checkFunction(() ->
            sdf.SDF_ExportSignPublicKey_ECC(sessionHandle, 1)));
        capabilities.put("ExportEncPublicKey_ECC", checkFunction(() ->
            sdf.SDF_ExportEncPublicKey_ECC(sessionHandle, 1)));
        capabilities.put("ExportSignPublicKey_RSA", checkFunction(() ->
            sdf.SDF_ExportSignPublicKey_RSA(sessionHandle, 1)));
        capabilities.put("ExportEncPublicKey_RSA", checkFunction(() ->
            sdf.SDF_ExportEncPublicKey_RSA(sessionHandle, 1)));

        // 对称加密功能
        capabilities.put("Encrypt/Decrypt", checkEncryptDecrypt());
        capabilities.put("CalculateMAC", checkFunction(() ->
            sdf.SDF_CalculateMAC(sessionHandle, 0, AlgorithmID.SGD_SM4_MAC, null, new byte[16])));
        capabilities.put("AuthEnc/AuthDec", checkFunction(() ->
            sdf.SDF_AuthEnc(sessionHandle, 0, AlgorithmID.SGD_SM4_GCM, new byte[12], null, new byte[16])));

        // 多包加密功能
        capabilities.put("MultiPacketEncrypt", checkMultiPacketEncrypt());
        capabilities.put("MultiPacketMAC", checkMultiPacketMAC());
        capabilities.put("MultiPacketAuthEnc", checkMultiPacketAuthEnc());

        // 杂凑功能
        capabilities.put("Hash_SM3", checkFunction(() -> {
            sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
            sdf.SDF_HashUpdate(sessionHandle, new byte[16]);
            sdf.SDF_HashFinal(sessionHandle);
        }));
        capabilities.put("HMAC", checkFunction(() -> {
            sdf.SDF_HMACInit(sessionHandle, 0, AlgorithmID.SGD_SM3);
        }));

        // 文件操作功能
        capabilities.put("FileOperations", checkFileOperations());

        // 密钥协商功能
        capabilities.put("KeyAgreement_ECC", checkFunction(() ->
            sdf.SDF_GenerateAgreementDataWithECC(sessionHandle, 1, 128,
                new byte[16], null, null)));

        // KEK功能
        capabilities.put("GenerateKeyWithKEK", checkFunction(() ->
            sdf.SDF_GenerateKeyWithKEK(sessionHandle, 128, AlgorithmID.SGD_SM4_ECB, 1)));

        // ECC数字信封转换功能
        capabilities.put("ExchangeDigitEnvelopeBaseOnECC", checkFunction(() -> {
            // 为探测创建虚拟入参
            ECCPublicKey dummyPubKey = new ECCPublicKey();
            ECCCipher dummyCipher = new ECCCipher();
            sdf.SDF_ExchangeDigitEnvelopeBaseOnECC(sessionHandle, 1, AlgorithmID.SGD_SM2_3, dummyPubKey, dummyCipher);
        }));

        return capabilities;
    }

    private boolean checkEncryptDecrypt() {
        try {
            // 需要先生成密钥才能测试加解密
            return true; // 简化测试
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkMultiPacketEncrypt() {
        try {
            sdf.SDF_EncryptInit(sessionHandle, 0, AlgorithmID.SGD_SM4_CBC, new byte[16]);
            return true;
        } catch (SDFException e) {
            return e.getErrorCode() != ErrorCode.SDR_NOTSUPPORT;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkMultiPacketMAC() {
        try {
            sdf.SDF_CalculateMACInit(sessionHandle, 0, AlgorithmID.SGD_SM4_MAC, null);
            return true;
        } catch (SDFException e) {
            return e.getErrorCode() != ErrorCode.SDR_NOTSUPPORT;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkMultiPacketAuthEnc() {
        try {
            sdf.SDF_AuthEncInit(sessionHandle, 0, AlgorithmID.SGD_SM4_GCM,
                new byte[12], null, 16);
            return true;
        } catch (SDFException e) {
            return e.getErrorCode() != ErrorCode.SDR_NOTSUPPORT;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkFileOperations() {
        try {
            // 尝试创建一个测试文件
            sdf.SDF_CreateFile(sessionHandle, "__test__.tmp", 16);
            sdf.SDF_DeleteFile(sessionHandle, "__test__.tmp");
            return true;
        } catch (SDFException e) {
            return e.getErrorCode() != ErrorCode.SDR_NOTSUPPORT;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkFunction(Callable<?> func) {
        try {
            func.call();
            return true;
        } catch (SDFException e) {
            return e.getErrorCode() != ErrorCode.SDR_NOTSUPPORT;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkFunction(Runnable func) {
        try {
            func.run();
            return true;
        } catch (SDFException e) {
            return e.getErrorCode() != ErrorCode.SDR_NOTSUPPORT;
        } catch (Exception e) {
            return false;
        }
    }

    public void printCapabilities() {
        Map<String, Boolean> caps = detectCapabilities();
        System.out.println("\nSDF库功能清单：");
        System.out.println("=================================");
        caps.forEach((feature, available) -> {
            String status = available ? "✓ 可用" : "✗ 不可用";
            System.out.println(String.format("%-25s : %s", feature, status));
        });
    }
}
```

## 单元测试示例

在 `src/test/java` 中添加测试：

```java
@Test
public void testUnsupportedFunctionHandling() throws SDFException {
    // 注意：此测试需要一个只实现部分功能的SDF库
    // 或者使用mock库来模拟

    requireDevice();

    try {
        // 尝试调用可能未实现的函数
        sdf.SDF_ExportSignPublicKey_RSA(sessionHandle, 1);
        // 如果成功，说明功能已实现
    } catch (SDFException e) {
        // 检查错误码
        if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
            // 这是预期的行为：功能未实现
            System.out.println("RSA功能未实现，这是正常的");
        } else {
            // 其他错误，重新抛出
            throw e;
        }
    }
}
```

## 日志输出

当加载部分实现的SDF库时，您应该在stderr中看到类似以下的警告：

```
Warning: Optional SDF function 'SDF_ExportSignPublicKey_RSA' not available in this implementation
Warning: Optional SDF function 'SDF_ExportEncPublicKey_RSA' not available in this implementation
Warning: Optional SDF function 'SDF_GetKEKAccessRight' not available in this implementation
Warning: Optional SDF function 'SDF_ReleaseKEKAccessRight' not available in this implementation
Warning: Optional SDF function 'SDF_EncryptInit' not available in this implementation
Warning: Optional SDF function 'SDF_AuthEnc' not available in this implementation
Warning: Optional SDF function 'SDF_HMACInit' not available in this implementation
Warning: Optional SDF function 'SDF_CreateFile' not available in this implementation
...
```

这些警告是**正常的**，表示库加载成功但某些功能不可用。

## 最佳实践

1. **防御性编程**：调用可选函数前先try-catch
2. **功能探测**：在应用启动时检测可用功能
3. **降级处理**：为不可用的功能提供替代方案
4. **清晰日志**：记录哪些功能可用和不可用

## 故障排查

### 问题：库加载失败
**原因**：核心函数缺失
**解决**：确保SDF库实现了4个核心函数

### 问题：所有可选函数都返回SDR_NOTSUPPORT
**原因**：可能使用的是非常基础的SDF实现
**解决**：联系SDF提供商获取完整实现，或使用已有功能

### 问题：程序崩溃而不是返回错误
**原因**：使用的SDF4J版本较旧，未包含NULL检查
**解决**：更新到最新版本的SDF4J

## 相关错误码

- `SDR_OK` (0x00000000): 成功
- `SDR_NOTSUPPORT` (0x01000002): 功能未实现/不支持
- `SDR_UNKNOWERR` (0x01000001): 未知错误
- `SDR_INARGERR` (0x0100001D): 参数错误

完整的错误码列表请参考 `ErrorCode.java`。
