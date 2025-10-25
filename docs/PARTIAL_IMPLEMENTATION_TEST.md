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
所有其他函数均为可选：
- 设备管理：`SDF_GetDeviceInfo`, `SDF_GenerateRandom`, 等
- 密钥管理：所有 `Export*` 和 `Destroy*` 函数
- 加密算法：所有加密、解密、签名、验签函数
- 杂凑算法：所有Hash函数

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
        Map<String, Boolean> capabilities = new HashMap<>();

        // 设备管理
        capabilities.put("GetDeviceInfo", checkFunction(() ->
            sdf.SDF_GetDeviceInfo(sessionHandle)));
        capabilities.put("GenerateRandom", checkFunction(() ->
            sdf.SDF_GenerateRandom(sessionHandle, 16)));

        // 密钥管理 (需要有效的密钥索引)
        capabilities.put("ExportSignPublicKey_ECC", checkFunction(() ->
            sdf.SDF_ExportSignPublicKey_ECC(sessionHandle, 1)));
        capabilities.put("ExportSignPublicKey_RSA", checkFunction(() ->
            sdf.SDF_ExportSignPublicKey_RSA(sessionHandle, 1)));

        // 更多功能检测...

        return capabilities;
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

    public void printCapabilities() {
        Map<String, Boolean> caps = detectCapabilities();
        System.out.println("\nSDF库功能清单：");
        System.out.println("=================================");
        caps.forEach((feature, available) -> {
            String status = available ? "✓ 可用" : "✗ 不可用";
            System.out.println(feature + ": " + status);
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
Warning: Optional SDF function 'SDF_InternalSign_RSA' not available in this implementation
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
