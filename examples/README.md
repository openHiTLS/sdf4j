# SDF4J 示例

本模块包含使用 JUnit 测试编写的 SDF4J 使用示例。

## 概述

本模块包含使用 JUnit 测试框架编写的 SDF4J 示例程序，演示如何使用 SDF4J 进行各种密码操作。

## 配置

### 测试配置文件

SDF4J 示例使用配置文件来管理设备特定的设置，如密钥索引和密码。

**配置文件**（位于 `src/test/resources/`）：
- `test-config.properties` - 示例测试的配置

**配置属性**：
```properties
# SM2 内部密钥索引
sm2.internal.key.index=10

# 获取私钥访问权限的密码
sm2.key.access.password=<your-device-password>

# SM2 默认用户 ID（GM/T 0009-2012 标准）
sm2.default.user.id=1234567812345678

# 环境标识符
environment.name=default

#其他配置
...

```

### 配置您的设备

根据您的设备设置编辑 `test-config.properties`：

```bash
# 编辑配置文件
vi examples/src/test/resources/test-config.properties

# 根据您的 SDF 设备更新这些值：
# sm2.internal.key.index=10
# sm2.key.access.password=<your-device-password>
# sm2.default.user.id=1234567812345678
# environment.name=default

# 运行测试
mvn test
```

## 运行示例

### 运行所有示例

```bash
cd examples
mvn test

# 运行特定测试类
mvn test -Dtest=SM2Example
mvn test -Dtest=SM3Example
mvn test -Dtest=SM4Example

# 运行特定测试方法
mvn test -Dtest=SM2Example#testExternalSign
mvn test -Dtest=SM3Example#testSM3Hash
mvn test -Dtest=SM4Example#testSM4ECB
```

### SDF 库配置

运行测试之前，请确保已配置 SDF 库：

```bash
mvn test -Dsdf4j.library.name=swsds -Dsdf4j.library.path=/opt/sdf/lib
```

## 可用示例

示例程序位于 `src/test/java/org/openhitls/` 目录，使用 JUnit 测试框架实现。

### SM2Example.java

SM2 非对称加密算法测试：
- `testExternalSign()` - 外部密钥签名和验签
- `testExternalEncrypt()` - 外部密钥加密和解密

**运行测试**：
```bash
mvn test -Dtest=SM2Example

# 或运行单个测试方法
mvn test -Dtest=SM2Example#testExternalSign
mvn test -Dtest=SM2Example#testExternalEncrypt
```

### SM3Example.java

SM3 哈希算法测试：
- `testSM3Hash()` - SM3 哈希计算

**运行测试**：
```bash
mvn test -Dtest=SM3Example

# 或运行单个测试方法
mvn test -Dtest=SM3Example#testSM3Hash
```

### SM4Example.java

SM4 对称加密算法测试：
- `testSM4ECB()` - ECB 模式加密解密
- `testSM4CBC()` - CBC 模式加密解密

**配置要求**：需要配置密钥索引和密码（见上方配置说明）

**运行测试**：
```bash
mvn test -Dtest=SM4Example

# 或运行单个测试方法
mvn test -Dtest=SM4Example#testSM4ECB
mvn test -Dtest=SM4Example#testSM4CBC
```

## 依赖

本模块依赖于 `sdf4j-core` 和 JUnit：
```xml
<!-- SDF4J Core -->
<dependency>
    <groupId>org.openhitls</groupId>
    <artifactId>sdf4j-core</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>

```

JNI 库（`libsdf4j-jni.so`）从 `../sdf4j-core/target/native/` 加载。

## 测试结构

每个示例测试类遵循以下结构：

```java
public class Example {
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
        // 清理资源
        sdf.SDF_CloseSession(sessionHandle);
        sdf.SDF_CloseDevice(deviceHandle);
    }

    @Test
    public void testSomething() throws SDFException {
        // 测试实现
    }
}
```

## 设备特定说明

根据您的设备设置编辑 `test-config.properties`：
- 更新 `sm2.internal.key.index` 以匹配设备中预置的密钥
- 更新 `sm2.key.access.password` 以匹配您的设备密码

## 故障排查

**配置文件未找到**：
```
Warning: Configuration file not found: test-config-xxx.properties
```
解决方案：检查 `src/test/resources/` 中是否存在配置文件

**无效的密钥索引**：
```
SDFException: SDR_KEYNOTEXIST (0x01000104)
```
解决方案：更新 `sm2.internal.key.index` 以匹配设备中的密钥

**密码错误**：
```
SDFException: Authentication failed
```
解决方案：更新 `sm2.key.access.password` 以匹配您的设备密码

## 安全注意事项

- **不要**将敏感密码提交到版本控制
- 如果 `test-config.properties` 包含敏感数据，考虑将其添加到 `.gitignore`：
  ```bash
  echo "examples/src/test/resources/test-config.properties" >> .gitignore
  ```
- 生产环境使用强密码
- 生产环境中考虑使用环境变量或安全密钥库存储敏感数据

## 注意事项

- 示例需要在 `sdf4j-core` 中配置可用的 SDF 库
- 测试需要合理处理可选函数的 `SDR_NOTSUPPORT` 错误
- 某些测试需要在 SDF 设备中预配置密钥
- 所有示例都在 `@After` 方法中包含适当的资源清理
- 基于配置的方法使示例可以跨不同设备移植
