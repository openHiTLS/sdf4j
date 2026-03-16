# SDF4J JCE Provider

基于 GM/T 0018-2023 《密码设备应用接口规范》的 Java Cryptography Extension (JCE) Provider，提供标准 JCA 接口访问国密算法硬件设备。

## 功能特性

- **SM3 消息摘要** - `MessageDigest.getInstance("SM3", "SDF")`
- **SM4 对称加密** - 支持 ECB/CBC/GCM 模式，支持 NoPadding/PKCS5Padding/PKCS7Padding
- **SM2 非对称加密/签名** - `Signature.getInstance("SM3withSM2", "SDF")`，遵循 GM/T 0009-2012 标准
- **硬件随机数** - `SecureRandom.getInstance("SDF", "SDF")`
- **HMAC-SM3** - `Mac.getInstance("HmacSM3", "SDF")`
- **SM4-MAC** - `Mac.getInstance("SM4-MAC", "SDF")`

## 快速开始

### 1. 添加依赖

编译并安装到本地 Maven 仓库：

```bash
cd sdf4j
mvn clean install -DskipTests
```

在项目中添加依赖：

```xml
<dependency>
    <groupId>org.openhitls</groupId>
    <artifactId>sdf4j-jce</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

### 2. 初始化 Provider

```java
import org.openhitls.sdf4j.jce.SDFProvider;
import java.security.Security;

// 创建并注册 Provider
SDFProvider provider = new SDFProvider();
Security.addProvider(provider);
```

### 3. 使用 JCE 接口

```java
// SM3 摘要
MessageDigest md = MessageDigest.getInstance("SM3", "SDF");
byte[] hash = md.digest("Hello".getBytes());

// SM4 加密
KeyGenerator kg = KeyGenerator.getInstance("SM4", "SDF");
SecretKey key = kg.generateKey();
Cipher cipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", "SDF");
cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(new byte[16]));
byte[] ciphertext = cipher.doFinal("Hello".getBytes());

// SM2 签名
KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "SDF");
KeyPair keyPair = kpg.generateKeyPair();
Signature signer = Signature.getInstance("SM3withSM2", "SDF");
signer.initSign(keyPair.getPrivate());
signer.setParameter(new SM2ParameterSpec((SM2PublicKey) keyPair.getPublic()));
signer.update("Hello".getBytes());
byte[] signature = signer.sign();

// 硬件随机数
SecureRandom sr = SecureRandom.getInstance("SDF", "SDF");
byte[] random = new byte[32];
sr.nextBytes(random);
```

## 配置说明

### SDF 库路径配置

SDF4J JCE Provider 需要加载符合 GM/T 0018-2023 标准的 SDF 设备驱动库。
支持以下几种配置方式（按优先级排序）：

#### 1. Java 系统属性（最高优先级）

```bash
# 方式1：指定库目录 + 名称（推荐）
java -Dsdf.library.path=/opt/sdf/lib -Dsdf.library.name=sdf_openhitls ...

# 方式2：直接指定完整库文件路径
java -Dsdf.library.path=/opt/sdf/lib/libsdf_openhitls.so ...

# Maven 测试时使用（与 sdf4j 模块使用相同的属性名）
mvn test -pl sdf4j-jce -Dsdf.library.path=/opt/sdf/lib -Dsdf.library.name=sdf_openhitls
```

**注意**：`sdf.library.*` 属性与 `sdf4j` 模块共享，可在父 pom 中统一配置。

#### 2. 配置文件

在类路径下创建 `sdf4j-jce.properties` 文件：

```properties
# 方式1：指定库目录 + 名称
library.path=/opt/sdf/lib
library.name=sdf_openhitls

# 方式2：直接指定完整库文件路径
library.path=/opt/sdf/lib/libsdf_openhitls.so
```

#### 3. Maven 编译时配置

```bash
# 编译时指定库配置，将写入 JAR 内的 sdf4j-jce.properties
mvn clean package -Dsdf.library.path=/opt/sdf/lib -Dsdf.library.name=sdf_openhitls
```

#### 4. 环境变量（最低优先级）

```bash
# 设置 SDF 平台库路径
export SDF_LIBRARY_PATH=/path/to/libsdf_openhitls.so

# 运行测试
mvn test -pl sdf4j-jce
```

### 使用 OpenHiTLS 平台库

本项目提供了基于 OpenHiTLS 的 SDF 平台库实现（位于 `platform/sdfx` 目录）：

```bash
# 编译 OpenHiTLS 平台库
cd platform/sdfx/build
cmake ..
make -j$(nproc)

# 使用方式1：环境变量
export SDF_LIBRARY_PATH=/path/to/platform/sdfx/build/libsdf_openhitls.so

# 使用方式2：Maven 命令行参数（与 sdf4j 模块统一）
mvn test -pl sdf4j-jce -Dsdf.library.path=./platform/sdfx/build/ -Dsdf.library.name=sdf_openhitls
```

### 无设备测试

没有 SDF 设备时，可以跳过集成测试：

```bash
# 只运行单元测试（不依赖硬件）
mvn test -pl sdf4j-jce -Dtest=SM2KeyTest,SDFProviderTest
```

## 编译

### 系统要求

- JDK 8 或更高版本
- GCC 4.8 或更高版本
- CMake 3.10 或更高版本
- JNI 头文件（通常随 JDK 一起安装）

### 编译步骤

```bash
# 克隆仓库
git clone https://github.com/openhitls/sdf4j.git
cd sdf4j

# 编译全部模块
mvn clean install

# 只编译 JCE Provider
mvn clean install -pl sdf4j-jce -am
```

### 编译输出

```
sdf4j-jce/target/
├── sdf4j-jce-1.0.0-SNAPSHOT.jar          # JAR 包（包含 native 库）
├── sdf4j-jce-1.0.0-SNAPSHOT-sources.jar  # 源码包
└── native/
    └── libsdf4j-jce.so                    # 独立的 native 库
```

## 测试

### 运行全部测试

```bash
# 需要先设置 环境变量 指向 SDF 平台库，或者设置SDF_LIBRARY_PATH
export SDF_LIBRARY_PATH=/path/to/libsdf_openhitls.so
mvn test -pl sdf4j-jce
或者
mvn test -pl sdf4j-jce -Dsdf.library.path=/opt/sdf/lib -Dsdf.library.name=sdf_openhitls
```

## API 文档

### 支持的算法

| 算法 | 类型 | JCA 名称 | 说明 |
|------|------|----------|------|
| SM3 | MessageDigest | `SM3` | 国密摘要算法 |
| SM4 | Cipher | `SM4/ECB/NoPadding` | SM4 ECB 模式 |
| SM4 | Cipher | `SM4/ECB/PKCS5Padding` | SM4 ECB + PKCS5 填充 |
| SM4 | Cipher | `SM4/ECB/PKCS7Padding` | PKCS5Padding 别名 |
| SM4 | Cipher | `SM4/CBC/NoPadding` | SM4 CBC 模式 |
| SM4 | Cipher | `SM4/CBC/PKCS5Padding` | SM4 CBC + PKCS5 填充 |
| SM4 | Cipher | `SM4/CBC/PKCS7Padding` | PKCS5Padding 别名 |
| SM4 | Cipher | `SM4/GCM/NoPadding` | SM4 GCM 模式（AEAD） |
| SM2 | Cipher | `SM2` | SM2 非对称加密 |
| SM2 | Signature | `SM3withSM2` | SM2 签名（GM/T 0009-2012） |
| SM2 | KeyPairGenerator | `SM2` | SM2 密钥对生成 |
| SM4 | KeyGenerator | `SM4` | SM4 密钥生成 |
| SDF | SecureRandom | `SDF` | 硬件随机数 |
| HmacSM3 | Mac | `HmacSM3` | HMAC-SM3 |
| SM4-MAC | Mac | `SM4-MAC` | SM4 CBC-MAC |

### SDFProvider 方法

```java
// 构造函数
SDFProvider()                    // 自动从 SDF_LIBRARY_PATH 加载库
SDFProvider(String libraryPath)  // libraryPath 参数已废弃，使用环境变量

// 状态检查
boolean isInitialized()          // 检查是否已初始化
void shutdown()                  // 关闭 Provider 并释放资源

// 注册 Provider
Security.addProvider(provider)
Security.removeProvider("SDF")
```

## 故障排查

### UnsatisfiedLinkError: 找不到 SDF 库

```
java.lang.UnsatisfiedLinkError: /path/to/libsdf_openhitls.so: cannot open shared object
```

**解决方法**：
1. 检查库路径是否正确：`ls -l $SDF_LIBRARY_PATH`
2. 检查库依赖：`ldd /path/to/libsdf_openhitls.so`
3. 设置 LD_LIBRARY_PATH：`export LD_LIBRARY_PATH=/path/to/platform/libsdf_openhitls.so:$LD_LIBRARY_PATH`

### Unsupported JNI version

```
java.lang.UnsatisfiedLinkError: unsupported JNI version 0xFFFFFFFF
```

**解决方法**：清理旧的临时库文件
```bash
rm -rf /tmp/sdf4j-jce-native/
mvn clean package
```

## 许可证

```
Copyright (c) 2025 OpenHitls
SDF4J is licensed under Mulan PSL v2.
You may obtain a copy of Mulan PSL v2 at:
         http://license.coscl.org.cn/MulanPSL2
```

## 相关链接

- [GM/T 0018-2023 密码设备应用接口规范](https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=1A075AF31E3DD6E90DFC381672F9AA0A)
- [GM/T 0009-2012 SM2 密码密码使用规范](https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=DD402445FA8931EF1165FBC177BE07D)
- [openHiTLS](https://github.com/openhitls/openhitls)
- [SDF4J 主项目](../README.md)
