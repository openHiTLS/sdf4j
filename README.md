# SDF4J

[![License](https://img.shields.io/badge/license-Mulan%20PSL%20v2-blue)](LICENSE)
[![Java](https://img.shields.io/badge/Java-8%2B-orange)](https://www.oracle.com/java/)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)](https://www.linux.org/)

**SDF4J** 是 [openHiTLS](https://github.com/openhitls/openhitls) 项目的子项目，提供符合 **GM/T 0018-2023《密码设备应用接口规范》** 的 Java 语言封装。

## 目录

- [特性](#特性)
- [快速开始](#快速开始)
- [安装](#安装)
- [编译](#编译)
- [使用示例](#使用示例)
- [文档](#文档)
- [测试](#测试)
- [常见问题](#常见问题)
- [贡献](#贡献)
- [许可证](#许可证)

## 特性

- **完整的SDF接口** - 覆盖设备管理、密钥管理、加解密、签名验签等核心功能
- **国密算法支持** - SM2、SM3、SM4、SM9 等国密算法
- **部分实现支持** - 合理处理未完整实现GM/T 0018-2023的SDF库，可选函数返回 `SDR_NOTSUPPORT` 错误码
- **编译时配置** - 编译时指定 SDF 库，生成的 JAR 包开箱即用，无需运行时配置
- **动态库加载** - 支持灵活配置密码设备库路径，多厂商兼容
- **类型安全** - 完整的 Java 类型定义和参数校验
- **异常处理** - 统一的异常体系和错误码映射
- **跨平台** - 支持 Linux x86_64 和 aarch64

## 快速开始

### 前置要求

#### 运行环境
- **Java**: JDK 8 或更高版本
- **SDF库**: 符合 GM/T 0018-2023 标准的密码设备库（如 `libswsds.so`, `libgmapi.so` 等，不同厂商命名不同）
- **操作系统**: Linux (x86_64 或 aarch64)

#### 编译环境（从源码构建）
- **JDK**: 8 或更高版本（需要包含 javac 和 javah）
- **Maven**: 3.6 或更高版本
- **CMake**: 3.10 或更高版本
- **GCC/G++**: 支持 C11 标准的编译器

**注意**：SDF标准头文件已包含在项目中（`src/main/native/include/`），编译时无需外部SDF开发包。仅运行时需要SDF库文件，且需要在配置文件中指定库名称。

检查编译环境：
```bash
# 检查工具版本
java -version    # >= 1.8.0
mvn -version     # >= 3.6.0
cmake --version  # >= 3.10
gcc --version    # >= 4.8
```

### 本地安装到Maven仓库（可选）

如需在其他项目中使用SDF4J，可将其安装到本地Maven仓库：

```bash
# 构建并安装到本地Maven仓库
mvn clean install

# 在其他项目的pom.xml中添加依赖
# <dependency>
#     <groupId>org.openhitls</groupId>
#     <artifactId>sdf4j</artifactId>
#     <version>1.0.0-SNAPSHOT</version>
# </dependency>
```

### 基本用法

```java
import org.openhitls.sdf4j.*;
import org.openhitls.sdf4j.types.*;

public class Example {
    public static void main(String[] args) throws SDFException {
        // 创建SDF实例（库会自动加载）
        SDF sdf = new SDF();

        // 打开设备和会话
        long deviceHandle = sdf.SDF_OpenDevice();
        long sessionHandle = sdf.SDF_OpenSession(deviceHandle);

        // 获取设备信息
        DeviceInfo info = sdf.SDF_GetDeviceInfo(sessionHandle);
        System.out.println("设备型号: " + info.getDeviceName());

        // 生成随机数
        byte[] random = sdf.SDF_GenerateRandom(sessionHandle, 32);

        // 关闭会话和设备
        sdf.SDF_CloseSession(sessionHandle);
        sdf.SDF_CloseDevice(deviceHandle);
    }
}
```

## 安装

### 从源码构建

```bash
# 1. 克隆仓库
git clone https://github.com/openhitls/sdf4j.git
cd sdf4j

# 2. 一键构建（Maven自动编译JNI库和Java代码）
mvn clean package

# 3. 验证构建产物
ls -lh target/sdf4j-*.jar              # Java JAR包
ls -lh target/native/libsdf4j-jni.so   # JNI动态库
```

**构建产物：**
- `target/sdf4j-1.0.0-SNAPSHOT.jar` - 主JAR包
- `target/sdf4j-1.0.0-SNAPSHOT-sources.jar` - 源码JAR
- `target/sdf4j-1.0.0-SNAPSHOT-javadoc.jar` - Javadoc JAR
- `target/native/libsdf4j-jni.so` - JNI动态库

**使用构建产物：**
```bash
# 运行应用（假设已在 sdf4j.properties 中配置了 library.name）
java -cp target/sdf4j-1.0.0-SNAPSHOT.jar \
     -Djava.library.path=target/native \
     YourApp

# 使用系统属性指定库名称和路径
java -cp target/sdf4j-1.0.0-SNAPSHOT.jar \
     -Djava.library.path=target/native \
     -Dsdf4j.library.name=sdf \
     -Dsdf4j.library.path=/opt/sdf/lib \
     YourApp
```

## 编译

### 编译时配置 SDF 库（推荐）

**为什么在编译时配置？**
- 编译出的 JAR 包已包含库配置，使用更方便
- 不同环境可编译不同配置的 JAR 包
- 默认配置：`libsdf.so`，从系统路径查找

**基本编译（使用默认配置）：**
```bash
# 默认配置：library.name=sdf, library.path=空（系统路径）
mvn clean package
# 生成的 JAR 会在 /usr/lib、/usr/local/lib 等路径查找 libsdf.so
```

**编译时指定 SDF 库：**
```bash
# 指定库名称（可选）和路径（可选）
mvn clean package -DskipTests \
    -Dsdf.library.name=name_of_sdf \
    -Dsdf.library.path=/opt/sdf/lib

# 仅指定库名称，从系统路径查找
mvn clean package -Dsdf.library.name=sdf
```

**编译时配置的好处**：编译后的 JAR 包可直接使用，无需运行时配置：
```bash
# JAR 包已包含库配置，直接运行
java -cp target/sdf4j-1.0.0-SNAPSHOT.jar \
     -Djava.library.path=target/native \
     YourApp
```

---

### 构建模式选择

**不同构建模式：**

```bash
# Debug模式：启用调试符号，禁用优化（调试JNI问题时使用）
mvn clean package -Pdebug

# Release模式：启用优化，禁用调试符号（生产环境使用）
mvn clean package -Prelease

# 仅编译不测试（快速验证）
mvn clean package -DskipTests

# 组合：Release模式 + 自定义库
mvn clean package -Prelease \
    -Dsdf.library.name=adf \
    -Dsdf.library.path=/opt/vendor/lib
```

### Maven常用命令

```bash
# 仅编译
mvn clean compile

# 运行测试
mvn test

# 生成Javadoc文档
mvn javadoc:javadoc
# 输出: target/site/apidocs/

# 生成测试覆盖率报告
mvn test jacoco:report
# 报告位于: target/site/jacoco/index.html
```

### 独立编译JNI（仅调试用）

**注意：** 通常不需要单独编译JNI，Maven会自动处理。仅在调试JNI层问题时使用。

```bash
cd src/main/native

# 创建构建目录
mkdir -p build && cd build

# 配置CMake（指定构建类型）
# 注意: SDF头文件已包含在项目中，SDF库在运行时动态加载
cmake .. \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo

# 编译
cmake --build . -j

# Debug模式：-DCMAKE_BUILD_TYPE=Debug
# Release模式：-DCMAKE_BUILD_TYPE=Release
```

**输出：** `target/native/libsdf4j-jni.so`

### 编译故障排查

#### 问题：找不到 JNI 头文件

```bash
# 错误：jni.h: No such file or directory
# 解决：设置 JAVA_HOME
export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
mvn clean compile
```

#### 问题：找不到 SDF 库文件

```bash
# 错误：运行时找不到 SDF 库
# 解决：配置库名称（必填）和库路径（可选）
# 编译时不需要 SDF 库，只需要运行时配置

# 方式1：在 sdf4j.properties 中配置
library.name=swsds
library.path=/opt/sdf/lib

# 方式2：使用系统属性
java -Dsdf4j.library.name=swsds -Dsdf4j.library.path=/opt/sdf/lib ...
```

#### 问题：CMake 版本过低

```bash
# 错误：CMake 3.10 or higher is required
# 解决：升级 CMake
sudo apt-get install cmake  # Debian/Ubuntu
# 或从源码安装: https://cmake.org/download/
```

### 验证编译结果

```bash
# 检查JNI库依赖
ldd target/native/libsdf4j-jni.so

# 检查JNI库符号
nm -D target/native/libsdf4j-jni.so | grep Java

# 运行快速测试
mvn test -Dtest=ErrorCodeTest,AlgorithmIDTest
```

## 使用示例

项目包含三个完整的示例程序：

### 运行示例测试

```bash
# 进入 examples 目录
cd examples

# 运行所有示例测试
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

### SM2Example.java

SM2 非对称加密算法测试：
- `testExternalSign()` - 外部密钥签名和验签
- `testExternalEncrypt()` - 外部密钥加密和解密

### SM3Example.java

SM3 哈希算法测试：
- `testSM3Hash()` - SM3 哈希计算

### SM4Example.java

SM4 对称加密算法测试：
- `testSM4ECB()` - ECB 模式加密解密
- `testSM4CBC()` - CBC 模式加密解密

**配置要求**：需要配置密钥索引和密码（见 examples/README.md）

## 文档

### 用户指南

- **API 使用指南**: [docs/API_GUIDE.md](docs/API_GUIDE.md) - 详细的 API 使用说明
- **部分实现测试**: [docs/PARTIAL_IMPLEMENTATION_TEST.md](docs/PARTIAL_IMPLEMENTATION_TEST.md) - 如何处理未完整实现标准的 SDF 库


### 特性说明

#### 部分实现支持

SDF4J 支持未完整实现 GM/T 0018-2023 标准的 SDF 库。详见 [部分实现测试指南](docs/PARTIAL_IMPLEMENTATION_TEST.md)。

**核心函数**（必须实现）：
- `SDF_OpenDevice`、`SDF_CloseDevice`
- `SDF_OpenSession`、`SDF_CloseSession`

**可选函数**：其他所有函数均为可选。调用未实现的函数时会抛出 `SDFException`，错误码为 `SDR_NOTSUPPORT` (0x01000002)。

**功能探测示例**：
```java
try {
    ECCPublicKey key = sdf.SDF_ExportSignPublicKey_ECC(session, 1);
    System.out.println("SM2签名公钥导出功能可用");
} catch (SDFException e) {
    if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
        System.out.println("此SDF库不支持SM2签名公钥导出");
        // 使用替代方案
    }
}
```

### SDF 库配置

SDF4J 支持灵活配置不同厂商的 SDF 库。配置包含两个参数：

**1. 库名称（必填）**
- 配置文件：编辑 `src/main/resources/sdf4j.properties`
  ```properties
  library.name=sdf  # 对应 libsdf.so
  ```
- 或系统属性：`-Dsdf4j.library.name=sdf`
- 或环境变量：`export SDF_LIBRARY_NAME=sdf`

**2. 库路径（可选）**
- 如果库在系统路径（`/usr/lib`, `/usr/local/lib`）：不需要配置
- 如果库在自定义路径：
  ```properties
  library.path=/opt/sdf/lib  # 库所在目录
  ```

**快速示例**：
```bash
# 方式1：修改配置文件 sdf4j.properties
library.name=sdf

# 方式2：运行时指定
java -Dsdf4j.library.name=sdf -Djava.library.path=target/native YourApp

# 方式3：自定义路径
java -Dsdf4j.library.name=sdf -Dsdf4j.library.path=/opt/sdf/lib YourApp
```

> **重要**: 编译时不需要 SDF 库，只在运行时需要。构建始终成功。

## 测试

### 测试环境配置

#### 方式一：使用真实SDF设备

```bash
# 方式1：配置环境变量
export SDF_LIBRARY_NAME=swsds
export SDF_LIBRARY_PATH=/opt/sdf/lib

# 方式2：在运行测试时指定系统属性
mvn test -Dsdf4j.library.name=swsds -Dsdf4j.library.path=/opt/sdf/lib

# 方式3：在 sdf4j.properties 中配置（推荐）
# library.name=swsds
# library.path=/opt/sdf/lib
mvn test
```

#### 方式二：无设备环境（推荐用于CI）

没有真实设备时，只运行不依赖设备的测试：

```bash
# 只运行常量和类型测试
mvn test -Dtest=ErrorCodeTest,AlgorithmIDTest,SDFExceptionTest,DeviceInfoTest

# 跳过设备相关测试
mvn test -Dtest=!DeviceManagementTest
```

#### 方式三：Mock SDF库（高级）

创建Mock SDF库用于测试：

```bash
# 创建最小化的Mock库（仅实现核心4个函数）
cat > mock_sdf.c << 'EOF'
#include <stddef.h>

int SDF_OpenDevice(void** handle) { *handle = (void*)1; return 0; }
int SDF_CloseDevice(void* handle) { return 0; }
int SDF_OpenSession(void* device, void** session) { *session = (void*)1; return 0; }
int SDF_CloseSession(void* session) { return 0; }
EOF

gcc -shared -fPIC -o libsdf-mock.so mock_sdf.c

# 使用Mock库测试部分实现支持
mvn test -Dsdf4j.library.path=./libsdf-mock.so
```

### 运行测试

#### 运行所有测试

```bash
mvn test
```

#### 运行特定测试类

```bash
# 运行常量测试（无需设备）
mvn test -Dtest=ErrorCodeTest,AlgorithmIDTest

# 运行设备管理测试（需要真实设备）
mvn test -Dtest=DeviceManagementTest

# 运行异常处理测试
mvn test -Dtest=SDFExceptionTest
```

#### 运行特定测试方法

```bash
# 运行单个测试方法
mvn test -Dtest=ErrorCodeTest#testBasicErrorCodes
```

### 测试覆盖率

```bash
# 生成覆盖率报告
mvn test jacoco:report

# 查看报告
open target/site/jacoco/index.html  # macOS
xdg-open target/site/jacoco/index.html  # Linux
```

### 测试部分实现的SDF库

参见 [docs/PARTIAL_IMPLEMENTATION_TEST.md](docs/PARTIAL_IMPLEMENTATION_TEST.md) 获取完整的测试指南。

快速测试示例：

```java
@Test
public void testPartialImplementation() {
    try {
        sdf.SDF_GenerateRandom(session, 16);
        assertTrue("随机数生成功能可用", true);
    } catch (SDFException e) {
        if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
            // 预期行为：功能未实现
            System.out.println("随机数生成功能未实现");
        } else {
            throw e;  // 其他错误应该失败
        }
    }
}
```

**注意**: 部分测试需要真实的密码设备。如果没有设备，相关测试将自动跳过或使用Mock库。

## 常见问题

### Q: UnsatisfiedLinkError: no sdf4j-jni in java.library.path

**A**: JNI库未找到，请确保：
1. `libsdf4j-jni.so` 在 `java.library.path` 中
2. 使用 `-Djava.library.path=target/native` 指定路径

### Q: SDF library not loaded 或 library name not configured

**A**: SDF库加载失败，请检查：

1. **确认已配置库名称**（必填）：
   ```properties
   # sdf4j.properties
   library.name=swsds
   ```
   或使用系统属性：`-Dsdf4j.library.name=swsds`

2. **检查库文件是否存在**：
   ```bash
   # 如果配置了 library.path
   ls -l /opt/sdf/lib/libswsds.so

   # 如果使用系统路径，查找库
   find /usr/lib /usr/local/lib -name "libswsds.so"
   ```

3. **检查库依赖**：
   ```bash
   ldd /path/to/libswsds.so
   ```

4. **使用系统属性明确指定**：
   ```bash
   java -Dsdf4j.library.name=swsds \
        -Dsdf4j.library.path=/opt/sdf/lib \
        ...
   ```

### Q: 某些SDF函数返回 SDR_NOTSUPPORT (0x01000002)

**A**: 这是**正常行为**。您使用的SDF库未实现该功能。

**背景**：不同的SDF提供商可能只实现GM/T 0018-2023标准的部分功能。

**处理方法**：
```java
try {
    byte[] random = sdf.SDF_GenerateRandom(session, 16);
} catch (SDFException e) {
    if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
        // 功能未实现，使用替代方案
        System.out.println("随机数生成功能不可用");
    } else {
        throw e;  // 其他错误
    }
}
```

参见 [部分实现测试指南](docs/PARTIAL_IMPLEMENTATION_TEST.md) 获取详细说明。

### Q: 如何检测SDF库支持哪些功能？

**A**: 使用try-catch进行功能探测：

```java
Map<String, Boolean> capabilities = new HashMap<>();

// 测试随机数生成
try {
    sdf.SDF_GenerateRandom(session, 16);
    capabilities.put("RandomGeneration", true);
} catch (SDFException e) {
    capabilities.put("RandomGeneration",
        e.getErrorCode() != ErrorCode.SDR_NOTSUPPORT);
}

// 测试SM2公钥导出
try {
    sdf.SDF_ExportSignPublicKey_ECC(session, 1);
    capabilities.put("SM2Export", true);
} catch (SDFException e) {
    capabilities.put("SM2Export",
        e.getErrorCode() != ErrorCode.SDR_NOTSUPPORT);
}
```

完整的功能规格示例见 [docs/PARTIAL_IMPLEMENTATION_TEST.md](docs/PARTIAL_IMPLEMENTATION_TEST.md)。

### Q: 库加载时看到 "Warning: Optional SDF function 'XXX' not available"

**A**: 这是**正常警告**。表示您的SDF库没有实现某些可选函数。

- 只要核心4个函数存在（OpenDevice/CloseDevice/OpenSession/CloseSession），库就能正常加载
- 可以使用已实现的功能
- 调用未实现的函数时会抛出 `SDR_NOTSUPPORT` 异常

### Q: 如何在没有设备的情况下测试？

**A**: 三种方法：

1. **只运行无设备测试**：
   ```bash
   mvn test -Dtest=ErrorCodeTest,AlgorithmIDTest,SDFExceptionTest
   ```

2. **使用Mock SDF库**（见测试章节的"方式三"）

3. **设备相关测试会自动跳过**（如果检测不到SDF库）

### Q: 支持哪些算法？

**A**: SDF4J 支持所有 GM/T 0018-2023 定义的算法：
- **对称**: SM1, SM4, SM7, SSF33, AES
- **非对称**: RSA, SM2, SM9
- **杂凑**: SM3, SHA-1, SHA-256, SHA-384, SHA-512

**具体支持的算法取决于底层密码设备的实现程度**。使用功能探测方法检测可用算法。

### Q: 编译时提示找不到 sdf.h

**A**: SDF标准头文件已包含在项目中（`src/main/native/include/`），编译时无需外部头文件。

仅运行时需要SDF库文件：

```bash
# 检查是否有SDF库文件（不同厂商名称不同）
find /usr -name "libswsds.so" -o -name "libgmapi.so" -o -name "libsdf.so" 2>/dev/null

# 如果没有，向SDF库提供商获取库文件
# 编译不需要指定路径，运行时配置即可

# 在 sdf4j.properties 中配置
library.name=swsds
library.path=/opt/sdf/lib

# 或使用系统属性
java -Dsdf4j.library.name=swsds -Dsdf4j.library.path=/opt/sdf/lib ...
```

## 贡献

欢迎贡献代码！

### 开发流程

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 提交 Pull Request

### 代码规范

- 遵循 Java 代码规范
- 添加必要的注释和文档
- 确保所有测试通过
- 更新相关文档

## 许可证

本项目采用 [木兰宽松许可证第2版（Mulan PSL v2）](LICENSE)

```
Copyright (c) 2025 openHiTLS
SDF4J is licensed under Mulan PSL v2.
You can use this software according to the terms and conditions of the Mulan PSL v2.
You may obtain a copy of Mulan PSL v2 at:
         http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.
```

## 相关链接

- [openHiTLS 项目](https://gitcode.com/openhitls/openhitls)
- [GM/T 0018-2023 标准](http://www.gmbz.org.cn/)
- [问题反馈](https://gitcode.com/openhitls/sdf4j/issues)

## 联系方式

- 项目主页: https://gitcode.com/openhitls/sdf4j
- 问题反馈: https://gitcode.com/openhitls/sdf4j/issues
- openHiTLS: https://gitcode.com/openhitls/openhitls

---

**SDF4J** - Java Binding for GM/T 0018-2023 SDF
