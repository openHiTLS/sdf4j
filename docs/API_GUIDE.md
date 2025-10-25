# SDF4J API 使用指南

## 目录

- [简介](#简介)
- [环境要求](#环境要求)
- [快速开始](#快速开始)
- [设备管理](#设备管理)
- [密钥管理](#密钥管理)
- [对称加密](#对称加密)
- [非对称加密](#非对称加密)
- [杂凑运算](#杂凑运算)
- [错误处理](#错误处理)
- [最佳实践](#最佳实践)
- [常见问题](#常见问题)

---

## 简介

SDF4J是OpenHitls项目的子项目，提供符合**GM/T 0018-2023《密码设备应用接口规范》**的Java语言封装。
该库支持国密SM2、SM3、SM4等算法，适用于需要使用密码设备的Java应用程序。

### 主要特性

- ✅ **完整的SDF接口** - 覆盖设备管理、密钥管理、加解密、签名验签等所有核心功能
- ✅ **国密算法支持** - SM2、SM3、SM4、SM9等国密算法
- ✅ **动态库加载** - 支持灵活配置密码设备库路径
- ✅ **类型安全** - 完整的Java类型定义和参数校验
- ✅ **异常处理** - 统一的异常体系和错误码映射

---

## 环境要求

### 软件要求

- **Java**: JDK 8 或更高版本
- **Maven**: 3.6+ (如果从源码构建)
- **操作系统**: Linux x86_64 或 aarch64

### 依赖库

1. **SDF动态库** (`libsdfx.so`): 符合GM/T 0018-2023标准的密码设备库
2. **JNI桥接库** (`libsdf4j-jni.so`): SDF4J提供的JNI实现

### Maven依赖

```xml
<dependency>
    <groupId>org.openhitls</groupId>
    <artifactId>sdf4j</artifactId>
    <version>1.0.0</version>
</dependency>
```

---

## 快速开始

### 1. 配置库路径

SDF4J支持多种方式配置SDF库路径（按优先级排序）：

#### 方式一：Java系统属性

```bash
java -Dsdf4j.library.path=/usr/lib/libsdfx.so -jar your-app.jar
```

#### 方式二：配置文件

在 `src/main/resources/sdf4j.properties` 中配置：

```properties
library.name=sdfx
library.search.paths=/usr/lib:/usr/local/lib
```

#### 方式三：环境变量

```bash
export SDF_LIBRARY_PATH=/usr/lib/libsdfx.so
```

#### 方式四：默认路径

SDF4J会自动搜索以下路径：
- `/usr/lib`
- `/usr/local/lib`
- `/lib`

### 2. 基本用法示例

```java
import org.openhitls.sdf4j.*;
import org.openhitls.sdf4j.types.*;
import org.openhitls.sdf4j.constants.*;

public class SDF4JExample {
    public static void main(String[] args) {
        try {
            // 创建SDF实例（库会自动加载）
            SDF sdf = new SDF();

            // 打开设备
            long deviceHandle = sdf.SDF_OpenDevice();
            System.out.println("设备句柄: " + deviceHandle);

            // 打开会话
            long sessionHandle = sdf.SDF_OpenSession(deviceHandle);
            System.out.println("会话句柄: " + sessionHandle);

            // 获取设备信息
            DeviceInfo info = sdf.SDF_GetDeviceInfo(sessionHandle);
            System.out.println("设备厂商: " + info.getIssuerName());
            System.out.println("设备型号: " + info.getDeviceName());
            System.out.println("设备序列号: " + info.getDeviceSerial());

            // 生成随机数
            byte[] random = sdf.SDF_GenerateRandom(sessionHandle, 32);
            System.out.println("随机数长度: " + random.length);

            // 关闭会话和设备
            sdf.SDF_CloseSession(sessionHandle);
            sdf.SDF_CloseDevice(deviceHandle);

            System.out.println("操作成功!");

        } catch (SDFException e) {
            System.err.println("SDF错误: " + e.getErrorCodeHex() + " - " + e.getMessage());
            e.printStackTrace();
        }
    }
}
```

---

## 设备管理

### 打开和关闭设备

```java
SDF sdf = new SDF();

// 打开设备
long deviceHandle = sdf.SDF_OpenDevice();

// 使用设备...

// 关闭设备
sdf.SDF_CloseDevice(deviceHandle);
```

### 会话管理

```java
// 打开会话
long sessionHandle = sdf.SDF_OpenSession(deviceHandle);

// 在会话中执行操作...

// 关闭会话
sdf.SDF_CloseSession(sessionHandle);
```

### 获取设备信息

```java
DeviceInfo info = sdf.SDF_GetDeviceInfo(sessionHandle);

System.out.println("厂商: " + info.getIssuerName());
System.out.println("型号: " + info.getDeviceName());
System.out.println("序列号: " + info.getDeviceSerial());
System.out.println("版本: " + info.getDeviceVersion());
System.out.println("标准版本: " + info.getStandardVersion());
System.out.println("缓冲区大小: " + info.getBufferSize());
```

### 生成随机数

```java
// 生成32字节随机数
byte[] random = sdf.SDF_GenerateRandom(sessionHandle, 32);
System.out.println("随机数: " + bytesToHex(random));
```

### 私钥访问权限管理

```java
// 获取私钥访问权限（需要密码）
sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, 1, "password123");

// 使用私钥进行操作...

// 释放私钥访问权限
sdf.SDF_ReleasePrivateKeyAccessRight(sessionHandle, 1);
```

---

## 密钥管理

### 导出RSA公钥

```java
// 导出签名公钥
RSAPublicKey signPubKey = sdf.SDF_ExportSignPublicKey_RSA(sessionHandle, 1);
System.out.println("RSA密钥位数: " + signPubKey.getBits());
System.out.println("模数n: " + bytesToHex(signPubKey.getM()));
System.out.println("指数e: " + bytesToHex(signPubKey.getE()));

// 导出加密公钥
RSAPublicKey encPubKey = sdf.SDF_ExportEncPublicKey_RSA(sessionHandle, 1);
```

### 导出ECC公钥

```java
// 导出ECC签名公钥
ECCPublicKey eccSignPubKey = sdf.SDF_ExportSignPublicKey_ECC(sessionHandle, 1);
System.out.println("ECC密钥位数: " + eccSignPubKey.getBits());
System.out.println("X坐标: " + bytesToHex(eccSignPubKey.getX()));
System.out.println("Y坐标: " + bytesToHex(eccSignPubKey.getY()));

// 导出ECC加密公钥
ECCPublicKey eccEncPubKey = sdf.SDF_ExportEncPublicKey_ECC(sessionHandle, 1);
```

### 销毁密钥

```java
// 销毁会话密钥
sdf.SDF_DestroyKey(sessionHandle, keyHandle);
```

---

## 对称加密

### SM4加密解密

```java
import org.openhitls.sdf4j.constants.AlgorithmID;

// SM4-ECB加密
byte[] plaintext = "Hello SDF4J!".getBytes("UTF-8");
byte[] ciphertext = sdf.SDF_Encrypt(
    sessionHandle,
    keyHandle,
    AlgorithmID.SGD_SM4_ECB,
    null,  // ECB模式不需要IV
    plaintext
);
System.out.println("密文: " + bytesToHex(ciphertext));

// SM4-ECB解密
byte[] decrypted = sdf.SDF_Decrypt(
    sessionHandle,
    keyHandle,
    AlgorithmID.SGD_SM4_ECB,
    null,
    ciphertext
);
System.out.println("明文: " + new String(decrypted, "UTF-8"));
```

### SM4-CBC模式

```java
// 生成初始向量
byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 16);

// SM4-CBC加密
byte[] ciphertext = sdf.SDF_Encrypt(
    sessionHandle,
    keyHandle,
    AlgorithmID.SGD_SM4_CBC,
    iv,
    plaintext
);

// SM4-CBC解密
byte[] decrypted = sdf.SDF_Decrypt(
    sessionHandle,
    keyHandle,
    AlgorithmID.SGD_SM4_CBC,
    iv,
    ciphertext
);
```

### 计算MAC

```java
byte[] data = "Message to authenticate".getBytes("UTF-8");

// 计算SM4-MAC
byte[] mac = sdf.SDF_CalculateMAC(
    sessionHandle,
    keyHandle,
    AlgorithmID.SGD_SM4_MAC,
    null,
    data
);
System.out.println("MAC: " + bytesToHex(mac));
```

---

## 非对称加密

### SM2签名和验签

#### 内部私钥签名

```java
byte[] data = "Document to sign".getBytes("UTF-8");

// 使用设备内部私钥进行SM2签名
ECCSignature signature = sdf.SDF_InternalSign_ECC(sessionHandle, 1, data);
System.out.println("签名r: " + bytesToHex(signature.getR()));
System.out.println("签名s: " + bytesToHex(signature.getS()));

// 使用设备内部公钥验证签名
sdf.SDF_InternalVerify_ECC(sessionHandle, 1, data, signature);
System.out.println("验签成功!");
```

#### 外部公钥验签

```java
// 导出公钥
ECCPublicKey publicKey = sdf.SDF_ExportSignPublicKey_ECC(sessionHandle, 1);

// 使用外部公钥验签
sdf.SDF_ExternalVerify_ECC(
    sessionHandle,
    AlgorithmID.SGD_SM2_1,
    publicKey,
    data,
    signature
);
System.out.println("外部验签成功!");
```

### SM2加密

```java
byte[] plaintext = "Confidential message".getBytes("UTF-8");

// 导出加密公钥
ECCPublicKey encPublicKey = sdf.SDF_ExportEncPublicKey_ECC(sessionHandle, 1);

// SM2公钥加密
ECCCipher cipher = sdf.SDF_ExternalEncrypt_ECC(
    sessionHandle,
    AlgorithmID.SGD_SM2_3,
    encPublicKey,
    plaintext
);

System.out.println("密文长度: " + cipher.getC().length);
System.out.println("MAC: " + bytesToHex(cipher.getM()));
```

---

## 杂凑运算

### SM3杂凑

```java
byte[] data = "Data to hash".getBytes("UTF-8");

// 初始化杂凑运算
sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);

// 更新数据（可多次调用）
sdf.SDF_HashUpdate(sessionHandle, data);

// 完成杂凑运算
byte[] hash = sdf.SDF_HashFinal(sessionHandle);
System.out.println("SM3杂凑值: " + bytesToHex(hash));
```

### 多包杂凑

```java
// 初始化
sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);

// 分批更新数据
byte[] part1 = "First part ".getBytes("UTF-8");
byte[] part2 = "Second part ".getBytes("UTF-8");
byte[] part3 = "Third part".getBytes("UTF-8");

sdf.SDF_HashUpdate(sessionHandle, part1);
sdf.SDF_HashUpdate(sessionHandle, part2);
sdf.SDF_HashUpdate(sessionHandle, part3);

// 获取最终结果
byte[] finalHash = sdf.SDF_HashFinal(sessionHandle);
System.out.println("多包杂凑值: " + bytesToHex(finalHash));
```

### SM3 Z值计算（带用户ID）

```java
// 导出公钥
ECCPublicKey publicKey = sdf.SDF_ExportSignPublicKey_ECC(sessionHandle, 1);

// 用户ID
byte[] userId = "1234567812345678".getBytes("UTF-8");

// 初始化SM3 Z值计算
sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, publicKey, userId);

// 更新消息
byte[] message = "Message to hash".getBytes("UTF-8");
sdf.SDF_HashUpdate(sessionHandle, message);

// 获取杂凑值（Z值+消息的杂凑）
byte[] hash = sdf.SDF_HashFinal(sessionHandle);
System.out.println("SM3杂凑值（含Z值）: " + bytesToHex(hash));
```

---

## 错误处理

### 捕获和处理异常

```java
try {
    long deviceHandle = sdf.SDF_OpenDevice();
    // ...
} catch (SDFException e) {
    // 获取错误码
    int errorCode = e.getErrorCode();
    String errorHex = e.getErrorCodeHex();

    System.err.println("错误码: " + errorHex);
    System.err.println("错误消息: " + e.getMessage());

    // 根据错误码进行处理
    switch (errorCode) {
        case ErrorCode.SDR_NODEVICE:
            System.err.println("设备未连接");
            break;
        case ErrorCode.SDR_STEPERR:
            System.err.println("操作顺序错误");
            break;
        case ErrorCode.SDR_INARGERR:
            System.err.println("参数错误");
            break;
        default:
            System.err.println("其他错误");
    }
}
```

### 错误码说明

SDF4J定义了31个错误码，主要分类如下：

| 错误码 | 常量 | 说明 |
|--------|------|------|
| 0x00000000 | SDR_OK | 成功 |
| 0x01000001 | SDR_UNKNOWERR | 未知错误 |
| 0x01000002 | SDR_NOTSUPPORT | 不支持的功能 |
| 0x01000003 | SDR_COMMFAIL | 通信失败 |
| 0x01000004 | SDR_HARDFAIL | 硬件错误 |
| 0x01000005 | SDR_OPENDEVICE | 打开设备失败 |
| 0x0100000F | SDR_OPENSESSION | 打开会话失败 |
| 0x01000014 | SDR_KEYNOTEXIST | 密钥不存在 |
| 0x0100001D | SDR_INARGERR | 参数错误 |

完整的错误码列表请参考 `ErrorCode` 类。

---

## 最佳实践

### 1. 资源管理

使用try-with-resources或finally确保资源正确释放：

```java
SDF sdf = new SDF();
long deviceHandle = 0;
long sessionHandle = 0;

try {
    deviceHandle = sdf.SDF_OpenDevice();
    sessionHandle = sdf.SDF_OpenSession(deviceHandle);

    // 执行操作...

} catch (SDFException e) {
    // 处理异常
} finally {
    // 确保资源释放
    try {
        if (sessionHandle != 0) {
            sdf.SDF_CloseSession(sessionHandle);
        }
        if (deviceHandle != 0) {
            sdf.SDF_CloseDevice(deviceHandle);
        }
    } catch (SDFException e) {
        System.err.println("关闭资源失败: " + e.getMessage());
    }
}
```

### 2. 多线程使用

每个线程应使用独立的会话句柄：

```java
public class SDFWorker implements Runnable {
    private final long deviceHandle;

    public SDFWorker(long deviceHandle) {
        this.deviceHandle = deviceHandle;
    }

    @Override
    public void run() {
        SDF sdf = new SDF();
        long sessionHandle = 0;

        try {
            // 每个线程创建自己的会话
            sessionHandle = sdf.SDF_OpenSession(deviceHandle);

            // 执行操作...
            byte[] random = sdf.SDF_GenerateRandom(sessionHandle, 32);

        } catch (SDFException e) {
            e.printStackTrace();
        } finally {
            // 关闭会话
            if (sessionHandle != 0) {
                try {
                    sdf.SDF_CloseSession(sessionHandle);
                } catch (SDFException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
```

### 3. 密码处理

处理敏感数据（如密码）后及时清零：

```java
char[] password = getPasswordFromUser();
String passwordStr = new String(password);

try {
    sdf.SDF_GetPrivateKeyAccessRight(sessionHandle, keyIndex, passwordStr);

    // 使用密钥...

} finally {
    // 清除密码
    Arrays.fill(password, '0');
    passwordStr = null;
}
```

### 4. 日志记录

记录关键操作和错误信息：

```java
import java.util.logging.Logger;

public class SDFLogger {
    private static final Logger logger = Logger.getLogger(SDFLogger.class.getName());

    public void performOperation() {
        SDF sdf = new SDF();

        try {
            logger.info("Opening device...");
            long deviceHandle = sdf.SDF_OpenDevice();
            logger.info("Device opened: " + deviceHandle);

            // ...

        } catch (SDFException e) {
            logger.severe("SDF operation failed: " + e.getErrorCodeHex() + " - " + e.getMessage());
            throw new RuntimeException("Failed to perform SDF operation", e);
        }
    }
}
```

---

## 常见问题

### Q1: 如何确认SDF库是否正确加载？

```java
try {
    SDF sdf = new SDF();
    System.out.println("SDF库加载成功");
} catch (UnsatisfiedLinkError e) {
    System.err.println("SDF库加载失败: " + e.getMessage());
    System.err.println("请检查java.library.path: " + System.getProperty("java.library.path"));
}
```

### Q2: 如何处理"Library not loaded"错误？

确保：
1. JNI库（libsdf4j-jni.so）在java.library.path中
2. SDF库（libsdfx.so）在配置的路径中
3. 所有依赖库都已安装

使用以下命令检查依赖：
```bash
ldd libsdf4j-jni.so
ldd libsdfx.so
```

### Q3: 如何在多线程环境中使用SDF4J？

- 设备句柄可以在线程间共享
- 每个线程应使用独立的会话句柄
- 对共享资源（如密钥句柄）进行适当同步

### Q4: 支持哪些算法？

SDF4J支持所有GM/T 0018-2023标准定义的算法：
- **对称**: SM1, SM4, SM7, SSF33, AES
- **非对称**: RSA, SM2, SM9
- **杂凑**: SM3, SHA-1, SHA-256, SHA-384, SHA-512

具体支持的算法取决于底层密码设备的能力。

### Q5: 如何查看设备支持的算法？

```java
DeviceInfo info = sdf.SDF_GetDeviceInfo(sessionHandle);

// 检查对称算法能力
long symAlg = info.getSymAlgAbility();
if ((symAlg & AlgorithmID.SGD_SM4_ECB) != 0) {
    System.out.println("支持SM4-ECB");
}

// 检查非对称算法能力
long[] asymAlg = info.getAsymAlgAbility();
// ...

// 检查杂凑算法能力
long hashAlg = info.getHashAlgAbility();
if ((hashAlg & AlgorithmID.SGD_SM3) != 0) {
    System.out.println("支持SM3");
}
```

### Q6: 如何调试JNI问题？

启用JNI详细日志：
```bash
java -Xcheck:jni -verbose:jni -jar your-app.jar
```

---

## 工具方法

### 字节数组转十六进制字符串

```java
public static String bytesToHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes) {
        sb.append(String.format("%02x", b));
    }
    return sb.toString();
}
```

### 十六进制字符串转字节数组

```java
public static byte[] hexToBytes(String hex) {
    int len = hex.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
        data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                            + Character.digit(hex.charAt(i+1), 16));
    }
    return data;
}
```

---

## 参考资料

- [GM/T 0018-2023 密码设备应用接口规范](http://www.gmbz.org.cn/)
- [OpenHitls 项目](https://github.com/openhitls/openhitls)
- [SDF4J Javadoc](./target/site/apidocs/index.html)

---

## 许可证

SDF4J使用[木兰宽松许可证第2版（Mulan PSL v2）](../LICENSE)

Copyright © 2025 OpenHitls. All Rights Reserved.
