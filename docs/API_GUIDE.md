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
- [文件操作](#文件操作)
- [日志管理](#日志管理)
- [错误处理](#错误处理)
- [最佳实践](#最佳实践)
- [常见问题](#常见问题)
- [API参考](#api参考)

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

### KEK密钥访问权限管理

KEK（Key Encryption Key）是用于加密保护其他密钥的密钥。

```java
// 获取KEK密钥访问权限
sdf.SDF_GetKEKAccessRight(sessionHandle, 1, "kek_password");

// 使用KEK密钥进行密钥加解密操作...

// 释放KEK密钥访问权限
sdf.SDF_ReleaseKEKAccessRight(sessionHandle, 1);
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

### 使用KEK生成和导入会话密钥

```java
import org.openhitls.sdf4j.types.KeyEncryptionResult;

// 使用KEK生成会话密钥
KeyEncryptionResult result = sdf.SDF_GenerateKeyWithKEK(
    sessionHandle,
    128,                        // 密钥长度（位）
    AlgorithmID.SGD_SM4_ECB,    // 算法标识
    1                           // KEK索引
);
long keyHandle = result.getKeyHandle();
byte[] encryptedKey = result.getEncryptedKey();

// 导入使用KEK加密的会话密钥
long importedKeyHandle = sdf.SDF_ImportKeyWithKEK(
    sessionHandle,
    AlgorithmID.SGD_SM4_ECB,
    1,                          // KEK索引
    encryptedKey
);
```

### 使用RSA生成和导入会话密钥

```java
// 使用内部RSA公钥生成会话密钥
KeyEncryptionResult rsaResult = sdf.SDF_GenerateKeyWithIPK_RSA(
    sessionHandle,
    1,      // 公钥索引
    128     // 密钥长度（位）
);

// 使用内部RSA私钥导入会话密钥
long rsaKeyHandle = sdf.SDF_ImportKeyWithISK_RSA(
    sessionHandle,
    1,                              // 私钥索引
    rsaResult.getEncryptedKey()
);
```

### 使用ECC生成和导入会话密钥

```java
// 使用内部ECC公钥生成会话密钥
KeyEncryptionResult eccResult = sdf.SDF_GenerateKeyWithIPK_ECC(
    sessionHandle,
    1,      // 公钥索引
    128     // 密钥长度（位）
);

// 使用内部ECC私钥导入会话密钥
long eccKeyHandle = sdf.SDF_ImportKeyWithISK_ECC(
    sessionHandle,
    1,                          // 私钥索引
    eccResult.getEccCipher()    // ECC密文
);
```

### 密钥协商（SM2）

密钥协商用于两方安全地生成共享会话密钥。

```java
// 发起方：生成协商参数
byte[] sponsorID = "SponsorID1234567".getBytes("UTF-8");
ECCPublicKey sponsorPubKey = sdf.SDF_ExportSignPublicKey_ECC(sessionHandle, 1);
// 发起方生成临时密钥对
Object[] sponsorTmpKeyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, 256);
ECCPublicKey sponsorTmpPubKey = (ECCPublicKey) sponsorTmpKeyPair[0];

long agreementHandle = sdf.SDF_GenerateAgreementDataWithECC(
    sessionHandle,
    1,                      // 密钥索引
    128,                    // 会话密钥长度（位）
    sponsorID,
    sponsorPubKey,
    sponsorTmpPubKey
);

// 响应方：生成协商数据并计算会话密钥
byte[] responseID = "ResponseID123456".getBytes("UTF-8");
ECCPublicKey responsePubKey = sdf.SDF_ExportSignPublicKey_ECC(sessionHandle, 2);
// 响应方生成临时密钥对
Object[] responseTmpKeyPair = sdf.SDF_GenerateKeyPair_ECC(sessionHandle, AlgorithmID.SGD_SM2_1, 256);
ECCPublicKey responseTmpPubKey = (ECCPublicKey) responseTmpKeyPair[0];

// 发起方计算会话密钥
long sessionKey = sdf.SDF_GenerateKeyWithECC(
    sessionHandle,
    responseID,
    responsePubKey,
    responseTmpPubKey,
    agreementHandle
);
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

### 多包加密（分块加密）

适用于大数据量的分块加密处理：

```java
// 初始化加密
byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 16);
sdf.SDF_EncryptInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_CBC, iv);

// 分块加密
ByteArrayOutputStream cipherStream = new ByteArrayOutputStream();
byte[] block1 = "First block data".getBytes("UTF-8");
byte[] block2 = "Second block data".getBytes("UTF-8");

cipherStream.write(sdf.SDF_EncryptUpdate(sessionHandle, block1));
cipherStream.write(sdf.SDF_EncryptUpdate(sessionHandle, block2));

// 完成加密
cipherStream.write(sdf.SDF_EncryptFinal(sessionHandle));
byte[] ciphertext = cipherStream.toByteArray();
```

### 多包解密（分块解密）

```java
// 初始化解密
sdf.SDF_DecryptInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_CBC, iv);

// 分块解密
ByteArrayOutputStream plainStream = new ByteArrayOutputStream();
// 假设密文分成多个块处理
for (byte[] cipherBlock : cipherBlocks) {
    plainStream.write(sdf.SDF_DecryptUpdate(sessionHandle, cipherBlock));
}

// 完成解密
plainStream.write(sdf.SDF_DecryptFinal(sessionHandle));
byte[] plaintext = plainStream.toByteArray();
```

### 多包MAC计算

```java
// 初始化MAC计算
sdf.SDF_CalculateMACInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_MAC, null);

// 分块更新数据
sdf.SDF_CalculateMACUpdate(sessionHandle, "Part 1 data".getBytes("UTF-8"));
sdf.SDF_CalculateMACUpdate(sessionHandle, "Part 2 data".getBytes("UTF-8"));
sdf.SDF_CalculateMACUpdate(sessionHandle, "Part 3 data".getBytes("UTF-8"));

// 获取MAC值
byte[] mac = sdf.SDF_CalculateMACFinal(sessionHandle);
```

### 认证加密（AEAD）

认证加密同时提供数据加密和完整性保护：

```java
byte[] plaintext = "Sensitive data".getBytes("UTF-8");
byte[] iv = sdf.SDF_GenerateRandom(sessionHandle, 12);  // GCM模式通常使用12字节IV
byte[] aad = "Additional authenticated data".getBytes("UTF-8");

// 认证加密
byte[][] authEncResult = sdf.SDF_AuthEnc(
    sessionHandle,
    keyHandle,
    AlgorithmID.SGD_SM4_GCM,
    iv,
    aad,
    plaintext
);
byte[] ciphertext = authEncResult[0];  // 密文
byte[] authTag = authEncResult[1];      // 认证标签

System.out.println("密文: " + bytesToHex(ciphertext));
System.out.println("认证标签: " + bytesToHex(authTag));
```

### 认证解密

```java
// 认证解密
byte[] decrypted = sdf.SDF_AuthDec(
    sessionHandle,
    keyHandle,
    AlgorithmID.SGD_SM4_GCM,
    iv,
    aad,
    authTag,
    ciphertext
);
System.out.println("解密结果: " + new String(decrypted, "UTF-8"));
```

### 多包认证加密

```java
// 初始化认证加密
int totalDataLength = 1024;  // 总数据长度
sdf.SDF_AuthEncInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM4_GCM,
                    iv, aad, totalDataLength);

// 分块加密
ByteArrayOutputStream cipherStream = new ByteArrayOutputStream();
cipherStream.write(sdf.SDF_AuthEncUpdate(sessionHandle, dataBlock1));
cipherStream.write(sdf.SDF_AuthEncUpdate(sessionHandle, dataBlock2));

// 完成认证加密，获取最终密文和认证标签
byte[][] finalResult = sdf.SDF_AuthEncFinal(sessionHandle, null);
byte[] finalCiphertext = finalResult[0];
byte[] authTag = finalResult[1];
```

### 外部密钥加密

使用外部提供的密钥进行加密（常用于调试）：

```java
byte[] externalKey = new byte[16];  // 16字节SM4密钥
// 填充密钥...

byte[] ciphertext = sdf.SDF_ExternalKeyEncrypt(
    sessionHandle,
    AlgorithmID.SGD_SM4_ECB,
    externalKey,
    null,           // ECB模式不需要IV
    plaintext
);

byte[] decrypted = sdf.SDF_ExternalKeyDecrypt(
    sessionHandle,
    AlgorithmID.SGD_SM4_ECB,
    externalKey,
    null,
    ciphertext
);
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

### HMAC计算

HMAC（基于Hash的消息认证码）使用密钥进行消息认证：

```java
// 使用内部密钥初始化HMAC
sdf.SDF_HMACInit(sessionHandle, keyHandle, AlgorithmID.SGD_SM3);

// 更新数据（可多次调用）
sdf.SDF_HMACUpdate(sessionHandle, "Part 1".getBytes("UTF-8"));
sdf.SDF_HMACUpdate(sessionHandle, "Part 2".getBytes("UTF-8"));

// 获取HMAC值
byte[] hmac = sdf.SDF_HMACFinal(sessionHandle);
System.out.println("HMAC: " + bytesToHex(hmac));
```

### 外部密钥HMAC

使用外部提供的密钥计算HMAC：

```java
byte[] hmacKey = "HMACSecretKey123".getBytes("UTF-8");

// 使用外部密钥初始化HMAC
sdf.SDF_ExternalKeyHMACInit(sessionHandle, AlgorithmID.SGD_SM3, hmacKey);

// 更新数据
sdf.SDF_HMACUpdate(sessionHandle, "Message data".getBytes("UTF-8"));

// 获取HMAC值
byte[] hmac = sdf.SDF_HMACFinal(sessionHandle);
```

---

## 文件操作

SDF设备支持在设备内部存储文件，用于保存配置或密钥相关数据。

### 创建文件

```java
// 创建一个1024字节的文件
sdf.SDF_CreateFile(sessionHandle, "config.dat", 1024);
```

### 写入文件

```java
byte[] data = "Configuration data...".getBytes("UTF-8");

// 从偏移量0开始写入数据
sdf.SDF_WriteFile(sessionHandle, "config.dat", 0, data);
```

### 读取文件

```java
// 从偏移量0开始读取100字节
byte[] content = sdf.SDF_ReadFile(sessionHandle, "config.dat", 0, 100);
System.out.println("文件内容: " + new String(content, "UTF-8"));
```

### 删除文件

```java
// 删除文件
sdf.SDF_DeleteFile(sessionHandle, "config.dat");
```

---

## 日志管理

SDF4J提供灵活的日志管理功能，支持Java回调日志和文件日志。

### 设置自定义日志回调

```java
import org.openhitls.sdf4j.SDFLogger;

// 实现自定义日志回调
SDFLogger customLogger = new SDFLogger() {
    @Override
    public void log(int level, String message) {
        String levelStr = getLevelString(level);
        System.out.println("[" + levelStr + "] " + message);
    }

    private String getLevelString(int level) {
        switch (level) {
            case 0: return "DEBUG";
            case 1: return "INFO";
            case 2: return "WARN";
            case 3: return "ERROR";
            default: return "UNKNOWN";
        }
    }
};

// 设置日志回调
SDF.setLogger(customLogger);
```

### 控制日志输出

```java
// 启用/禁用Java回调日志
SDF.setJavaLoggingEnabled(true);

// 启用/禁用文件日志
SDF.setFileLoggingEnabled(false);
```

### 获取当前日志实例

```java
SDFLogger currentLogger = SDF.getLogger();
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

## API参考

### 设备管理类函数（6.2）

| 函数 | 说明 |
|------|------|
| `SDF_OpenDevice()` | 打开设备，返回设备句柄 |
| `SDF_CloseDevice(deviceHandle)` | 关闭设备 |
| `SDF_OpenSession(deviceHandle)` | 创建会话，返回会话句柄 |
| `SDF_CloseSession(sessionHandle)` | 关闭会话 |
| `SDF_GetDeviceInfo(sessionHandle)` | 获取设备信息 |
| `SDF_GenerateRandom(sessionHandle, length)` | 产生随机数 |
| `SDF_GetPrivateKeyAccessRight(sessionHandle, keyIndex, password)` | 获取私钥使用权限 |
| `SDF_ReleasePrivateKeyAccessRight(sessionHandle, keyIndex)` | 释放私钥使用权限 |
| `SDF_GetKEKAccessRight(sessionHandle, keyIndex, password)` | 获取KEK密钥使用权限 |
| `SDF_ReleaseKEKAccessRight(sessionHandle, keyIndex)` | 释放KEK密钥使用权限 |

### 密钥管理类函数（6.3）

| 函数 | 说明 |
|------|------|
| `SDF_ExportSignPublicKey_RSA(sessionHandle, keyIndex)` | 导出RSA签名公钥 |
| `SDF_ExportEncPublicKey_RSA(sessionHandle, keyIndex)` | 导出RSA加密公钥 |
| `SDF_ExportSignPublicKey_ECC(sessionHandle, keyIndex)` | 导出ECC签名公钥 |
| `SDF_ExportEncPublicKey_ECC(sessionHandle, keyIndex)` | 导出ECC加密公钥 |
| `SDF_GenerateKeyWithIPK_RSA(sessionHandle, keyIndex, keyBits)` | 用内部RSA公钥生成会话密钥 |
| `SDF_GenerateKeyWithEPK_RSA(sessionHandle, keyBits, publicKey)` | 用外部RSA公钥生成会话密钥 |
| `SDF_ImportKeyWithISK_RSA(sessionHandle, keyIndex, encryptedKey)` | 用内部RSA私钥导入会话密钥 |
| `SDF_GenerateKeyWithIPK_ECC(sessionHandle, keyIndex, keyBits)` | 用内部ECC公钥生成会话密钥 |
| `SDF_GenerateKeyWithEPK_ECC(sessionHandle, keyBits, algID, publicKey)` | 用外部ECC公钥生成会话密钥 |
| `SDF_ImportKeyWithISK_ECC(sessionHandle, keyIndex, cipher)` | 用内部ECC私钥导入会话密钥 |
| `SDF_GenerateAgreementDataWithECC(...)` | 生成密钥协商参数 |
| `SDF_GenerateKeyWithECC(...)` | 计算会话密钥 |
| `SDF_GenerateAgreementDataAndKeyWithECC(...)` | 产生协商数据并计算会话密钥 |
| `SDF_GenerateKeyWithKEK(sessionHandle, keyBits, algID, kekIndex)` | 用KEK生成会话密钥 |
| `SDF_ImportKeyWithKEK(sessionHandle, algID, kekIndex, encryptedKey)` | 用KEK导入会话密钥 |
| `SDF_DestroyKey(sessionHandle, keyHandle)` | 销毁会话密钥 |

### 非对称算法运算类函数（6.4）

| 函数 | 说明 |
|------|------|
| `SDF_ExternalPublicKeyOperation_RSA(sessionHandle, publicKey, data)` | 外部公钥RSA运算 |
| `SDF_InternalPublicKeyOperation_RSA(sessionHandle, keyIndex, data)` | 内部公钥RSA运算 |
| `SDF_InternalPrivateKeyOperation_RSA(sessionHandle, keyIndex, data)` | 内部私钥RSA运算 |
| `SDF_InternalSign_ECC(sessionHandle, keyIndex, data)` | 内部私钥ECC签名 |
| `SDF_InternalVerify_ECC(sessionHandle, keyIndex, data, signature)` | 内部公钥ECC验签 |
| `SDF_ExternalVerify_ECC(sessionHandle, algID, publicKey, data, signature)` | 外部公钥ECC验签 |
| `SDF_ExternalEncrypt_ECC(sessionHandle, algID, publicKey, data)` | 外部公钥ECC加密 |
| `SDF_InternalEncrypt_ECC(sessionHandle, keyIndex, data)` | 内部公钥ECC加密 |
| `SDF_InternalDecrypt_ECC(sessionHandle, keyIndex, eccKeyType, cipher)` | 内部私钥ECC解密 |

### 对称算法运算类函数（6.5）

| 函数 | 说明 |
|------|------|
| `SDF_Encrypt(sessionHandle, keyHandle, algID, iv, data)` | 单包对称加密 |
| `SDF_Decrypt(sessionHandle, keyHandle, algID, iv, encData)` | 单包对称解密 |
| `SDF_CalculateMAC(sessionHandle, keyHandle, algID, iv, data)` | 计算单包MAC |
| `SDF_AuthEnc(sessionHandle, keyHandle, algID, iv, aad, data)` | 单包认证加密 |
| `SDF_AuthDec(sessionHandle, keyHandle, algID, iv, aad, authTag, encData)` | 单包认证解密 |
| `SDF_EncryptInit(sessionHandle, keyHandle, algID, iv)` | 多包加密初始化 |
| `SDF_EncryptUpdate(sessionHandle, data)` | 多包加密更新 |
| `SDF_EncryptFinal(sessionHandle)` | 多包加密结束 |
| `SDF_DecryptInit(sessionHandle, keyHandle, algID, iv)` | 多包解密初始化 |
| `SDF_DecryptUpdate(sessionHandle, encData)` | 多包解密更新 |
| `SDF_DecryptFinal(sessionHandle)` | 多包解密结束 |
| `SDF_CalculateMACInit(sessionHandle, keyHandle, algID, iv)` | 多包MAC初始化 |
| `SDF_CalculateMACUpdate(sessionHandle, data)` | 多包MAC更新 |
| `SDF_CalculateMACFinal(sessionHandle)` | 多包MAC结束 |
| `SDF_AuthEncInit(sessionHandle, keyHandle, algID, iv, aad, dataLength)` | 多包认证加密初始化 |
| `SDF_AuthEncUpdate(sessionHandle, data)` | 多包认证加密更新 |
| `SDF_AuthEncFinal(sessionHandle, pucEncData)` | 多包认证加密结束 |
| `SDF_AuthDecInit(sessionHandle, keyHandle, algID, iv, aad, authTag, dataLength)` | 多包认证解密初始化 |
| `SDF_AuthDecUpdate(sessionHandle, encData)` | 多包认证解密更新 |
| `SDF_AuthDecFinal(sessionHandle)` | 多包认证解密结束 |

### 杂凑运算类函数（6.6）

| 函数 | 说明 |
|------|------|
| `SDF_HMACInit(sessionHandle, keyHandle, algID)` | HMAC初始化 |
| `SDF_HMACUpdate(sessionHandle, data)` | HMAC更新 |
| `SDF_HMACFinal(sessionHandle)` | HMAC结束 |
| `SDF_HashInit(sessionHandle, algID, publicKey, id)` | 杂凑初始化 |
| `SDF_HashUpdate(sessionHandle, data)` | 杂凑更新 |
| `SDF_HashFinal(sessionHandle)` | 杂凑结束 |

### 用户文件操作类函数（6.7）

| 函数 | 说明 |
|------|------|
| `SDF_CreateFile(sessionHandle, fileName, fileSize)` | 创建文件 |
| `SDF_ReadFile(sessionHandle, fileName, offset, length)` | 读取文件 |
| `SDF_WriteFile(sessionHandle, fileName, offset, data)` | 写入文件 |
| `SDF_DeleteFile(sessionHandle, fileName)` | 删除文件 |

### 验证调试类函数（6.8）

| 函数 | 说明 |
|------|------|
| `SDF_GenerateKeyPair_RSA(sessionHandle, keyBits)` | 生成RSA密钥对 |
| `SDF_GenerateKeyPair_ECC(sessionHandle, algID, keyBits)` | 生成ECC密钥对 |
| `SDF_ExternalPrivateKeyOperation_RSA(sessionHandle, privateKey, data)` | 外部私钥RSA运算 |
| `SDF_ExternalSign_ECC(sessionHandle, algID, privateKey, data)` | 外部私钥ECC签名 |
| `SDF_ExternalDecrypt_ECC(sessionHandle, algID, privateKey, cipher)` | 外部私钥ECC解密 |
| `SDF_ExternalKeyEncrypt(sessionHandle, algID, key, iv, data)` | 外部密钥对称加密 |
| `SDF_ExternalKeyDecrypt(sessionHandle, algID, key, iv, encData)` | 外部密钥对称解密 |
| `SDF_ExternalKeyEncryptInit(sessionHandle, algID, key, iv)` | 外部密钥多包加密初始化 |
| `SDF_ExternalKeyDecryptInit(sessionHandle, algID, key, iv)` | 外部密钥多包解密初始化 |
| `SDF_ExternalKeyHMACInit(sessionHandle, algID, key)` | 外部密钥HMAC初始化 |

### 日志管理函数

| 函数 | 说明 |
|------|------|
| `SDF.setLogger(logger)` | 设置日志回调 |
| `SDF.getLogger()` | 获取当前日志回调 |
| `SDF.setFileLoggingEnabled(enable)` | 启用/禁用文件日志 |
| `SDF.setJavaLoggingEnabled(enable)` | 启用/禁用Java回调日志 |

---

## 参考资料

- [GM/T 0018-2023 密码设备应用接口规范](http://www.gmbz.org.cn/)
- [OpenHitls 项目](https://github.com/openhitls/openhitls)
- [SDF4J Javadoc](./target/site/apidocs/index.html)

---

## 许可证

SDF4J使用[木兰宽松许可证第2版（Mulan PSL v2）](../LICENSE)

Copyright © 2025 OpenHitls. All Rights Reserved.
