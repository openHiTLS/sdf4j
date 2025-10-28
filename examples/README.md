# SDF4J Examples

This module contains example usage of SDF4J, including both standalone programs and JUnit tests.

## Overview

Examples are written as JUnit tests instead of standalone programs with `main()` methods. This provides:
- Better resource management with `@Before` and `@After` hooks
- Assertions to verify correct behavior
- Easy integration with Maven test lifecycle
- Graceful handling of optional SDF functions (SDR_NOTSUPPORT)

## Configuration

### Test Configuration Files

SDF4J examples use a configuration file to manage device-specific settings like key indices and passwords. This makes examples more flexible and easier to adapt to different SDF devices.

**Configuration file** (located in `src/test/resources/`):
- `test-config.properties` - Configuration for test examples

**Configuration properties**:
```properties
# SM2 internal key index (used by SM2InternalKeyExampleTest and SM4ExampleTest)
sm2.internal.key.index=10

# Password to obtain private key access right
sm2.key.access.password=<your-device-password>

# SM2 default user ID (GM/T 0009-2012 standard)
sm2.default.user.id=1234567812345678

# Environment identifier
environment.name=default
```

### Configuring for Your Device

Edit `test-config.properties` with your device-specific settings:

```bash
# Edit the config file
vi examples/src/test/resources/test-config.properties

# Update these values according to your SDF device:
# sm2.internal.key.index=10
# sm2.key.access.password=<your-device-password>
# sm2.default.user.id=1234567812345678
# environment.name=default

# Run tests
mvn test
```

## Running Examples

### Run All Examples
```bash
cd sdf4j-examples
mvn test
```

### Run Specific Example
```bash
# Basic device and session management
mvn test -Dtest=BasicExampleTest

# SM3 hash algorithm demonstrations
mvn test -Dtest=SM3ExampleTest

# SM2 with internal device keys (complete examples)
mvn test -Dtest=SM2InternalKeyExampleTest

# SM2 with external generated keys (complete examples)
mvn test -Dtest=SM2ExternalKeyExampleTest

# SM4 symmetric encryption (ECB/CBC/MAC)
mvn test -Dtest=SM4ExampleTest
```

### Run Specific Test Method
```bash
# Run a specific test method
mvn test -Dtest=BasicExampleTest#testGenerateRandom
mvn test -Dtest=SM2InternalKeyExampleTest#testInternalSignAndVerify
mvn test -Dtest=SM2ExternalKeyExampleTest#testExternalEncryptDecrypt
```

### Run with Custom SDF Library
```bash
mvn test -Dsdf4j.library.name=swsds -Dsdf4j.library.path=/opt/sdf/lib
```

## Available Examples

All examples are implemented as JUnit tests in the `src/test/java` directory.

### JUnit Test Examples

#### BasicExampleTest
Demonstrates fundamental SDF operations:
- `testDeviceAndSessionManagement()` - Opening/closing devices and sessions
- `testGetDeviceInfo()` - Retrieving device information
- `testGenerateRandom()` - Generating random numbers
- `testMultipleSessions()` - Managing multiple concurrent sessions

#### SM3ExampleTest
SM3 (Chinese cryptographic hash algorithm) demonstrations:
- `testBasicSM3Hash()` - Basic SM3 hash calculation
- `testStreamingSM3Hash()` - Streaming/chunked SM3 calculation (for large files)
- `testSM3WithUserID()` - SM3 for SM2 signature scenarios (with user ID and public key)
- `testSM3HMAC()` - SM3-HMAC (keyed message authentication code)
- `testCompareHashLengths()` - Comparison of different hash algorithm output lengths

#### SM2InternalKeyExampleTest (内部密钥完整示例)
Complete SM2 examples using internal device keys:
- `testSignAndVerify()` - Sign with internal private key and verify signature
- `testVerifyWithTamperedData()` - Verify data integrity protection

**Configuration Required**: Yes - uses `sm2.internal.key.index` and `sm2.key.access.password`

**Use Case**: Enterprise scenarios requiring hardware-protected keys that never leave the secure device.

**Running with configuration**:
```bash
mvn test -Dtest=SM2InternalKeyExampleTest
```

#### SM2ExternalKeyExampleTest (外部密钥完整示例)
Complete SM2 examples using dynamically generated external key pairs:
- `testGenerateKeyPair()` - Generate temporary SM2 key pair (public + private)
- `testExternalSignAndVerify()` - Sign with external private key, verify with external public key
- `testExternalEncryptDecrypt()` - Complete encrypt/decrypt cycle with external keys
- `testMultipleKeyPairs()` - Generate and use multiple independent key pairs
- `testCrossVerification()` - Verify key isolation (wrong key pair cannot verify)

**Use Case**: Scenarios requiring temporary keys, multi-user key management, or key exportability.

#### SM4ExampleTest
SM4 symmetric encryption examples:
- `testSM4ECB()` - ECB mode encryption/decryption
- `testSM4CBC()` - CBC mode encryption/decryption with IV
- `testSM4MAC()` - Message authentication code calculation

**Configuration Required**: Yes - uses `sm2.internal.key.index` for generating SM4 session keys

**Note:** SM4 tests use internal ECC keys to generate session keys. The key index is read from configuration.

**Running with configuration**:
```bash
mvn test -Dtest=SM4ExampleTest
```

## Dependencies

This module depends on `sdf4j-core`:
```xml
<dependency>
    <groupId>org.openhitls</groupId>
    <artifactId>sdf4j-core</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

The JNI library (`libsdf4j-jni.so`) is loaded from `../sdf4j-core/target/native/`.

## Writing New Examples

1. Create a new test class in `src/test/java/org/openhitls/sdf4j/examples/`
2. Use JUnit annotations:
   ```java
   @Before
   public void setUp() throws SDFException {
       sdf = new SDF();
       deviceHandle = sdf.SDF_OpenDevice();
       sessionHandle = sdf.SDF_OpenSession(deviceHandle);
   }

   @After
   public void tearDown() {
       // Clean up resources
   }

   @Test
   public void testSomeFeature() throws SDFException {
       // Your test code with assertions
   }
   ```
3. Handle optional functions gracefully:
   ```java
   try {
       sdf.SDF_SomeOptionalFunction(...);
   } catch (SDFException e) {
       if (e.getErrorCode() == ErrorCode.SDR_NOTSUPPORT) {
           System.out.println("⚠ Function not implemented");
       } else {
           throw e;
       }
   }
   ```

## Device-Specific Notes

Edit `test-config.properties` with your device-specific settings:
- Update `sm2.internal.key.index` to match keys provisioned in your device
- Update `sm2.key.access.password` to match your device's password
- If your device doesn't require passwords, errors will be gracefully handled

## Troubleshooting

**Configuration file not found**:
```
Warning: Configuration file not found: test-config-xxx.properties
```
Solution: Check that the config file exists in `src/test/resources/`

**Invalid key index**:
```
SDFException: SDR_KEYNOTEXIST (0x01000104)
```
Solution: Update `sm2.internal.key.index` to match a key in your device

**Wrong password**:
```
SDFException: Authentication failed
```
Solution: Update `sm2.key.access.password` to match your device's password

## Security Considerations

- **DO NOT** commit sensitive passwords to version control
- Consider adding `test-config.properties` to `.gitignore` if it contains sensitive data:
  ```bash
  echo "examples/src/test/resources/test-config.properties" >> .gitignore
  ```
- Use strong passwords for production environments
- Consider using environment variables or secure vaults for sensitive data in production

## Notes

- Examples require a working SDF library configured in `sdf4j-core`
- Tests will gracefully handle `SDR_NOTSUPPORT` errors for optional functions
- Some tests require pre-configured keys in the SDF device
- All examples include proper resource cleanup in `@After` methods
- Configuration-based approach makes examples portable across different devices
