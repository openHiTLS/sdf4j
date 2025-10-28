# SDF4J Examples

This module contains example usage of SDF4J implemented as JUnit tests.

## Overview

Examples are written as JUnit tests instead of standalone programs with `main()` methods. This provides:
- Better resource management with `@Before` and `@After` hooks
- Assertions to verify correct behavior
- Easy integration with Maven test lifecycle
- Graceful handling of optional SDF functions (SDR_NOTSUPPORT)

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

# SM2 asymmetric cryptography (sign/verify/encrypt)
mvn test -Dtest=SM2ExampleTest

# SM4 symmetric encryption (ECB/CBC/MAC)
mvn test -Dtest=SM4ExampleTest
```

### Run Specific Test Method
```bash
mvn test -Dtest=BasicExampleTest#testGenerateRandom
mvn test -Dtest=SM2ExampleTest#testSM2InternalSignAndVerify
```

### Run with Custom SDF Library
```bash
mvn test -Dsdf4j.library.name=swsds -Dsdf4j.library.path=/opt/sdf/lib
```

## Available Examples

### BasicExampleTest
Demonstrates fundamental SDF operations:
- `testDeviceAndSessionManagement()` - Opening/closing devices and sessions
- `testGetDeviceInfo()` - Retrieving device information
- `testGenerateRandom()` - Generating random numbers
- `testMultipleSessions()` - Managing multiple concurrent sessions

### SM2ExampleTest
SM2 asymmetric cryptography examples:
- `testExportSM2PublicKey()` - Exporting signing and encryption public keys
- `testSM2InternalSignAndVerify()` - Signing with internal key and verifying
- `testSM2ExternalVerify()` - Verifying with exported public key
- `testSM2ExternalEncrypt()` - Encrypting with public key
- `testVerifyWithTamperedData()` - Demonstrating signature verification failure

### SM4ExampleTest
SM4 symmetric encryption examples:
- `testSM4ECB()` - ECB mode encryption/decryption
- `testSM4CBC()` - CBC mode encryption/decryption with IV
- `testSM4MAC()` - Message authentication code calculation

**Note:** SM4 tests require a valid key handle. If not available, tests will indicate that key generation is needed.

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

## Notes

- Examples require a working SDF library configured in `sdf4j-core`
- Tests will gracefully handle `SDR_NOTSUPPORT` errors for optional functions
- Some tests (especially SM4) may require pre-configured keys in the SDF device
- All examples include proper resource cleanup in `@After` methods
