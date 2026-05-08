---
name: minisign-java
description: a Java library to sign and verify signatures with highly secure Ed25519 public-key signature system
---

## Dependency

Add following dependency into your `pom.xml` file:

```xml

<dependency>
    <groupId>org.mvnsearch</groupId>
    <artifactId>minisign-java</artifactId>
    <version>0.2.1</version>
</dependency>
```

**Attention**: Java 17 or later is required for native EdDSA support.

## SDK Core

- `MinisignService`: Minisign Service interface
- `MinisignServiceImpl`: Minisign Service implementation
- `MinisignPublicKey`: Minisign Public Key with parsing
- `MinisignSecretKey`: Minisign Secret Key with parsing

A java demo:

```java
MinisignService service = new MinisignServiceImpl();
// get secret key from base64
final MinisignSecretKey secretKey = MinisignSecretKey.fromBase64("xxx");
// get public key from base64
final MinisignPublicKey publicKey = MinisignPublicKey.fromBase64("xxx");
// signature data
byte[] data = "hello world!".getBytes();
MinisignSignature sig = service.sign(data, keyPair.getSecretKey());
// base64(<signature_algorithm> || <key_id> || <signature>)
final String signatureBase64 = sig.toSignatureBase64();
// verify signature
boolean result = service.verify(data, signatureBase64, publicKey);
```

## Compare with Command Line

|                 | Command                 | API                                                              |
|-----------------|-------------------------|------------------------------------------------------------------|
| create key pair | minisign -G             | MinisignService.generateKeyPair(), MinisignService.saveKeyPair() |
| Signing a file  | minisign -Sm myfile.txt | MiniSignService.sign(data/file, secretKey)                       |
| verify a fil    | minisign -Vm myfile.txt | MiniSignService.verify(data/file, signature, publicKey)          |

- Load private key: `MinisignSecretKey.fromBase64()` or `MinisignSecretKey.fromFileContent()`
- Load public key: `MinisignPublicKey.fromBase64()` or `MinisignPublicKey.fromFileContent()`
- Load global key pair: `MinisignService.loadKeyPair()`

**Attention**: password of the secret key is not supported now, please use `minisign -C -W` to clear the password.

## References

* Minisign Docs: https://jedisct1.github.io/minisign/
* Minisign GitHub Repository: https://github.com/jedisct1/minisign