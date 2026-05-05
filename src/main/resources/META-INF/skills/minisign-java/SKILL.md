---
name: minisign-java
description: Minisign Java SDK is a Java library to sign and verify signatures with highly secure Ed25519 public-key
signature system
---

## Dependency

Add following dependency into your `pom.xml` file:

```xml

<dependency>
    <groupId>org.mvnsearch</groupId>
    <artifactId>minisign-java</artifactId>
    <version>0.1.1</version>
</dependency>
```

## SDK Core

- `MinisignService`: Minisign Service interface
- `MinisignServiceImpl`: Minisign Service implementation
- `MinisignPublicKey`: Minisign Public Key with parsing
- `MinisignSecretKey`: Minisign Secret Key with parsing

A java demo:

```java
MinisignService service = new MinisignServiceImpl();
// get public key from base64
final MinisignPublicKey publicKey = MinisignPublicKey.fromBase64("xxx");
// verify signature
byte[] data = "hello world!".getBytes();
String signature = "RWSfST7entCa/bXk4JCe8PKXRRU89mxxxx";
boolean result = service.verify(data, signature, publicKey);
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
                         
