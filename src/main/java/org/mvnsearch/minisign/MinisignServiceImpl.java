package org.mvnsearch.minisign;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.Base64;

public class MinisignServiceImpl implements MinisignService {
    private static final String algorithm = NamedParameterSpec.ED25519.getName();

    private static final Path MINISIGN_DIR =
            Path.of(System.getProperty("user.home"), ".minisign");
    public static final Path SECRET_KEY_PATH = MINISIGN_DIR.resolve("minisign.key");
    public static final Path PUBLIC_KEY_PATH = MINISIGN_DIR.resolve("minisign.pub");

    @Override
    public MinisignKeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);
        KeyPair kp = kpg.generateKeyPair();

        byte[] seed = extractSeed(kp.getPrivate());
        byte[] pubKeyBytes = extractPublicKeyBytes(kp.getPublic());

        // 64-byte secret key: seed + public key (libsodium convention)
        byte[] secretBytes = new byte[64];
        System.arraycopy(seed, 0, secretBytes, 0, 32);
        System.arraycopy(pubKeyBytes, 0, secretBytes, 32, 32);

        // Random 8-byte key ID
        byte[] keyId = new byte[8];
        SecureRandom.getInstanceStrong().nextBytes(keyId);

        MinisignPublicKey publicKey = new MinisignPublicKey(keyId, pubKeyBytes);
        MinisignSecretKey secretKey = new MinisignSecretKey(keyId, secretBytes);
        return new MinisignKeyPair(publicKey, secretKey);
    }

    @Override
    public void saveKeyPair(MinisignKeyPair keyPair) throws IOException {
        Files.createDirectories(MINISIGN_DIR);
        Files.writeString(SECRET_KEY_PATH, keyPair.getSecretKey().toFileContent());
        Files.writeString(PUBLIC_KEY_PATH, keyPair.getPublicKey().toFileContent());
    }

    @Override
    public MinisignKeyPair loadKeyPair() throws IOException {
        MinisignSecretKey sk = MinisignSecretKey.fromFileContent(Files.readString(SECRET_KEY_PATH));
        MinisignPublicKey pk = new MinisignPublicKey(sk.getKeyId(), sk.getEmbeddedPublicKey());
        return new MinisignKeyPair(pk, sk);
    }

    @Override
    public MinisignPublicKey loadPublicKey() throws IOException {
        return MinisignPublicKey.fromFileContent(Files.readString(PUBLIC_KEY_PATH));
    }

    @Override
    public MinisignSignature sign(byte[] data, MinisignSecretKey secretKey) throws Exception {
        return sign(data, secretKey, null, null);
    }

    @Override
    public MinisignSignature signFile(Path file, MinisignSecretKey secretKey) throws Exception {
        return signFile(file, secretKey, null, null);
    }

    @Override
    public MinisignSignature sign(byte[] data, MinisignSecretKey secretKey, String untrustedComment, String trustedComment) throws Exception {
        PrivateKey privKey = buildPrivateKey(secretKey.getSeed());
        byte[] sig = ed25519Sign(privKey, data);

        if (trustedComment == null || trustedComment.isEmpty()) {
            trustedComment = "timestamp:" + System.currentTimeMillis() / 1000 + "\thashed";
        }
        byte[] globalSig = computeGlobalSignature(privKey, sig, trustedComment);

        final MinisignSignature signature = new MinisignSignature(secretKey.getKeyId(), sig, trustedComment, globalSig);
        if (untrustedComment != null && !untrustedComment.isEmpty()) {
            signature.setUntrustedComment(untrustedComment);
        }
        return signature;
    }

    @Override
    public MinisignSignature signFile(Path file, MinisignSecretKey secretKey, String untrustedComment, String trustedComment) throws Exception {
        byte[] data = Files.readAllBytes(file);
        PrivateKey privKey = buildPrivateKey(secretKey.getSeed());
        byte[] sig = ed25519Sign(privKey, data);

        if (trustedComment == null || trustedComment.isEmpty()) {
            trustedComment = "timestamp:" + System.currentTimeMillis() / 1000
                    + "\tfile:" + file.getFileName();
        }
        byte[] globalSig = computeGlobalSignature(privKey, sig, trustedComment);

        final MinisignSignature signature = new MinisignSignature(secretKey.getKeyId(), sig, trustedComment, globalSig);
        if (untrustedComment != null && !untrustedComment.isEmpty()) {
            signature.setUntrustedComment(untrustedComment);
        }
        return signature;
    }

    @Override
    public boolean verify(byte[] data, MinisignSignature sig, MinisignPublicKey publicKey) throws Exception {
        if (!Arrays.equals(sig.getKeyId(), publicKey.getKeyId())) {
            return false;
        }
        PublicKey pubKey = buildPublicKey(publicKey.getKeyBytes());
        if (!ed25519Verify(pubKey, data, sig.getSignature())) {
            return false;
        }
        return verifyGlobalSignature(pubKey, sig);
    }

    @Override
    public boolean verify(byte[] data, String signatureData, MinisignPublicKey publicKey) throws Exception {
        byte[] sigDataBytes = Base64.getDecoder().decode(signatureData);
        PublicKey pubKey = buildPublicKey(publicKey.getKeyBytes());
        byte[] signature = new byte[64];
        System.arraycopy(sigDataBytes, 10, signature, 0, 64);
        return ed25519Verify(pubKey, data, signature);
    }

    @Override
    public boolean verifyFile(Path file, MinisignSignature sig, MinisignPublicKey publicKey) throws Exception {
        return verify(Files.readAllBytes(file), sig, publicKey);
    }

    @Override
    public boolean verifyFile(Path file, String signature, MinisignPublicKey publicKey) throws Exception {
        return verify(Files.readAllBytes(file), signature, publicKey);
    }

    // -------------------------------------------------------------------------
    // Ed25519 helpers
    // -------------------------------------------------------------------------

    private byte[] extractSeed(PrivateKey privKey) throws Exception {
        // EdECPrivateKey.getBytes() returns the raw 32-byte seed
        var edPrivKey = (java.security.interfaces.EdECPrivateKey) privKey;
        return edPrivKey.getBytes().orElseThrow(() ->
                new IllegalStateException("Unable to extract Ed25519 seed"));
    }

    private byte[] extractPublicKeyBytes(PublicKey pubKey) {
        // The X.509 DER encoding ends with the 32 raw public key bytes.
        byte[] encoded = pubKey.getEncoded();
        return Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
    }

    private PrivateKey buildPrivateKey(byte[] seed) throws Exception {
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        return kf.generatePrivate(new EdECPrivateKeySpec(NamedParameterSpec.ED25519, seed));
    }

    private PublicKey buildPublicKey(byte[] rawBytes) throws Exception {
        // Decode the 32-byte compressed point:
        // - bytes are little-endian Y coordinate
        // - the highest bit of the last byte is the sign of X
        byte[] yBytes = rawBytes.clone();
        boolean xOdd = (yBytes[31] & 0x80) != 0;
        yBytes[31] &= 0x7F;
        // Reverse to big-endian for BigInteger
        for (int i = 0, j = yBytes.length - 1; i < j; i++, j--) {
            byte tmp = yBytes[i];
            yBytes[i] = yBytes[j];
            yBytes[j] = tmp;
        }
        BigInteger y = new BigInteger(1, yBytes);
        EdECPoint point = new EdECPoint(xOdd, y);
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        return kf.generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, point));
    }

    private byte[] ed25519Sign(PrivateKey privKey, byte[] message) throws Exception {
        Signature signer = Signature.getInstance(algorithm);
        signer.initSign(privKey);
        signer.update(message);
        return signer.sign();
    }

    private boolean ed25519Verify(PublicKey pubKey, byte[] message, byte[] signature) throws Exception {
        Signature verifier = Signature.getInstance(algorithm);
        verifier.initVerify(pubKey);
        verifier.update(message);
        return verifier.verify(signature);
    }

    private byte[] computeGlobalSignature(PrivateKey privKey, byte[] sig,
                                          String trustedComment) throws Exception {
        byte[] tc = trustedComment.getBytes(StandardCharsets.UTF_8);
        byte[] input = new byte[sig.length + tc.length];
        System.arraycopy(sig, 0, input, 0, sig.length);
        System.arraycopy(tc, 0, input, sig.length, tc.length);
        return ed25519Sign(privKey, input);
    }

    private boolean verifyGlobalSignature(PublicKey pubKey, MinisignSignature sig) throws Exception {
        byte[] tc = sig.getTrustedComment().getBytes(StandardCharsets.UTF_8);
        byte[] rawSig = sig.getSignature();
        byte[] input = new byte[rawSig.length + tc.length];
        System.arraycopy(rawSig, 0, input, 0, rawSig.length);
        System.arraycopy(tc, 0, input, rawSig.length, tc.length);
        return ed25519Verify(pubKey, input, sig.getGlobalSignature());
    }
}
