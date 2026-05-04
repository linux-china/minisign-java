package org.mvnsearch.minisign;

public class MinisignKeyPair {

    private final MinisignPublicKey publicKey;
    private final MinisignSecretKey secretKey;

    public MinisignKeyPair(MinisignPublicKey publicKey, MinisignSecretKey secretKey) {
        this.publicKey = publicKey;
        this.secretKey = secretKey;
    }

    public MinisignPublicKey getPublicKey() {
        return publicKey;
    }

    public MinisignSecretKey getSecretKey() {
        return secretKey;
    }
}
