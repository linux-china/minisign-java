package org.mvnsearch.minisign;

import java.io.IOException;
import java.nio.file.Path;

public interface MinisignService {

    /**
     * Generate a new Ed25519 key pair.
     */
    MinisignKeyPair generateKeyPair() throws Exception;

    /**
     * Save key pair to $HOME/.minisign/minisign.key and minisign.pub.
     */
    void saveKeyPair(MinisignKeyPair keyPair) throws IOException;

    /**
     * Load key pair from $HOME/.minisign/.
     */
    MinisignKeyPair loadKeyPair() throws IOException;

    /**
     * Load only the public key from $HOME/.minisign/minisign.pub.
     */
    MinisignPublicKey loadPublicKey() throws IOException;

    /**
     * Sign a byte array.
     */
    MinisignSignature sign(byte[] data, MinisignSecretKey secretKey) throws Exception;

    /**
     * Sign a file.
     */
    MinisignSignature signFile(Path file, MinisignSecretKey secretKey) throws Exception;

    /**
     * Verify a signature over a byte array.
     */
    boolean verify(byte[] data, MinisignSignature signature, MinisignPublicKey publicKey) throws Exception;

    /**
     *
     * Verify a signature over a byte array
     *
     * @param signature second line, format as base64
     */
    boolean verify(byte[] data, String signature, MinisignPublicKey publicKey) throws Exception;

    /**
     * Verify a signature over a file.
     */
    boolean verifyFile(Path file, MinisignSignature signature, MinisignPublicKey publicKey) throws Exception;
}
