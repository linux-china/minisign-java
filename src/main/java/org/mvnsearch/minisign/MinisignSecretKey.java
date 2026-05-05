package org.mvnsearch.minisign;

import java.util.Arrays;
import java.util.Base64;

import static org.mvnsearch.minisign.MinisignConstant.*;

public class MinisignSecretKey {

    private final byte[] keyId;        // 8 bytes
    private final byte[] secretBytes;  // 64 bytes: seed(32) + public_key(32)

    public MinisignSecretKey(byte[] keyId, byte[] secretBytes) {
        this.keyId = keyId;
        this.secretBytes = secretBytes;
    }

    public byte[] getKeyId() {
        return keyId;
    }

    /**
     * Full 64-byte secret key: seed (32 bytes) + public key (32 bytes).
     */
    public byte[] getSecretBytes() {
        return secretBytes;
    }

    /**
     * The 32-byte seed used for Ed25519 signing.
     */
    public byte[] getSeed() {
        return Arrays.copyOfRange(secretBytes, 0, 32);
    }

    /**
     * The 32-byte Ed25519 public key embedded in the secret key.
     */
    public byte[] getEmbeddedPublicKey() {
        return Arrays.copyOfRange(secretBytes, 32, 64);
    }

    /**
     * Encode as the base64 line stored in the secret key file.
     * <p>
     * Structure (158 bytes total):
     * sig_algorithm(2) "Ed"
     * kdf_algorithm(2) "NA" (no password)
     * chk_algorithm(2) "B2"
     * kdf_salt(32)     zeros
     * kdf_opslimit(8)  zeros
     * kdf_memlimit(8)  zeros
     * keynum_sk(104):
     * key_id(8)
     * secret_key(64)
     * checksum(32) = BLAKE2b-256(key_id + secret_key)
     */
    public String toBase64() {
        byte[] data = new byte[158];
        data[0] = 'E';
        data[1] = 'd';   // sig_algorithm
        data[2] = 0;
        data[3] = 0;   //  no password protection: kdf
        data[4] = 'B';
        data[5] = '2';   // chk_algorithm
        // bytes 6..53: kdf_salt(32) + opslimit(8) + memlimit(8) = zeros
        System.arraycopy(keyId, 0, data, 54, 8);
        System.arraycopy(secretBytes, 0, data, 62, 64);

        // <signature_algorithm> || <key_id> || <secret_key> || <public_key>
        byte[] toHash = new byte[74];
        toHash[0] = 'E';
        toHash[1] = 'd';
        System.arraycopy(keyId, 0, toHash, 2, 8);
        System.arraycopy(secretBytes, 0, toHash, 10, 64);
        byte[] chk = Blake2b.hash256(toHash);
        System.arraycopy(chk, 0, data, 126, 32);

        return Base64.getEncoder().encodeToString(data);
    }

    /**
     * Parse from the base64 data line in the secret key file.
     */
    public static MinisignSecretKey fromBase64(String base64) {
        byte[] data = Base64.getDecoder().decode(base64.trim());
        if (data.length < 158 || !isEd(data[0], data[1])) {
            throw new IllegalArgumentException("Invalid secret key format");
        }
        // password protection -  kdf_algorithm: Sc
        if (isKdf(data[2], data[3])) {
            throw new UnsupportedOperationException("Password-protected keys are not supported");
        }
        byte[] signatureAlgorithm = new byte[2];
        byte[] keyId = new byte[8];
        byte[] keyPair = new byte[64];
        System.arraycopy(data, 0, signatureAlgorithm, 0, 2);
        System.arraycopy(data, 54, keyId, 0, 8);
        System.arraycopy(data, 62, keyPair, 0, 64);

        byte[] actualChk = Arrays.copyOfRange(data, 126, 158);
        if (actualChk[0] != 0 && actualChk[31] != 0) {
            // <signature_algorithm> || <key_id> || <secret_key> || <public_key>
            byte[] toHash = new byte[74];
            System.arraycopy(signatureAlgorithm, 0, toHash, 0, 2);
            System.arraycopy(keyId, 0, toHash, 2, 8);
            System.arraycopy(keyPair, 0, toHash, 10, 64);
            byte[] expectedChk = Blake2b.hash256(toHash);
            if (!Arrays.equals(expectedChk, actualChk)) {
                throw new IllegalArgumentException("Secret key checksum mismatch");
            }
        }
        return new MinisignSecretKey(keyId, keyPair);
    }

    /**
     * Parse from full .key file content (two lines).
     */
    public static MinisignSecretKey fromFileContent(String content) {
        String[] lines = content.trim().split("\\r?\\n");
        for (String rawLine : lines) {
            String line = rawLine.trim();
            if (!line.isEmpty()) {
                if (!(line.contains(":") || line.contains(" "))) {
                    return fromBase64(line);
                }
            }
        }
        throw new IllegalArgumentException("Invalid secret key format");
    }

    /**
     * Format as .key file content.
     */
    public String toFileContent() {
        return COMMENT_PREFIX + SECRETKEY_DEFAULT_COMMENT + "\n"
                + toBase64() + "\n";
    }
}
