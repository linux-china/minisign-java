package org.mvnsearch.minisign;

import java.util.Base64;

import static org.mvnsearch.minisign.MinisignConstant.COMMENT_PREFIX;
import static org.mvnsearch.minisign.MinisignConstant.isEd;

public class MinisignPublicKey {

    private final byte[] keyId;       // 8 bytes
    private final byte[] keyBytes;    // 32 bytes Ed25519 public key

    public MinisignPublicKey(byte[] keyId, byte[] keyBytes) {
        this.keyId = keyId;
        this.keyBytes = keyBytes;
    }

    public byte[] getKeyId() {
        return keyId;
    }

    public byte[] getKeyBytes() {
        return keyBytes;
    }

    public String getKeyIdHex() {
        StringBuilder sb = new StringBuilder(16);
        for (byte b : keyId) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    /**
     * Encode as the single base64 line stored in the public key file.
     */
    public String toBase64() {
        // sig_algorithm(2) + key_id(8) + public_key(32) = 42 bytes
        byte[] data = new byte[42];
        data[0] = 'E';
        data[1] = 'd';
        System.arraycopy(keyId, 0, data, 2, 8);
        System.arraycopy(keyBytes, 0, data, 10, 32);
        return Base64.getEncoder().withoutPadding().encodeToString(data);
    }

    /**
     * Parse from the base64 data line.
     */
    public static MinisignPublicKey fromBase64(String base64) {
        byte[] data = Base64.getDecoder().decode(base64.trim());
        if (data.length < 42 || !isEd(data[0], data[1])) {
            throw new IllegalArgumentException("Invalid public key format");
        }
        byte[] keyId = new byte[8];
        byte[] keyBytes = new byte[32];
        System.arraycopy(data, 2, keyId, 0, 8);
        System.arraycopy(data, 10, keyBytes, 0, 32);
        return new MinisignPublicKey(keyId, keyBytes);
    }

    /**
     * Parse from full .pub file content (two lines).
     */
    public static MinisignPublicKey fromFileContent(String content) {
        String[] lines = content.trim().split("\\r?\\n");
        for (String rawLine : lines) {
            String line = rawLine.trim();
            if (!line.isEmpty()) {
                if (!(line.contains(":") || line.contains(" "))) {
                    return fromBase64(line);
                }
            }
        }
        throw new IllegalArgumentException("Invalid public key format");
    }

    /**
     * Format as .pub file content.
     */
    public String toFileContent() {
        return COMMENT_PREFIX + "minisign public key " + getKeyIdHex() + "\n"
                + toBase64() + "\n";
    }
}
