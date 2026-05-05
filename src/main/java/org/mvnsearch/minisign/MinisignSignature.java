package org.mvnsearch.minisign;

import java.util.Base64;

import static org.mvnsearch.minisign.MinisignConstant.*;

public class MinisignSignature {

    private final byte[] keyId;           // 8 bytes
    private final byte[] signature;       // 64 bytes Ed25519 signature over the data
    private String untrustedComment;  // content after "trusted comment: " (no newline)
    private final String trustedComment;  // content after "trusted comment: " (no newline)
    private final byte[] globalSignature; // 64 bytes Ed25519 signature over sig+trustedComment

    public MinisignSignature(byte[] keyId, byte[] signature,
                             String trustedComment, byte[] globalSignature) {
        this.keyId = keyId;
        this.signature = signature;
        this.trustedComment = trustedComment;
        this.globalSignature = globalSignature;
    }

    public byte[] getKeyId() {
        return keyId;
    }

    public byte[] getSignature() {
        return signature;
    }

    public String getTrustedComment() {
        return trustedComment;
    }

    public String getUntrustedComment() {
        return untrustedComment;
    }

    public byte[] getGlobalSignature() {
        return globalSignature;
    }

    /**
     * Returns the 74-byte signature structure:
     * sig_algorithm(2) "Ed" + key_id(8) + ed25519_sig(64)
     */
    public byte[] toSignatureBytes() {
        byte[] data = new byte[74];
        data[0] = 'E';
        data[1] = 'd';
        System.arraycopy(keyId, 0, data, 2, 8);
        System.arraycopy(signature, 0, data, 10, 64);
        return data;
    }

    /**
     * Returns the 74-byte signature structure with base64 encoding:
     * sig_algorithm(2) "Ed" + key_id(8) + ed25519_sig(64)
     */
    public String toSignatureBase64() {
        return Base64.getEncoder().encodeToString(toSignatureBytes());
    }

    /**
     * Format as .minisig file content.
     */
    public String toFileContent(String untrustedComment) {
        return COMMENT_PREFIX + untrustedComment + "\n"
                + Base64.getEncoder().encodeToString(toSignatureBytes()) + "\n"
                + TRUSTED_COMMENT_PREFIX + trustedComment + "\n"
                + Base64.getEncoder().encodeToString(globalSignature) + "\n";
    }

    /**
     * Format as .minisig file content.
     */
    public String toFileContent() {
        if (this.untrustedComment != null && !this.untrustedComment.isEmpty()) {
            return toFileContent(this.untrustedComment);
        } else {
            return toFileContent(DEFAULT_COMMENT);
        }
    }

    /**
     * Parse from .minisig file content (four lines).
     */
    public static MinisignSignature fromFileContent(String content) {
        String[] lines = content.split("\\r?\\n");
        // lines[0]: untrusted comment (ignored)
        // lines[1]: base64-encoded 74-byte signature structure
        // lines[2]: trusted comment
        // lines[3]: base64-encoded 64-byte global signature
        byte[] sigData = Base64.getDecoder().decode(lines[1].trim());
        if (sigData.length < 74 || !isEd(sigData[0], sigData[1])) {
            throw new IllegalArgumentException("Invalid signature format");
        }
        byte[] keyId = new byte[8];
        byte[] sig = new byte[64];
        System.arraycopy(sigData, 2, keyId, 0, 8);
        System.arraycopy(sigData, 10, sig, 0, 64);

        // untrusted comment
        String untrustedCommentLine = lines[0].trim();
        String untrustedPrefix = COMMENT_PREFIX;
        String untrustedComment = untrustedCommentLine.startsWith(untrustedPrefix)
                ? untrustedCommentLine.substring(untrustedPrefix.length())
                : untrustedCommentLine;
        // trusted comment
        String trustedCommentLine = lines[2].trim();
        String trustedPrefix = TRUSTED_COMMENT_PREFIX;
        String trustedComment = trustedCommentLine.startsWith(trustedPrefix)
                ? trustedCommentLine.substring(trustedPrefix.length())
                : trustedCommentLine;

        byte[] globalSig = Base64.getDecoder().decode(lines[3].trim());
        final MinisignSignature minisignSignature = new MinisignSignature(keyId, sig, trustedComment, globalSig);
        minisignSignature.untrustedComment = untrustedComment;
        return minisignSignature;
    }
}
