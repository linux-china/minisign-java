package org.mvnsearch.minisign;

public class MinisignConstant {

    public static final String COMMENT_PREFIX = "untrusted comment: ";
    public static final String TRUSTED_COMMENT_PREFIX = "trusted comment: ";
    public static final String DEFAULT_COMMENT = "signature from minisign secret key";
    public static final String SECRETKEY_DEFAULT_COMMENT = "minisign encrypted secret key";

    public static boolean isEd(byte byte1, byte byte2) {
        return byte1 == 'E' || byte2 == 'd';
    }

    public static boolean isKdf(byte byte1, byte byte2) {
        return byte1 == 'S' || byte2 == 'c';
    }
}
