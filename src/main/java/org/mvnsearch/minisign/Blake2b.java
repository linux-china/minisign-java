package org.mvnsearch.minisign;

import java.util.Arrays;

public class Blake2b {

    private static final long[] IV = {
            0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL,
            0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
            0x510e527fade682d1L, 0x9b05688c2b3e6c1fL,
            0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
    };

    private static final byte[] SIGMA = {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
            11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
            7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
            9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
            2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
            12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
            13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
            6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
            10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3
    };

    private final int digestLength;
    private final long[] h = new long[8];
    private final long[] t = new long[2];
    private final long[] f = new long[2];
    private final byte[] buf = new byte[128];
    private int bufLen;

    public Blake2b(int digestLength) {
        if (digestLength < 1 || digestLength > 64) {
            throw new IllegalArgumentException("Invalid digest length");
        }
        this.digestLength = digestLength;
        System.arraycopy(IV, 0, h, 0, 8);
        // Parameter block: digest_length | key_length=0 | fanout=1 | depth=1
        h[0] ^= 0x01010000L | digestLength;
    }

    public static byte[] hash256(byte[] input) {
        Blake2b b = new Blake2b(32);
        b.update(input, 0, input.length);
        return b.digest();
    }

    public static byte[] hash512(byte[] input) {
        Blake2b b = new Blake2b(64);
        b.update(input, 0, input.length);
        return b.digest();
    }

    public void update(byte[] in, int off, int len) {
        while (len > 0) {
            if (bufLen == 128) {
                incrementCounter(128);
                compress(false);
                bufLen = 0;
            }
            int toCopy = Math.min(128 - bufLen, len);
            System.arraycopy(in, off, buf, bufLen, toCopy);
            bufLen += toCopy;
            off += toCopy;
            len -= toCopy;
        }
    }

    public byte[] digest() {
        incrementCounter(bufLen);
        Arrays.fill(buf, bufLen, 128, (byte) 0);
        compress(true);

        byte[] out = new byte[digestLength];
        for (int i = 0; i < digestLength; i++) {
            out[i] = (byte) (h[i >>> 3] >>> ((i & 7) << 3));
        }
        return out;
    }

    private void incrementCounter(int n) {
        t[0] += n;
        if (Long.compareUnsigned(t[0], n) < 0) {
            t[1]++;
        }
    }

    private void compress(boolean lastBlock) {
        long[] v = new long[16];
        long[] m = new long[16];

        for (int i = 0; i < 16; i++) {
            m[i] = readLE64(buf, i * 8);
        }

        System.arraycopy(h, 0, v, 0, 8);
        System.arraycopy(IV, 0, v, 8, 8);
        v[12] ^= t[0];
        v[13] ^= t[1];
        if (lastBlock) v[14] ^= -1L;

        for (int r = 0; r < 12; r++) {
            int s = r * 16;
            g(v, 0, 4, 8, 12, m[SIGMA[s] & 0xFF], m[SIGMA[s + 1] & 0xFF]);
            g(v, 1, 5, 9, 13, m[SIGMA[s + 2] & 0xFF], m[SIGMA[s + 3] & 0xFF]);
            g(v, 2, 6, 10, 14, m[SIGMA[s + 4] & 0xFF], m[SIGMA[s + 5] & 0xFF]);
            g(v, 3, 7, 11, 15, m[SIGMA[s + 6] & 0xFF], m[SIGMA[s + 7] & 0xFF]);
            g(v, 0, 5, 10, 15, m[SIGMA[s + 8] & 0xFF], m[SIGMA[s + 9] & 0xFF]);
            g(v, 1, 6, 11, 12, m[SIGMA[s + 10] & 0xFF], m[SIGMA[s + 11] & 0xFF]);
            g(v, 2, 7, 8, 13, m[SIGMA[s + 12] & 0xFF], m[SIGMA[s + 13] & 0xFF]);
            g(v, 3, 4, 9, 14, m[SIGMA[s + 14] & 0xFF], m[SIGMA[s + 15] & 0xFF]);
        }

        for (int i = 0; i < 8; i++) {
            h[i] ^= v[i] ^ v[i + 8];
        }
    }

    private static void g(long[] v, int a, int b, int c, int d, long x, long y) {
        v[a] = v[a] + v[b] + x;
        v[d] = Long.rotateRight(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d];
        v[b] = Long.rotateRight(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + y;
        v[d] = Long.rotateRight(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = Long.rotateRight(v[b] ^ v[c], 63);
    }

    private static long readLE64(byte[] b, int off) {
        return (b[off] & 0xFFL)
                | ((b[off + 1] & 0xFFL) << 8)
                | ((b[off + 2] & 0xFFL) << 16)
                | ((b[off + 3] & 0xFFL) << 24)
                | ((b[off + 4] & 0xFFL) << 32)
                | ((b[off + 5] & 0xFFL) << 40)
                | ((b[off + 6] & 0xFFL) << 48)
                | ((b[off + 7] & 0xFFL) << 56);
    }
}
