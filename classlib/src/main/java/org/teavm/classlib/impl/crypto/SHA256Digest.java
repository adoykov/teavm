/*
 *  Copyright 2021 Legion of the Bouncy Castle.
 *
 *  License: Bouncy Castle license (MIT like).
 */
package org.teavm.classlib.impl.crypto;

/**
 * FIPS 180-2 implementation of SHA-256.
 *
 * <pre>
 *         block  word  digest
 * SHA-1   512    32    160
 * SHA-256 512    32    256
 * SHA-384 1024   64    384
 * SHA-512 1024   64    512
 * </pre>
 */
public class SHA256Digest extends GeneralDigest {
    private static final int DIGEST_LENGTH = 32;

    private int h1;
    private int h2;
    private int h3;
    private int h4;
    private int h5;
    private int h6;
    private int h7;
    private int h8;

    private int[] x = new int[64];
    private int xOff;

    /**
     * Standard constructor
     */
    public SHA256Digest() {
        reset();
    }

    /**
     * Copy constructor.  This will copy the state of the provided
     * message digest.
     */
    public SHA256Digest(SHA256Digest t) {
        super(t);

        copyIn(t);
    }

    private void copyIn(SHA256Digest t) {
        super.copyIn(t);

        h1 = t.h1;
        h2 = t.h2;
        h3 = t.h3;
        h4 = t.h4;
        h5 = t.h5;
        h6 = t.h6;
        h7 = t.h7;
        h8 = t.h8;

        System.arraycopy(t.x, 0, x, 0, t.x.length);
        xOff = t.xOff;
    }

    /**
     * State constructor - create a digest initialised with the state of a previous one.
     *
     * @param encodedState the encoded state from the originating digest.
     */
    public SHA256Digest(byte[] encodedState) {
        super(encodedState);

        h1 = Pack.bigEndianToInt(encodedState, 16);
        h2 = Pack.bigEndianToInt(encodedState, 20);
        h3 = Pack.bigEndianToInt(encodedState, 24);
        h4 = Pack.bigEndianToInt(encodedState, 28);
        h5 = Pack.bigEndianToInt(encodedState, 32);
        h6 = Pack.bigEndianToInt(encodedState, 36);
        h7 = Pack.bigEndianToInt(encodedState, 40);
        h8 = Pack.bigEndianToInt(encodedState, 44);

        xOff = Pack.bigEndianToInt(encodedState, 48);
        for (int i = 0; i != xOff; i++) {
            x[i] = Pack.bigEndianToInt(encodedState, 52 + (i * 4));
        }
    }

    public String getAlgorithmName() {
        return "SHA-256";
    }

    public int getDigestSize() {
        return DIGEST_LENGTH;
    }

    protected void processWord(byte[] in, int inOff) {
        // Note: Inlined for performance
//        X[xOff] = Pack.bigEndianToInt(in, inOff);
        int n = in[inOff] << 24;
        n |= (in[++inOff] & 0xff) << 16;
        n |= (in[++inOff] & 0xff) << 8;
        n |= in[++inOff] & 0xff;
        x[xOff] = n;

        if (++xOff == 16) {
            processBlock();
        }
    }

    protected void processLength(
            long bitLength) {
        if (xOff > 14) {
            processBlock();
        }

        x[14] = (int) (bitLength >>> 32);
        x[15] = (int) (bitLength & 0xffffffff);
    }

    public int doFinal(
            byte[] out,
            int outOff) {
        finish();

        Pack.intToBigEndian(h1, out, outOff);
        Pack.intToBigEndian(h2, out, outOff + 4);
        Pack.intToBigEndian(h3, out, outOff + 8);
        Pack.intToBigEndian(h4, out, outOff + 12);
        Pack.intToBigEndian(h5, out, outOff + 16);
        Pack.intToBigEndian(h6, out, outOff + 20);
        Pack.intToBigEndian(h7, out, outOff + 24);
        Pack.intToBigEndian(h8, out, outOff + 28);

        reset();

        return DIGEST_LENGTH;
    }

    /**
     * reset the chaining variables
     */
    public void reset() {
        super.reset();

        /* SHA-256 initial hash value
         * The first 32 bits of the fractional parts of the square roots
         * of the first eight prime numbers
         */

        h1 = 0x6a09e667;
        h2 = 0xbb67ae85;
        h3 = 0x3c6ef372;
        h4 = 0xa54ff53a;
        h5 = 0x510e527f;
        h6 = 0x9b05688c;
        h7 = 0x1f83d9ab;
        h8 = 0x5be0cd19;

        xOff = 0;
        for (int i = 0; i != x.length; i++) {
            x[i] = 0;
        }
    }

    protected void processBlock() {
        //
        // expand 16 word block into 64 word blocks.
        //
        for (int t = 16; t <= 63; t++) {
            x[t] = theta1(x[t - 2]) + x[t - 7] + theta0(x[t - 15]) + x[t - 16];
        }

        //
        // set up working variables.
        //
        int a = h1;
        int b = h2;
        int c = h3;
        int d = h4;
        int e = h5;
        int f = h6;
        int g = h7;
        int h = h8;

        int t = 0;
        for (int i = 0; i < 8; i++) {
            // t = 8 * i
            h += sum1(e) + ch(e, f, g) + k[t] + x[t];
            d += h;
            h += sum0(a) + maj(a, b, c);
            ++t;

            // t = 8 * i + 1
            g += sum1(d) + ch(d, e, f) + k[t] + x[t];
            c += g;
            g += sum0(h) + maj(h, a, b);
            ++t;

            // t = 8 * i + 2
            f += sum1(c) + ch(c, d, e) + k[t] + x[t];
            b += f;
            f += sum0(g) + maj(g, h, a);
            ++t;

            // t = 8 * i + 3
            e += sum1(b) + ch(b, c, d) + k[t] + x[t];
            a += e;
            e += sum0(f) + maj(f, g, h);
            ++t;

            // t = 8 * i + 4
            d += sum1(a) + ch(a, b, c) + k[t] + x[t];
            h += d;
            d += sum0(e) + maj(e, f, g);
            ++t;

            // t = 8 * i + 5
            c += sum1(h) + ch(h, a, b) + k[t] + x[t];
            g += c;
            c += sum0(d) + maj(d, e, f);
            ++t;

            // t = 8 * i + 6
            b += sum1(g) + ch(g, h, a) + k[t] + x[t];
            f += b;
            b += sum0(c) + maj(c, d, e);
            ++t;

            // t = 8 * i + 7
            a += sum1(f) + ch(f, g, h) + k[t] + x[t];
            e += a;
            a += sum0(b) + maj(b, c, d);
            ++t;
        }

        h1 += a;
        h2 += b;
        h3 += c;
        h4 += d;
        h5 += e;
        h6 += f;
        h7 += g;
        h8 += h;

        //
        // reset the offset and clean out the word buffer.
        //
        xOff = 0;
        for (int i = 0; i < 16; i++) {
            x[i] = 0;
        }
    }

    /* SHA-256 functions */
    private static int ch(int x, int y, int z) {
        return (x & y) ^ ((~x) & z);
    }

    private static int maj(int x, int y, int z) {
        return (x & y) | (z & (x ^ y));
    }

    private static int sum0(int x) {
        return ((x >>> 2) | (x << 30)) ^ ((x >>> 13) | (x << 19)) ^ ((x >>> 22) | (x << 10));
    }

    private static int sum1(int x) {
        return ((x >>> 6) | (x << 26)) ^ ((x >>> 11) | (x << 21)) ^ ((x >>> 25) | (x << 7));
    }

    private static int theta0(int x) {
        return ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
    }

    private static int theta1(int x) {
        return ((x >>> 17) | (x << 15)) ^ ((x >>> 19) | (x << 13)) ^ (x >>> 10);
    }

    /* SHA-256 Constants
     * (represent the first 32 bits of the fractional parts of the
     * cube roots of the first sixty-four prime numbers)
     */
    static final int[] k = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    public Memoable copy() {
        return new SHA256Digest(this);
    }

    public void reset(Memoable other) {
        SHA256Digest d = (SHA256Digest) other;

        copyIn(d);
    }

    public byte[] getEncodedState() {
        byte[] state = new byte[52 + xOff * 4];

        super.populateState(state);

        Pack.intToBigEndian(h1, state, 16);
        Pack.intToBigEndian(h2, state, 20);
        Pack.intToBigEndian(h3, state, 24);
        Pack.intToBigEndian(h4, state, 28);
        Pack.intToBigEndian(h5, state, 32);
        Pack.intToBigEndian(h6, state, 36);
        Pack.intToBigEndian(h7, state, 40);
        Pack.intToBigEndian(h8, state, 44);
        Pack.intToBigEndian(xOff, state, 48);

        for (int i = 0; i != xOff; i++) {
            Pack.intToBigEndian(x[i], state, 52 + (i * 4));
        }

        return state;
    }
}