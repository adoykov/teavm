/*
 * Copyright 2021 Legion of the Bouncy Castle.
 *
 * License: Bouncy Castle license (MIT like).
 */
package org.teavm.classlib.impl.crypto;

/**
 * FIPS 180-2 implementation of SHA-512.
 *
 * <pre>
 *         block  word  digest
 * SHA-1   512    32    160
 * SHA-256 512    32    256
 * SHA-384 1024   64    384
 * SHA-512 1024   64    512
 * </pre>
 */
public class SHA512Digest extends LongDigest {
    private static final int DIGEST_LENGTH = 64;

    /**
     * Standard constructor
     */
    public SHA512Digest() {
    }

    /**
     * Copy constructor.  This will copy the state of the provided
     * message digest.
     */
    public SHA512Digest(SHA512Digest t) {
        super(t);
    }

    /**
     * State constructor - create a digest initialised with the state of a previous one.
     *
     * @param encodedState the encoded state from the originating digest.
     */
    public SHA512Digest(byte[] encodedState) {
        restoreState(encodedState);
    }

    public String getAlgorithmName() {
        return "SHA-512";
    }

    public int getDigestSize() {
        return DIGEST_LENGTH;
    }

    public int doFinal(
            byte[] out,
            int outOff) {
        finish();

        Pack.longToBigEndian(h1, out, outOff);
        Pack.longToBigEndian(h2, out, outOff + 8);
        Pack.longToBigEndian(h3, out, outOff + 16);
        Pack.longToBigEndian(h4, out, outOff + 24);
        Pack.longToBigEndian(h5, out, outOff + 32);
        Pack.longToBigEndian(h6, out, outOff + 40);
        Pack.longToBigEndian(h7, out, outOff + 48);
        Pack.longToBigEndian(h8, out, outOff + 56);

        reset();

        return DIGEST_LENGTH;
    }

    /**
     * reset the chaining variables
     */
    public void reset() {
        super.reset();

        /* SHA-512 initial hash value
         * The first 64 bits of the fractional parts of the square roots
         * of the first eight prime numbers
         */
        h1 = 0x6a09e667f3bcc908L;
        h2 = 0xbb67ae8584caa73bL;
        h3 = 0x3c6ef372fe94f82bL;
        h4 = 0xa54ff53a5f1d36f1L;
        h5 = 0x510e527fade682d1L;
        h6 = 0x9b05688c2b3e6c1fL;
        h7 = 0x1f83d9abfb41bd6bL;
        h8 = 0x5be0cd19137e2179L;
    }

    public Memoable copy() {
        return new SHA512Digest(this);
    }

    public void reset(Memoable other) {
        SHA512Digest d = (SHA512Digest) other;

        copyIn(d);
    }

    public byte[] getEncodedState() {
        byte[] encoded = new byte[getEncodedStateSize()];
        super.populateState(encoded);
        return encoded;
    }
}
