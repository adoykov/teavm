/*
 *  Copyright 2021 R3 Ltd.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.teavm.classlib.java.security;

import java.nio.ByteBuffer;
import java.security.DigestException;
import java.security.MessageDigestSpi;
import java.security.Provider;
import java.util.Arrays;
import java.util.Objects;
import org.teavm.classlib.impl.crypto.Digest;
import org.teavm.classlib.impl.crypto.SHA256Digest;
import org.teavm.classlib.impl.crypto.SHA512Digest;

public abstract class TMessageDigest extends MessageDigestSpi {
    private String algorithm;
    private MessageDigestSpi spi;

    protected TMessageDigest(String algorithm) {
        this.algorithm = algorithm;
    }

    public static TMessageDigest getInstance(String algorithm) throws TNoSuchAlgorithmException {
        final Digest digest;
        if (algorithm.equals("SHA-256")) {
            digest = new SHA256Digest();
        } else if (algorithm.equals("SHA-512")) {
            digest = new SHA512Digest();
        } else {
            throw new TNoSuchAlgorithmException(algorithm);
        }
        return new TMessageDigest(algorithm) {
            @Override
            protected void engineUpdate(byte input) {
                digest.update(input);
            }

            @Override
            protected void engineUpdate(byte[] input, int offset, int len) {
                digest.update(input, offset, len);
            }

            @Override
            protected byte[] engineDigest() {
                byte[] result = new byte[digest.getDigestSize()];
                digest.doFinal(result, 0);
                return result;
            }

            @Override
            protected int engineGetDigestLength() {
                return digest.getDigestSize();
            }

            @Override
            protected void engineReset() {
                digest.reset();
            }
        };
    }

    public static TMessageDigest getInstance(String algorithm, String provider) throws
            TNoSuchAlgorithmException /*, NoSuchProviderException */ {
        return getInstance(algorithm);
    }

    public static TMessageDigest getInstance(String algorithm, Provider provider) throws TNoSuchAlgorithmException {
        return getInstance(algorithm);
    }

    public final Provider getProvider() {
        throw new UnsupportedOperationException("Stub");
    }

    public void update(byte input) {
        engineUpdate(input);
    }

    public void update(byte[] input, int offset, int len) {
        if (input == null || input.length - offset < len) {
            throw new IllegalArgumentException();
        }
        engineUpdate(input, offset, len);
    }

    public void update(byte[] input) {
        engineUpdate(input, 0, input.length);
    }

    public final void update(ByteBuffer input) {
        engineUpdate(input);
    }

    public byte[] digest() {
        return engineDigest();
    }

    public int digest(byte[] buf, int offset, int len) throws DigestException {
        Objects.requireNonNull(buf);
        if (buf.length - offset < len) {
            throw new IllegalArgumentException();
        }
        return engineDigest(buf, offset, len);
    }

    public byte[] digest(byte[] input) {
        update(input);
        return digest();
    }

    private String getProviderName() {
        return "(no provider)";
    }

    public void reset() {
        engineReset();
    }

    public final String getAlgorithm() {
        return this.algorithm;
    }

    public final int getDigestLength() {
        int digestLen = engineGetDigestLength();
        if (digestLen != 0) {
            return digestLen;
        }
        try {
            return ((TMessageDigest) clone()).digest().length;
        } catch (CloneNotSupportedException e) {
            return digestLen;
        }
    }

    public Object clone() throws CloneNotSupportedException {
        if (this instanceof Cloneable) {
            return super.clone();
        } else {
            throw new CloneNotSupportedException();
        }
    }

    public static boolean isEqual(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return false;
        }

        if (b.length == 0) {
            return a.length == 0;
        }

        int result = 0;
        result |= a.length - b.length;

        for (int i = 0; i < a.length; i++) {
            // 1 if i < b.length, 0 if i >= b.length
            int posFlag = (i - b.length) >>> 31;
            // posFlag * i == i or zero
            result |= a[i] ^ b[posFlag * i];
        }
        return result == 0;
    }
}
