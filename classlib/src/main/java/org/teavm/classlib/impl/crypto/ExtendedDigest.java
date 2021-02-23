/*
 *  Copyright 2021 Legion of the Bouncy Castle.
 *
 *  License: Bouncy Castle license (MIT like).
 */
package org.teavm.classlib.impl.crypto;

public interface ExtendedDigest extends Digest {
    /**
     * Return the size in bytes of the internal buffer the digest applies it's compression
     * function to.
     *
     * @return byte length of the digests internal buffer.
     */
    int getByteLength();
}
