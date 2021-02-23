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

import java.security.SecureRandom;
import org.teavm.classlib.java.util.TRandom;
import org.teavm.jso.JSBody;

public class TSecureRandom extends TRandom {
    @Override
    protected final int next(int numBits) {
        if (numBits > 32) {
            throw new IllegalArgumentException();
        }
        int next = 0;
        int arraySize = (numBits + 7) / 8;
        byte[] randomBytes = new byte[arraySize];
        nextBytes(randomBytes);
        for (int i = 0; i < arraySize; i++) {
            next = (next << 8) + (randomBytes[i] & 0xFF);
        }
        return next >>> (arraySize * 8 - numBits);
    }


    @Override
    public void nextBytes(byte[] bytes) {
        // There's a more efficient way to do this that avoids the copy but it would require special casing the
        // compiler to not do a copy at the Java/JS boundary. Perf impact probably doesn't matter.
        System.arraycopy(cryptoGenerateValues(bytes.length), 0, bytes, 0, bytes.length);
    }

    public byte[] generateSeed(int numBytes) {
        byte[] bytes = new byte[numBytes];
        nextBytes(bytes);
        return bytes;
    }

    public static byte[] getSeed(int numBytes) {
        return new TSecureRandom().generateSeed(numBytes);
    }

    @JSBody(params = { "len" }, script = "return [].slice.call(window.crypto.getRandomValues(new Uint8Array(len)));")
    private static native byte[] cryptoGenerateValues(int len);
}
