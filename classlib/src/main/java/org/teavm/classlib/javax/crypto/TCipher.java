/*
 *  Copyright 2021 mikehearn.
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
package org.teavm.classlib.javax.crypto;

import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import org.teavm.classlib.java.lang.TUnsupportedOperationException;
import org.teavm.classlib.java.security.TNoSuchAlgorithmException;
import org.teavm.interop.Async;
import org.teavm.interop.AsyncCallback;
import org.teavm.jso.JSBody;
import org.teavm.jso.JSByRef;
import org.teavm.jso.JSFunctor;
import org.teavm.jso.JSObject;

public class TCipher {
    public static final int ENCRYPT_MODE = 1;
    public static final int DECRYPT_MODE = 2;
    public static final int WRAP_MODE = 3;
    public static final int UNWRAP_MODE = 4;
    public static final int PUBLIC_KEY = 1;
    public static final int PRIVATE_KEY = 2;
    public static final int SECRET_KEY = 3;

    private final String transformation;

    private TCipher(String transformation) {
        this.transformation = transformation;
    }

    public static TCipher getInstance(String transformation) throws TNoSuchAlgorithmException {
        if (transformation.equals("AES/GCM/NoPadding")) {
            return new AESGCM(transformation);
        }
        throw new TNoSuchAlgorithmException(transformation);
    }

    public final String getAlgorithm() {
        return transformation;
    }

    public /*final*/ int getBlockSize() {
        throw new UnsupportedOperationException();
    }

    public /*final*/ int getOutputSize(int inputLen) {
        throw new UnsupportedOperationException();
    }

    public /*final*/ byte[] getIV() {
        throw new TUnsupportedOperationException();
    }

    public /*final*/ AlgorithmParameters getParameters() {
        throw new UnsupportedOperationException();
    }

    public final void init(int opmode, Key key) {
        init(opmode, key, (AlgorithmParameterSpec) null);
    }

    public final void init(int opmode, Key key, SecureRandom random) {
        init(opmode, key, null, random);
    }

    public final void init(int opmode, Key key, AlgorithmParameterSpec params) {
        init(opmode, key, params, new SecureRandom());
    }

    public /*final*/ void init(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) {
        throw new TUnsupportedOperationException();
    }

    public final byte[] update(byte[] input) {
        return update(input, 0, input.length);
    }

    public final byte[] update(byte[] input, int inputOffset, int inputLen) {
        byte[] result = new byte[getOutputSize(input.length)];
        update(input, 0, input.length, result);
        return result;
    }

    public final int update(byte[] input, int inputOffset, int inputLen, byte[] output) {
        return update(input, inputOffset, inputLen, output, 0);
    }

    public /*final*/ int update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        throw new TUnsupportedOperationException();
    }

    public /*final*/ byte[] doFinal(byte[] input, int inputOffset, int inputLength) {
        throw new TUnsupportedOperationException();
    }

    public final byte[] doFinal(byte[] input) {
        return doFinal(input, 0, input.length);
    }

    public final int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset) {
        // This could be optimised by avoiding the copy.
        byte[] res = doFinal(input, inputOffset, inputLength);
        System.arraycopy(res, 0, output, outputOffset, res.length);
        return res.length;
    }

    public /*final*/ void updateAAD(byte[] src) {
        throw new TUnsupportedOperationException();
    }

    @JSFunctor
    private interface JSBytesConsumer extends JSObject {
        void accept(byte[] bytes);
    }

    @JSFunctor
    private interface JSObjectConsumer extends JSObject {
        void accept(JSObject object);
    }

    private static class AESGCM extends TCipher {
        private static final int TAG_LEN_BYTES = 16;
        private int opmode;
        private GCMParameterSpec params;
        private JSObject jsKey;
        private byte[] aad;

        // JS crypto apis are all async for some reason so we need a lot of boilerplate to convert worlds and sync types.
        //
        // Arrays have to be passed as ByRef to (a) avoid pointless copies and (b) avoid the API barfing because it wants
        // an Int8Array instead of an Array. In js all normal numeric arrays are actually arrays of floats, which doesn't
        // match Java semantics, so TeaVM converts at the boundary. But here actually JS is closer to Java. The crypto
        // API works in terms of "ArrayBuffers" which are basically java.nio.Buffer objects. We have to convert to
        // an Int8Array in the callback because the crypto API gives us an ArrayBuffer which is useless (can't index it).

        // region importKey
        @Async
        private static native JSObject importKey(String format, byte[] keyData, String algorithm, boolean extractable,
                String[] keyUsages);
        private static void importKey(String format, byte[] keyData, String algorithm, boolean extractable,
                String[] keyUsages, AsyncCallback<JSObject> callback) {
            importKey(format, keyData, algorithm, extractable, keyUsages, callback::complete);
        }
        @JSBody(
                params = { "format", "keyData", "algorithm", "extractable", "keyUsages", "consumer" },
                script = "return window.crypto.subtle.importKey(format, keyData, algorithm, extractable, keyUsages).catch(function (e) { throw e }).then(consumer);"
        )
        private static native JSObject importKey(String format, @JSByRef byte[] keyData, String algorithm, boolean extractable,
                String[] keyUsages, JSObjectConsumer consumer);
        // endregion

        // region encrypt
        @Async
        private static native byte[] encrypt(JSObject key, byte[] iv, byte[] aad, byte[] data);
        private static void encrypt(JSObject key, byte[] iv, byte[] aad, byte[] data, AsyncCallback<byte[]> callback) {
            // We can't pass null straight through to the encrypt function because it gets dereferenced to get the
            // data inside and crashes at that point, so we need this unfortunate duplication.
            if (aad != null) {
                encryptAsyncAAD(key, iv, aad, data, callback::complete);
            } else {
                encryptAsync(key, iv, data, callback::complete);
            }
        }
        @JSBody(
                params = { "key", "iv", "aad", "data", "consumer" },
                // TeaVM parses the script and can't handle => syntax, nor capturing parameters in a lambda.
                script = "let tmp = consumer; window.crypto.subtle.encrypt({name: \"AES-GCM\", iv: iv, additionalData: aad}, key, data)" +
                         ".catch(function (e) { throw e }).then(function(bytes) { tmp(new Int8Array(bytes)); });"
        )
        private static native void encryptAsyncAAD(JSObject key, @JSByRef byte[] iv, @JSByRef byte[] aad, @JSByRef byte[] data, JSBytesConsumer consumer);
        @JSBody(
                params = { "key", "iv", "data", "consumer" },
                script = "let tmp = consumer; window.crypto.subtle.encrypt({name: \"AES-GCM\", iv: iv}, key, data)" +
                        ".catch(function (e) { throw e }).then(function(bytes) { tmp(new Int8Array(bytes)); });"
        )
        private static native void encryptAsync(JSObject key, @JSByRef byte[] iv, @JSByRef byte[] data, JSBytesConsumer consumer);
        // endregion


        // region decrypt
        @Async
        private static native byte[] decrypt(JSObject key, byte[] iv, byte[] aad, byte[] data);
        private static void decrypt(JSObject key, byte[] iv, byte[] aad, byte[] data, AsyncCallback<byte[]> callback) {
            if (aad != null) {
                decryptAsyncAAD(key, iv, aad, data, callback::complete);
            } else {
                decryptAsync(key, iv, data, callback::complete);
            }
        }
        @JSBody(
                params = { "key", "iv", "aad", "data", "consumer" },
                script = "let tmp = consumer; window.crypto.subtle.decrypt({name: \"AES-GCM\", iv: iv, additionalData: aad}, key, data)" +
                        ".catch(function (e) { throw e }).then(function(bytes) { tmp(new Int8Array(bytes)) });"
        )
        private static native void decryptAsyncAAD(JSObject key, @JSByRef byte[] iv, @JSByRef byte[] aad, @JSByRef byte[] data, JSBytesConsumer consumer);
        @JSBody(
                params = { "key", "iv", "data", "consumer" },
                script = "let tmp = consumer; window.crypto.subtle.decrypt({name: \"AES-GCM\", iv: iv}, key, data)" +
                        ".catch(function (e) { throw e }).then(function(bytes) { tmp(new Int8Array(bytes)) });"
        )
        private static native void decryptAsync(JSObject key, @JSByRef byte[] iv, @JSByRef byte[] data, JSBytesConsumer consumer);
        // endregion decrypt

        AESGCM(String transformation) {
            super(transformation);
        }

        @Override
        public int getBlockSize() {
            return 16;
        }

        @Override
        public int getOutputSize(int inputLen) {
            return inputLen + TAG_LEN_BYTES;   // lazy ... should incorporate all buffered data.
        }

        @Override
        public byte[] getIV() {
            byte[] iv = params.getIV();
            return Arrays.copyOf(iv, iv.length);
        }

        @Override
        public void init(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) {
            this.opmode = opmode;
            if (opmode != TCipher.ENCRYPT_MODE && opmode != TCipher.DECRYPT_MODE) {
                throw new UnsupportedOperationException();
            }
            this.params = (GCMParameterSpec) params;
            this.jsKey = importKey("raw", key.getEncoded(), "AES-GCM", false, new String[] { "encrypt", "decrypt" });
            this.aad = null;
        }

        @Override
        public byte[] doFinal(byte[] input, int inputOffset, int inputLength) {
            byte[] slice = input;
            if (inputOffset > 0 || inputLength != input.length) {
                slice = Arrays.copyOfRange(input, inputOffset, inputOffset + inputLength);
            }
            if (opmode == Cipher.ENCRYPT_MODE) {
                return encrypt(jsKey, params.getIV(), aad, slice);
            }
            return decrypt(jsKey, params.getIV(), aad, slice);
        }

        @Override
        public void updateAAD(byte[] src) {
            aad = src;
        }
    }
}