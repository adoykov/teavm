/*
 *  Copyright 2015 Alexey Andreev.
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
package org.teavm.classlib.java.nio.charset;

import org.teavm.classlib.java.lang.TIllegalArgumentException;

public class TUnsupportedCharsetException extends TIllegalArgumentException {
    private static final long serialVersionUID = 2668607022458967777L;
    private String charsetName;

    public TUnsupportedCharsetException(String charsetName) {
        super("TeaVM does not support the " + charsetName + " character set.");
        this.charsetName = charsetName;
    }

    public String getCharsetName() {
        return charsetName;
    }

    @Override
    public String toString() {
        return "UnsupportedCharsetException: " + getMessage();
    }
}
