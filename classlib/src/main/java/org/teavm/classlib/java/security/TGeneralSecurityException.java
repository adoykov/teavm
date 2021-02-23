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

public class TGeneralSecurityException extends Exception {
    public TGeneralSecurityException() {
        super();
    }

    public TGeneralSecurityException(String message) {
        super(message);
    }

    public TGeneralSecurityException(String message, Throwable cause) {
        super(message, cause);
    }

    public TGeneralSecurityException(Throwable cause) {
        super(cause);
    }
}
