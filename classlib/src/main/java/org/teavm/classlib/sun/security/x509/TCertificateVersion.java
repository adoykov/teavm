/*
 *  Copyright 2021 alexander.
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
package org.teavm.classlib.sun.security.x509;

public class TCertificateVersion {
    public static final int     V1 = 0;
    /**
     * X509Certificate Version 2
     */
    public static final int     V2 = 1;
    /**
     * X509Certificate Version 3
     */
    public static final int     V3 = 2;
    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT = "x509.info.version";
    /**
     * Sub attributes name for this CertAttrSet.
     */
    public static final String NAME = "version";
    public static final String VERSION = "number";
}
