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

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.util.HashMap;
import java.util.Map;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.UniqueIdentity;
import sun.security.x509.X500Name;
import sun.security.x509.X509AttributeName;
import sun.security.x509.X509CertInfo;

public class TX509CertInfo {
    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    public static final String IDENT = "x509.info";
    // Certificate attribute names
    public static final String NAME = "info";
    public static final String DN_NAME = "dname";
    public static final String VERSION = TCertificateVersion.NAME;
    public static final String SERIAL_NUMBER = TCertificateSerialNumber.NAME;
    public static final String ALGORITHM_ID = TCertificateAlgorithmId.NAME;
    public static final String ISSUER = "issuer";
    public static final String SUBJECT = "subject";
    public static final String VALIDITY = TCertificateValidity.NAME;
    public static final String KEY = TCertificateX509Key.NAME;
    public static final String ISSUER_ID = "issuerID";
    public static final String SUBJECT_ID = "subjectID";
    public static final String EXTENSIONS = TCertificateExtensions.NAME;

    // X509.v1 data
    protected CertificateVersion version = new CertificateVersion();
    protected CertificateSerialNumber serialNum = null;
    protected CertificateAlgorithmId algId = null;
    protected X500Name issuer = null;
    protected X500Name                  subject = null;
    protected CertificateValidity interval = null;
    protected CertificateX509Key pubKey = null;

    // X509.v2 & v3 extensions
    protected UniqueIdentity issuerUniqueId = null;
    protected UniqueIdentity  subjectUniqueId = null;

    protected CertificateExtensions extensions = null;

    private static final int ATTR_VERSION = 1;
    private static final int ATTR_SERIAL = 2;
    private static final int ATTR_ALGORITHM = 3;
    private static final int ATTR_ISSUER = 4;
    private static final int ATTR_VALIDITY = 5;
    private static final int ATTR_SUBJECT = 6;
    private static final int ATTR_KEY = 7;
    private static final int ATTR_ISSUER_ID = 8;
    private static final int ATTR_SUBJECT_ID = 9;
    private static final int ATTR_EXTENSIONS = 10;

    public Object get(String name)
            throws CertificateException, IOException {
        X509AttributeName attrName = new X509AttributeName(name);

        int attr = attributeMap(attrName.getPrefix());
        if (attr == 0) {
            throw new CertificateParsingException(
                    "Attribute name not recognized: " + name);
        }
        String suffix = attrName.getSuffix();

        switch (attr) { // frequently used attributes first
            case (ATTR_EXTENSIONS):
                if (suffix == null) {
                    return(extensions);
                } else {
                    if (extensions == null) {
                        return null;
                    } else {
                        return(extensions.get(suffix));
                    }
                }
            case (ATTR_SUBJECT):
                if (suffix == null) {
                    return(subject);
                } else {
                    return(getX500Name(suffix, false));
                }
            case (ATTR_ISSUER):
                if (suffix == null) {
                    return(issuer);
                } else {
                    return(getX500Name(suffix, true));
                }
            case (ATTR_KEY):
                if (suffix == null) {
                    return(pubKey);
                } else {
                    return(pubKey.get(suffix));
                }
            case (ATTR_ALGORITHM):
                if (suffix == null) {
                    return(algId);
                } else {
                    return(algId.get(suffix));
                }
            case (ATTR_VALIDITY):
                if (suffix == null) {
                    return(interval);
                } else {
                    return(interval.get(suffix));
                }
            case (ATTR_VERSION):
                if (suffix == null) {
                    return(version);
                } else {
                    return(version.get(suffix));
                }
            case (ATTR_SERIAL):
                if (suffix == null) {
                    return(serialNum);
                } else {
                    return(serialNum.get(suffix));
                }
            case (ATTR_ISSUER_ID):
                return(issuerUniqueId);
            case (ATTR_SUBJECT_ID):
                return(subjectUniqueId);
        }
        return null;
    }

    private int attributeMap(String name) {
        Integer num = map.get(name);
        if (num == null) {
            return 0;
        }
        return num.intValue();
    }

    // The certificate attribute name to integer mapping stored here
    private static final Map<String,Integer> map = new HashMap<String,Integer>();
    static {
        map.put(VERSION, Integer.valueOf(ATTR_VERSION));
        map.put(SERIAL_NUMBER, Integer.valueOf(ATTR_SERIAL));
        map.put(ALGORITHM_ID, Integer.valueOf(ATTR_ALGORITHM));
        map.put(ISSUER, Integer.valueOf(ATTR_ISSUER));
        map.put(VALIDITY, Integer.valueOf(ATTR_VALIDITY));
        map.put(SUBJECT, Integer.valueOf(ATTR_SUBJECT));
        map.put(KEY, Integer.valueOf(ATTR_KEY));
        map.put(ISSUER_ID, Integer.valueOf(ATTR_ISSUER_ID));
        map.put(SUBJECT_ID, Integer.valueOf(ATTR_SUBJECT_ID));
        map.put(EXTENSIONS, Integer.valueOf(ATTR_EXTENSIONS));
    }

    /*
     * Get the Issuer or Subject name
     */
    private Object getX500Name(String name, boolean getIssuer)
            throws IOException {
        if (name.equalsIgnoreCase(X509CertInfo.DN_NAME)) {
            return getIssuer ? issuer : subject;
        } else if (name.equalsIgnoreCase("x500principal")) {
            return getIssuer ? issuer.asX500Principal()
                    : subject.asX500Principal();
        } else {
            throw new IOException("Attribute name not recognized.");
        }
    }

}
