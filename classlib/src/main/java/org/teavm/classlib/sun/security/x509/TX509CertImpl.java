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

import java.security.PublicKey;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import org.teavm.classlib.java.security.cert.TX509Certificate;
import org.teavm.classlib.javax.security.auth.x500.TX500Principal;
import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

public class TX509CertImpl {

    private static final long serialVersionUID = -3457612960190864406L;

    private static final String DOT = ".";
    /**
     * Public attribute names.
     */
    public static final String NAME = "x509";
    public static final String INFO = TX509CertInfo.NAME;
    public static final String ALG_ID = "algorithm";
    public static final String SIGNATURE = "signature";
    public static final String SIGNED_CERT = "signed_cert";

    /**
     * The following are defined for ease-of-use. These
     * are the most frequently retrieved attributes.
     */
    // x509.info.subject.dname
    public static final String SUBJECT_DN = NAME + DOT + INFO + DOT +
            TX509CertInfo.SUBJECT + DOT + TX509CertInfo.DN_NAME;
    // x509.info.issuer.dname
    public static final String ISSUER_DN = NAME + DOT + INFO + DOT +
            TX509CertInfo.ISSUER + DOT + TX509CertInfo.DN_NAME;
    // x509.info.serialNumber.number
    public static final String SERIAL_ID = NAME + DOT + INFO + DOT +
            TX509CertInfo.SERIAL_NUMBER + DOT +
            TCertificateSerialNumber.NUMBER;
    // x509.info.key.value
    public static final String PUBLIC_KEY = NAME + DOT + INFO + DOT +
            TX509CertInfo.KEY + DOT +
            TCertificateX509Key.KEY;

    // x509.info.version.value
    public static final String VERSION = NAME + DOT + INFO + DOT +
            TX509CertInfo.VERSION + DOT +
            TCertificateVersion.VERSION;

    // x509.algorithm
    public static final String SIG_ALG = NAME + DOT + ALG_ID;

    // x509.signature
    public static final String SIG = NAME + DOT + SIGNATURE;

    // when we sign and decode we set this to true
    // this is our means to make certificates immutable
    private boolean readOnly = false;

    // Certificate data, and its envelope
    private byte[]              signedCert = null;
    protected TX509CertInfo info = null;
    protected TAlgorithmId algId = null;
    protected byte[]            signature = null;

    // recognized extension OIDS
    private static final String KEY_USAGE_OID = "2.5.29.15";
    private static final String EXTENDED_KEY_USAGE_OID = "2.5.29.37";
    private static final String BASIC_CONSTRAINT_OID = "2.5.29.19";
    private static final String SUBJECT_ALT_NAME_OID = "2.5.29.17";
    private static final String ISSUER_ALT_NAME_OID = "2.5.29.18";
    private static final String AUTH_INFO_ACCESS_OID = "1.3.6.1.5.5.7.1.1";

    // number of standard key usage bits.
    private static final int NUM_STANDARD_KEY_USAGE = 9;

    // SubjectAlterntativeNames cache
    private Collection<List<?>> subjectAlternativeNames;

    // IssuerAlternativeNames cache
    private Collection<List<?>> issuerAlternativeNames;

    // ExtendedKeyUsage cache
    private List<String> extKeyUsage;

    // AuthorityInformationAccess cache
    private Set<TAccessDescription> authInfoAccess;

    /**
     * PublicKey that has previously been used to verify
     * the signature of this certificate. Null if the certificate has not
     * yet been verified.
     */
    private PublicKey verifiedPublicKey;
    /**
     * If verifiedPublicKey is not null, name of the provider used to
     * successfully verify the signature of this certificate, or the
     * empty String if no provider was explicitly specified.
     */
    private String verifiedProvider;
    /**
     * If verifiedPublicKey is not null, result of the verification using
     * verifiedPublicKey and verifiedProvider. If true, verification was
     * successful, if false, it failed.
     */
    private boolean verificationResult;

    /**
     * Default constructor.
     */
    public TX509CertImpl() { }

    public TX500Principal getIssuerX500Principal() {
        if (info == null) {
            return null;
        }
        try {
            TX500Principal issuer = (TX500Principal)info.get(
                    TX509CertInfo.ISSUER + DOT +
                            "x500principal");
            return issuer;
        } catch (Exception e) {
            return null;
        }
    }

    public static TX500Principal getIssuerX500Principal(TX509Certificate cert) {
        try {
            return getX500Principal(cert, true);
        } catch (Exception e) {
            throw new RuntimeException("Could not parse issuer", e);
        }
    }

    private static TX500Principal getX500Principal(TX509Certificate cert,
            boolean getIssuer) throws Exception {
        byte[] encoded = cert.getEncoded();
        DerInputStream derIn = new DerInputStream(encoded);
        DerValue tbsCert = derIn.getSequence(3)[0];
        DerInputStream tbsIn = tbsCert.data;
        DerValue tmp;
        tmp = tbsIn.getDerValue();
        // skip version number if present
        if (tmp.isContextSpecific((byte)0)) {
            tmp = tbsIn.getDerValue();
        }
        // tmp always contains serial number now
        tmp = tbsIn.getDerValue();              // skip signature
        tmp = tbsIn.getDerValue();              // issuer
        if (getIssuer == false) {
            tmp = tbsIn.getDerValue();          // skip validity
            tmp = tbsIn.getDerValue();          // subject
        }
        byte[] principalBytes = tmp.toByteArray();
        return new TX500Principal(principalBytes);
    }
}
