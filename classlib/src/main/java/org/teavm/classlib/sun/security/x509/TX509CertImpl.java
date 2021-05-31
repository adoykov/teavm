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
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.ProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.teavm.classlib.java.security.TPublicKey;
import org.teavm.classlib.java.security.cert.TCertificate;
import org.teavm.classlib.java.security.cert.TX509Certificate;
import org.teavm.classlib.javax.security.auth.x500.TX500Principal;

public class TX509CertImpl extends TX509Certificate {

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
    private TPublicKey verifiedPublicKey;
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

    @Override
    public void checkValidity()
            throws CertificateExpiredException, CertificateNotYetValidException {
        Date date = new Date();
        checkValidity(date);
    }

    @Override
    public byte[] getEncoded() throws CertificateEncodingException {
        return getEncodedInternal().clone();
    }

    public void verify(TPublicKey key)
            throws CertificateException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchProviderException, SignatureException {
        verify(key, "");
    }

    /**
     * Throws an exception if the certificate was not signed using the
     * verification key provided.  Successfully verifying a certificate
     * does <em>not</em> indicate that one should trust the entity which
     * it represents.
     *
     * @param key the public key used for verification.
     * @param sigProvider the name of the provider.
     *
     * @exception NoSuchAlgorithmException on unsupported signature
     * algorithms.
     * @exception InvalidKeyException on incorrect key.
     * @exception NoSuchProviderException on incorrect provider.
     * @exception SignatureException on signature errors.
     * @exception CertificateException on encoding errors.
     */
    public synchronized void verify(TPublicKey key, String sigProvider)
            throws CertificateException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchProviderException, SignatureException {
        if (sigProvider == null) {
            sigProvider = "";
        }
        if ((verifiedPublicKey != null) && verifiedPublicKey.equals(key)) {
            // this certificate has already been verified using
            // this public key. Make sure providers match, too.
            if (sigProvider.equals(verifiedProvider)) {
                if (verificationResult) {
                    return;
                } else {
                    throw new SignatureException("Signature does not match.");
                }
            }
        }
        if (signedCert == null) {
            throw new CertificateEncodingException("Uninitialized certificate");
        }
        // Verify the signature ...
        Signature sigVerf = null;
        String sigName = algId.getName();
        if (sigProvider.length() == 0) {
            sigVerf = Signature.getInstance(sigName);
        } else {
            sigVerf = Signature.getInstance(sigName, sigProvider);
        }

        try {
            initVerifyWithParam(sigVerf, key,
                    getParamSpec(sigName, getSigAlgParams()));
        } catch (ProviderException e) {
            throw new CertificateException(e.getMessage(), e.getCause());
        } catch (InvalidAlgorithmParameterException e) {
            throw new CertificateException(e);
        }

        byte[] rawCert = info.getEncodedInfo();
        sigVerf.update(rawCert, 0, rawCert.length);

        // verify may throw SignatureException for invalid encodings, etc.
        verificationResult = sigVerf.verify(signature);
        verifiedPublicKey = key;
        verifiedProvider = sigProvider;

        if (verificationResult == false) {
            throw new SignatureException("Signature does not match.");
        }
    }



    public byte[] getSigAlgParams() {
        if (algId == null) {
            return null;
        }
        try {
            return algId.getEncodedParams();
        } catch (IOException e) {
            return null;
        }
    }

    @Override
    public int getVersion() {
        if (info == null) {
            return -1;
        }
        try {
            int vers = ((Integer)info.get(NAME
                    + DOT + VERSION)).intValue();
            return vers+1;
        } catch (Exception e) {
            return -1;
        }
    }

    @Override
    public byte[] getExtensionValue(String oid) {
        try {
            ObjectIdentifier findOID = new ObjectIdentifier(oid);
            String extAlias = OIDMap.getName(findOID);
            Extension certExt = null;
            CertificateExtensions exts = (CertificateExtensions)info.get(
                    CertificateExtensions.NAME);

            if (extAlias == null) { // may be unknown
                // get the extensions, search thru' for this oid
                if (exts == null) {
                    return null;
                }

                for (Extension ex : exts.getAllExtensions()) {
                    ObjectIdentifier inCertOID = ex.getExtensionId();
                    if (inCertOID.equals((Object)findOID)) {
                        certExt = ex;
                        break;
                    }
                }
            } else { // there's sub-class that can handle this extension
                try {
                    certExt = (Extension)this.get(extAlias);
                } catch (CertificateException e) {
                    // get() throws an Exception instead of returning null, ignore
                }
            }
            if (certExt == null) {
                if (exts != null) {
                    certExt = exts.getUnparseableExtensions().get(oid);
                }
                if (certExt == null) {
                    return null;
                }
            }
            byte[] extData = certExt.getExtensionValue();
            if (extData == null) {
                return null;
            }
            DerOutputStream out = new DerOutputStream();
            out.putOctetString(extData);
            return out.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    public Object get(String name)
            throws CertificateParsingException {
        X509AttributeName attr = new X509AttributeName(name);
        String id = attr.getPrefix();
        if (!(id.equalsIgnoreCase(NAME))) {
            throw new CertificateParsingException("Invalid root of "
                    + "attribute name, expected [" + NAME +
                    "], received " + "[" + id + "]");
        }
        attr = new X509AttributeName(attr.getSuffix());
        id = attr.getPrefix();

        if (id.equalsIgnoreCase(INFO)) {
            if (info == null) {
                return null;
            }
            if (attr.getSuffix() != null) {
                try {
                    return info.get(attr.getSuffix());
                } catch (IOException e) {
                    throw new CertificateParsingException(e.toString());
                } catch (CertificateException e) {
                    throw new CertificateParsingException(e.toString());
                }
            } else {
                return info;
            }
        } else if (id.equalsIgnoreCase(ALG_ID)) {
            return(algId);
        } else if (id.equalsIgnoreCase(SIGNATURE)) {
            if (signature != null) {
                return signature.clone();
            } else {
                return null;
            }
        } else if (id.equalsIgnoreCase(SIGNED_CERT)) {
            if (signedCert != null) {
                return signedCert.clone();
            } else {
                return null;
            }
        } else {
            throw new CertificateParsingException("Attribute name not "
                    + "recognized or get() not allowed for the same: " + id);
        }
    }

    @Override
    public BigInteger getSerialNumber() {
        SerialNumber ser = getSerialNumberObject();

        return ser != null ? ser.getNumber() : null;
    }

    public SerialNumber getSerialNumberObject() {
        if (info == null) {
            return null;
        }
        try {
            SerialNumber ser = (SerialNumber)info.get(
                    CertificateSerialNumber.NAME + DOT +
                            CertificateSerialNumber.NUMBER);
            return ser;
        } catch (Exception e) {
            return null;
        }
    }


    @Override
    public Set<String> getNonCriticalExtensionOIDs() {
        if (info == null) {
            return null;
        }
        try {
            CertificateExtensions exts = (CertificateExtensions)info.get(
                    CertificateExtensions.NAME);
            if (exts == null) {
                return null;
            }
            Set<String> extSet = new TreeSet<>();
            for (Extension ex : exts.getAllExtensions()) {
                if (!ex.isCritical()) {
                    extSet.add(ex.getExtensionId().toString());
                }
            }
            extSet.addAll(exts.getUnparseableExtensions().keySet());
            return extSet;
        } catch (Exception e) {
            return null;
        }
    }


    @Override
    public Set<String> getCriticalExtensionOIDs() {
        if (info == null) {
            return null;
        }
        try {
            CertificateExtensions exts = (CertificateExtensions)info.get(
                    CertificateExtensions.NAME);
            if (exts == null) {
                return null;
            }
            Set<String> extSet = new TreeSet<>();
            for (Extension ex : exts.getAllExtensions()) {
                if (ex.isCritical()) {
                    extSet.add(ex.getExtensionId().toString());
                }
            }
            return extSet;
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public boolean hasUnsupportedCriticalExtension() {
        if (info == null) {
            return false;
        }
        try {
            CertificateExtensions exts = (CertificateExtensions)info.get(
                    CertificateExtensions.NAME);
            if (exts == null) {
                return false;
            }
            return exts.hasUnsupportedCriticalExtension();
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public Principal getIssuerDN() {
        if (info == null) {
            return null;
        }
        try {
            Principal issuer = (Principal)info.get(X509CertInfo.ISSUER + DOT +
                    X509CertInfo.DN_NAME);
            return issuer;
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public void checkValidity(Date date)
            throws CertificateExpiredException, CertificateNotYetValidException {

        CertificateValidity interval = null;
        try {
            interval = (CertificateValidity)info.get(CertificateValidity.NAME);
        } catch (Exception e) {
            throw new CertificateNotYetValidException("Incorrect validity period");
        }
        if (interval == null) {
            throw new CertificateNotYetValidException("Null validity period");
        }
        interval.valid(date);
    }

    public static byte[] getEncodedInternal(TCertificate cert)
            throws CertificateEncodingException {
        if (cert instanceof TX509CertImpl) {
            return ((TX509CertImpl)cert).getEncodedInternal();
        } else {
            return cert.getEncoded();
        }
    }

    public byte[] getEncodedInternal() throws CertificateEncodingException {
        if (signedCert == null) {
            throw new CertificateEncodingException(
                    "Null certificate to encode");
        }
        return signedCert;
    }

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
