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

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.X509CRLEntry;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import javax.security.auth.x500.X500Principal;
import org.teavm.classlib.java.security.cert.TX509CRL;
import org.teavm.classlib.java.security.cert.TX509Certificate;
import org.teavm.classlib.javax.security.auth.x500.TX500Principal;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.HexDumpEncoder;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CRLExtensions;
import sun.security.x509.Extension;
import sun.security.x509.OIDMap;
import sun.security.x509.X500Name;

public class TX509CRLImpl extends TX509CRL {

    // CRL data, and its envelope
    private byte[]      signedCRL = null; // DER encoded crl
    private byte[]      signature = null; // raw signature bits
    private byte[]      tbsCertList = null; // DER encoded "to-be-signed" CRL
    private AlgorithmId sigAlgId = null; // sig alg in CRL

    // crl information
    private int              version;
    private AlgorithmId      infoSigAlgId; // sig alg in "to-be-signed" crl
    private X500Name issuer = null;
    private X500Principal    issuerPrincipal = null;
    private Date thisUpdate = null;
    private Date             nextUpdate = null;
    private Map<TX509IssuerSerial,X509CRLEntry> revokedMap = new TreeMap<>();
    private List<X509CRLEntry> revokedList = new LinkedList<>();
    private CRLExtensions extensions = null;
    private final static boolean isExplicit = true;

    private boolean readOnly = false;

    /**
     * PublicKey that has previously been used to successfully verify
     * the signature of this CRL. Null if the CRL has not
     * yet been verified (successfully).
     */
    private PublicKey verifiedPublicKey;
    /**
     * If verifiedPublicKey is not null, name of the provider used to
     * successfully verify the signature of this CRL, or the
     * empty String if no provider was explicitly specified.
     */
    private String verifiedProvider;


    public static byte[] getEncodedInternal(TX509CRL crl) throws CRLException {
        if (crl instanceof TX509CRLImpl) {
            return ((TX509CRLImpl)crl).getEncodedInternal();
        } else {
            return crl.getEncoded();
        }
    }

    public byte[] getEncoded() throws CRLException {
        return getEncodedInternal().clone();
    }

    public byte[] getTBSCertList() throws CRLException {
        if (tbsCertList == null) {
            throw new CRLException("Uninitialized CRL");
        }
        return tbsCertList.clone();
    }

    public byte[] getEncodedInternal() throws CRLException {
        if (signedCRL == null) {
            throw new CRLException("Null CRL to encode");
        }
        return signedCRL;
    }

    public X509CRLEntry getRevokedCertificate(BigInteger serialNumber) {
        if (revokedMap.isEmpty()) {
            return null;
        }
        // assume this is a direct CRL entry (cert and CRL issuer are the same)
        TX509IssuerSerial issuerSerial = new TX509IssuerSerial
                (getIssuerX500Principal(), serialNumber);
        return revokedMap.get(issuerSerial);
    }

    public Set<String> getCriticalExtensionOIDs() {
        if (extensions == null) {
            return null;
        }
        Set<String> extSet = new TreeSet<>();
        for (Extension ex : extensions.getAllExtensions()) {
            if (ex.isCritical()) {
                extSet.add(ex.getExtensionId().toString());
            }
        }
        return extSet;
    }

    public byte[] getExtensionValue(String oid) {
        if (extensions == null) {
            return null;
        }
        try {
            String extAlias = OIDMap.getName(new ObjectIdentifier(oid));
            Extension crlExt = null;

            if (extAlias == null) { // may be unknown
                ObjectIdentifier findOID = new ObjectIdentifier(oid);
                Extension ex = null;
                ObjectIdentifier inCertOID;
                for (Enumeration<Extension> e = extensions.getElements();
                     e.hasMoreElements();) {
                    ex = e.nextElement();
                    inCertOID = ex.getExtensionId();
                    if (inCertOID.equals((Object)findOID)) {
                        crlExt = ex;
                        break;
                    }
                }
            } else {
                crlExt = extensions.get(extAlias);
            }
            if (crlExt == null) {
                return null;
            }
            byte[] extData = crlExt.getExtensionValue();
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

    public Set<String> getNonCriticalExtensionOIDs() {
        if (extensions == null) {
            return null;
        }
        Set<String> extSet = new TreeSet<>();
        for (Extension ex : extensions.getAllExtensions()) {
            if (!ex.isCritical()) {
                extSet.add(ex.getExtensionId().toString());
            }
        }
        return extSet;
    }

    public boolean isRevoked(Certificate cert) {
        if (revokedMap.isEmpty() || (!(cert instanceof TX509Certificate))) {
            return false;
        }
        TX509Certificate xcert = (TX509Certificate) cert;
        TX509IssuerSerial issuerSerial = new TX509IssuerSerial(xcert);
        return revokedMap.containsKey(issuerSerial);
    }

    public boolean hasUnsupportedCriticalExtension() {
        if (extensions == null) {
            return false;
        }
        return extensions.hasUnsupportedCriticalExtension();
    }

    public static TX500Principal getIssuerX500Principal(TX509CRL crl) {
        try {
            byte[] encoded = crl.getEncoded();
            DerInputStream derIn = new DerInputStream(encoded);
            DerValue tbsCert = derIn.getSequence(3)[0];
            DerInputStream tbsIn = tbsCert.data;

            DerValue tmp;
            // skip version number if present
            byte nextByte = (byte)tbsIn.peekByte();
            if (nextByte == DerValue.tag_Integer) {
                tmp = tbsIn.getDerValue();
            }

            tmp = tbsIn.getDerValue();  // skip signature
            tmp = tbsIn.getDerValue();  // issuer
            byte[] principalBytes = tmp.toByteArray();
            return new TX500Principal(principalBytes);
        } catch (Exception e) {
            throw new RuntimeException("Could not parse issuer", e);
        }
    }

    public byte[] getSignature() {
        if (signature == null) {
            return null;
        }
        return signature.clone();
    }

    public String toString() {
        return toStringWithAlgName("" + sigAlgId);
    }

    // Specifically created for keytool to append a (weak) label to sigAlg
    public String toStringWithAlgName(String name) {
        StringBuffer sb = new StringBuffer();
        sb.append("X.509 CRL v" + (version+1) + "\n");
        if (sigAlgId != null) {
            sb.append("Signature Algorithm: " + name.toString() +
                    ", OID=" + (sigAlgId.getOID()).toString() + "\n");
        }
        if (issuer != null) {
            sb.append("Issuer: " + issuer.toString() + "\n");
        }
        if (thisUpdate != null) {
            sb.append("\nThis Update: " + thisUpdate.toString() + "\n");
        }
        if (nextUpdate != null) {
            sb.append("Next Update: " + nextUpdate.toString() + "\n");
        }
        if (revokedList.isEmpty()) {
            sb.append("\nNO certificates have been revoked\n");
        } else {
            sb.append("\nRevoked Certificates: " + revokedList.size());
            int i = 1;
            for (X509CRLEntry entry: revokedList) {
                sb.append("\n[" + i++ + "] " + entry.toString());
            }
        }
        if (extensions != null) {
            Collection<Extension> allExts = extensions.getAllExtensions();
            Object[] objs = allExts.toArray();
            sb.append("\nCRL Extensions: " + objs.length);
            for (int i = 0; i < objs.length; i++) {
                sb.append("\n[" + (i+1) + "]: ");
                Extension ext = (Extension)objs[i];
                try {
                    if (OIDMap.getClass(ext.getExtensionId()) == null) {
                        sb.append(ext.toString());
                        byte[] extValue = ext.getExtensionValue();
                        if (extValue != null) {
                            DerOutputStream out = new DerOutputStream();
                            out.putOctetString(extValue);
                            extValue = out.toByteArray();
                            HexDumpEncoder enc = new HexDumpEncoder();
                            sb.append("Extension unknown: "
                                    + "DER encoded OCTET string =\n"
                                    + enc.encodeBuffer(extValue) + "\n");
                        }
                    } else {
                        sb.append(ext.toString()); // sub-class exists
                    }
                } catch (Exception e) {
                    sb.append(", Error parsing this extension");
                }
            }
        }
        if (signature != null) {
            HexDumpEncoder encoder = new HexDumpEncoder();
            sb.append("\nSignature:\n" + encoder.encodeBuffer(signature)
                    + "\n");
        } else {
            sb.append("NOT signed yet\n");
        }
        return sb.toString();
    }

    private final static class TX509IssuerSerial
            implements Comparable<TX509IssuerSerial> {
        final TX500Principal issuer;
        final BigInteger serial;
        volatile int hashcode = 0;

        /**
         * Create an X509IssuerSerial.
         *
         * @param issuer the issuer DN
         * @param serial the serial number
         */
        TX509IssuerSerial(TX500Principal issuer, BigInteger serial) {
            this.issuer = issuer;
            this.serial = serial;
        }

        /**
         * Construct an X509IssuerSerial from an X509Certificate.
         */
        TX509IssuerSerial(TX509Certificate cert) {
            this(cert.getIssuerX500Principal(), cert.getSerialNumber());
        }

        /**
         * Returns the issuer.
         *
         * @return the issuer
         */
        TX500Principal getIssuer() {
            return issuer;
        }

        /**
         * Returns the serial number.
         *
         * @return the serial number
         */
        BigInteger getSerial() {
            return serial;
        }

        /**
         * Compares this X509Serial with another and returns true if they
         * are equivalent.
         *
         * @param o the other object to compare with
         * @return true if equal, false otherwise
         */
        public boolean equals(Object o) {
            if (o == this) {
                return true;
            }

            if (!(o instanceof TX509IssuerSerial)) {
                return false;
            }

            TX509IssuerSerial other = (TX509IssuerSerial) o;
            if (serial.equals(other.getSerial()) &&
                    issuer.equals(other.getIssuer())) {
                return true;
            }
            return false;
        }

        /**
         * Returns a hash code value for this X509IssuerSerial.
         *
         * @return the hash code value
         */
        public int hashCode() {
            if (hashcode == 0) {
                int result = 17;
                result = 37*result + issuer.hashCode();
                result = 37*result + serial.hashCode();
                hashcode = result;
            }
            return hashcode;
        }

        @Override
        public int compareTo(TX509IssuerSerial another) {
            int cissuer = issuer.toString()
                    .compareTo(another.issuer.toString());
            if (cissuer != 0) {
                return cissuer;
            }
            return this.serial.compareTo(another.serial);
        }
    }
}
