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
package org.teavm.classlib.java.security.cert;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Extension;
import java.util.Arrays;
import javax.security.auth.x500.X500Principal;
import org.teavm.classlib.javax.security.auth.x500.TX500Principal;
import org.teavm.classlib.sun.security.x509.TX509CRLImpl;
import sun.security.util.SignatureUtil;
import sun.security.x509.AlgorithmId;

public abstract class TX509CRL extends TCRL implements X509Extension {
    private transient TX500Principal issuerPrincipal;
    private AlgorithmId sigAlgId = null; // sig alg in CRL

    /**
     * Constructor for X.509 CRLs.
     */
    protected TX509CRL() {
        super("X.509");
    }

    /**
     * Compares this CRL for equality with the given
     * object. If the {@code other} object is an
     * {@code instanceof} {@code X509CRL}, then
     * its encoded form is retrieved and compared with the
     * encoded form of this CRL.
     *
     * @param other the object to test for equality with this CRL.
     *
     * @return true iff the encoded forms of the two CRLs
     * match, false otherwise.
     */
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof TX509CRL)) {
            return false;
        }
        try {
            byte[] thisCRL = TX509CRLImpl.getEncodedInternal(this);
            byte[] otherCRL = TX509CRLImpl.getEncodedInternal((TX509CRL)other);

            return Arrays.equals(thisCRL, otherCRL);
        } catch (CRLException e) {
            return false;
        }
    }

    /**
     * Returns a hashcode value for this CRL from its
     * encoded form.
     *
     * @return the hashcode value.
     */
    public int hashCode() {
        int retval = 0;
        try {
            byte[] crlData = TX509CRLImpl.getEncodedInternal(this);
            for (int i = 1; i < crlData.length; i++) {
                retval += crlData[i] * i;
            }
            return retval;
        } catch (CRLException e) {
            return retval;
        }
    }

    /**
     * Verifies that this CRL was signed using the
     * private key that corresponds to the given public key.
     * This method uses the signature verification engine
     * supplied by the given provider. Note that the specified Provider object
     * does not have to be registered in the provider list.
     *
     * This method was added to version 1.8 of the Java Platform Standard
     * Edition. In order to maintain backwards compatibility with existing
     * service providers, this method is not {@code abstract}
     * and it provides a default implementation.
     *
     * @param key the PublicKey used to carry out the verification.
     * @param sigProvider the signature provider.
     *
     * @exception NoSuchAlgorithmException on unsupported signature
     * algorithms.
     * @exception InvalidKeyException on incorrect key.
     * @exception SignatureException on signature errors.
     * @exception CRLException on encoding errors.
     * @since 1.8
     */
    public void verify(PublicKey key, Provider sigProvider)
            throws CRLException, NoSuchAlgorithmException,
            InvalidKeyException, SignatureException {
        String sigAlgName = getSigAlgName();
        Signature sig = (sigProvider == null)
                ? Signature.getInstance(sigAlgName)
                : Signature.getInstance(sigAlgName, sigProvider);

        try {
            byte[] paramBytes = getSigAlgParams();
            SignatureUtil.initVerifyWithParam(sig, key,
                    SignatureUtil.getParamSpec(sigAlgName, paramBytes));
        } catch (ProviderException e) {
            throw new CRLException(e.getMessage(), e.getCause());
        } catch (InvalidAlgorithmParameterException e) {
            throw new CRLException(e);
        }

        byte[] tbsCRL = getTBSCertList();
        sig.update(tbsCRL, 0, tbsCRL.length);

        if (sig.verify(getSignature()) == false) {
            throw new SignatureException("Signature does not match.");
        }
    }
    public String getSigAlgName() {
        if (sigAlgId == null) {
            return null;
        }
        return sigAlgId.getName();
    }

    public byte[] getSigAlgParams() {
        if (sigAlgId == null) {
            return null;
        }
        try {
            return sigAlgId.getEncodedParams();
        } catch (IOException e) {
            return null;
        }
    }
    /**
     * Returns the issuer (issuer distinguished name) value from the
     * CRL as an {@code X500Principal}.
     * <p>
     * It is recommended that subclasses override this method.
     *
     * @return an {@code X500Principal} representing the issuer
     *          distinguished name
     * @since 1.4
     */
    public TX500Principal getIssuerX500Principal() {
        if (issuerPrincipal == null) {
            issuerPrincipal = TX509CRLImpl.getIssuerX500Principal(this);
        }
        return issuerPrincipal;
    }

    public abstract X509CRLEntry
    getRevokedCertificate(BigInteger serialNumber);

    public abstract byte[] getEncoded()
            throws CRLException;

    /**
     * Get the CRL entry, if any, for the given certificate.
     *
     * <p>This method can be used to lookup CRL entries in indirect CRLs,
     * that means CRLs that contain entries from issuers other than the CRL
     * issuer. The default implementation will only return entries for
     * certificates issued by the CRL issuer. Subclasses that wish to
     * support indirect CRLs should override this method.
     *
     * @param certificate the certificate for which a CRL entry is to be looked
     *   up
     * @return the entry for the given certificate, or null if no such entry
     *   exists in this CRL.
     * @exception NullPointerException if certificate is null
     *
     * @since 1.5
     */
    public X509CRLEntry getRevokedCertificate(TX509Certificate certificate) {
        TX500Principal certIssuer = certificate.getIssuerX500Principal();
        TX500Principal crlIssuer = getIssuerX500Principal();
        if (certIssuer.equals(crlIssuer) == false) {
            return null;
        }
        return getRevokedCertificate(certificate.getSerialNumber());
    }


    public abstract byte[] getSignature();
    public abstract byte[] getTBSCertList() throws CRLException;

}
