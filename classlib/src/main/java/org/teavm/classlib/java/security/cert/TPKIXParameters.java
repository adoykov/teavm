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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class TPKIXParameters {
    private Set<TrustAnchor> unmodTrustAnchors;
    private Date date;
    private List<PKIXCertPathChecker> certPathCheckers;
    private String sigProvider;
    private boolean revocationEnabled = true;
    private Set<String> unmodInitialPolicies;
    private boolean explicitPolicyRequired = false;
    private boolean policyMappingInhibited = false;
    private boolean anyPolicyInhibited = false;
    private boolean policyQualifiersRejected = true;
    private List<CertStore> certStores;
    private CertSelector certSelector;

    /**
     * Creates an instance of {@code PKIXParameters} with the specified
     * {@code Set} of most-trusted CAs. Each element of the
     * set is a {@link TrustAnchor TrustAnchor}.
     * <p>
     * Note that the {@code Set} is copied to protect against
     * subsequent modifications.
     *
     * @param trustAnchors a {@code Set} of {@code TrustAnchor}s
     * @throws InvalidAlgorithmParameterException if the specified
     * {@code Set} is empty {@code (trustAnchors.isEmpty() == true)}
     * @throws NullPointerException if the specified {@code Set} is
     * {@code null}
     * @throws ClassCastException if any of the elements in the {@code Set}
     * are not of type {@code java.security.cert.TrustAnchor}
     */
    public TPKIXParameters(Set<TrustAnchor> trustAnchors)
            throws InvalidAlgorithmParameterException
    {
        setTrustAnchors(trustAnchors);

        this.unmodInitialPolicies = Collections.<String>emptySet();
        this.certPathCheckers = new ArrayList<PKIXCertPathChecker>();
        this.certStores = new ArrayList<CertStore>();
    }

    public void setRevocationEnabled(boolean val) {
        revocationEnabled = val;
    }

    public void setDate(Date date) {
        if (date != null) {
            this.date = (Date) date.clone();
        } else {
            date = null;
        }
    }

    /**
     * Creates an instance of {@code PKIXParameters} that
     * populates the set of most-trusted CAs from the trusted
     * certificate entries contained in the specified {@code KeyStore}.
     * Only keystore entries that contain trusted {@code X509Certificates}
     * are considered; all other certificate types are ignored.
     *
     * @param keystore a {@code KeyStore} from which the set of
     * most-trusted CAs will be populated
     * @throws KeyStoreException if the keystore has not been initialized
     * @throws InvalidAlgorithmParameterException if the keystore does
     * not contain at least one trusted certificate entry
     * @throws NullPointerException if the keystore is {@code null}
     */
    public TPKIXParameters(KeyStore keystore)
            throws KeyStoreException, InvalidAlgorithmParameterException
    {
        if (keystore == null) {
            throw new NullPointerException("the keystore parameter must be " +
                    "non-null");
        }
        Set<TrustAnchor> hashSet = new HashSet<TrustAnchor>();
        Enumeration<String> aliases = keystore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keystore.isCertificateEntry(alias)) {
                Certificate cert = keystore.getCertificate(alias);
                if (cert instanceof X509Certificate) {
                    hashSet.add(new TrustAnchor((X509Certificate)cert, null));
                }
            }
        }
        setTrustAnchors(hashSet);
        this.unmodInitialPolicies = Collections.<String>emptySet();
        this.certPathCheckers = new ArrayList<PKIXCertPathChecker>();
        this.certStores = new ArrayList<CertStore>();
    }

    public void setTrustAnchors(Set<TrustAnchor> trustAnchors)
            throws InvalidAlgorithmParameterException
    {
        if (trustAnchors == null) {
            throw new NullPointerException("the trustAnchors parameters must" +
                    " be non-null");
        }
        if (trustAnchors.isEmpty()) {
            throw new InvalidAlgorithmParameterException("the trustAnchors " +
                    "parameter must be non-empty");
        }
        for (Iterator<TrustAnchor> i = trustAnchors.iterator(); i.hasNext(); ) {
            if (!(i.next() instanceof TrustAnchor)) {
                throw new ClassCastException("all elements of set must be "
                        + "of type java.security.cert.TrustAnchor");
            }
        }
        this.unmodTrustAnchors = Collections.unmodifiableSet
                (new HashSet<TrustAnchor>(trustAnchors));
    }

}
