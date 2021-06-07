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
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import sun.security.x509.NameConstraintsExtension;

public class TTrustAnchor {
    private final PublicKey pubKey;
    private final String caName;
    private final X500Principal caPrincipal;
    private final X509Certificate trustedCert;
    private byte[] ncBytes;
    private NameConstraintsExtension nc;

    /**
     * Creates an instance of {@code TrustAnchor} with the specified
     * {@code X509Certificate} and optional name constraints, which
     * are intended to be used as additional constraints when validating
     * an X.509 certification path.
     * <p>
     * The name constraints are specified as a byte array. This byte array
     * should contain the DER encoded form of the name constraints, as they
     * would appear in the NameConstraints structure defined in
     * <a href="http://tools.ietf.org/html/rfc5280">RFC 5280</a>
     * and X.509. The ASN.1 definition of this structure appears below.
     *
     * <pre>{@code
     *  NameConstraints ::= SEQUENCE {
     *       permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
     *       excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
     *
     *  GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
     *
     *  GeneralSubtree ::= SEQUENCE {
     *       base                    GeneralName,
     *       minimum         [0]     BaseDistance DEFAULT 0,
     *       maximum         [1]     BaseDistance OPTIONAL }
     *
     *  BaseDistance ::= INTEGER (0..MAX)
     *
     *  GeneralName ::= CHOICE {
     *       otherName                       [0]     OtherName,
     *       rfc822Name                      [1]     IA5String,
     *       dNSName                         [2]     IA5String,
     *       x400Address                     [3]     ORAddress,
     *       directoryName                   [4]     Name,
     *       ediPartyName                    [5]     EDIPartyName,
     *       uniformResourceIdentifier       [6]     IA5String,
     *       iPAddress                       [7]     OCTET STRING,
     *       registeredID                    [8]     OBJECT IDENTIFIER}
     * }</pre>
     * <p>
     * Note that the name constraints byte array supplied is cloned to protect
     * against subsequent modifications.
     *
     * @param trustedCert a trusted {@code X509Certificate}
     * @param nameConstraints a byte array containing the ASN.1 DER encoding of
     * a NameConstraints extension to be used for checking name constraints.
     * Only the value of the extension is included, not the OID or criticality
     * flag. Specify {@code null} to omit the parameter.
     * @throws IllegalArgumentException if the name constraints cannot be
     * decoded
     * @throws NullPointerException if the specified
     * {@code X509Certificate} is {@code null}
     */
    public TTrustAnchor(X509Certificate trustedCert, byte[] nameConstraints)
    {
        if (trustedCert == null) {
            throw new NullPointerException("the trustedCert parameter must " +
                    "be non-null");
        }
        this.trustedCert = trustedCert;
        this.pubKey = null;
        this.caName = null;
        this.caPrincipal = null;
        setNameConstraints(nameConstraints);
    }

    /**
     * Creates an instance of {@code TrustAnchor} where the
     * most-trusted CA is specified as an X500Principal and public key.
     * Name constraints are an optional parameter, and are intended to be used
     * as additional constraints when validating an X.509 certification path.
     * <p>
     * The name constraints are specified as a byte array. This byte array
     * contains the DER encoded form of the name constraints, as they
     * would appear in the NameConstraints structure defined in RFC 5280
     * and X.509. The ASN.1 notation for this structure is supplied in the
     * documentation for
     * {@link #TrustAnchor(X509Certificate, byte[])
     * TrustAnchor(X509Certificate trustedCert, byte[] nameConstraints) }.
     * <p>
     * Note that the name constraints byte array supplied here is cloned to
     * protect against subsequent modifications.
     *
     * @param caPrincipal the name of the most-trusted CA as X500Principal
     * @param pubKey the public key of the most-trusted CA
     * @param nameConstraints a byte array containing the ASN.1 DER encoding of
     * a NameConstraints extension to be used for checking name constraints.
     * Only the value of the extension is included, not the OID or criticality
     * flag. Specify {@code null} to omit the parameter.
     * @throws NullPointerException if the specified {@code caPrincipal} or
     * {@code pubKey} parameter is {@code null}
     * @since 1.5
     */
    public TTrustAnchor(X500Principal caPrincipal, PublicKey pubKey,
            byte[] nameConstraints) {
        if ((caPrincipal == null) || (pubKey == null)) {
            throw new NullPointerException();
        }
        this.trustedCert = null;
        this.caPrincipal = caPrincipal;
        this.caName = caPrincipal.getName();
        this.pubKey = pubKey;
        setNameConstraints(nameConstraints);
    }

    private void setNameConstraints(byte[] bytes) {
        if (bytes == null) {
            ncBytes = null;
            nc = null;
        } else {
            ncBytes = bytes.clone();
            // validate DER encoding
            try {
                nc = new NameConstraintsExtension(Boolean.FALSE, bytes);
            } catch (IOException ioe) {
                IllegalArgumentException iae =
                        new IllegalArgumentException(ioe.getMessage());
                iae.initCause(ioe);
                throw iae;
            }
        }
    }
}
