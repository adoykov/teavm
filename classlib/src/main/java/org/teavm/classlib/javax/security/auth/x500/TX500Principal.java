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
package org.teavm.classlib.javax.security.auth.x500;

import java.util.Collections;
import java.util.Map;
import sun.security.x509.X500Name;

/**
 * <p> This class represents an X.500 {@code Principal}.
 * {@code X500Principal}s are represented by distinguished names such as
 * "CN=Duke, OU=JavaSoft, O=Sun Microsystems, C=US".
 *
 * <p> This class can be instantiated by using a string representation
 * of the distinguished name, or by using the ASN.1 DER encoded byte
 * representation of the distinguished name.  The current specification
 * for the string representation of a distinguished name is defined in
 * <a href="http://tools.ietf.org/html/rfc2253">RFC 2253: Lightweight
 * Directory Access Protocol (v3): UTF-8 String Representation of
 * Distinguished Names</a>. This class, however, accepts string formats from
 * both RFC 2253 and <a href="http://tools.ietf.org/html/rfc1779">RFC 1779:
 * A String Representation of Distinguished Names</a>, and also recognizes
 * attribute type keywords whose OIDs (Object Identifiers) are defined in
 * <a href="http://tools.ietf.org/html/rfc5280">RFC 5280: Internet X.509
 * Public Key Infrastructure Certificate and CRL Profile</a>.
 *
 * <p> The string representation for this {@code X500Principal}
 * can be obtained by calling the {@code getName} methods.
 *
 * <p> Note that the {@code getSubjectX500Principal} and
 * {@code getIssuerX500Principal} methods of
 * {@code X509Certificate} return X500Principals representing the
 * issuer and subject fields of the certificate.
 *
 * @see java.security.cert.X509Certificate
 * @since 1.4
 */
public final class TX500Principal implements java.io.Serializable {

    private static final long serialVersionUID = -500463348111345721L;

    /**
     * RFC 1779 String format of Distinguished Names.
     */
    public static final String RFC1779 = "RFC1779";
    /**
     * RFC 2253 String format of Distinguished Names.
     */
    public static final String RFC2253 = "RFC2253";
    /**
     * Canonical String format of Distinguished Names.
     */
    public static final String CANONICAL = "CANONICAL";

    /**
     * The X500Name representing this principal.
     *
     * NOTE: this field is reflectively accessed from within X500Name.
     */
    private transient X500Name thisX500Name;

    /**
     * Creates an {@code X500Principal} from a string representation of
     * an X.500 distinguished name (ex:
     * "CN=Duke, OU=JavaSoft, O=Sun Microsystems, C=US").
     * The distinguished name must be specified using the grammar defined in
     * RFC 1779 or RFC 2253 (either format is acceptable).
     *
     * <p>This constructor recognizes the attribute type keywords
     * defined in RFC 1779 and RFC 2253
     * (and listed in {@link #getName(String format) getName(String format)}),
     * as well as the T, DNQ or DNQUALIFIER, SURNAME, GIVENNAME, INITIALS,
     * GENERATION, EMAILADDRESS, and SERIALNUMBER keywords whose Object
     * Identifiers (OIDs) are defined in RFC 5280.
     * Any other attribute type must be specified as an OID.
     *
     * <p>This implementation enforces a more restrictive OID syntax than
     * defined in RFC 1779 and 2253. It uses the more correct syntax defined in
     * <a href="http://www.ietf.org/rfc/rfc4512.txt">RFC 4512</a>, which
     * specifies that OIDs contain at least 2 digits:
     *
     * <p>{@code numericoid = number 1*( DOT number ) }
     *
     * @param name an X.500 distinguished name in RFC 1779 or RFC 2253 format
     * @exception NullPointerException if the {@code name}
     *                  is {@code null}
     * @exception IllegalArgumentException if the {@code name}
     *                  is improperly specified
     */
    public TX500Principal(String name) {
        this(name, Collections.<String, String>emptyMap());
    }

    public TX500Principal(byte[] name) {
        try {
            thisX500Name = new X500Name(name);
        } catch (Exception e) {
            IllegalArgumentException iae = new IllegalArgumentException
                    ("improperly specified input name");
            iae.initCause(e);
            throw iae;
        }
    }

    /**
     * Creates an {@code X500Principal} from a string representation of
     * an X.500 distinguished name (ex:
     * "CN=Duke, OU=JavaSoft, O=Sun Microsystems, C=US").
     * The distinguished name must be specified using the grammar defined in
     * RFC 1779 or RFC 2253 (either format is acceptable).
     *
     * <p> This constructor recognizes the attribute type keywords specified
     * in {@link #X500Principal(String)} and also recognizes additional
     * keywords that have entries in the {@code keywordMap} parameter.
     * Keyword entries in the keywordMap take precedence over the default
     * keywords recognized by {@code X500Principal(String)}. Keywords
     * MUST be specified in all upper-case, otherwise they will be ignored.
     * Improperly specified keywords are ignored; however if a keyword in the
     * name maps to an improperly specified Object Identifier (OID), an
     * {@code IllegalArgumentException} is thrown. It is permissible to
     * have 2 different keywords that map to the same OID.
     *
     * <p>This implementation enforces a more restrictive OID syntax than
     * defined in RFC 1779 and 2253. It uses the more correct syntax defined in
     * <a href="http://www.ietf.org/rfc/rfc4512.txt">RFC 4512</a>, which
     * specifies that OIDs contain at least 2 digits:
     *
     * <p>{@code numericoid = number 1*( DOT number ) }
     *
     * @param name an X.500 distinguished name in RFC 1779 or RFC 2253 format
     * @param keywordMap an attribute type keyword map, where each key is a
     *   keyword String that maps to a corresponding object identifier in String
     *   form (a sequence of nonnegative integers separated by periods). The map
     *   may be empty but never {@code null}.
     * @exception NullPointerException if {@code name} or
     *   {@code keywordMap} is {@code null}
     * @exception IllegalArgumentException if the {@code name} is
     *   improperly specified or a keyword in the {@code name} maps to an
     *   OID that is not in the correct form
     * @since 1.6
     */
    public TX500Principal(String name, Map<String, String> keywordMap) {
        if (name == null) {
            throw new NullPointerException
                    (sun.security.util.ResourcesMgr.getString
                            ("provided.null.name"));
        }
        if (keywordMap == null) {
            throw new NullPointerException
                    (sun.security.util.ResourcesMgr.getString
                            ("provided.null.keyword.map"));
        }

        try {
            thisX500Name = new X500Name(name, keywordMap);
        } catch (Exception e) {
            IllegalArgumentException iae = new IllegalArgumentException
                    ("improperly specified input name: " + name);
            iae.initCause(e);
            throw iae;
        }
    }

}
