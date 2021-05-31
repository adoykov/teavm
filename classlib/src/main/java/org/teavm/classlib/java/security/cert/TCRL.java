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


import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;

/**
 * This class is an abstraction of certificate revocation lists (CRLs) that
 * have different formats but important common uses. For example, all CRLs
 * share the functionality of listing revoked certificates, and can be queried
 * on whether or not they list a given certificate.
 * <p>
 * Specialized CRL types can be defined by subclassing off of this abstract
 * class.
 *
 * @author Hemma Prafullchandra
 *
 *
 * @see X509CRL
 * @see CertificateFactory
 *
 * @since 1.2
 */

public abstract class TCRL {

    // the CRL type
    private String type;

    /**
     * Creates a CRL of the specified type.
     *
     * @param type the standard name of the CRL type.
     * See the <a href=
     * "{@docRoot}/../specs/security/standard-names.html">
     * Java Security Standard Algorithm Names</a> document
     * for information about standard CRL types.
     */
    protected TCRL(String type) {
        this.type = type;
    }

    /**
     * Returns the type of this CRL.
     *
     * @return the type of this CRL.
     */
    public final String getType() {
        return this.type;
    }

    /**
     * Returns a string representation of this CRL.
     *
     * @return a string representation of this CRL.
     */
    public abstract String toString();

    /**
     * Checks whether the given certificate is on this CRL.
     *
     * @param cert the certificate to check for.
     * @return true if the given certificate is on this CRL,
     * false otherwise.
     */
    public abstract boolean isRevoked(TCertificate cert);
}