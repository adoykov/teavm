/*
 *  Copyright 2021 Alexander.
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

import java.io.ByteArrayInputStream;
import java.io.NotSerializableException;
import java.io.ObjectStreamException;
import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Iterator;
import java.util.List;

public abstract class TCertPath implements Serializable {

    private static final long serialVersionUID = 6068470306649138683L;

    private String type;        // the type of certificates in this chain

    /**
     * Creates a {@code CertPath} of the specified type.
     * <p>
     * This constructor is protected because most users should use a
     * {@code CertificateFactory} to create {@code CertPath}s.
     *
     * @param type the standard name of the type of
     * {@code Certificate}s in this path
     */
    protected TCertPath(String type) {
        this.type = type;
    }

    /**
     * Returns the type of {@code Certificate}s in this certification
     * path. This is the same string that would be returned by
     * {@link java.security.cert.Certificate#getType() cert.getType()}
     * for all {@code Certificate}s in the certification path.
     *
     * @return the type of {@code Certificate}s in this certification
     * path (never null)
     */
    public String getType() {
        return type;
    }

    /**
     * Returns an iteration of the encodings supported by this certification
     * path, with the default encoding first. Attempts to modify the returned
     * {@code Iterator} via its {@code remove} method result in an
     * {@code UnsupportedOperationException}.
     *
     * @return an {@code Iterator} over the names of the supported
     *         encodings (as Strings)
     */
    public abstract Iterator<String> getEncodings();

    /**
     * Compares this certification path for equality with the specified
     * object. Two {@code CertPath}s are equal if and only if their
     * types are equal and their certificate {@code List}s (and by
     * implication the {@code Certificate}s in those {@code List}s)
     * are equal. A {@code CertPath} is never equal to an object that is
     * not a {@code CertPath}.
     * <p>
     * This algorithm is implemented by this method. If it is overridden,
     * the behavior specified here must be maintained.
     *
     * @param other the object to test for equality with this certification path
     * @return true if the specified object is equal to this certification path,
     * false otherwise
     */
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }

        if (! (other instanceof java.security.cert.CertPath)) {
            return false;
        }

        java.security.cert.CertPath otherCP = (java.security.cert.CertPath) other;
        if (! otherCP.getType().equals(type)) {
            return false;
        }

        List<? extends Certificate> thisCertList = this.getCertificates();
        List<? extends Certificate> otherCertList = otherCP.getCertificates();
        return(thisCertList.equals(otherCertList));
    }

    /**
     * Returns the hashcode for this certification path. The hash code of
     * a certification path is defined to be the result of the following
     * calculation:
     * <pre>{@code
     *  hashCode = path.getType().hashCode();
     *  hashCode = 31*hashCode + path.getCertificates().hashCode();
     * }</pre>
     * This ensures that {@code path1.equals(path2)} implies that
     * {@code path1.hashCode()==path2.hashCode()} for any two certification
     * paths, {@code path1} and {@code path2}, as required by the
     * general contract of {@code Object.hashCode}.
     *
     * @return the hashcode value for this certification path
     */
    public int hashCode() {
        int hashCode = type.hashCode();
        hashCode = 31*hashCode + getCertificates().hashCode();
        return hashCode;
    }

    /**
     * Returns a string representation of this certification path.
     * This calls the {@code toString} method on each of the
     * {@code Certificate}s in the path.
     *
     * @return a string representation of this certification path
     */
    public String toString() {
        StringBuffer sb = new StringBuffer();
        Iterator<? extends Certificate> stringIterator =
                getCertificates().iterator();

        sb.append("\n" + type + " Cert Path: length = "
                + getCertificates().size() + ".\n");
        sb.append("[\n");
        int i = 1;
        while (stringIterator.hasNext()) {
            sb.append("=========================================="
                    + "===============Certificate " + i + " start.\n");
            Certificate stringCert = stringIterator.next();
            sb.append(stringCert.toString());
            sb.append("\n========================================"
                    + "=================Certificate " + i + " end.\n\n\n");
            i++;
        }

        sb.append("\n]");
        return sb.toString();
    }

    /**
     * Returns the encoded form of this certification path, using the default
     * encoding.
     *
     * @return the encoded bytes
     * @exception CertificateEncodingException if an encoding error occurs
     */
    public abstract byte[] getEncoded()
            throws CertificateEncodingException;

    /**
     * Returns the encoded form of this certification path, using the
     * specified encoding.
     *
     * @param encoding the name of the encoding to use
     * @return the encoded bytes
     * @exception CertificateEncodingException if an encoding error occurs or
     *   the encoding requested is not supported
     */
    public abstract byte[] getEncoded(String encoding)
            throws CertificateEncodingException;

    /**
     * Returns the list of certificates in this certification path.
     * The {@code List} returned must be immutable and thread-safe.
     *
     * @return an immutable {@code List} of {@code Certificate}s
     *         (may be empty, but not null)
     */
    public abstract List<? extends Certificate> getCertificates();

    protected Object writeReplace() throws ObjectStreamException {
        try {
            return new CertPathRep(type, getEncoded());
        } catch (CertificateException ce) {
            NotSerializableException nse =
                    new NotSerializableException
                            ("java.security.cert.CertPath: " + type);
            nse.initCause(ce);
            throw nse;
        }
    }

    /**
     * Alternate {@code CertPath} class for serialization.
     * @since 1.4
     */
    protected static class CertPathRep implements Serializable {

        private static final long serialVersionUID = 3015633072427920915L;

        /** The Certificate type */
        private String type;
        /** The encoded form of the cert path */
        private byte[] data;

        /**
         * Creates a {@code CertPathRep} with the specified
         * type and encoded form of a certification path.
         *
         * @param type the standard name of a {@code CertPath} type
         * @param data the encoded form of the certification path
         */
        protected CertPathRep(String type, byte[] data) {
            this.type = type;
            this.data = data;
        }

        /**
         * Returns a {@code CertPath} constructed from the type and data.
         *
         * @return the resolved {@code CertPath} object
         *
         * @throws ObjectStreamException if a {@code CertPath} could not
         * be constructed
         */
        protected Object readResolve() throws ObjectStreamException {
            try {
                CertificateFactory cf = CertificateFactory.getInstance(type);
                return cf.generateCertPath(new ByteArrayInputStream(data));
            } catch (CertificateException ce) {
                NotSerializableException nse =
                        new NotSerializableException
                                ("java.security.cert.CertPath: " + type);
                nse.initCause(ce);
                throw nse;
            }
        }
    }
}
