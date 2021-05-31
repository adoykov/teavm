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
import java.util.HashMap;

public class TAlgorithmId {

    private ObjectIdentifier algid;
    protected DerValue          params;
    private static final Map<ObjectIdentifier,String> nameTable;


    /**
     * Algorithm ID for the MD2 Message Digest Algorthm, from RFC 1319.
     * OID = 1.2.840.113549.2.2
     */
    public static final ObjectIdentifier MD2_oid =
            ObjectIdentifier.newInternal(new int[] {1, 2, 840, 113549, 2, 2});

    /**
     * Algorithm ID for the MD5 Message Digest Algorthm, from RFC 1321.
     * OID = 1.2.840.113549.2.5
     */
    public static final ObjectIdentifier MD5_oid =
            ObjectIdentifier.newInternal(new int[] {1, 2, 840, 113549, 2, 5});

    /**
     * Algorithm ID for the SHA1 Message Digest Algorithm, from FIPS 180-1.
     * This is sometimes called "SHA", though that is often confusing since
     * many people refer to FIPS 180 (which has an error) as defining SHA.
     * OID = 1.3.14.3.2.26. Old SHA-0 OID: 1.3.14.3.2.18.
     */
    public static final ObjectIdentifier SHA_oid =
            ObjectIdentifier.newInternal(new int[] {1, 3, 14, 3, 2, 26});

    public static final ObjectIdentifier SHA224_oid =
            ObjectIdentifier.newInternal(new int[] {2, 16, 840, 1, 101, 3, 4, 2, 4});

    public static final ObjectIdentifier SHA256_oid =
            ObjectIdentifier.newInternal(new int[] {2, 16, 840, 1, 101, 3, 4, 2, 1});

    public static final ObjectIdentifier SHA384_oid =
            ObjectIdentifier.newInternal(new int[] {2, 16, 840, 1, 101, 3, 4, 2, 2});

    public static final ObjectIdentifier SHA512_oid =
            ObjectIdentifier.newInternal(new int[] {2, 16, 840, 1, 101, 3, 4, 2, 3});

    public static final ObjectIdentifier SHA512_224_oid =
            ObjectIdentifier.newInternal(new int[] {2, 16, 840, 1, 101, 3, 4, 2, 5});

    public static final ObjectIdentifier SHA512_256_oid =
            ObjectIdentifier.newInternal(new int[] {2, 16, 840, 1, 101, 3, 4, 2, 6});

    /*
     * COMMON PUBLIC KEY TYPES
     */
    private static final int[] DH_data = { 1, 2, 840, 113549, 1, 3, 1 };
    private static final int[] DH_PKIX_data = { 1, 2, 840, 10046, 2, 1 };
    private static final int[] DSA_OIW_data = { 1, 3, 14, 3, 2, 12 };
    private static final int[] DSA_PKIX_data = { 1, 2, 840, 10040, 4, 1 };
    private static final int[] RSA_data = { 2, 5, 8, 1, 1 };

    public static final ObjectIdentifier DH_oid;
    public static final ObjectIdentifier DH_PKIX_oid;
    public static final ObjectIdentifier DSA_oid;
    public static final ObjectIdentifier DSA_OIW_oid;
    public static final ObjectIdentifier EC_oid = oid(1, 2, 840, 10045, 2, 1);
    public static final ObjectIdentifier ECDH_oid = oid(1, 3, 132, 1, 12);
    public static final ObjectIdentifier RSA_oid;
    public static final ObjectIdentifier RSAEncryption_oid =
            oid(1, 2, 840, 113549, 1, 1, 1);
    public static final ObjectIdentifier RSAES_OAEP_oid =
            oid(1, 2, 840, 113549, 1, 1, 7);
    public static final ObjectIdentifier mgf1_oid =
            oid(1, 2, 840, 113549, 1, 1, 8);
    public static final ObjectIdentifier RSASSA_PSS_oid =
            oid(1, 2, 840, 113549, 1, 1, 10);

    /*
     * COMMON SECRET KEY TYPES
     */
    public static final ObjectIdentifier AES_oid =
            oid(2, 16, 840, 1, 101, 3, 4, 1);

    /*
     * COMMON SIGNATURE ALGORITHMS
     */
    private static final int[] md2WithRSAEncryption_data =
            { 1, 2, 840, 113549, 1, 1, 2 };
    private static final int[] md5WithRSAEncryption_data =
            { 1, 2, 840, 113549, 1, 1, 4 };
    private static final int[] sha1WithRSAEncryption_data =
            { 1, 2, 840, 113549, 1, 1, 5 };
    private static final int[] sha1WithRSAEncryption_OIW_data =
            { 1, 3, 14, 3, 2, 29 };
    private static final int[] sha224WithRSAEncryption_data =
            { 1, 2, 840, 113549, 1, 1, 14 };
    private static final int[] sha256WithRSAEncryption_data =
            { 1, 2, 840, 113549, 1, 1, 11 };
    private static final int[] sha384WithRSAEncryption_data =
            { 1, 2, 840, 113549, 1, 1, 12 };
    private static final int[] sha512WithRSAEncryption_data =
            { 1, 2, 840, 113549, 1, 1, 13 };

    private static final int[] shaWithDSA_OIW_data =
            { 1, 3, 14, 3, 2, 13 };
    private static final int[] sha1WithDSA_OIW_data =
            { 1, 3, 14, 3, 2, 27 };
    private static final int[] dsaWithSHA1_PKIX_data =
            { 1, 2, 840, 10040, 4, 3 };

    public static final ObjectIdentifier md2WithRSAEncryption_oid;
    public static final ObjectIdentifier md5WithRSAEncryption_oid;
    public static final ObjectIdentifier sha1WithRSAEncryption_oid;
    public static final ObjectIdentifier sha1WithRSAEncryption_OIW_oid;
    public static final ObjectIdentifier sha224WithRSAEncryption_oid;
    public static final ObjectIdentifier sha256WithRSAEncryption_oid;
    public static final ObjectIdentifier sha384WithRSAEncryption_oid;
    public static final ObjectIdentifier sha512WithRSAEncryption_oid;
    public static final ObjectIdentifier sha512_224WithRSAEncryption_oid =
            oid(1, 2, 840, 113549, 1, 1, 15);
    public static final ObjectIdentifier sha512_256WithRSAEncryption_oid =
            oid(1, 2, 840, 113549, 1, 1, 16);;

    public static final ObjectIdentifier shaWithDSA_OIW_oid;
    public static final ObjectIdentifier sha1WithDSA_OIW_oid;
    public static final ObjectIdentifier sha1WithDSA_oid;
    public static final ObjectIdentifier sha224WithDSA_oid =
            oid(2, 16, 840, 1, 101, 3, 4, 3, 1);
    public static final ObjectIdentifier sha256WithDSA_oid =
            oid(2, 16, 840, 1, 101, 3, 4, 3, 2);

    public static final ObjectIdentifier sha1WithECDSA_oid =
            oid(1, 2, 840, 10045, 4, 1);
    public static final ObjectIdentifier sha224WithECDSA_oid =
            oid(1, 2, 840, 10045, 4, 3, 1);
    public static final ObjectIdentifier sha256WithECDSA_oid =
            oid(1, 2, 840, 10045, 4, 3, 2);
    public static final ObjectIdentifier sha384WithECDSA_oid =
            oid(1, 2, 840, 10045, 4, 3, 3);
    public static final ObjectIdentifier sha512WithECDSA_oid =
            oid(1, 2, 840, 10045, 4, 3, 4);
    public static final ObjectIdentifier specifiedWithECDSA_oid =
            oid(1, 2, 840, 10045, 4, 3);

    /**
     * Algorithm ID for the PBE encryption algorithms from PKCS#5 and
     * PKCS#12.
     */
    public static final ObjectIdentifier pbeWithMD5AndDES_oid =
            ObjectIdentifier.newInternal(new int[]{1, 2, 840, 113549, 1, 5, 3});
    public static final ObjectIdentifier pbeWithMD5AndRC2_oid =
            ObjectIdentifier.newInternal(new int[] {1, 2, 840, 113549, 1, 5, 6});
    public static final ObjectIdentifier pbeWithSHA1AndDES_oid =
            ObjectIdentifier.newInternal(new int[] {1, 2, 840, 113549, 1, 5, 10});
    public static final ObjectIdentifier pbeWithSHA1AndRC2_oid =
            ObjectIdentifier.newInternal(new int[] {1, 2, 840, 113549, 1, 5, 11});
    public static ObjectIdentifier pbeWithSHA1AndDESede_oid =
            ObjectIdentifier.newInternal(new int[] {1, 2, 840, 113549, 1, 12, 1, 3});
    public static ObjectIdentifier pbeWithSHA1AndRC2_40_oid =
            ObjectIdentifier.newInternal(new int[] {1, 2, 840, 113549, 1, 12, 1, 6});

    static {
        /*
         * Note the preferred OIDs are named simply with no "OIW" or
         * "PKIX" in them, even though they may point to data from these
         * specs; e.g. SHA_oid, DH_oid, DSA_oid, SHA1WithDSA_oid...
         */
        /**
         * Algorithm ID for Diffie Hellman Key agreement, from PKCS #3.
         * Parameters include public values P and G, and may optionally specify
         * the length of the private key X.  Alternatively, algorithm parameters
         * may be derived from another source such as a Certificate Authority's
         * certificate.
         * OID = 1.2.840.113549.1.3.1
         */
        DH_oid = ObjectIdentifier.newInternal(DH_data);

        /**
         * Algorithm ID for the Diffie Hellman Key Agreement (DH), from RFC 3279.
         * Parameters may include public values P and G.
         * OID = 1.2.840.10046.2.1
         */
        DH_PKIX_oid = ObjectIdentifier.newInternal(DH_PKIX_data);

        /**
         * Algorithm ID for the Digital Signing Algorithm (DSA), from the
         * NIST OIW Stable Agreements part 12.
         * Parameters may include public values P, Q, and G; or these may be
         * derived from
         * another source such as a Certificate Authority's certificate.
         * OID = 1.3.14.3.2.12
         */
        DSA_OIW_oid = ObjectIdentifier.newInternal(DSA_OIW_data);

        /**
         * Algorithm ID for the Digital Signing Algorithm (DSA), from RFC 3279.
         * Parameters may include public values P, Q, and G; or these may be
         * derived from another source such as a Certificate Authority's
         * certificate.
         * OID = 1.2.840.10040.4.1
         */
        DSA_oid = ObjectIdentifier.newInternal(DSA_PKIX_data);

        /**
         * Algorithm ID for RSA keys used for any purpose, as defined in X.509.
         * The algorithm parameter is a single value, the number of bits in the
         * public modulus.
         * OID = 2.5.8.1.1
         */
        RSA_oid = ObjectIdentifier.newInternal(RSA_data);

        /**
         * Identifies a signing algorithm where an MD2 digest is encrypted
         * using an RSA private key; defined in PKCS #1.  Use of this
         * signing algorithm is discouraged due to MD2 vulnerabilities.
         * OID = 1.2.840.113549.1.1.2
         */
        md2WithRSAEncryption_oid =
                ObjectIdentifier.newInternal(md2WithRSAEncryption_data);

        /**
         * Identifies a signing algorithm where an MD5 digest is
         * encrypted using an RSA private key; defined in PKCS #1.
         * OID = 1.2.840.113549.1.1.4
         */
        md5WithRSAEncryption_oid =
                ObjectIdentifier.newInternal(md5WithRSAEncryption_data);

        /**
         * Identifies a signing algorithm where a SHA1 digest is
         * encrypted using an RSA private key; defined by RSA DSI.
         * OID = 1.2.840.113549.1.1.5
         */
        sha1WithRSAEncryption_oid =
                ObjectIdentifier.newInternal(sha1WithRSAEncryption_data);

        /**
         * Identifies a signing algorithm where a SHA1 digest is
         * encrypted using an RSA private key; defined in NIST OIW.
         * OID = 1.3.14.3.2.29
         */
        sha1WithRSAEncryption_OIW_oid =
                ObjectIdentifier.newInternal(sha1WithRSAEncryption_OIW_data);

        /**
         * Identifies a signing algorithm where a SHA224 digest is
         * encrypted using an RSA private key; defined by PKCS #1.
         * OID = 1.2.840.113549.1.1.14
         */
        sha224WithRSAEncryption_oid =
                ObjectIdentifier.newInternal(sha224WithRSAEncryption_data);

        /**
         * Identifies a signing algorithm where a SHA256 digest is
         * encrypted using an RSA private key; defined by PKCS #1.
         * OID = 1.2.840.113549.1.1.11
         */
        sha256WithRSAEncryption_oid =
                ObjectIdentifier.newInternal(sha256WithRSAEncryption_data);

        /**
         * Identifies a signing algorithm where a SHA384 digest is
         * encrypted using an RSA private key; defined by PKCS #1.
         * OID = 1.2.840.113549.1.1.12
         */
        sha384WithRSAEncryption_oid =
                ObjectIdentifier.newInternal(sha384WithRSAEncryption_data);

        /**
         * Identifies a signing algorithm where a SHA512 digest is
         * encrypted using an RSA private key; defined by PKCS #1.
         * OID = 1.2.840.113549.1.1.13
         */
        sha512WithRSAEncryption_oid =
                ObjectIdentifier.newInternal(sha512WithRSAEncryption_data);

        /**
         * Identifies the FIPS 186 "Digital Signature Standard" (DSS), where a
         * SHA digest is signed using the Digital Signing Algorithm (DSA).
         * This should not be used.
         * OID = 1.3.14.3.2.13
         */
        shaWithDSA_OIW_oid = ObjectIdentifier.newInternal(shaWithDSA_OIW_data);

        /**
         * Identifies the FIPS 186 "Digital Signature Standard" (DSS), where a
         * SHA1 digest is signed using the Digital Signing Algorithm (DSA).
         * OID = 1.3.14.3.2.27
         */
        sha1WithDSA_OIW_oid = ObjectIdentifier.newInternal(sha1WithDSA_OIW_data);

        /**
         * Identifies the FIPS 186 "Digital Signature Standard" (DSS), where a
         * SHA1 digest is signed using the Digital Signing Algorithm (DSA).
         * OID = 1.2.840.10040.4.3
         */
        sha1WithDSA_oid = ObjectIdentifier.newInternal(dsaWithSHA1_PKIX_data);

        nameTable = new HashMap<>();
        nameTable.put(MD5_oid, "MD5");
        nameTable.put(MD2_oid, "MD2");
        nameTable.put(SHA_oid, "SHA-1");
        nameTable.put(SHA224_oid, "SHA-224");
        nameTable.put(SHA256_oid, "SHA-256");
        nameTable.put(SHA384_oid, "SHA-384");
        nameTable.put(SHA512_oid, "SHA-512");
        nameTable.put(SHA512_224_oid, "SHA-512/224");
        nameTable.put(SHA512_256_oid, "SHA-512/256");
        nameTable.put(RSAEncryption_oid, "RSA");
        nameTable.put(RSA_oid, "RSA");
        nameTable.put(DH_oid, "Diffie-Hellman");
        nameTable.put(DH_PKIX_oid, "Diffie-Hellman");
        nameTable.put(DSA_oid, "DSA");
        nameTable.put(DSA_OIW_oid, "DSA");
        nameTable.put(EC_oid, "EC");
        nameTable.put(ECDH_oid, "ECDH");

        nameTable.put(AES_oid, "AES");

        nameTable.put(sha1WithECDSA_oid, "SHA1withECDSA");
        nameTable.put(sha224WithECDSA_oid, "SHA224withECDSA");
        nameTable.put(sha256WithECDSA_oid, "SHA256withECDSA");
        nameTable.put(sha384WithECDSA_oid, "SHA384withECDSA");
        nameTable.put(sha512WithECDSA_oid, "SHA512withECDSA");
        nameTable.put(md5WithRSAEncryption_oid, "MD5withRSA");
        nameTable.put(md2WithRSAEncryption_oid, "MD2withRSA");
        nameTable.put(sha1WithDSA_oid, "SHA1withDSA");
        nameTable.put(sha1WithDSA_OIW_oid, "SHA1withDSA");
        nameTable.put(shaWithDSA_OIW_oid, "SHA1withDSA");
        nameTable.put(sha224WithDSA_oid, "SHA224withDSA");
        nameTable.put(sha256WithDSA_oid, "SHA256withDSA");
        nameTable.put(sha1WithRSAEncryption_oid, "SHA1withRSA");
        nameTable.put(sha1WithRSAEncryption_OIW_oid, "SHA1withRSA");
        nameTable.put(sha224WithRSAEncryption_oid, "SHA224withRSA");
        nameTable.put(sha256WithRSAEncryption_oid, "SHA256withRSA");
        nameTable.put(sha384WithRSAEncryption_oid, "SHA384withRSA");
        nameTable.put(sha512WithRSAEncryption_oid, "SHA512withRSA");
        nameTable.put(sha512_224WithRSAEncryption_oid, "SHA512/224withRSA");
        nameTable.put(sha512_256WithRSAEncryption_oid, "SHA512/256withRSA");
        nameTable.put(RSASSA_PSS_oid, "RSASSA-PSS");
        nameTable.put(RSAES_OAEP_oid, "RSAES-OAEP");

        nameTable.put(pbeWithMD5AndDES_oid, "PBEWithMD5AndDES");
        nameTable.put(pbeWithMD5AndRC2_oid, "PBEWithMD5AndRC2");
        nameTable.put(pbeWithSHA1AndDES_oid, "PBEWithSHA1AndDES");
        nameTable.put(pbeWithSHA1AndRC2_oid, "PBEWithSHA1AndRC2");
        nameTable.put(pbeWithSHA1AndDESede_oid, "PBEWithSHA1AndDESede");
        nameTable.put(pbeWithSHA1AndRC2_40_oid, "PBEWithSHA1AndRC2_40");
    }

    private static ObjectIdentifier oid(int ... values) {
        return ObjectIdentifier.newInternal(values);
    }

    public String getName() {
        String algName = nameTable.get(algid);
        if (algName != null) {
            return algName;
        }
        if ((params != null) && algid.equals((Object)specifiedWithECDSA_oid)) {
            try {
                AlgorithmId paramsId =
                        AlgorithmId.parse(new DerValue(params.toByteArray()));
                String paramsName = paramsId.getName();
                algName = makeSigAlg(paramsName, "EC");
            } catch (IOException e) {
                // ignore
            }
        }
        return (algName == null) ? algid.toString() : algName;
    }

    public static String makeSigAlg(String digAlg, String encAlg) {
        digAlg = digAlg.replace("-", "");
        if (encAlg.equalsIgnoreCase("EC")) {
            encAlg = "ECDSA";
        }

        return digAlg + "with" + encAlg;
    }

    public byte[] getEncodedParams() throws IOException {
        return (params == null || algid.equals(specifiedWithECDSA_oid))
                ? null
                : params.toByteArray();
    }

}
