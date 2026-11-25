package sk.fiit.sipvs.validator.utils;

import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;

public final class XadesAlgorithms {

    public static final String C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    public static final String C14N_11 = "http://www.w3.org/2006/12/xml-c14n11";
    public static final String EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";

    public static final Set<String> CANONICALIZATION_METHODS = Set.of(C14N, C14N_11, EXC_C14N);

    public static final Set<String> TRANSFORMS = CANONICALIZATION_METHODS;

    public static final String RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    public static final String RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
    public static final String RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    public static final String RSA_SHA3_256 = "urn:oid:2.16.840.1.101.3.4.3.14";
    public static final String RSA_SHA3_384 = "urn:oid:2.16.840.1.101.3.4.3.15";
    public static final String RSA_SHA3_512 = "urn:oid:2.16.840.1.101.3.4.3.16";
    public static final String ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    public static final String ECDSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
    public static final String ECDSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
    public static final String ECDSA_SHA3_256 = "urn:oid:2.16.840.1.101.3.4.3.10";
    public static final String ECDSA_SHA3_384 = "urn:oid:2.16.840.1.101.3.4.3.11";
    public static final String ECDSA_SHA3_512 = "urn:oid:2.16.840.1.101.3.4.3.12";
    public static final String RSA_PSS = "http://www.w3.org/2007/05/xmldsig-more#rsa-pss";
    public static final String MGF1 = "http://www.w3.org/2007/05/xmldsig-more#MGF1";

    public static final Map<String, String> SIGNATURE_METHODS = Map.ofEntries(
        Map.entry(RSA_SHA256, "SHA256withRSA"),
        Map.entry(RSA_SHA384, "SHA384withRSA"),
        Map.entry(RSA_SHA512, "SHA512withRSA"),
        Map.entry(RSA_SHA3_256, "SHA3-256withRSA"),
        Map.entry(RSA_SHA3_384, "SHA3-384withRSA"),
        Map.entry(RSA_SHA3_512, "SHA3-512withRSA"),
        Map.entry(ECDSA_SHA256, "SHA256withECDSAinP1363Format"),
        Map.entry(ECDSA_SHA384, "SHA384withECDSAinP1363Format"),
        Map.entry(ECDSA_SHA512, "SHA512withECDSAinP1363Format"),
        Map.entry(ECDSA_SHA3_256, "SHA3-256withECDSAinP1363Format"),
        Map.entry(ECDSA_SHA3_384, "SHA3-384withECDSAinP1363Format"),
        Map.entry(ECDSA_SHA3_512, "SHA3-512withECDSAinP1363Format"),
        Map.entry(RSA_PSS, "RSASSA-PSS"));

    public static final String SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
    public static final String SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
    public static final String SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512";
    public static final String SHA3_224 = "http://www.w3.org/2007/05/xmldsig-more#sha3-224";
    public static final String SHA3_256 = "http://www.w3.org/2007/05/xmldsig-more#sha3-256";
    public static final String SHA3_384 = "http://www.w3.org/2007/05/xmldsig-more#sha3-384";
    public static final String SHA3_512 = "http://www.w3.org/2007/05/xmldsig-more#sha3-512";

    public static final Map<String, String> DIGEST_METHODS = Map.of(
        SHA256, "SHA-256",
        SHA384, "SHA-384",
        SHA512, "SHA-512",
        SHA3_224, "SHA3-224",
        SHA3_256, "SHA3-256",
        SHA3_384, "SHA3-384",
        SHA3_512, "SHA3-512");

    // The DIGEST_METHODS hash functions by OID, the form in which a time-stamp token (RFC 3161) names its MessageImprint hash.
    public static final Map<String, String> DIGEST_OIDS = Map.of(
        NISTObjectIdentifiers.id_sha256.getId(), "SHA-256",
        NISTObjectIdentifiers.id_sha384.getId(), "SHA-384",
        NISTObjectIdentifiers.id_sha512.getId(), "SHA-512",
        NISTObjectIdentifiers.id_sha3_224.getId(), "SHA3-224",
        NISTObjectIdentifiers.id_sha3_256.getId(), "SHA3-256",
        NISTObjectIdentifiers.id_sha3_384.getId(), "SHA3-384",
        NISTObjectIdentifiers.id_sha3_512.getId(), "SHA3-512");

    private XadesAlgorithms() {}
}
