package sk.fiit.sipvs.validator.utils;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;

public final class CertificateUtil {

    private static final String OID_PREFIX = "OID.";

    private static final Map<String, String> NAME_OIDS = Map.ofEntries(
        Map.entry("CN", "2.5.4.3"),
        Map.entry("SN", "2.5.4.4"),
        Map.entry("SURNAME", "2.5.4.4"),
        Map.entry("SERIALNUMBER", "2.5.4.5"),
        Map.entry("C", "2.5.4.6"),
        Map.entry("L", "2.5.4.7"),
        Map.entry("ST", "2.5.4.8"),
        Map.entry("S", "2.5.4.8"),
        Map.entry("STREET", "2.5.4.9"),
        Map.entry("O", "2.5.4.10"),
        Map.entry("OU", "2.5.4.11"),
        Map.entry("POSTALCODE", "2.5.4.17"),
        Map.entry("DC", "0.9.2342.19200300.100.1.25"),
        Map.entry("T", "2.5.4.12"),
        Map.entry("TITLE", "2.5.4.12"),
        Map.entry("G", "2.5.4.42"),
        Map.entry("GN", "2.5.4.42"),
        Map.entry("GIVENNAME", "2.5.4.42"),
        Map.entry("E", "1.2.840.113549.1.9.1"),
        Map.entry("EMAILADDRESS", "1.2.840.113549.1.9.1"));

    private CertificateUtil() {}

    public static boolean sameName(X500Principal certificateName, String xmlName) {
        Set<String> expected = new HashSet<>();
        for (RDN rdn : X500Name.getInstance(certificateName.getEncoded()).getRDNs()) {
            for (AttributeTypeAndValue value : rdn.getTypesAndValues()) {
                String text = value.getValue() instanceof ASN1String string ? string.getString() : value.getValue().toString();
                expected.add(value.getType().getId() + "=" + text);
            }
        }
        Set<String> actual = new HashSet<>();
        try {
            for (Rdn rdn : new LdapName(xmlName).getRdns()) {
                NamingEnumeration<? extends Attribute> attributes = rdn.toAttributes().getAll();
                while (attributes.hasMore()) {
                    Attribute attribute = attributes.next();
                    actual.add(oid(attribute.getID()) + "=" + value(attribute.get()));
                }
            }
        } catch (NamingException | IllegalArgumentException e) {
            return false;
        }
        return expected.equals(actual);
    }

    public static BigInteger serialNumber(String text) {
        try {
            return new BigInteger(text);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    public static X509Certificate missingIssuer(X509Certificate certificate, List<X509Certificate> candidates) {
        X509Certificate current = certificate;
        for (int i = 0; i <= candidates.size(); i++) {
            if (isSignedBy(current, current)) {
                return null;
            }
            X509Certificate subject = current;
            X509Certificate issuer = candidates.stream().filter(candidate -> isSignedBy(subject, candidate)).findFirst().orElse(null);
            if (issuer == null) {
                return current;
            }
            current = issuer;
        }
        return current;
    }

    public static boolean isSignedBy(X509Certificate certificate, X509Certificate issuer) {
        if (!certificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
            return false;
        }
        try {
            certificate.verify(issuer.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    public static boolean isSignedBy(X509CRL crl, X509Certificate issuer) {
        if (!crl.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
            return false;
        }
        try {
            crl.verify(issuer.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    public static List<BigInteger> ocspSerialNumbers(OCSPResp response) throws OCSPException {
        if (response.getResponseObject() instanceof BasicOCSPResp basic) {
            return Arrays.stream(basic.getResponses()).map(single -> single.getCertID().getSerialNumber()).toList();
        }
        return List.of();
    }

    private static String value(Object value) {
        if (!(value instanceof byte[] bytes)) {
            return String.valueOf(value);
        }
        try {
            ASN1Primitive primitive = ASN1Primitive.fromByteArray(bytes);
            return primitive instanceof ASN1String string ? string.getString() : primitive.toString();
        } catch (IOException | RuntimeException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static String oid(String type) {
        String upper = StringUtils.upperCase(type, Locale.ROOT);
        if (Strings.CS.startsWith(upper, OID_PREFIX)) {
            return Strings.CS.removeStart(upper, OID_PREFIX);
        }
        return NAME_OIDS.getOrDefault(upper, upper);
    }
}
