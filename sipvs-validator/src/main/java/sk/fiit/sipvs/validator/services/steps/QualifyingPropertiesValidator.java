package sk.fiit.sipvs.validator.services.steps;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.xml.datatype.DatatypeConstants;
import javax.xml.datatype.DatatypeFactory;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import sk.fiit.sipvs.validator.converters.CertificateConverter;
import sk.fiit.sipvs.validator.enums.Detail;
import sk.fiit.sipvs.validator.enums.State;
import sk.fiit.sipvs.validator.utils.CertificateUtil;
import sk.fiit.sipvs.validator.utils.CryptoUtil;
import sk.fiit.sipvs.validator.utils.SchemaUtil;
import sk.fiit.sipvs.validator.utils.TrustAnchorUtil;
import sk.fiit.sipvs.validator.utils.XadesAlgorithms;
import sk.fiit.sipvs.validator.utils.XadesConstants;
import sk.fiit.sipvs.validator.utils.XmlUtil;

import static sk.fiit.sipvs.validator.utils.ValidationUtil.allowedMimeTypes;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.checkAlgorithm;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.checkChildren;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.checkCount;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.decode;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.error;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.parseCertificate;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.requireId;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.required;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.requiredText;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.safe;
import static sk.fiit.sipvs.validator.utils.XadesConstants.ALGORITHM;
import static sk.fiit.sipvs.validator.utils.XadesConstants.HASH;
import static sk.fiit.sipvs.validator.utils.XadesConstants.ID;
import static sk.fiit.sipvs.validator.utils.XadesConstants.NS_DS;
import static sk.fiit.sipvs.validator.utils.XadesConstants.NS_XADES;
import static sk.fiit.sipvs.validator.utils.XadesConstants.TARGET;
import static sk.fiit.sipvs.validator.utils.XadesConstants.TYPE;
import static sk.fiit.sipvs.validator.utils.XadesConstants.URI;

@Service
public class QualifyingPropertiesValidator {

    private static final Logger log = LoggerFactory.getLogger(QualifyingPropertiesValidator.class);

    private static final List<String> TIMESTAMP_FORBIDDEN_CHILDREN = List.of("Include", "XMLTimeStamp");
    private static final Pattern OID = Pattern.compile("(urn:oid:)?[0-2](\\.(0|[1-9]\\d*))+");

    private final TrustAnchorUtil trustAnchor;

    public QualifyingPropertiesValidator(TrustAnchorUtil trustAnchor) {
        this.trustAnchor = trustAnchor;
    }

    public void validate(SignatureContext ctx) {
        checkQualifyingProperties(ctx);
        checkSignedSignatureProperties(ctx);
        checkDataObjectFormats(ctx);
        checkUnsignedProperties(ctx);
        checkPropertyCounts(ctx);
        checkDataObjectFormatCounts(ctx);
        checkSignaturePolicy(ctx);
        checkArchiveTimestamps(ctx);
        checkCertificatePath(ctx);
        checkOcspValues(ctx);
        checkRevocationValuesContent(ctx);
        checkSignatureSchema(ctx);
    }

    private void checkQualifyingProperties(SignatureContext ctx) {
        Element properties = ctx.qualifyingProperties();
        String target = HASH + ctx.signature.getAttribute(ID);
        if (!target.equals(properties.getAttribute(TARGET))) {
            throw error(XmlUtil.attributeNode(properties, TARGET), "xades:QualifyingProperties/@Target", State.NOT_CORRECT,
                Detail.QUALIFYING_PROPERTIES_TARGET, properties.getAttribute(TARGET), target);
        }
        checkChildren(properties, xades(XadesConstants.QUALIFYING_PROPERTIES_CHILDREN));
        checkCount(properties, XmlUtil.children(properties, NS_XADES, "SignedProperties"), "xades:SignedProperties");
        Element signedProperties = XmlUtil.child(properties, NS_XADES, "SignedProperties");
        checkChildren(signedProperties, xades(XadesConstants.SIGNED_PROPERTIES_CHILDREN));
        checkChildren(required(signedProperties, NS_XADES, "xades:SignedSignatureProperties"),
            xades(XadesConstants.SIGNED_SIGNATURE_PROPERTIES_CHILDREN));
        checkChildren(required(signedProperties, NS_XADES, "xades:SignedDataObjectProperties"),
            xades(XadesConstants.SIGNED_DATA_OBJECT_PROPERTIES_CHILDREN));
    }

    private void checkSignedSignatureProperties(SignatureContext ctx) {
        Element signedProperties = XmlUtil.child(ctx.qualifyingProperties(), NS_XADES, "SignedProperties");
        Element properties = XmlUtil.child(signedProperties, NS_XADES, "SignedSignatureProperties");
        checkSigningTime(requiredText(properties, NS_XADES, "xades:SigningTime"));
        checkSigningCertificate(ctx, required(properties, NS_XADES, "xades:SigningCertificate"));
        Element policy = XmlUtil.child(properties, NS_XADES, "SignaturePolicyIdentifier");
        if (policy != null) {
            Element policyId = required(policy, NS_XADES, "xades:SignaturePolicyId");
            requiredText(required(policyId, NS_XADES, "xades:SigPolicyId"), NS_XADES, "xades:Identifier");
            Element hash = required(policyId, NS_XADES, "xades:SigPolicyHash");
            required(hash, NS_DS, "ds:DigestMethod");
            decode(required(hash, NS_DS, "ds:DigestValue"), "xades:SigPolicyHash");
        }
    }

    private void checkDataObjectFormats(SignatureContext ctx) {
        Map<String, Element> references = new HashMap<>();
        ctx.references().forEach(reference -> references.put(HASH + reference.getAttribute(ID), reference));
        for (Element format : ctx.dataObjectFormats()) {
            String objectReference = format.getAttribute("ObjectReference");
            if (!references.containsKey(objectReference)) {
                throw error(XmlUtil.attributeNode(format, "ObjectReference"), "xades:DataObjectFormat/@ObjectReference", State.NOT_CORRECT,
                    Detail.OBJECT_REFERENCE, objectReference);
            }
            Element encoding = XmlUtil.child(format, NS_XADES, "Encoding");
            if (encoding != null) {
                throw error(encoding, "xades:Encoding", State.NOT_CORRECT, Detail.ENCODING_NOT_ALLOWED, objectReference);
            }
        }
        for (Element reference : ctx.references()) {
            String type = reference.getAttribute(TYPE);
            if (XadesConstants.TYPE_SIGNED_PROPERTIES.equals(type)) {
                continue;
            }
            String uri = reference.getAttribute(URI);
            Element mimeTypeElement = ctx.mimeTypeElement(reference);
            String mimeType = XmlUtil.text(mimeTypeElement);
            if (StringUtils.isEmpty(mimeType)) {
                throw error(reference, "xades:MimeType", State.NOT_PROVIDED, Detail.MIME_TYPE_MISSING, uri);
            }
            if (StringUtils.isNotEmpty(type) && !XadesConstants.MIME_SIGNATURE_PART.equals(mimeType)) {
                throw error(XmlUtil.textNode(mimeTypeElement), "xades:MimeType", State.NOT_CORRECT, Detail.WRONG_VALUE, mimeType,
                    XadesConstants.MIME_SIGNATURE_PART);
            }
            if (StringUtils.isEmpty(type) && !XadesConstants.DATA_OBJECT_MIME_TYPES.contains(mimeType)) {
                throw error(XmlUtil.textNode(mimeTypeElement), "xades:MimeType", State.NOT_CORRECT, Detail.MIME_TYPE_NOT_ALLOWED, uri, mimeType,
                    allowedMimeTypes());
            }
        }
    }

    private void checkUnsignedProperties(SignatureContext ctx) {
        Element unsigned = required(ctx.qualifyingProperties(), NS_XADES, "xades:UnsignedProperties");
        checkChildren(unsigned, xades(XadesConstants.UNSIGNED_PROPERTIES_CHILDREN));
        Element properties = required(unsigned, NS_XADES, "xades:UnsignedSignatureProperties");
        checkChildren(properties, child -> child.getNamespaceURI() != null && child.getNamespaceURI().equals(
            XadesConstants.UNSIGNED_SIGNATURE_PROPERTIES_CHILDREN.get(child.getLocalName())));

        List<Element> timestamps = XmlUtil.children(properties, NS_XADES, "SignatureTimeStamp");
        if (timestamps.isEmpty()) {
            throw error(properties, "xades:SignatureTimeStamp", State.NOT_PROVIDED, Detail.ELEMENT_MISSING,
                "xades:SignatureTimeStamp");
        }
        for (Element timestamp : timestamps) {
            checkTimestampElement(timestamp, "xades:SignatureTimeStamp");
            Element c14n = XmlUtil.child(timestamp, NS_DS, "CanonicalizationMethod");
            if (c14n != null) {
                checkAlgorithm(timestamp, c14n, "ds:CanonicalizationMethod", XadesAlgorithms.CANONICALIZATION_METHODS);
            }
        }
        Element certificateValues = XmlUtil.child(properties, NS_XADES, "CertificateValues");
        Element revocationValues = XmlUtil.child(properties, NS_XADES, "RevocationValues");
        if (certificateValues != null) {
            checkCertificateValues(ctx, certificateValues);
        }
        if (revocationValues != null) {
            checkRevocationValues(ctx, revocationValues);
        }
        for (Element archive : XmlUtil.children(properties, XadesConstants.NS_XADES_141, "ArchiveTimeStamp")) {
            checkTimestampElement(archive, "xadesv141:ArchiveTimeStamp");
            if (certificateValues == null || revocationValues == null) {
                throw error(archive, "xadesv141:ArchiveTimeStamp", State.NOT_CORRECT, Detail.ARCHIVE_TIMESTAMP_VALUES);
            }
        }
    }

    private void checkPropertyCounts(SignatureContext ctx) {
        Element properties = ctx.qualifyingProperties();
        Element signedProperties = XmlUtil.child(properties, NS_XADES, "SignedProperties");
        Element unsigned = XmlUtil.child(properties, NS_XADES, "UnsignedProperties");
        checkAtMostOne(signedProperties, "SignedSignatureProperties", "SignedDataObjectProperties");
        checkAtMostOne(ctx.signedSignatureProperties(), "SigningTime", "SigningCertificate", "SignaturePolicyIdentifier");
        checkAtMostOne(properties, "UnsignedProperties");
        checkAtMostOne(unsigned, "UnsignedSignatureProperties");
        checkAtMostOne(ctx.unsignedSignatureProperties(), "CertificateValues", "RevocationValues");
    }

    private void checkDataObjectFormatCounts(SignatureContext ctx) {
        Map<String, List<Element>> formats = ctx.dataObjectFormats().stream()
            .collect(Collectors.groupingBy(format -> format.getAttribute("ObjectReference"), LinkedHashMap::new, Collectors.toList()));
        formats.forEach((objectReference, found) -> {
            if (found.size() > 1) {
                throw error(found.get(1), "xades:DataObjectFormat", State.NOT_CORRECT, Detail.DATA_OBJECT_FORMAT_COUNT,
                    objectReference, found.size());
            }
        });
        for (Element reference : ctx.references()) {
            String type = reference.getAttribute(TYPE);
            if (StringUtils.isEmpty(type) || XadesConstants.TYPE_SIGNED_PROPERTIES.equals(type)) {
                continue;
            }
            Element format = (Element) ctx.mimeTypeElement(reference).getParentNode();
            for (Element child : XmlUtil.children(format)) {
                if (!XmlUtil.is(child, NS_XADES, "MimeType")) {
                    throw error(child, "xades:DataObjectFormat", State.NOT_CORRECT, Detail.TRIVIAL_FORMAT_CONTENT,
                        reference.getAttribute(URI), child.getTagName());
                }
            }
        }
    }

    private void checkSignaturePolicy(SignatureContext ctx) {
        Element policy = XmlUtil.child(ctx.signedSignatureProperties(), NS_XADES, "SignaturePolicyIdentifier");
        if (policy == null) {
            return;
        }
        Element policyId = XmlUtil.child(policy, NS_XADES, "SignaturePolicyId");
        Element identifier = XmlUtil.child(XmlUtil.child(policyId, NS_XADES, "SigPolicyId"), NS_XADES, "Identifier");
        String value = XmlUtil.text(identifier);
        if (!OID.matcher(value).matches()) {
            throw error(XmlUtil.textNode(identifier), "xades:SigPolicyId", State.NOT_CORRECT, Detail.POLICY_NOT_OID, value);
        }
        Element hash = XmlUtil.child(policyId, NS_XADES, "SigPolicyHash");
        checkAlgorithm(hash, XmlUtil.child(hash, NS_DS, "DigestMethod"), "ds:DigestMethod", XadesAlgorithms.DIGEST_METHODS.keySet());
    }

    private void checkArchiveTimestamps(SignatureContext ctx) {
        for (Element archive : XmlUtil.children(ctx.unsignedSignatureProperties(), XadesConstants.NS_XADES_141, "ArchiveTimeStamp")) {
            checkAlgorithm(archive, XmlUtil.child(archive, NS_DS, "CanonicalizationMethod"), "ds:CanonicalizationMethod",
                XadesAlgorithms.CANONICALIZATION_METHODS);
        }
    }

    private void checkCertificatePath(SignatureContext ctx) {
        Element values = XmlUtil.child(ctx.unsignedSignatureProperties(), NS_XADES, "CertificateValues");
        if (values == null) {
            return;
        }
        List<Element> elements = XmlUtil.children(values, NS_XADES, "EncapsulatedX509Certificate");
        List<X509Certificate> certificates = ctx.certificateValues;
        int signing = certificates.indexOf(ctx.certificate);
        if (signing >= 0) {
            throw error(XmlUtil.textNode(elements.get(signing)), "xades:CertificateValues", State.NOT_CORRECT,
                Detail.SIGNING_CERTIFICATE_IN_VALUES, ctx.certificate.getSerialNumber());
        }
        X509Certificate missing = CertificateUtil.missingIssuer(ctx.certificate, certificates);
        if (missing != null) {
            throw error(values, "xades:CertificateValues", State.NOT_CORRECT, Detail.CERTIFICATE_PATH_INCOMPLETE,
                missing.getIssuerX500Principal().getName(), missing.getSubjectX500Principal().getName());
        }
    }

    private void checkOcspValues(SignatureContext ctx) {
        Element values = XmlUtil.child(ctx.unsignedSignatureProperties(), NS_XADES, "RevocationValues");
        List<OCSPResp> responses = new ArrayList<>();
        for (Element element : XmlUtil.descendants(values, NS_XADES, "EncapsulatedOCSPValue")) {
            byte[] der = decode(element, "xades:RevocationValues");
            try {
                responses.add(CertificateConverter.toOcspResponse(der));
            } catch (IOException | RuntimeException e) {
                log.debug("Invalid xades:EncapsulatedOCSPValue: {}", safe(ExceptionUtils.getRootCauseMessage(e)));
                throw error(XmlUtil.textNode(element), "xades:RevocationValues", State.NOT_CORRECT, Detail.OCSP_NOT_PARSED,
                    "xades:EncapsulatedOCSPValue");
            }
        }
        ctx.ocspValues = responses;
    }

    private void checkRevocationValuesContent(SignatureContext ctx) {
        Element values = XmlUtil.child(ctx.unsignedSignatureProperties(), NS_XADES, "RevocationValues");
        if (values == null) {
            return;
        }
        X509Certificate certificate = ctx.certificate;
        List<X509Certificate> issuers = new ArrayList<>(ctx.certificateValues);
        issuers.add(trustAnchor.certificate());
        issuers.removeIf(issuer -> !CertificateUtil.isSignedBy(certificate, issuer));
        List<String> found = new ArrayList<>();
        for (X509CRL crl : ctx.crlValues) {
            found.add("CRL " + crl.getIssuerX500Principal().getName());
            if (issuers.stream().anyMatch(issuer -> CertificateUtil.isSignedBy(crl, issuer))) {
                return;
            }
        }
        for (OCSPResp response : ctx.ocspValues) {
            List<BigInteger> serials;
            try {
                serials = CertificateUtil.ocspSerialNumbers(response);
            } catch (OCSPException e) {
                log.debug("Invalid xades:EncapsulatedOCSPValue: {}", safe(ExceptionUtils.getRootCauseMessage(e)));
                serials = List.of();
            }
            serials.forEach(serial -> found.add("OCSP " + serial));
            if (serials.contains(certificate.getSerialNumber())) {
                return;
            }
        }
        throw error(values, "xades:RevocationValues", State.NOT_CORRECT, Detail.REVOCATION_VALUES_INCOMPLETE,
            certificate.getIssuerX500Principal().getName(), certificate.getSerialNumber(), found.isEmpty() ? "-" : String.join("; ", found));
    }

    private void checkSignatureSchema(SignatureContext ctx) {
        for (SchemaUtil.SchemaError schemaError : ctx.container.schemaErrors(ctx.fileName, ctx.document)) {
            Element signature = ownerSignature(schemaError.element());
            if (signature == null || signature == ctx.signature) {
                throw error(schemaError.element(), schemaError.element().getTagName(), State.NOT_CORRECT, Detail.SCHEMA_INVALID,
                    ctx.fileName, schemaError.message());
            }
        }
    }

    private static void checkSigningTime(Element signingTime) {
        String value = XmlUtil.text(signingTime);
        try {
            if (DatatypeFactory.newInstance().newXMLGregorianCalendar(value).getXMLSchemaType() == DatatypeConstants.DATETIME) {
                return;
            }
        } catch (Exception e) {
            log.debug("Invalid xades:SigningTime {}: {}", safe(value), safe(ExceptionUtils.getRootCauseMessage(e)));
        }
        throw error(XmlUtil.textNode(signingTime), "xades:SigningTime", State.NOT_CORRECT, Detail.SIGNING_TIME, value);
    }

    private static void checkSigningCertificate(SignatureContext ctx, Element signingCertificate) {
        List<Element> certs = XmlUtil.children(signingCertificate, NS_XADES, "Cert");
        for (Element cert : certs) {
            if (matchesCertificate(cert, ctx.certificate)) {
                return;
            }
        }
        throw error(signingCertificate, "xades:SigningCertificate", State.NOT_CORRECT, Detail.SIGNING_CERTIFICATE);
    }

    private static boolean matchesCertificate(Element cert, X509Certificate certificate) {
        Element certDigest = required(cert, NS_XADES, "xades:CertDigest");
        Element digestMethod = required(certDigest, NS_DS, "ds:DigestMethod");
        checkAlgorithm(certDigest, digestMethod, "ds:DigestMethod", XadesAlgorithms.DIGEST_METHODS.keySet());
        byte[] expected = decode(required(certDigest, NS_DS, "ds:DigestValue"), "xades:CertDigest");
        Element issuerSerial = required(cert, NS_XADES, "xades:IssuerSerial");
        String serial = XmlUtil.text(XmlUtil.child(issuerSerial, NS_DS, "X509SerialNumber"));
        String issuer = XmlUtil.text(XmlUtil.child(issuerSerial, NS_DS, "X509IssuerName"));
        try {
            byte[] digest = CryptoUtil.digest(digestMethod.getAttribute(ALGORITHM), certificate.getEncoded());
            return MessageDigest.isEqual(digest, expected)
                && certificate.getSerialNumber().equals(CertificateUtil.serialNumber(serial))
                && CertificateUtil.sameName(certificate.getIssuerX500Principal(), issuer);
        } catch (Exception e) {
            log.debug("Cannot compare xades:Cert with the signing certificate: {}", safe(ExceptionUtils.getRootCauseMessage(e)));
            return false;
        }
    }

    private static void checkTimestampElement(Element timestamp, String name) {
        requireId(timestamp, name);
        requiredText(timestamp, NS_XADES, "xades:EncapsulatedTimeStamp");
        decode(XmlUtil.child(timestamp, NS_XADES, "EncapsulatedTimeStamp"), "xades:EncapsulatedTimeStamp");
        for (String forbidden : TIMESTAMP_FORBIDDEN_CHILDREN) {
            Element child = XmlUtil.child(timestamp, NS_XADES, forbidden);
            if (child != null) {
                throw error(child, child.getTagName(), State.NOT_CORRECT, Detail.TIMESTAMP_CHILD_NOT_ALLOWED, child.getTagName(), name);
            }
        }
        List<Element> tokens = XmlUtil.children(timestamp, NS_XADES, "EncapsulatedTimeStamp");
        if (tokens.size() > 1) {
            throw error(tokens.get(1), "xades:EncapsulatedTimeStamp", State.NOT_CORRECT, Detail.TIMESTAMP_TOKEN_COUNT, name,
                tokens.size());
        }
    }

    private static void checkCertificateValues(SignatureContext ctx, Element values) {
        requireId(values, "xades:CertificateValues");
        ctx.certificateValues = XmlUtil.children(values, NS_XADES, "EncapsulatedX509Certificate").stream()
            .map(element -> parseCertificate(element, "xades:CertificateValues"))
            .toList();
    }

    private static void checkRevocationValues(SignatureContext ctx, Element values) {
        requireId(values, "xades:RevocationValues");
        List<X509CRL> crls = new ArrayList<>();
        for (Element element : XmlUtil.descendants(values, NS_XADES, "EncapsulatedCRLValue")) {
            byte[] der = decode(element, "xades:RevocationValues");
            try {
                crls.add(CertificateConverter.toCrl(der));
            } catch (Exception e) {
                throw error(XmlUtil.textNode(element), "xades:RevocationValues", State.NOT_CORRECT, Detail.CRL_NOT_PARSED,
                    "xades:RevocationValues");
            }
        }
        ctx.crlValues = crls;
        for (Element element : XmlUtil.descendants(values, NS_XADES, "EncapsulatedOCSPValue")) {
            decode(element, "xades:RevocationValues");
        }
    }

    private static Predicate<Element> xades(Set<String> names) {
        return child -> XmlUtil.is(child, NS_XADES, child.getLocalName()) && names.contains(child.getLocalName());
    }

    private static void checkAtMostOne(Element parent, String... names) {
        for (String name : names) {
            List<Element> found = XmlUtil.children(parent, NS_XADES, name);
            if (!found.isEmpty()) {
                checkCount(parent, found, "xades:" + name);
            }
        }
    }

    private static Element ownerSignature(Node node) {
        for (Node current = node; current instanceof Element element; current = current.getParentNode()) {
            if (XmlUtil.is(element, NS_DS, "Signature")) {
                return element;
            }
        }
        return null;
    }
}
