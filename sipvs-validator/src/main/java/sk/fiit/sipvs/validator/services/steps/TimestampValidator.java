package sk.fiit.sipvs.validator.services.steps;

import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.tsp.TSPUtil;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.w3c.dom.Element;
import sk.fiit.sipvs.validator.converters.Base64Converter;
import sk.fiit.sipvs.validator.converters.CanonicalizationConverter;
import sk.fiit.sipvs.validator.converters.CertificateConverter;
import sk.fiit.sipvs.validator.converters.HexConverter;
import sk.fiit.sipvs.validator.converters.TimestampConverter;
import sk.fiit.sipvs.validator.enums.Detail;
import sk.fiit.sipvs.validator.enums.State;
import sk.fiit.sipvs.validator.exceptions.AttributeException;
import sk.fiit.sipvs.validator.utils.XadesAlgorithms;
import sk.fiit.sipvs.validator.utils.XadesConstants;
import sk.fiit.sipvs.validator.utils.XmlUtil;

import static sk.fiit.sipvs.validator.utils.ValidationUtil.error;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.safe;
import static sk.fiit.sipvs.validator.utils.XadesConstants.ALGORITHM;
import static sk.fiit.sipvs.validator.utils.XadesConstants.NS_DS;
import static sk.fiit.sipvs.validator.utils.XadesConstants.NS_XADES;

@Service
public class TimestampValidator {

    private static final Logger log = LoggerFactory.getLogger(TimestampValidator.class);

    private static final String ARCHIVE_TIMESTAMP = "xadesv141:ArchiveTimeStamp";

    private final CertificateTrustValidator certificateTrust;

    public TimestampValidator(CertificateTrustValidator certificateTrust) {
        this.certificateTrust = certificateTrust;
    }

    public void validate(SignatureContext ctx, List<TimeStampToken> timestamps) {
        List<Element> elements = timestampElements(ctx);
        for (int i = 0; i < timestamps.size(); i++) {
            checkTimestampCertificate(ctx, elements.get(i), timestamps.get(i), "xades:EncapsulatedTimeStamp");
            checkMessageImprint(ctx, elements.get(i), timestamps.get(i));
        }
        for (Element archive : XmlUtil.children(ctx.unsignedSignatureProperties(), XadesConstants.NS_XADES_141, "ArchiveTimeStamp")) {
            TimeStampToken timestamp = readTimestamp(archive, ARCHIVE_TIMESTAMP);
            checkTimestampCertificate(ctx, archive, timestamp, ARCHIVE_TIMESTAMP);
            checkArchiveImprint(ctx, archive, timestamp);
        }
    }

    private void checkTimestampCertificate(SignatureContext ctx, Element element, TimeStampToken timestamp, String attribute) {
        Element encapsulated = XmlUtil.child(element, NS_XADES, "EncapsulatedTimeStamp");
        @SuppressWarnings("unchecked")
        Collection<X509CertificateHolder> matches = timestamp.getCertificates().getMatches(timestamp.getSID());
        if (matches.isEmpty()) {
            throw error(XmlUtil.textNode(encapsulated), attribute, State.NOT_CORRECT, Detail.TSA_CERTIFICATE_MISSING);
        }
        X509CertificateHolder holder = matches.iterator().next();
        X509Certificate certificate;
        try {
            certificate = CertificateConverter.toCertificate(holder);
        } catch (CertificateException e) {
            throw error(XmlUtil.textNode(encapsulated), attribute, State.NOT_CORRECT, Detail.CERTIFICATE_NOT_PARSED,
                "xades:EncapsulatedTimeStamp");
        }
        Instant now = Instant.now();
        log.debug("TSA certificate serial {}, valid to {}", certificate.getSerialNumber(), certificate.getNotAfter());
        certificateTrust.checkValidity(certificate, now, encapsulated, attribute);
        X509CRLEntry entry = certificateTrust.trustedCrl(ctx.container, encapsulated, certificate).getRevokedCertificate(certificate);
        if (entry != null) {
            throw error(XmlUtil.textNode(encapsulated), attribute, State.NOT_CORRECT, Detail.CERTIFICATE_REVOKED,
                certificate.getSerialNumber(), entry.getRevocationDate(), now);
        }
        try {
            TSPUtil.validateCertificate(holder);
        } catch (TSPValidationException | IllegalArgumentException e) {
            throw error(XmlUtil.textNode(encapsulated), attribute, State.NOT_CORRECT, Detail.TSA_EXTENDED_KEY_USAGE,
                certificate.getSerialNumber());
        }
        if (!isTimestampSignatureValid(timestamp, certificate)) {
            throw error(XmlUtil.textNode(encapsulated), attribute, State.NOT_CORRECT, Detail.TIMESTAMP_SIGNATURE);
        }
        certificateTrust.checkIssuedByTrustAnchor(certificate, encapsulated, attribute);
    }

    private void checkMessageImprint(SignatureContext ctx, Element element, TimeStampToken timestamp) {
        Element encapsulated = XmlUtil.child(element, NS_XADES, "EncapsulatedTimeStamp");
        Element signatureValue = XmlUtil.child(ctx.signature, NS_DS, "SignatureValue");
        String c14n = StringUtils.defaultIfEmpty(
            XmlUtil.attribute(XmlUtil.child(element, NS_DS, "CanonicalizationMethod"), ALGORITHM), XadesAlgorithms.C14N);
        byte[] expected = timestamp.getTimeStampInfo().getMessageImprintDigest();
        byte[] digest;
        try {
            String algorithm = timestamp.getTimeStampInfo().getMessageImprintAlgOID().getId();
            digest = MessageDigest.getInstance(algorithm).digest(CanonicalizationConverter.canonicalize(c14n, signatureValue));
        } catch (Exception e) {
            throw error(XmlUtil.textNode(encapsulated), "MessageImprint", State.NOT_CORRECT, Detail.IMPRINT_NOT_COMPUTED,
                ExceptionUtils.getRootCauseMessage(e));
        }
        if (!MessageDigest.isEqual(digest, expected)) {
            throw error(XmlUtil.textNode(encapsulated), "MessageImprint", State.NOT_CORRECT, Detail.MESSAGE_IMPRINT,
                HexConverter.encode(expected), HexConverter.encode(digest));
        }
        checkImprintAlgorithm(encapsulated, timestamp, "MessageImprint");
    }

    private static void checkImprintAlgorithm(Element encapsulated, TimeStampToken timestamp, String attribute) {
        ASN1ObjectIdentifier oid = timestamp.getTimeStampInfo().getMessageImprintAlgOID();
        if (!XadesAlgorithms.DIGEST_OIDS.containsKey(oid.getId())) {
            String name = new DefaultAlgorithmNameFinder().getAlgorithmName(oid);
            String found = oid.getId().equals(name) ? name : name + " (" + oid.getId() + ")";
            throw error(XmlUtil.textNode(encapsulated), attribute, State.NOT_CORRECT, Detail.TIMESTAMP_DIGEST_NOT_ALLOWED, found,
                XadesAlgorithms.DIGEST_OIDS.values().stream().sorted().collect(Collectors.joining(", ")));
        }
    }

    private void checkArchiveImprint(SignatureContext ctx, Element archive, TimeStampToken timestamp) {
        Element encapsulated = XmlUtil.child(archive, NS_XADES, "EncapsulatedTimeStamp");
        String c14n = XmlUtil.child(archive, NS_DS, "CanonicalizationMethod").getAttribute(ALGORITHM);
        byte[] expected = timestamp.getTimeStampInfo().getMessageImprintDigest();
        byte[] digest;
        try {
            MessageDigest md = MessageDigest.getInstance(timestamp.getTimeStampInfo().getMessageImprintAlgOID().getId());
            for (Element reference : ctx.references()) {
                md.update(ctx.referencedData(reference, c14n));
            }
            for (Element element : archivedElements(ctx, archive)) {
                md.update(CanonicalizationConverter.canonicalize(c14n, element));
            }
            digest = md.digest();
        } catch (AttributeException e) {
            throw e;
        } catch (Exception e) {
            log.debug("Cannot compute the data of {}: {}", ARCHIVE_TIMESTAMP, safe(ExceptionUtils.getRootCauseMessage(e)));
            throw error(XmlUtil.textNode(encapsulated), ARCHIVE_TIMESTAMP, State.NOT_CORRECT, Detail.ARCHIVE_IMPRINT_NOT_COMPUTED,
                ExceptionUtils.getRootCauseMessage(e));
        }
        if (!MessageDigest.isEqual(digest, expected)) {
            throw error(XmlUtil.textNode(encapsulated), ARCHIVE_TIMESTAMP, State.NOT_CORRECT, Detail.ARCHIVE_MESSAGE_IMPRINT,
                HexConverter.encode(expected), HexConverter.encode(digest));
        }
        checkImprintAlgorithm(encapsulated, timestamp, ARCHIVE_TIMESTAMP);
    }

    private static List<Element> archivedElements(SignatureContext ctx, Element archive) {
        List<Element> elements = new ArrayList<>(List.of(ctx.signedInfo(), XmlUtil.child(ctx.signature, NS_DS, "SignatureValue"),
            XmlUtil.child(ctx.signature, NS_DS, "KeyInfo")));
        for (Element property : XmlUtil.children(ctx.unsignedSignatureProperties())) {
            if (property == archive) {
                break;
            }
            elements.add(property);
        }
        for (Element object : XmlUtil.children(ctx.signature, NS_DS, "Object")) {
            if (XmlUtil.child(object, NS_XADES, "QualifyingProperties") == null) {
                elements.add(object);
            }
        }
        return elements;
    }

    public List<TimeStampToken> readTimestamps(SignatureContext ctx) {
        List<TimeStampToken> tokens = new ArrayList<>();
        for (Element element : timestampElements(ctx)) {
            tokens.add(readTimestamp(element, "xades:EncapsulatedTimeStamp"));
        }
        return tokens;
    }

    private static TimeStampToken readTimestamp(Element element, String attribute) {
        Element encapsulated = XmlUtil.child(element, NS_XADES, "EncapsulatedTimeStamp");
        try {
            return TimestampConverter.toToken(Base64Converter.decode(XmlUtil.text(encapsulated)));
        } catch (Exception e) {
            throw error(XmlUtil.textNode(encapsulated), attribute, State.NOT_CORRECT, Detail.TIMESTAMP_NOT_PARSED,
                ExceptionUtils.getRootCauseMessage(e));
        }
    }

    private static List<Element> timestampElements(SignatureContext ctx) {
        return XmlUtil.children(ctx.unsignedSignatureProperties(), NS_XADES, "SignatureTimeStamp");
    }

    private static boolean isTimestampSignatureValid(TimeStampToken timestamp, X509Certificate certificate) {
        try {
            timestamp.validate(new JcaSimpleSignerInfoVerifierBuilder().build(certificate));
            return true;
        } catch (Exception e) {
            log.debug("Cannot verify timestamp signature: {}", safe(ExceptionUtils.getRootCauseMessage(e)));
            return false;
        }
    }
}
