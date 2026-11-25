package sk.fiit.sipvs.validator.services.steps;

import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.time.Instant;

import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.w3c.dom.Element;
import sk.fiit.sipvs.validator.enums.Detail;
import sk.fiit.sipvs.validator.enums.State;
import sk.fiit.sipvs.validator.utils.XmlUtil;

import static sk.fiit.sipvs.validator.utils.ValidationUtil.error;
import static sk.fiit.sipvs.validator.utils.XadesConstants.NS_DS;
import static sk.fiit.sipvs.validator.utils.XadesConstants.X509_CERTIFICATE;

@Service
public class SigningCertificateValidator {

    private static final Logger log = LoggerFactory.getLogger(SigningCertificateValidator.class);

    private final CertificateTrustValidator certificateTrust;

    public SigningCertificateValidator(CertificateTrustValidator certificateTrust) {
        this.certificateTrust = certificateTrust;
    }

    public void validate(SignatureContext ctx, TimeStampToken timestamp) {
        checkSigningCertificateRevocation(ctx, timestamp.getTimeStampInfo().getGenTime().toInstant());
    }

    private void checkSigningCertificateRevocation(SignatureContext ctx, Instant time) {
        X509Certificate certificate = ctx.certificate;
        Element element = XmlUtil.first(ctx.signature, NS_DS, X509_CERTIFICATE);
        log.debug("Signing certificate serial {}, valid {} to {}, time T {}", certificate.getSerialNumber(),
            certificate.getNotBefore(), certificate.getNotAfter(), time);
        certificateTrust.checkValidity(certificate, time, element, "ds:X509Certificate");
        X509CRLEntry entry = certificateTrust.trustedCrl(ctx.container, element, certificate).getRevokedCertificate(certificate);
        if (entry != null && entry.getRevocationDate().toInstant().isBefore(time)) {
            throw error(XmlUtil.textNode(element), "ds:X509Certificate", State.NOT_CORRECT, Detail.CERTIFICATE_REVOKED,
                certificate.getSerialNumber(), entry.getRevocationDate(), time);
        }
        certificateTrust.checkIssuedByTrustAnchor(certificate, element, "ds:X509Certificate");
    }
}
