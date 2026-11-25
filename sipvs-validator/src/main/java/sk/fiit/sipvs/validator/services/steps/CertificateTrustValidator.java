package sk.fiit.sipvs.validator.services.steps;

import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.w3c.dom.Element;
import sk.fiit.sipvs.validator.clients.CrlClient;
import sk.fiit.sipvs.validator.enums.Detail;
import sk.fiit.sipvs.validator.enums.State;
import sk.fiit.sipvs.validator.utils.TrustAnchorUtil;
import sk.fiit.sipvs.validator.utils.XadesConstants;
import sk.fiit.sipvs.validator.utils.XmlUtil;

import static sk.fiit.sipvs.validator.utils.ValidationUtil.error;

@Service
public class CertificateTrustValidator {

    private static final Logger log = LoggerFactory.getLogger(CertificateTrustValidator.class);

    private final CrlClient crlClient;
    private final TrustAnchorUtil trustAnchor;
    private volatile X509CRL cachedCrl;

    public CertificateTrustValidator(CrlClient crlClient, TrustAnchorUtil trustAnchor) {
        this.crlClient = crlClient;
        this.trustAnchor = trustAnchor;
    }

    void checkValidity(X509Certificate certificate, Instant time, Element element, String attribute) {
        try {
            certificate.checkValidity(Date.from(time));
        } catch (CertificateException e) {
            throw error(XmlUtil.textNode(element), attribute, State.NOT_CORRECT, Detail.CERTIFICATE_NOT_VALID,
                certificate.getNotBefore(), certificate.getNotAfter(), time);
        }
    }

    X509CRL trustedCrl(Container container, Element element, X509Certificate certificate) {
        if (container.crl == null) {
            container.crl = currentCrl(element);
        }
        X509CRL crl = container.crl;
        if (!crl.getIssuerX500Principal().equals(certificate.getIssuerX500Principal())) {
            throw error(element, "CRL", State.NOT_AVAILABLE, Detail.CRL_OTHER_ISSUER,
                crl.getIssuerX500Principal().getName(), certificate.getIssuerX500Principal().getName());
        }
        X509Certificate anchor = trustAnchor.certificate();
        try {
            crl.verify(anchor.getPublicKey());
        } catch (GeneralSecurityException e) {
            throw error(element, "CRL", State.NOT_CORRECT, Detail.CRL_SIGNATURE, crl.getIssuerX500Principal().getName(),
                anchor.getSubjectX500Principal().getName());
        }
        Instant now = Instant.now();
        Date nextUpdate = crl.getNextUpdate();
        if (nextUpdate == null || nextUpdate.toInstant().isBefore(now)) {
            throw error(element, "CRL", State.NOT_AVAILABLE, Detail.CRL_EXPIRED, nextUpdate == null ? "-" : nextUpdate, now);
        }
        cachedCrl = crl;
        return crl;
    }

    public void clearCrlCache() {
        cachedCrl = null;
    }

    void checkIssuedByTrustAnchor(X509Certificate certificate, Element element, String attribute) {
        X509Certificate anchor = trustAnchor.certificate();
        try {
            certificate.verify(anchor.getPublicKey());
        } catch (GeneralSecurityException e) {
            throw error(XmlUtil.textNode(element), attribute, State.NOT_CORRECT, Detail.CERTIFICATE_NOT_TRUSTED,
                certificate.getSerialNumber(), certificate.getIssuerX500Principal().getName(), anchor.getSubjectX500Principal().getName());
        }
    }

    private X509CRL currentCrl(Element element) {
        X509CRL cached = cachedCrl;
        if (cached != null && cached.getNextUpdate().toInstant().isAfter(Instant.now())) {
            return cached;
        }
        return downloadCrl(element);
    }

    private X509CRL downloadCrl(Element element) {
        String url = XadesConstants.CRL_URL;
        try {
            return crlClient.download(url);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw error(element, "CRL", State.NOT_AVAILABLE, Detail.CRL_DOWNLOAD, url,
                ExceptionUtils.getRootCauseMessage(e));
        } catch (Exception e) {
            log.warn("CRL download failed: {}", url, e);
            throw error(element, "CRL", State.NOT_AVAILABLE, Detail.CRL_DOWNLOAD, url,
                ExceptionUtils.getRootCauseMessage(e));
        }
    }
}
