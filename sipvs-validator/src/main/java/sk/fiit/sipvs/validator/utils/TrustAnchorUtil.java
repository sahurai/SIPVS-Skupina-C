package sk.fiit.sipvs.validator.utils;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.springframework.stereotype.Component;
import sk.fiit.sipvs.validator.converters.CertificateConverter;

@Component
public class TrustAnchorUtil {

    private static final String CERTIFICATE_FILE = "certificates/ditec-test-ca-sha256-rsa.cer";

    private final X509Certificate certificate;

    public TrustAnchorUtil() {
        try (InputStream in = TrustAnchorUtil.class.getClassLoader().getResourceAsStream(CERTIFICATE_FILE)) {
            if (in == null) {
                throw new IllegalStateException("Missing bundled certificate " + CERTIFICATE_FILE);
            }
            certificate = CertificateConverter.toCertificate(in.readAllBytes());
        } catch (IOException | CertificateException e) {
            throw new IllegalStateException("Bundled certificate " + CERTIFICATE_FILE + " cannot be read", e);
        }
    }

    public X509Certificate certificate() {
        return certificate;
    }
}
