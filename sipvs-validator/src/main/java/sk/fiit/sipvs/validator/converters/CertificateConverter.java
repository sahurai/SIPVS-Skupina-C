package sk.fiit.sipvs.validator.converters;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.OCSPResp;

public final class CertificateConverter {

    private static final String X509 = "X.509";

    private CertificateConverter() {}

    public static X509Certificate toCertificate(byte[] der) throws CertificateException {
        return (X509Certificate) CertificateFactory.getInstance(X509).generateCertificate(new ByteArrayInputStream(der));
    }

    public static X509Certificate toCertificate(X509CertificateHolder holder) throws CertificateException {
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    public static OCSPResp toOcspResponse(byte[] der) throws IOException {
        return new OCSPResp(der);
    }

    public static X509CRL toCrl(byte[] der) throws CertificateException, CRLException {
        return (X509CRL) CertificateFactory.getInstance(X509).generateCRL(new ByteArrayInputStream(der));
    }
}
