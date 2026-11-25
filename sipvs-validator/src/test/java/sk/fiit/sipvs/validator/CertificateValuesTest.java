package sk.fiit.sipvs.validator;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import sk.fiit.sipvs.validator.converters.CertificateConverter;
import sk.fiit.sipvs.validator.utils.CertificateUtil;

class CertificateValuesTest {

    private static final String ROOT = "CN=Test Root CA";
    private static final String INTERMEDIATE = "CN=Test CA";

    private static KeyPair intermediateKeys;
    private static X509Certificate root;
    private static X509Certificate intermediate;
    private static X509Certificate leaf;
    private static X509Certificate fakeIntermediate;

    @BeforeAll
    static void createCertificates() throws Exception {
        KeyPair rootKeys = TestCertificates.keyPair();
        intermediateKeys = TestCertificates.keyPair();
        KeyPair otherKeys = TestCertificates.keyPair();
        root = TestCertificates.certificate(ROOT, rootKeys.getPublic(), ROOT, rootKeys.getPrivate());
        intermediate = TestCertificates.certificate(INTERMEDIATE, intermediateKeys.getPublic(), ROOT, rootKeys.getPrivate());
        leaf = TestCertificates.certificate("CN=Signer", TestCertificates.keyPair().getPublic(), INTERMEDIATE, intermediateKeys.getPrivate());
        fakeIntermediate = TestCertificates.certificate(INTERMEDIATE, otherKeys.getPublic(), ROOT, rootKeys.getPrivate());
    }

    @Test
    void pathEndingInSelfSignedRootIsComplete() {
        assertNull(CertificateUtil.missingIssuer(leaf, List.of(root, intermediate)));
    }

    @Test
    void certificateWithoutIssuerInValuesIsReturned() {
        assertEquals(leaf, CertificateUtil.missingIssuer(leaf, List.of(root)));
    }

    @Test
    void pathWithoutSelfSignedRootIsIncomplete() {
        assertEquals(intermediate, CertificateUtil.missingIssuer(leaf, List.of(intermediate)));
    }

    @Test
    void issuerWithSameNameButOtherKeyIsNotAccepted() {
        assertEquals(leaf, CertificateUtil.missingIssuer(leaf, List.of(fakeIntermediate, root)));
    }

    @Test
    void certificatesIssuingEachOtherDoNotLoop() throws Exception {
        KeyPair a = TestCertificates.keyPair();
        KeyPair b = TestCertificates.keyPair();
        X509Certificate first = TestCertificates.certificate("CN=A", a.getPublic(), "CN=B", b.getPrivate());
        X509Certificate second = TestCertificates.certificate("CN=B", b.getPublic(), "CN=A", a.getPrivate());

        assertNotNull(CertificateUtil.missingIssuer(first, List.of(first, second)));
    }

    @Test
    void ocspResponseIsParsed() throws Exception {
        byte[] response = TestCertificates.ocspResponse(leaf, intermediate, intermediateKeys.getPrivate());

        assertDoesNotThrow(() -> CertificateConverter.toOcspResponse(response));
    }

    @Test
    void otherDataIsNotOcspResponse() throws Exception {
        byte[] certificate = leaf.getEncoded();

        assertThrows(Exception.class, () -> CertificateConverter.toOcspResponse(new byte[] {0, 1, 2}));
        assertThrows(Exception.class, () -> CertificateConverter.toOcspResponse(new byte[] {0x30, 0x00}));
        assertThrows(Exception.class, () -> CertificateConverter.toOcspResponse(certificate));
    }
}
