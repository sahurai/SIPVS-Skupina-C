package sk.fiit.sipvs.validator;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.tsp.MessageImprint;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;

// Generated keys, certificates, CRLs, OCSP responses and time-stamps for checks that no course sample reaches.
final class TestCertificates {

    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final ASN1ObjectIdentifier TSA_POLICY = new ASN1ObjectIdentifier("1.2.3.4.1");
    private static final AtomicLong SERIAL = new AtomicLong(System.currentTimeMillis());

    private TestCertificates() {}

    static KeyPair keyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    static X509Certificate certificate(String subject, PublicKey subjectKey, String issuer, PrivateKey issuerKey) throws Exception {
        return issue(subject, SubjectPublicKeyInfo.getInstance(subjectKey.getEncoded()), issuer, issuerKey, false);
    }

    // TSA certificate: BouncyCastle signs time-stamps only with a critical extended key usage that is only timeStamping.
    static X509Certificate timeStampingCertificate(String subject, PublicKey subjectKey, String issuer, PrivateKey issuerKey)
        throws Exception {
        return issue(subject, SubjectPublicKeyInfo.getInstance(subjectKey.getEncoded()), issuer, issuerKey, true);
    }

    // Certificate with an RSASSA-PSS key (OID 1.2.840.113549.1.1.10, RFC 4055) restricted to these parameters, or without
    // parameters when hash is null. The key pair itself is a plain RSA key pair, so a test can also sign with parameters
    // that the certificate does not allow.
    static X509Certificate pssCertificate(String subject, PublicKey subjectKey, ASN1ObjectIdentifier hash, ASN1ObjectIdentifier mgfHash,
        int saltLength, String issuer, PrivateKey issuerKey) throws Exception {
        RSAPublicKey key = (RSAPublicKey) subjectKey;
        AlgorithmIdentifier algorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS);
        if (hash != null) {
            algorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS, new RSASSAPSSparams(
                new AlgorithmIdentifier(hash, DERNull.INSTANCE),
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, new AlgorithmIdentifier(mgfHash, DERNull.INSTANCE)),
                new ASN1Integer(saltLength), new ASN1Integer(1)));
        }
        SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(algorithm,
            new org.bouncycastle.asn1.pkcs.RSAPublicKey(key.getModulus(), key.getPublicExponent()));
        return issue(subject, info, issuer, issuerKey, false);
    }

    static X509Certificate selfSigned(String subject) throws Exception {
        KeyPair keys = keyPair();
        return certificate(subject, keys.getPublic(), subject, keys.getPrivate());
    }

    static byte[] ocspResponse(X509Certificate certificate, X509Certificate issuer, PrivateKey responderKey) throws Exception {
        CertificateID id = new CertificateID(new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
            new JcaX509CertificateHolder(issuer), certificate.getSerialNumber());
        BasicOCSPResp response = new BasicOCSPRespBuilder(new RespID(new X500Name("CN=Test OCSP")))
            .addResponse(id, CertificateStatus.GOOD)
            .build(new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(responderKey), null, new Date());
        return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, response).getEncoded();
    }

    static byte[] crl(String issuer, PrivateKey issuerKey) throws Exception {
        Instant now = Instant.now();
        return crl(issuer, issuerKey, now, now.plus(Duration.ofDays(1)));
    }

    static byte[] crl(String issuer, PrivateKey issuerKey, Instant thisUpdate, Instant nextUpdate) throws Exception {
        return crl(new X500Name(issuer), issuerKey, thisUpdate, nextUpdate);
    }

    // A CRL whose issuer name is exactly the given name (for example the encoded issuer of a sample certificate).
    static byte[] crl(X500Name issuer, PrivateKey issuerKey, Instant thisUpdate, Instant nextUpdate) throws Exception {
        X509v2CRLBuilder builder = new X509v2CRLBuilder(issuer, Date.from(thisUpdate));
        builder.setNextUpdate(Date.from(nextUpdate));
        return builder.build(new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(issuerKey)).getEncoded();
    }

    // DER time-stamp token over a SHA-256 digest, signed with signingKey and carrying the TSA certificate. A signing key
    // that does not belong to the certificate gives a token whose signature does not verify.
    static byte[] timestamp(byte[] sha256, PrivateKey signingKey, X509Certificate tsa) throws Exception {
        return timestamp(TSPAlgorithms.SHA256, sha256, signingKey, tsa);
    }

    // As above, with a MessageImprint digest made with another hash function (digestAlgorithm, a TSPAlgorithms OID).
    static byte[] timestamp(ASN1ObjectIdentifier digestAlgorithm, byte[] digest, PrivateKey signingKey, X509Certificate tsa)
        throws Exception {
        return timestamp(digestAlgorithm, digest, signingKey, tsa, new Date());
    }

    // As above, with the given time-stamp time (genTime).
    static byte[] timestamp(ASN1ObjectIdentifier digestAlgorithm, byte[] digest, PrivateKey signingKey, X509Certificate tsa,
        Date genTime) throws Exception {
        return timestamp(digestAlgorithm, digest, signingKey, tsa, genTime, true);
    }

    // As timestamp(digestAlgorithm, digest, signingKey, tsa), without the TSA certificate in the token.
    static byte[] timestampWithoutCertificate(ASN1ObjectIdentifier digestAlgorithm, byte[] digest, PrivateKey signingKey,
        X509Certificate tsa) throws Exception {
        return timestamp(digestAlgorithm, digest, signingKey, tsa, new Date(), false);
    }

    private static byte[] timestamp(ASN1ObjectIdentifier digestAlgorithm, byte[] digest, PrivateKey signingKey, X509Certificate tsa,
        Date genTime, boolean withCertificate) throws Exception {
        TimeStampTokenGenerator generator = new TimeStampTokenGenerator(
            new JcaSimpleSignerInfoGeneratorBuilder().build(SIGNATURE_ALGORITHM, signingKey, tsa),
            new JcaDigestCalculatorProviderBuilder().build().get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)), TSA_POLICY);
        generator.addCertificates(new JcaCertStore(List.of(tsa)));
        TimeStampRequestGenerator requestGenerator = new TimeStampRequestGenerator();
        // Without certReq the generator leaves the TSA certificate out of the token.
        requestGenerator.setCertReq(withCertificate);
        TimeStampRequest request = requestGenerator.generate(digestAlgorithm, digest);
        return generator.generate(request, BigInteger.valueOf(SERIAL.incrementAndGet()), genTime).getEncoded();
    }

    // As above, signed with any certificate. TimeStampTokenGenerator refuses a certificate without the TSA extended key
    // usage, so the CMS SignedData is built by hand: the TSTInfo, the ESS signing-certificate-v2 attribute that every
    // RFC 3161 token has, and the certificate.
    static byte[] timestampFromAnyCertificate(ASN1ObjectIdentifier digestAlgorithm, byte[] digest, PrivateKey signingKey,
        X509Certificate certificate) throws Exception {
        TSTInfo info = new TSTInfo(TSA_POLICY, new MessageImprint(new AlgorithmIdentifier(digestAlgorithm), digest),
            new ASN1Integer(SERIAL.incrementAndGet()), new ASN1GeneralizedTime(new Date()), null, null, null, null, null);
        Attribute signingCertificate = new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2,
            new DERSet(new SigningCertificateV2(new ESSCertIDv2(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded())))));
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder()
            .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(signingCertificate)))
            .build(SIGNATURE_ALGORITHM, signingKey, certificate));
        generator.addCertificates(new JcaCertStore(List.of(certificate)));
        return generator.generate(new CMSProcessableByteArray(PKCSObjectIdentifiers.id_ct_TSTInfo, info.getEncoded(ASN1Encoding.DER)), true)
            .getEncoded();
    }

    private static X509Certificate issue(String subject, SubjectPublicKeyInfo subjectKey, String issuer, PrivateKey issuerKey,
        boolean timeStamping) throws Exception {
        Instant now = Instant.now();
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(new X500Name(issuer), BigInteger.valueOf(SERIAL.incrementAndGet()),
            Date.from(now.minus(Duration.ofDays(1))), Date.from(now.plus(Duration.ofDays(365))), new X500Name(subject), subjectKey);
        if (timeStamping) {
            builder.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
        }
        return new JcaX509CertificateConverter().getCertificate(builder.build(new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(issuerKey)));
    }
}
