package sk.fiit.sipvs.validator;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.springframework.core.io.ClassPathResource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import sk.fiit.sipvs.validator.converters.Base64Converter;
import sk.fiit.sipvs.validator.converters.XmlConverter;
import sk.fiit.sipvs.validator.utils.AsiceUtil;
import sk.fiit.sipvs.validator.utils.XadesAlgorithms;
import sk.fiit.sipvs.validator.utils.XadesConstants;
import sk.fiit.sipvs.validator.utils.XmlUtil;

import static sk.fiit.sipvs.validator.utils.XadesConstants.NS_DS;
import static sk.fiit.sipvs.validator.utils.XadesConstants.NS_XADES;

// Signs course sample 13X-T.asice again with generated keys, for checks that no course sample reaches. One generated root
// CA issues the signing certificate and both TSA certificates, because the validator checks all of them against one CRL.
// The XML is edited as text and parsed again after each step, so the bytes in the container are the bytes that were signed.
final class TestSigner {

    static final String ROOT = "CN=Test Root CA,O=Test,C=SK";
    static final String RSA_SHA256 = "<ds:SignatureMethod Algorithm=\"" + XadesAlgorithms.RSA_SHA256 + "\"/>";

    private static final String SAMPLE = "samples/13X-T.asice";
    private static final String SHA256 = "SHA-256";
    private static final String HASH = "#";

    static {
        Init.init();
    }

    final KeyPair rootKeys;
    final X509Certificate root;
    final KeyPair signerKeys;
    final X509Certificate signer;
    final KeyPair tsaKeys;
    final X509Certificate tsa;
    final KeyPair archiveTsaKeys;
    final X509Certificate archiveTsa;

    TestSigner() throws Exception {
        rootKeys = TestCertificates.keyPair();
        root = TestCertificates.certificate(ROOT, rootKeys.getPublic(), ROOT, rootKeys.getPrivate());
        signerKeys = TestCertificates.keyPair();
        signer = issue("CN=Test Signer,C=SK", signerKeys.getPublic());
        tsaKeys = TestCertificates.keyPair();
        tsa = TestCertificates.timeStampingCertificate("CN=Test TSA,C=SK", tsaKeys.getPublic(), ROOT, rootKeys.getPrivate());
        archiveTsaKeys = TestCertificates.keyPair();
        archiveTsa = TestCertificates.timeStampingCertificate("CN=Test Archive TSA,C=SK", archiveTsaKeys.getPublic(), ROOT,
            rootKeys.getPrivate());
    }

    X509Certificate issue(String subject, PublicKey key) throws Exception {
        return TestCertificates.certificate(subject, key, ROOT, rootKeys.getPrivate());
    }

    X509Certificate issuePss(String subject, PublicKey key, ASN1ObjectIdentifier hash, ASN1ObjectIdentifier mgfHash, int saltLength)
        throws Exception {
        return TestCertificates.pssCertificate(subject, key, hash, mgfHash, saltLength, ROOT, rootKeys.getPrivate());
    }

    Map<String, byte[]> sign() throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        return sign(signerKeys.getPrivate(), signer, RSA_SHA256, signature);
    }

    // Sample 13 with ds:SignatureMethod replaced by signatureMethod (the whole element), the certificate in ds:KeyInfo and
    // xades:SigningCertificate, new reference digests, a new ds:SignatureValue and a new xades:SignatureTimeStamp.
    Map<String, byte[]> sign(PrivateKey key, X509Certificate certificate, String signatureMethod, Signature signature) throws Exception {
        return sign(key, certificate, signatureMethod, signature, tsaKeys.getPrivate(), tsa);
    }

    // As above, with the xades:SignatureTimeStamp signed by tsaKey and carrying tsaCertificate.
    Map<String, byte[]> sign(PrivateKey key, X509Certificate certificate, String signatureMethod, Signature signature, PrivateKey tsaKey,
        X509Certificate tsaCertificate) throws Exception {
        return sign(key, certificate, signatureMethod, signature, tsaKey, tsaCertificate, UnaryOperator.identity());
    }

    // The signature file of a second signature over the same container: sample 13 with every Id renamed, signed again.
    // The Ids of all signature files in a container must be unique.
    byte[] secondSignature() throws Exception {
        return sign(signerKeys.getPrivate(), signer, RSA_SHA256, Signature.getInstance("SHA256withRSA"), tsaKeys.getPrivate(), tsa,
            xml -> xml.replace("signatureId", "secondSignatureId").replace("Reference_", "SecondReference_"))
            .get(AsiceUtil.SIGNATURE_FILE);
    }

    // As above, with the sample XML changed by edit before it is signed.
    private Map<String, byte[]> sign(PrivateKey key, X509Certificate certificate, String signatureMethod, Signature signature,
        PrivateKey tsaKey, X509Certificate tsaCertificate, UnaryOperator<String> edit) throws Exception {
        Map<String, byte[]> files;
        try (InputStream in = new ClassPathResource(SAMPLE).getInputStream()) {
            files = AsiceUtil.open(in);
        }
        String xml = edit.apply(text(files.get(AsiceUtil.SIGNATURE_FILE)));
        xml = xml.replaceFirst("<ds:SignatureMethod [^>]*/>", Matcher.quoteReplacement(signatureMethod));
        xml = set(xml, "(<ds:X509Certificate>)[^<]*(</ds:X509Certificate>)", base64(certificate.getEncoded()));
        xml = set(xml, "(<ds:X509IssuerName>)[^<]*(</ds:X509IssuerName>)", certificate.getIssuerX500Principal().getName());
        xml = set(xml, "(<ds:X509SerialNumber>)[^<]*(</ds:X509SerialNumber>)", certificate.getSerialNumber().toString());
        xml = set(xml, "(<ds:X509SubjectName>)[^<]*(</ds:X509SubjectName>)", certificate.getSubjectX500Principal().getName());
        xml = set(xml, "(<xades:CertDigest><ds:DigestMethod [^>]*/><ds:DigestValue>)[^<]*(</ds:DigestValue>)",
            base64(sha256(certificate.getEncoded())));

        Document document = parse(xml);
        for (Element reference : XmlUtil.children(first(document, NS_DS, "SignedInfo"), NS_DS, "Reference")) {
            String uri = reference.getAttribute("URI");
            if (uri.startsWith(HASH)) {
                byte[] digest = sha256(canonicalize(transform(reference), byId(document, uri.substring(1))));
                xml = set(xml, "(?s)(<ds:Reference [^>]*URI=\"" + Pattern.quote(uri) + "\"(?:(?!</ds:Reference>).)*?<ds:DigestValue>)[^<]*"
                    + "(</ds:DigestValue>)", base64(digest));
            }
        }

        Element signedInfo = first(parse(xml), NS_DS, "SignedInfo");
        signature.initSign(key);
        signature.update(canonicalize(XmlUtil.child(signedInfo, NS_DS, "CanonicalizationMethod").getAttribute("Algorithm"), signedInfo));
        xml = set(xml, "(<ds:SignatureValue[^>]*>)[^<]*(</ds:SignatureValue>)", base64(signature.sign()));

        byte[] imprint = sha256(canonicalize(XadesAlgorithms.C14N, first(parse(xml), NS_DS, "SignatureValue")));
        xml = set(xml, "(<xades:SignatureTimeStamp[^>]*><xades:EncapsulatedTimeStamp>)[^<]*(</xades:EncapsulatedTimeStamp>)",
            base64(TestCertificates.timestamp(imprint, tsaKey, tsaCertificate)));
        files.put(AsiceUtil.SIGNATURE_FILE, xml.getBytes(StandardCharsets.UTF_8));
        return files;
    }

    // Adds xades:CertificateValues (the root CA), xades:RevocationValues (a CRL of the root CA) and an
    // xadesv141:ArchiveTimeStamp signed with tokenKey. Without objects, the ds:Object elements are left out of the
    // time-stamped data, so the imprint is wrong.
    Map<String, byte[]> archive(Map<String, byte[]> files, String c14n, boolean withObjects, PrivateKey tokenKey) throws Exception {
        return archive(files, c14n, withObjects, tokenKey, SHA256, TSPAlgorithms.SHA256);
    }

    // As above, with the MessageImprint made by another hash function (digest: its MessageDigest name, digestOid: its OID).
    Map<String, byte[]> archive(Map<String, byte[]> files, String c14n, boolean withObjects, PrivateKey tokenKey, String digest,
        ASN1ObjectIdentifier digestOid) throws Exception {
        String xml = text(files.get(AsiceUtil.SIGNATURE_FILE)).replace("</xades:SignatureTimeStamp>", "</xades:SignatureTimeStamp>"
            + "<xades:CertificateValues Id=\"signatureIdCertificateValues\"><xades:EncapsulatedX509Certificate>" + base64(root.getEncoded())
            + "</xades:EncapsulatedX509Certificate></xades:CertificateValues>"
            + "<xades:RevocationValues Id=\"signatureIdRevocationValues\"><xades:CRLValues><xades:EncapsulatedCRLValue>"
            + base64(TestCertificates.crl(ROOT, rootKeys.getPrivate())) + "</xades:EncapsulatedCRLValue></xades:CRLValues></xades:RevocationValues>"
            + "<xadesv141:ArchiveTimeStamp xmlns:xadesv141=\"" + XadesConstants.NS_XADES_141 + "\" Id=\"signatureIdArchiveTimeStamp\">"
            + "<ds:CanonicalizationMethod Algorithm=\"" + c14n + "\"/><xades:EncapsulatedTimeStamp>AAAA</xades:EncapsulatedTimeStamp>"
            + "</xadesv141:ArchiveTimeStamp>");
        byte[] imprint = MessageDigest.getInstance(digest).digest(archiveInput(parse(xml), files, c14n, withObjects));
        xml = set(xml, "(<xadesv141:ArchiveTimeStamp[^>]*><ds:CanonicalizationMethod [^>]*/><xades:EncapsulatedTimeStamp>)[^<]*"
            + "(</xades:EncapsulatedTimeStamp>)", base64(TestCertificates.timestamp(digestOid, imprint, tokenKey, archiveTsa)));
        files.put(AsiceUtil.SIGNATURE_FILE, xml.getBytes(StandardCharsets.UTF_8));
        return files;
    }

    // Time-stamped data of xadesv141:ArchiveTimeStamp, written out step by step from ETSI TS 101 903 v1.4.2, clause 8.2.1.
    private static byte[] archiveInput(Document document, Map<String, byte[]> files, String c14n, boolean withObjects) throws Exception {
        Element signature = first(document, NS_DS, "Signature");
        Element signedInfo = XmlUtil.child(signature, NS_DS, "SignedInfo");
        ByteArrayOutputStream input = new ByteArrayOutputStream();
        // 2) Each ds:Reference after its transforms. The sample's same-document references end in a c14n transform; its
        // file reference has no transforms, so its octets are used as they are.
        for (Element reference : XmlUtil.children(signedInfo, NS_DS, "Reference")) {
            String uri = reference.getAttribute("URI");
            input.writeBytes(uri.startsWith(HASH) ? canonicalize(transform(reference), byId(document, uri.substring(1))) : files.get(uri));
        }
        // 3) ds:SignedInfo, ds:SignatureValue, ds:KeyInfo.
        input.writeBytes(canonicalize(c14n, signedInfo));
        input.writeBytes(canonicalize(c14n, XmlUtil.child(signature, NS_DS, "SignatureValue")));
        input.writeBytes(canonicalize(c14n, XmlUtil.child(signature, NS_DS, "KeyInfo")));
        // 4) The unsigned signature properties before the archive time-stamp.
        for (Element property : XmlUtil.children(first(document, NS_XADES, "UnsignedSignatureProperties"))) {
            if ("ArchiveTimeStamp".equals(property.getLocalName())) {
                break;
            }
            input.writeBytes(canonicalize(c14n, property));
        }
        // 5) Every ds:Object except the one with xades:QualifyingProperties.
        for (Element object : XmlUtil.children(signature, NS_DS, "Object")) {
            if (withObjects && XmlUtil.child(object, NS_XADES, "QualifyingProperties") == null) {
                input.writeBytes(canonicalize(c14n, object));
            }
        }
        return input.toByteArray();
    }

    private static String transform(Element reference) {
        return XmlUtil.first(reference, NS_DS, "Transform").getAttribute("Algorithm");
    }

    private static Element byId(Document document, String id) {
        return XmlUtil.descendants(document.getDocumentElement(), "*", "*").stream()
            .filter(element -> id.equals(element.getAttribute("Id")))
            .findFirst()
            .orElseThrow();
    }

    private static Element first(Document document, String ns, String localName) {
        return XmlUtil.first(document.getDocumentElement(), ns, localName);
    }

    private static byte[] canonicalize(String algorithm, Element element) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Canonicalizer.getInstance(algorithm).canonicalizeSubtree(element, out);
        return out.toByteArray();
    }

    private static String set(String xml, String regex, String value) {
        Matcher matcher = Pattern.compile(regex).matcher(xml);
        if (!matcher.find()) {
            throw new IllegalStateException("No match for " + regex);
        }
        return matcher.replaceAll("$1" + Matcher.quoteReplacement(value) + "$2");
    }

    private static Document parse(String xml) throws Exception {
        return XmlConverter.toDocument(xml.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance(SHA256).digest(data);
    }

    private static String base64(byte[] data) {
        return Base64Converter.encode(data);
    }

    private static String text(byte[] data) {
        return new String(data, StandardCharsets.UTF_8);
    }
}
