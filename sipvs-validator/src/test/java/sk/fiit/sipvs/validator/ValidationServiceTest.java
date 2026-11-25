package sk.fiit.sipvs.validator;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.security.auth.x500.X500Principal;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import com.sun.net.httpserver.HttpServer;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.apache.commons.lang3.function.FailableBiFunction;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.util.ReflectionTestUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import sk.fiit.sipvs.validator.clients.CrlClient;
import sk.fiit.sipvs.validator.converters.Base64Converter;
import sk.fiit.sipvs.validator.converters.CanonicalizationConverter;
import sk.fiit.sipvs.validator.converters.CertificateConverter;
import sk.fiit.sipvs.validator.converters.TimestampConverter;
import sk.fiit.sipvs.validator.converters.XmlConverter;
import sk.fiit.sipvs.validator.converters.XsltConverter;
import sk.fiit.sipvs.validator.dto.FileResult;
import sk.fiit.sipvs.validator.dto.Location;
import sk.fiit.sipvs.validator.enums.Detail;
import sk.fiit.sipvs.validator.enums.Mark;
import sk.fiit.sipvs.validator.enums.State;
import sk.fiit.sipvs.validator.exceptions.AttributeException;
import sk.fiit.sipvs.validator.services.ValidationService;
import sk.fiit.sipvs.validator.services.steps.CertificateTrustValidator;
import sk.fiit.sipvs.validator.utils.AsiceUtil;
import sk.fiit.sipvs.validator.utils.MessageUtil;
import sk.fiit.sipvs.validator.utils.PdfUtil;
import sk.fiit.sipvs.validator.utils.TrustAnchorUtil;
import sk.fiit.sipvs.validator.utils.XadesAlgorithms;
import sk.fiit.sipvs.validator.utils.XadesConstants;
import sk.fiit.sipvs.validator.utils.XmlUtil;

@SpringBootTest
class ValidationServiceTest {

    private static final String XHTML = "XHTML";
    private static final String DATA = "<a xmlns=\"urn:test\" Id=\"data\"><b>text</b></a>";
    private static final String XSD = "<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" targetNamespace=\"urn:test\" "
        + "elementFormDefault=\"qualified\"><xs:element name=\"a\"><xs:complexType><xs:sequence><xs:element name=\"b\" type=\"xs:string\"/>"
        + "</xs:sequence><xs:attribute name=\"Id\" type=\"xs:ID\"/></xs:complexType></xs:element></xs:schema>";
    private static final String HTML = "<html><body><p><xsl:value-of select=\"t:a/t:b\"/></p></body></html>";
    private static final String SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";
    private static final String PSS_SIGNER = "CN=Test PSS Signer,C=SK";
    private static final String PDF_METADATA = " /Metadata 3 0 R";
    private static final String PDFA_PART_1 = "<pdfaid:part>1</pdfaid:part>";
    // Calls itself twice per level, so n levels take 2^n calls. n = 31 runs about 20 s on a fast laptop, far over the 5 s limit.
    private static final String EXPONENTIAL_TEMPLATE = "<xsl:template name=\"r\"><xsl:param name=\"n\"/><xsl:if test=\"$n &gt; 0\">"
        + "<xsl:call-template name=\"r\"><xsl:with-param name=\"n\" select=\"$n - 1\"/></xsl:call-template>"
        + "<xsl:call-template name=\"r\"><xsl:with-param name=\"n\" select=\"$n - 1\"/></xsl:call-template></xsl:if></xsl:template>";
    // ZIP written by hand: a local header without the name and extra field, and the date 1980-01-01 in DOS format.
    private static final int LOCAL_HEADER_LENGTH = 30;
    private static final short DOS_DATE = 0x21;
    private static final UnaryOperator<String> SIGNING_TIME_AFTER_CERTIFICATE = xml -> xml.replaceFirst(
        "(?s)(<xades:SigningTime>[^<]*</xades:SigningTime>)(<xades:SigningCertificate>.*?</xades:SigningCertificate>)", "$2$1");

    @Autowired
    private ValidationService validationService;

    @Autowired
    private MessageUtil messages;

    @Autowired
    private CertificateTrustValidator certificateTrust;

    @MockitoSpyBean
    private CrlClient crlClient;

    @MockitoSpyBean
    private TrustAnchorUtil trustAnchor;

    private static TestSigner signer;

    @BeforeAll
    static void createSigner() throws Exception {
        signer = new TestSigner();
    }

    // Each test mocks its own CRL, so a CRL cached by an earlier test must not serve it.
    @BeforeEach
    void clearCrlCache() {
        certificateTrust.clearCrlCache();
    }

    static Stream<Arguments> samples() {
        return Stream.of(
            arguments("01X-T.asice", "xmlns:asic", State.NOT_CORRECT, "http://uri.etsi.org/02918/v2.1.2#"),
            arguments("02X-T.asice", "xzep:SignatureVersion", State.NOT_CORRECT, "xades_zepbp/v5.0"),
            arguments("03X-T.asice", "ds:SignatureMethod", State.NOT_CORRECT, "rsa-sha255"),
            arguments("04X-T.asice", "ds:CanonicalizationMethod", State.NOT_CORRECT, "REC-xml-c14n-20120315"),
            arguments("05X-T.asice", "ds:DigestValue", State.NOT_CORRECT, "#signatureIdSignatureProperties"),
            arguments("06X-T.asice", "ds:DigestValue", State.NOT_CORRECT, "KeyInfo"),
            arguments("07X-T.asice", "xmlns:ds", State.NOT_PROVIDED, "xmlns:ds"),
            arguments("08X-T.asice", "ds:SignatureValue/@Id", State.NOT_PROVIDED, "ds:SignatureValue nemá atribút Id"),
            arguments("09X-T.asice", "ds:X509IssuerSerial", State.NOT_CORRECT, "ds:X509SerialNumber je 2, certifikát má sériové číslo 1"),
            arguments("10X-T.asice", "ds:DigestValue", State.NOT_CORRECT, "object_0.txt"),
            arguments("11X-T.asice", "ds:Reference/@URI", State.NOT_CORRECT, "object_1.txt"),
            arguments("12X-T.asice", "MessageImprint", State.NOT_CORRECT, "MessageImprint časovej pečiatky je"),
            arguments("13X-T.asice", "ds:X509Certificate", State.NOT_CORRECT, "sériovým číslom 8 bol zrušený 2025-11-02")
        );
    }

    @ParameterizedTest(name = "{0} fails at {1}")
    @MethodSource("samples")
    void sampleFailsAtFirstWrongCheck(String sample, String attribute, State state, String expectedText)
        throws IOException {
        AttributeException exception = assertThrows(AttributeException.class,
            () -> validationService.validateSignature(container(sample, sampleBytes(sample))));

        String message = messages.error(exception);
        assertAll(
            () -> assertEquals(attribute, exception.getAttribute()),
            () -> assertEquals(state, exception.getState()),
            () -> assertFalse(message.contains("Krok"), message),
            () -> assertTrue(message.contains(expectedText), message)
        );
    }

    @Test
    void sample01MessageShowsFoundAndExpectedValue() throws IOException {
        AttributeException exception = assertThrows(AttributeException.class,
            () -> validationService.validateSignature(container("01X-T.asice", sampleBytes("01X-T.asice"))));

        assertEquals("xmlns:asic: nie je správny. Hodnota je http://uri.etsi.org/02918/v2.1.2#, "
            + "očakáva sa http://uri.etsi.org/02918/v1.2.1#.", messages.error(exception));
    }

    static Stream<Arguments> brokenSignatures() {
        return Stream.of(
            arguments("no ds:SignedInfo", (UnaryOperator<String>) xml -> xml.replaceAll("(?s)<ds:SignedInfo>.*</ds:SignedInfo>", ""),
                "ds:SignedInfo", State.NOT_PROVIDED),
            arguments("no ds:SignatureMethod", (UnaryOperator<String>) xml -> xml.replaceAll("<ds:SignatureMethod [^>]*/>", ""),
                "ds:SignatureMethod", State.NOT_PROVIDED),
            arguments("serial is not a number", (UnaryOperator<String>) xml -> xml.replaceFirst(
                    "<ds:X509SerialNumber>1</ds:X509SerialNumber>", "<ds:X509SerialNumber>abc</ds:X509SerialNumber>"),
                "ds:X509IssuerSerial", State.NOT_CORRECT),
            arguments("not well-formed XML", (UnaryOperator<String>) xml -> xml.replace("</asic:XAdESSignatures>", ""),
                AsiceUtil.SIGNATURE_FILE, State.NOT_CORRECT)
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("brokenSignatures")
    void brokenSignatureGivesAttributeError(String name, UnaryOperator<String> change, String attribute, State state)
        throws IOException {
        Map<String, byte[]> files = AsiceUtil.open(new ByteArrayInputStream(sampleBytes("10X-T.asice")));
        String xml = new String(files.get(AsiceUtil.SIGNATURE_FILE), StandardCharsets.UTF_8);
        files.put(AsiceUtil.SIGNATURE_FILE, change.apply(xml).getBytes(StandardCharsets.UTF_8));

        AttributeException exception = assertThrows(AttributeException.class,
            () -> validationService.validateSignature(container("broken.asice", zip(files))));

        assertAll(
            () -> assertEquals(attribute, exception.getAttribute()),
            () -> assertEquals(state, exception.getState())
        );
    }

    static Stream<Arguments> profileViolations() throws Exception {
        return Stream.of(
            arguments("duplicate Id", signature(xml -> xml.replace("Id=\"signatureIdSignatureValue\"", "Id=\"signatureIdKeyInfo\"")),
                "Id", Detail.DUPLICATE_ID),
            arguments("wrong root", signature(xml -> xml.replace("asic:XAdESSignatures", "asic:Signatures")),
                "asic:XAdESSignatures", Detail.WRONG_ROOT),
            arguments("encoding not UTF-8", signature(xml -> xml.replace("encoding=\"utf-8\"", "encoding=\"ISO-8859-1\"")),
                AsiceUtil.SIGNATURE_FILE, Detail.WRONG_ENCODING),
            arguments("wrong xades prefix", signature(xml -> xml.replaceAll("xades:SigningTime>", "x:SigningTime>")
                    .replace("<x:SigningTime>", "<x:SigningTime xmlns:x=\"http://uri.etsi.org/01903/v1.3.2#\">")),
                "xmlns:xades", Detail.WRONG_PREFIX),
            arguments("SHA-1 digest", signature(xml -> xml.replaceFirst("xmlenc#sha256", "xmldsig#sha1")),
                "ds:DigestMethod", Detail.UNSUPPORTED_ALGORITHM_IN_REFERENCE),
            arguments("reference without Id", signature(xml -> xml.replaceFirst(" Id=\"Reference_[^\"]*\"", "")),
                "ds:Reference/@Id", Detail.ATTRIBUTE_MISSING),
            arguments("digest not base64", signature(xml -> xml.replaceFirst("<ds:DigestValue>[^<]*<", "<ds:DigestValue>!!!<")),
                "ds:DigestValue", Detail.NOT_BASE64),
            arguments("extra element in ds:Signature", signature(xml -> xml.replace("</ds:Signature>", "<ds:Manifest/></ds:Signature>")),
                "ds:Manifest", Detail.ELEMENT_NOT_ALLOWED),
            arguments("no ProductVersion", signature(xml -> xml.replaceFirst("<xzep:ProductVersion>[^<]*</xzep:ProductVersion>", "")),
                "xzep:ProductVersion", Detail.ELEMENT_MISSING),
            arguments("wrong QualifyingProperties Target", signature(xml -> xml.replaceFirst(
                    "(<xades:QualifyingProperties[^>]*)Target=\"#signatureId\"", "$1Target=\"#other\"")),
                "xades:QualifyingProperties/@Target", Detail.QUALIFYING_PROPERTIES_TARGET),
            arguments("SigningTime not a date", signature(xml -> xml.replaceFirst("<xades:SigningTime>[^<]*<", "<xades:SigningTime>abc<")),
                "xades:SigningTime", Detail.SIGNING_TIME),
            arguments("SigningCertificate wrong serial", signature(xml -> xml.replaceFirst(
                    "<ds:X509SerialNumber>1</ds:X509SerialNumber></xades:IssuerSerial>",
                    "<ds:X509SerialNumber>2</ds:X509SerialNumber></xades:IssuerSerial>")),
                "xades:SigningCertificate", Detail.SIGNING_CERTIFICATE),
            arguments("Encoding in DataObjectFormat", signature(xml -> xml.replace("<xades:MimeType>text/plain",
                    "<xades:Encoding>x</xades:Encoding><xades:MimeType>text/plain")),
                "xades:Encoding", Detail.ENCODING_NOT_ALLOWED),
            arguments("data MimeType not allowed", signature(xml -> xml.replace("text/plain; charset=UTF-8</xades:MimeType>",
                    "text/html</xades:MimeType>")),
                "xades:MimeType", Detail.MIME_TYPE_NOT_ALLOWED),
            arguments("KeyInfo MimeType not application/xml", signature(xml -> xml.replaceFirst(
                    "<xades:MimeType>application/xml<", "<xades:MimeType>text/xml<")),
                "xades:MimeType", Detail.WRONG_VALUE),
            arguments("UnsignedDataObjectProperties", signature(xml -> xml.replace("<xades:UnsignedProperties>",
                    "<xades:UnsignedProperties><xades:UnsignedDataObjectProperties/>")),
                "xades:UnsignedDataObjectProperties", Detail.ELEMENT_NOT_ALLOWED),
            arguments("SignatureTimeStamp without Id", signature(xml -> xml.replace(" Id=\"signatureIdSignatureTimeStamp\"", "")),
                "xades:SignatureTimeStamp/@Id", Detail.ATTRIBUTE_MISSING),
            arguments("TXT not UTF-8", (UnaryOperator<Map<String, byte[]>>) files -> put(files, "object_0.txt", new byte[] {(byte) 0xC3, 0x28}),
                "object_0.txt", Detail.NOT_UTF8),
            arguments("TXT with control char", (UnaryOperator<Map<String, byte[]>>) files -> put(files, "object_0.txt",
                    "a\u0001b".getBytes(StandardCharsets.UTF_8)),
                "object_0.txt", Detail.INVALID_CHAR),
            arguments("manifest media-type", manifest(xml -> xml.replace("manifest:media-type=\"text/plain; charset=UTF-8\"",
                    "manifest:media-type=\"text/html\"")),
                AsiceUtil.MANIFEST_FILE, Detail.MANIFEST_MEDIA_TYPE),
            arguments("manifest extra entry", manifest(xml -> xml.replace("</manifest:manifest>",
                    "<manifest:file-entry manifest:full-path=\"extra.txt\" manifest:media-type=\"text/plain\" /></manifest:manifest>")),
                AsiceUtil.MANIFEST_FILE, Detail.MANIFEST_EXTRA_ENTRY),
            arguments("element without namespace", signature(xml -> xml.replace("</ds:Signature>", "<junk/></ds:Signature>")),
                "junk", Detail.ELEMENT_NOT_ALLOWED),
            arguments("timestamp wrapped in other element", signature(xml -> xml.replace("<xades:EncapsulatedTimeStamp>",
                    "<xades:Wrap><xades:EncapsulatedTimeStamp>").replace("</xades:EncapsulatedTimeStamp>",
                    "</xades:EncapsulatedTimeStamp></xades:Wrap>")),
                "xades:EncapsulatedTimeStamp", Detail.ELEMENT_MISSING),
            arguments("no UnsignedProperties", signature(xml -> xml.replaceAll(
                    "(?s)<xades:UnsignedProperties>.*</xades:UnsignedProperties>", "")),
                "xades:UnsignedProperties", Detail.ELEMENT_MISSING),
            arguments("default namespace instead of ds prefix", signature(xml -> xml.replace("<ds:KeyInfo Id=",
                    "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\" Id=").replace("</ds:KeyInfo>", "</KeyInfo>")),
                "xmlns:ds", Detail.NO_PREFIX),
            arguments("third ds:Object", signature(xml -> xml.replace("</ds:Signature>", "<ds:Object Id=\"extra\"/></ds:Signature>")),
                "ds:Object", Detail.OBJECT_COUNT),
            arguments("reference to ds:SignatureValue", signature(xml -> xml.replace("</ds:SignedInfo>",
                    "<ds:Reference Id=\"ReferenceValue\" URI=\"#signatureIdSignatureValue\"><ds:DigestMethod Algorithm=\""
                        + "http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo>")),
                "ds:Reference/@URI", Detail.REFERENCE_INTERNAL),
            arguments("two DataObjectFormat for one reference", signature(xml -> xml.replaceFirst(
                    "(<xades:DataObjectFormat ObjectReference=\"#ReferencesignatureIdKeyInfo\">.*?</xades:DataObjectFormat>)", "$1$1")),
                "xades:DataObjectFormat", Detail.DATA_OBJECT_FORMAT_COUNT),
            arguments("Description in KeyInfo DataObjectFormat", signature(xml -> xml.replace(
                    "<xades:DataObjectFormat ObjectReference=\"#ReferencesignatureIdKeyInfo\">",
                    "<xades:DataObjectFormat ObjectReference=\"#ReferencesignatureIdKeyInfo\"><xades:Description>x</xades:Description>")),
                "xades:DataObjectFormat", Detail.TRIVIAL_FORMAT_CONTENT),
            arguments("two SigningTime", signature(xml -> xml.replaceFirst("(<xades:SigningTime>[^<]*</xades:SigningTime>)", "$1$1")),
                "xades:SigningTime", Detail.ELEMENT_COUNT),
            arguments("two RevocationValues", unsignedProperties(
                    "<xades:RevocationValues Id=\"rv1\"/><xades:RevocationValues Id=\"rv2\"/>"),
                "xades:RevocationValues", Detail.ELEMENT_COUNT),
            arguments("xmlns:xzep not on ds:SignatureProperties", signature(xml -> xml.replace(" xmlns:xzep=\"" + XadesConstants.NS_XZEP + "\"", "")
                    .replace("<ds:Object><ds:SignatureProperties", "<ds:Object xmlns:xzep=\"" + XadesConstants.NS_XZEP + "\"><ds:SignatureProperties")),
                "xmlns:xzep", Detail.ATTRIBUTE_MISSING),
            arguments("xmlns:xades not on xades:QualifyingProperties", signature(xml -> xml.replace(
                    "<ds:Object><xades:QualifyingProperties xmlns:xades=\"" + XadesConstants.NS_XADES + "\"",
                    "<ds:Object xmlns:xades=\"" + XadesConstants.NS_XADES + "\"><xades:QualifyingProperties")),
                "xmlns:xades", Detail.ATTRIBUTE_MISSING),
            arguments("RSAPSSParams without dsm prefix", signature(xml -> xml.replaceFirst("(<ds:SignatureMethod [^>]*) />",
                    "$1><x:RSAPSSParams xmlns:x=\"" + XadesConstants.NS_DSM + "\"/></ds:SignatureMethod>")),
                "xmlns:dsm", Detail.WRONG_PREFIX),
            arguments("ArchiveTimeStamp without CanonicalizationMethod", unsignedProperties(
                    "<xades:CertificateValues Id=\"cv\"/><xades:RevocationValues Id=\"rv\"/><xadesv141:ArchiveTimeStamp xmlns:xadesv141=\""
                        + XadesConstants.NS_XADES_141 + "\" Id=\"ats\"><xades:EncapsulatedTimeStamp>AAAA</xades:EncapsulatedTimeStamp>"
                        + "</xadesv141:ArchiveTimeStamp>"),
                "ds:CanonicalizationMethod", Detail.ELEMENT_MISSING),
            arguments("signature file with letters in its name", (UnaryOperator<Map<String, byte[]>>) files -> put(files,
                    "META-INF/signaturesX.xml", files.get(AsiceUtil.SIGNATURE_FILE)),
                "META-INF/signaturesX.xml", Detail.SIGNATURE_FILE_NAME),
            arguments("manifest file-entry with manifest:size", manifest(xml -> xml.replace("manifest:full-path=\"object_0.txt\"",
                    "manifest:full-path=\"object_0.txt\" manifest:size=\"5\"")),
                AsiceUtil.MANIFEST_FILE, Detail.MANIFEST_ATTRIBUTE),
            arguments("ProductInfos without ProductInfo", signature(xml -> xml.replaceAll("(?s)<xzep:ProductInfos>.*</xzep:ProductInfos>",
                    "<xzep:ProductInfos></xzep:ProductInfos>")),
                "xzep:ProductInfo", Detail.ELEMENT_MISSING),
            arguments("xdc element with other prefix", dataObject(XadesConstants.MIME_XML_CONTAINER, xmlContainer("UTF-8",
                    "<xdc:XMLData><a/></xdc:XMLData><c:UsedSchemasEmbedded xmlns:c=\"" + XadesConstants.NS_XDC + "\"/>")),
                "object_0.txt", Detail.WRONG_PREFIX),
            arguments("XML container declared in ISO-8859-1", dataObject(XadesConstants.MIME_XML_CONTAINER, xmlContainer("ISO-8859-1",
                    "<xdc:XMLData><a/></xdc:XMLData>")),
                "object_0.txt", Detail.WRONG_ENCODING),
            arguments("Id in XML data same as in signature", dataObject(XadesConstants.MIME_XML_CONTAINER, xmlContainer("UTF-8",
                    "<xdc:XMLData><a Id=\"signatureId\"/></xdc:XMLData>")),
                "Id", Detail.DUPLICATE_ID),
            arguments("Id twice in XML data", dataObject(XadesConstants.MIME_XML_CONTAINER, xmlContainer("UTF-8",
                    "<xdc:XMLData><a Id=\"data\"><b Id=\"data\"/></a></xdc:XMLData>")),
                "Id", Detail.DUPLICATE_ID),
            arguments("PDF with signature dictionary", dataObject(XadesConstants.MIME_PDF, pdf("<</Type /Sig /ByteRange [0 1 2 3]>>")),
                "object_0.txt", Detail.NESTED_PDF_SIGNATURE),
            arguments("PNG header with other data", dataObject(XadesConstants.MIME_PNG,
                    new byte[] {(byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n', 1, 2, 3}),
                "object_0.txt", Detail.PNG_NOT_READABLE),
            arguments("policy identifier not an OID", signaturePolicy("policy-1", "http://www.w3.org/2001/04/xmlenc#sha256"),
                "xades:SigPolicyId", Detail.POLICY_NOT_OID),
            arguments("policy hash with SHA-1", signaturePolicy("urn:oid:1.2.3", "http://www.w3.org/2000/09/xmldsig#sha1"),
                "ds:DigestMethod", Detail.UNSUPPORTED_ALGORITHM),
            arguments("signing certificate in CertificateValues", signature(xml -> xml.replace("</xades:SignatureTimeStamp>",
                    "</xades:SignatureTimeStamp><xades:CertificateValues Id=\"cv\"><xades:EncapsulatedX509Certificate>"
                        + StringUtils.substringBetween(xml, "<ds:X509Certificate>", "</ds:X509Certificate>")
                        + "</xades:EncapsulatedX509Certificate></xades:CertificateValues>")),
                "xades:CertificateValues", Detail.SIGNING_CERTIFICATE_IN_VALUES),
            arguments("CertificateValues without issuer of signing certificate", unsignedProperties(
                    "<xades:CertificateValues Id=\"cv\"><xades:EncapsulatedX509Certificate>" + otherRootCertificate()
                        + "</xades:EncapsulatedX509Certificate></xades:CertificateValues>"),
                "xades:CertificateValues", Detail.CERTIFICATE_PATH_INCOMPLETE),
            arguments("EncapsulatedOCSPValue not OCSP", unsignedProperties("<xades:RevocationValues Id=\"rv\"><xades:OCSPValues>"
                    + "<xades:EncapsulatedOCSPValue>AAECAw==</xades:EncapsulatedOCSPValue></xades:OCSPValues></xades:RevocationValues>"),
                "xades:RevocationValues", Detail.OCSP_NOT_PARSED),
            arguments("EncapsulatedOCSPValue empty", unsignedProperties("<xades:RevocationValues Id=\"rv\"><xades:OCSPValues>"
                    + "<xades:EncapsulatedOCSPValue></xades:EncapsulatedOCSPValue></xades:OCSPValues></xades:RevocationValues>"),
                "xades:RevocationValues", Detail.EMPTY_VALUE),
            arguments("EncapsulatedOCSPValue not base64", unsignedProperties("<xades:RevocationValues Id=\"rv\"><xades:OCSPValues>"
                    + "<xades:EncapsulatedOCSPValue>!!!</xades:EncapsulatedOCSPValue></xades:OCSPValues></xades:RevocationValues>"),
                "xades:RevocationValues", Detail.NOT_BASE64),
            arguments("EncapsulatedCRLValue not CRL", unsignedProperties("<xades:RevocationValues Id=\"rv\"><xades:CRLValues>"
                    + "<xades:EncapsulatedCRLValue>AAECAw==</xades:EncapsulatedCRLValue></xades:CRLValues></xades:RevocationValues>"),
                "xades:RevocationValues", Detail.CRL_NOT_PARSED),
            arguments("EncapsulatedCRLValue empty", unsignedProperties("<xades:RevocationValues Id=\"rv\"><xades:CRLValues>"
                    + "<xades:EncapsulatedCRLValue></xades:EncapsulatedCRLValue></xades:CRLValues></xades:RevocationValues>"),
                "xades:RevocationValues", Detail.EMPTY_VALUE),
            arguments("EncapsulatedCRLValue not base64", unsignedProperties("<xades:RevocationValues Id=\"rv\"><xades:CRLValues>"
                    + "<xades:EncapsulatedCRLValue>!!!</xades:EncapsulatedCRLValue></xades:CRLValues></xades:RevocationValues>"),
                "xades:RevocationValues", Detail.NOT_BASE64),
            arguments("SigningTime after SigningCertificate", signature(SIGNING_TIME_AFTER_CERTIFICATE),
                "xades:SigningTime", Detail.SCHEMA_INVALID),
            arguments("XMLData not valid against embedded XSD", xmlDataObject(xdc("<a xmlns=\"urn:test\"><c/></a>", XSD, XHTML)),
                "xdc:XMLData", Detail.XML_DATA_INVALID),
            arguments("two elements in XMLData", xmlDataObject(xdc(DATA + "<a xmlns=\"urn:test\"><b>x</b></a>", XSD, XHTML)),
                "xdc:XMLData", Detail.EMBEDDED_CONTENT),
            arguments("XML data as escaped text", xmlDataObject(xdc("&lt;a xmlns=\"urn:test\"/&gt;", XSD, XHTML)),
                "xdc:XMLData", Detail.EMBEDDED_CONTENT),
            arguments("XML declaration inside XMLData", xmlDataObject(xdc("<?xml version=\"1.0\"?>" + DATA, XSD, XHTML)),
                "object_0.txt", Detail.XML_NOT_WELL_FORMED),
            arguments("schemas only referenced", xmlDataObject("<xdc:XMLData>" + DATA + "</xdc:XMLData><xdc:UsedSchemasReferenced>"
                    + "<xdc:UsedXSDReference>http://example.com/form.xsd</xdc:UsedXSDReference><xdc:UsedPresentationSchemaReference "
                    + "ContentType=\"application/xslt+xml\" MediaDestinationTypeDescription=\"HTML\">http://example.com/form.xslt"
                    + "</xdc:UsedPresentationSchemaReference></xdc:UsedSchemasReferenced>"),
                "xdc:UsedXSDEmbedded", Detail.SCHEMA_NOT_EMBEDDED),
            arguments("no presentation schema", xmlDataObject("<xdc:XMLData>" + DATA + "</xdc:XMLData><xdc:UsedSchemasEmbedded>"
                    + "<xdc:UsedXSDEmbedded>" + XSD + "</xdc:UsedXSDEmbedded></xdc:UsedSchemasEmbedded>"),
                "xdc:UsedPresentationSchemaEmbedded", Detail.SCHEMA_NOT_EMBEDDED),
            arguments("XSD imports a schema over http", xmlDataObject(xdc(DATA, XSD.replace("elementFormDefault=\"qualified\">",
                    "elementFormDefault=\"qualified\"><xs:import namespace=\"urn:other\" schemaLocation=\"http://example.invalid/o.xsd\"/>"),
                    XHTML)),
                "xdc:UsedXSDEmbedded", Detail.XSD_NOT_COMPILED),
            arguments("media destination PDF", xmlDataObject(xdc(DATA, XSD, "PDF", xslt("html", HTML))),
                "MediaDestinationTypeDescription", Detail.WRONG_VALUE),
            arguments("no media destination", xmlDataObject(xdc(DATA, XSD, null, xslt("html", HTML))),
                "MediaDestinationTypeDescription", Detail.ATTRIBUTE_MISSING),
            arguments("XSLT with xsl:import of an http URL", xmlDataObject(xdc(DATA, XSD, "HTML",
                    xslt("html", HTML).replace("<xsl:output", "<xsl:import href=\"http://example.invalid/a.xsl\"/><xsl:output"))),
                "xsl:import", Detail.XSLT_EXTERNAL_REFERENCE),
            arguments("XSLT with xsl:include", xmlDataObject(xdc(DATA, XSD, "HTML",
                    xslt("html", HTML).replace("<xsl:output", "<xsl:include href=\"common.xsl\"/><xsl:output"))),
                "xsl:include", Detail.XSLT_EXTERNAL_REFERENCE),
            arguments("XSLT reads another document", xmlDataObject(xdc(DATA, XSD, "HTML",
                    xslt("html", "<p><xsl:value-of select=\"document('file:///etc/hosts')\"/></p>"))),
                "xdc:UsedPresentationSchemaEmbedded", Detail.XSLT_EXTERNAL_REFERENCE),
            arguments("XSLT calls a Java extension function", xmlDataObject(xdc(DATA, XSD, "HTML",
                    xslt("html", "<p xmlns:rt=\"http://xml.apache.org/xalan/java/java.lang.Runtime\"><xsl:value-of select=\"rt:getRuntime()\"/></p>"))),
                "xdc:UsedPresentationSchemaEmbedded", Detail.XSLT_FAILED),
            arguments("XSLT recurses forever", xmlDataObject(xdc(DATA, XSD, "HTML",
                    xslt("html", "<xsl:call-template name=\"loop\"/>", "<xsl:template name=\"loop\"><xsl:call-template name=\"loop\"/></xsl:template>"))),
                "xdc:UsedPresentationSchemaEmbedded", Detail.XSLT_FAILED),
            arguments("XSLT output too large", xmlDataObject(xdc(DATA, XSD, "TXT", xslt("text", "<xsl:call-template name=\"r\">"
                    + "<xsl:with-param name=\"n\" select=\"100000\"/></xsl:call-template>", "<xsl:template name=\"r\"><xsl:param name=\"n\"/>"
                    + "<xsl:choose><xsl:when test=\"$n &gt; 1\"><xsl:call-template name=\"r\"><xsl:with-param name=\"n\" select=\"floor($n div 2)\"/>"
                    + "</xsl:call-template><xsl:call-template name=\"r\"><xsl:with-param name=\"n\" select=\"$n - floor($n div 2)\"/>"
                    + "</xsl:call-template></xsl:when><xsl:otherwise>" + "0123456789".repeat(10) + "</xsl:otherwise></xsl:choose></xsl:template>"))),
                "xdc:UsedPresentationSchemaEmbedded", Detail.XSLT_OUTPUT_TOO_LARGE),
            arguments("script element in HTML output", xmlDataObject(xdc(DATA, XSD, "HTML",
                    xslt("html", "<html><body><script>alert(1)</script></body></html>"))),
                "xdc:UsedPresentationSchemaEmbedded", Detail.FORBIDDEN_HTML_TAG),
            arguments("link created with xsl:element in XHTML output", xmlDataObject(xdc(DATA, XSD, XHTML,
                    xslt("xml", "<html><head><xsl:element name=\"link\"><xsl:attribute name=\"href\">a.css</xsl:attribute></xsl:element></head></html>"))),
                "xdc:UsedPresentationSchemaEmbedded", Detail.FORBIDDEN_HTML_TAG),
            arguments("script written with disable-output-escaping", xmlDataObject(xdc(DATA, XSD, "HTML",
                    xslt("html", "<p><xsl:text disable-output-escaping=\"yes\">&lt;script&gt;alert(1)&lt;/script&gt;</xsl:text></p>"))),
                "xdc:UsedPresentationSchemaEmbedded", Detail.FORBIDDEN_HTML_TAG),
            arguments("control character in TXT output", dataObject(XadesConstants.MIME_XML_CONTAINER, text(xmlContainer("UTF-8",
                    xdc("<a xmlns=\"urn:test\"><b>x&#1;y</b></a>", XSD, "TXT", xslt("text", "<xsl:value-of select=\"t:a/t:b\"/>"))))
                    .replaceFirst("<\\?xml version=\"1.0\"", "<?xml version=\"1.1\"").getBytes(StandardCharsets.UTF_8)),
                "xdc:UsedPresentationSchemaEmbedded", Detail.XSLT_OUTPUT_INVALID_CHAR),
            arguments("RSAPSSParams with SHA-1", signatureMethod(pssMethod(SHA1, XadesAlgorithms.SHA256, 32)),
                "ds:DigestMethod", Detail.UNSUPPORTED_ALGORITHM),
            arguments("MGF1 with SHA-1", signatureMethod(pssMethod(XadesAlgorithms.SHA256, SHA1, 32)),
                "ds:DigestMethod", Detail.UNSUPPORTED_ALGORITHM),
            arguments("mask generation function other than MGF1", signatureMethod(pssMethod(XadesAlgorithms.SHA256, XadesAlgorithms.SHA256, 32)
                    .replace("#MGF1\"", "#MGF2\"")),
                "dsm:MaskGenerationFunction", Detail.UNSUPPORTED_ALGORITHM),
            arguments("SaltLength not a number", signatureMethod(pssMethod(XadesAlgorithms.SHA256, XadesAlgorithms.SHA256, 32)
                    .replace(">32<", ">abc<")),
                "dsm:SaltLength", Detail.SCHEMA_INVALID),
            arguments("PNG larger than the pixel limit", dataObject(XadesConstants.MIME_PNG, DataObjectUtilTest.pngHeader(46000, 46000)),
                "object_0.txt", Detail.PNG_TOO_LARGE),
            arguments("PNG that takes more memory than the limit when decoded", dataObject(XadesConstants.MIME_PNG,
                    DataObjectUtilTest.pngHeader(7000, 7000, 16, 6)),
                "object_0.txt", Detail.PNG_DECODED_TOO_LARGE),
            arguments("XML container larger than the XML limit", dataObject(XadesConstants.MIME_XML_CONTAINER, xmlContainer("UTF-8",
                    "<xdc:XMLData><a>" + "x".repeat(XmlConverter.MAX_SIZE) + "</a></xdc:XMLData>")),
                "object_0.txt", Detail.XML_TOO_LARGE),
            arguments("XSLT that runs too long", xmlDataObject(xdc(DATA, XSD, "TXT", xslt("text", "<xsl:call-template name=\"r\">"
                    + "<xsl:with-param name=\"n\" select=\"31\"/></xsl:call-template>", EXPONENTIAL_TEMPLATE))),
                "xdc:UsedPresentationSchemaEmbedded", Detail.XSLT_TIMEOUT),
            arguments("XML container nested 20000 levels deep", dataObject(XadesConstants.MIME_XML_CONTAINER, xmlContainer("UTF-8",
                    "<xdc:XMLData>" + "<a>".repeat(20000) + "</a>".repeat(20000) + "</xdc:XMLData>")),
                "object_0.txt", Detail.XML_NOT_WELL_FORMED),
            arguments("two manifest:file-entry elements for one file", manifest(xml -> xml.replace("</manifest:manifest>",
                    "<manifest:file-entry manifest:full-path=\"object_0.txt\" manifest:media-type=\"text/plain; charset=UTF-8\"/>"
                    + "</manifest:manifest>")),
                AsiceUtil.MANIFEST_FILE, Detail.MANIFEST_DUPLICATE_ENTRY),
            arguments("mimetype with a trailing newline", (UnaryOperator<Map<String, byte[]>>) files -> put(files, AsiceUtil.MIMETYPE_FILE,
                    (AsiceUtil.MIMETYPE + "\n").getBytes(StandardCharsets.US_ASCII)),
                AsiceUtil.MIMETYPE_FILE, Detail.MIMETYPE_NOT_EXACT),
            arguments("xades:Include in SignatureTimeStamp", signature(xml -> xml.replace("<xades:EncapsulatedTimeStamp>",
                    "<xades:Include URI=\"#signatureIdSignatureValue\"/><xades:EncapsulatedTimeStamp>")),
                "xades:Include", Detail.TIMESTAMP_CHILD_NOT_ALLOWED),
            arguments("xades:XMLTimeStamp in SignatureTimeStamp", signature(xml -> xml.replace("</xades:EncapsulatedTimeStamp>",
                    "</xades:EncapsulatedTimeStamp><xades:XMLTimeStamp/>")),
                "xades:XMLTimeStamp", Detail.TIMESTAMP_CHILD_NOT_ALLOWED),
            arguments("two EncapsulatedTimeStamp in SignatureTimeStamp", signature(xml -> xml.replace("</xades:EncapsulatedTimeStamp>",
                    "</xades:EncapsulatedTimeStamp><xades:EncapsulatedTimeStamp>AAAA</xades:EncapsulatedTimeStamp>")),
                "xades:EncapsulatedTimeStamp", Detail.TIMESTAMP_TOKEN_COUNT),
            arguments("ProductVersion before ProductName", signature(xml -> xml.replaceFirst(
                    "(<xzep:ProductName>[^<]*</xzep:ProductName>)(<xzep:ProductVersion>[^<]*</xzep:ProductVersion>)", "$2$1")),
                "xzep:ProductVersion", Detail.XZEP_SCHEMA_INVALID),
            arguments("extra element in ProductInfo", signature(xml -> xml.replaceFirst("</xzep:ProductVersion>",
                    "$0<xzep:Vendor>x</xzep:Vendor>")),
                "xzep:Vendor", Detail.XZEP_SCHEMA_INVALID),
            arguments("RevocationValues without data for the signing certificate", unsignedProperties("<xades:RevocationValues Id=\"rv\"/>"),
                "xades:RevocationValues", Detail.REVOCATION_VALUES_INCOMPLETE),
            arguments("CRL with the issuer name, signed by another key", unsignedProperties("<xades:RevocationValues Id=\"rv\"><xades:CRLValues>"
                    + "<xades:EncapsulatedCRLValue>" + forgedIssuerCrl() + "</xades:EncapsulatedCRLValue></xades:CRLValues></xades:RevocationValues>"),
                "xades:RevocationValues", Detail.REVOCATION_VALUES_INCOMPLETE),
            arguments("OCSP response for another certificate", unsignedProperties("<xades:RevocationValues Id=\"rv\"><xades:OCSPValues>"
                    + "<xades:EncapsulatedOCSPValue>" + otherOcspResponse() + "</xades:EncapsulatedOCSPValue></xades:OCSPValues></xades:RevocationValues>"),
                "xades:RevocationValues", Detail.REVOCATION_VALUES_INCOMPLETE),
            arguments("PDF/A part 2", dataObject(XadesConstants.MIME_PDF, pdf(PDF_METADATA, "", "", "<pdfaid:part>2</pdfaid:part>", "<<>>")),
                "object_0.txt", Detail.PDFA_PART),
            arguments("pdfaid:part only outside the catalog", dataObject(XadesConstants.MIME_PDF, pdf("", "", "", PDFA_PART_1,
                    "<</Note (pdfaid:part)>>")),
                "object_0.txt", Detail.PDF_METADATA_MISSING),
            arguments("XMP metadata with a filter", dataObject(XadesConstants.MIME_PDF, pdf(PDF_METADATA, " /Filter /FlateDecode", "",
                    PDFA_PART_1, "<<>>")),
                "object_0.txt", Detail.PDF_METADATA_FILTERED),
            arguments("XMP metadata without pdfaid:part", dataObject(XadesConstants.MIME_PDF, pdf(PDF_METADATA, "", "", "", "<<>>")),
                "object_0.txt", Detail.NOT_PDFA),
            arguments("XMP metadata not well-formed", dataObject(XadesConstants.MIME_PDF, pdf(PDF_METADATA, "", "", "<pdfaid:part>1",
                    "<<>>")),
                "object_0.txt", Detail.PDF_METADATA_NOT_XML),
            arguments("manifest declared in ISO-8859-1", manifest(xml -> xml.replace("encoding=\"utf-8\"", "encoding=\"ISO-8859-1\"")),
                AsiceUtil.MANIFEST_FILE, Detail.WRONG_ENCODING),
            arguments("manifest in UTF-16 without declaration", (UnaryOperator<Map<String, byte[]>>) files -> put(files, AsiceUtil.MANIFEST_FILE,
                    text(files.get(AsiceUtil.MANIFEST_FILE)).replaceFirst("<\\?xml[^>]*\\?>", "").getBytes(StandardCharsets.UTF_16)),
                AsiceUtil.MANIFEST_FILE, Detail.NOT_UTF8)
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("profileViolations")
    void profileRuleViolationIsReported(String name, UnaryOperator<Map<String, byte[]>> change, String attribute,
        Detail detail) throws IOException {
        Map<String, byte[]> files = change.apply(AsiceUtil.open(new ByteArrayInputStream(sampleBytes("10X-T.asice"))));

        AttributeException exception = assertThrows(AttributeException.class,
            () -> validationService.validateSignature(container("broken.asice", zip(files))));

        assertAll(
            () -> assertEquals(attribute, exception.getAttribute(), messages.error(exception)),
            () -> assertEquals(detail, exception.getDetail(), messages.error(exception))
        );
    }

    static Stream<Arguments> profileValidEdits() throws Exception {
        String issuerName = signingCertificate("10X-T.asice").getIssuerX500Principal().getName();
        return Stream.of(
            arguments("XML container with XHTML presentation", dataObject(XadesConstants.MIME_XML_CONTAINER, xmlContainer("utf-8",
                xdc(DATA, XSD, XHTML)))),
            arguments("XML container with HTML and TXT presentation", xmlDataObject(xdc(DATA, XSD, "HTML", xslt("html", HTML))
                .replace("</xdc:UsedSchemasEmbedded>", presentation("TXT", xslt("text", "<xsl:value-of select=\"t:a/t:b\"/>"))
                    + "</xdc:UsedSchemasEmbedded>"))),
            arguments("PNG", dataObject(XadesConstants.MIME_PNG, DataObjectUtilTest.png())),
            arguments("PDF/A with signature field lock", dataObject(XadesConstants.MIME_PDF, pdf("<</Type /SigFieldLock /Action /All>>"))),
            arguments("PDF/A with pdfaid:part as an attribute", dataObject(XadesConstants.MIME_PDF, pdf(PDF_METADATA, "",
                " pdfaid:part=\"1\"", "", "<<>>"))),
            arguments("policy OID", signaturePolicy("1.2.840.113549", "http://www.w3.org/2001/04/xmlenc#sha256")),
            arguments("policy OID as URN", signaturePolicy("urn:oid:1.3.158.36061701.1.2.2", "http://www.w3.org/2001/04/xmlenc#sha256")),
            arguments("OCSP response", unsignedProperties("<xades:RevocationValues Id=\"rv\"><xades:OCSPValues><xades:EncapsulatedOCSPValue>"
                + ocspResponse() + "</xades:EncapsulatedOCSPValue></xades:OCSPValues></xades:RevocationValues>")),
            arguments("X509IssuerName as X500Principal.getName(), 2.5.4.97 written as #hex", signature(xml -> xml.replaceAll(
                "(<ds:X509IssuerName>)[^<]*", "$1" + Matcher.quoteReplacement(issuerName)))),
            arguments("X509SerialNumber 01 in both places", signature(xml -> xml.replace("<ds:X509SerialNumber>1<",
                "<ds:X509SerialNumber>01<"))),
            arguments("file name with a space, percent-encoded in the URI", renamedFile("object_0.txt", "my zmluva.pdf", "my%20zmluva.pdf"))
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("profileValidEdits")
    void profileValidEditReachesCoreValidation(String name, UnaryOperator<Map<String, byte[]>> change) throws Exception {
        doReturn(crlWithoutRevocations(signingCertificate("10X-T.asice").getIssuerX500Principal())).when(crlClient).download(any());
        Map<String, byte[]> files = change.apply(AsiceUtil.open(new ByteArrayInputStream(sampleBytes("10X-T.asice"))));

        AttributeException exception = assertThrows(AttributeException.class,
            () -> validationService.validateSignature(container("edited.asice", zip(files))));

        assertAll(
            () -> assertEquals(Detail.DIGEST_MISMATCH, exception.getDetail(), messages.error(exception))
        );
    }

    @Test
    void manifestExtraEntryMarksItsPath() throws Exception {
        Map<String, byte[]> files = manifest(xml -> xml.replace("</manifest:manifest>",
            "<manifest:file-entry manifest:full-path=\"extra.txt\" manifest:media-type=\"text/plain\" /></manifest:manifest>"))
            .apply(AsiceUtil.open(new ByteArrayInputStream(sampleBytes("10X-T.asice"))));

        AttributeException exception = assertThrows(AttributeException.class,
            () -> validationService.validateSignature(container("broken.asice", zip(files))));

        assertAll(
            () -> assertEquals(Detail.MANIFEST_EXTRA_ENTRY, exception.getDetail(), messages.error(exception)),
            () -> assertEquals(AsiceUtil.MANIFEST_FILE, exception.getFile()),
            () -> assertEquals("manifest:full-path", exception.getNode() == null ? null : exception.getNode().getNodeName()),
            () -> assertEquals("extra.txt", exception.getNode() == null ? null : exception.getNode().getNodeValue())
        );
    }

    // XML Signature applies the transforms one after another. The SignedProperties reference gets exc-c14n before its
    // c14n and a DigestValue over that chain, so it is correct and the first wrong digest is the one of object_0.txt.
    @Test
    void referenceTransformsAreAppliedInOrder() throws Exception {
        doReturn(crlWithoutRevocations(signingCertificate("10X-T.asice").getIssuerX500Principal())).when(crlClient).download(any());
        Map<String, byte[]> files = AsiceUtil.open(new ByteArrayInputStream(sampleBytes("10X-T.asice")));
        String xml = text(files.get(AsiceUtil.SIGNATURE_FILE));
        Element signedProperties = XmlUtil.descendants(XmlConverter.toDocument(files.get(AsiceUtil.SIGNATURE_FILE)).getDocumentElement(),
                XadesConstants.NS_XADES, "SignedProperties").get(0);
        byte[] chained = CanonicalizationConverter.canonicalize(XadesAlgorithms.C14N,
            CanonicalizationConverter.canonicalize(XadesAlgorithms.EXC_C14N, signedProperties));
        String transforms = "<ds:Transforms><ds:Transform Algorithm=\"" + XadesAlgorithms.C14N + "\" /></ds:Transforms>";
        String edited = xml
            .replaceFirst(Pattern.quote(transforms), Matcher.quoteReplacement("<ds:Transforms><ds:Transform Algorithm=\""
                + XadesAlgorithms.EXC_C14N + "\" /><ds:Transform Algorithm=\"" + XadesAlgorithms.C14N + "\" /></ds:Transforms>"))
            .replace("yatXkf334FScMXu8PbKpdpESjLPekyLwIrV86+fkiWA=",
                Base64Converter.encode(MessageDigest.getInstance("SHA-256").digest(chained)));
        put(files, AsiceUtil.SIGNATURE_FILE, edited.getBytes(StandardCharsets.UTF_8));

        AttributeException exception = assertThrows(AttributeException.class,
            () -> validationService.validateSignature(container("chained.asice", zip(files))));

        Element reference = (Element) exception.getNode().getParentNode().getParentNode();
        assertAll(
            () -> assertEquals(Detail.DIGEST_MISMATCH, exception.getDetail(), messages.error(exception)),
            () -> assertEquals("object_0.txt", reference.getAttribute("URI"), messages.error(exception))
        );
    }

    @Test
    void validContainerPassesAllSteps() throws Exception {
        doReturn(crlWithoutRevocations(signingCertificate("13X-T.asice").getIssuerX500Principal())).when(crlClient).download(any());

        List<FileResult> results = validationService.validate(List.of(container("13X-T.asice", sampleBytes("13X-T.asice"))));

        assertNull(results.get(0).error(), results.get(0).error());
    }

    @Test
    void containerSignedWithGeneratedKeysPassesAllSteps() throws Exception {
        assertValid(signer.sign());
    }

    @ParameterizedTest
    @ValueSource(strings = {XadesAlgorithms.C14N, XadesAlgorithms.C14N_11, XadesAlgorithms.EXC_C14N})
    void archiveTimeStampWithCorrectImprintPasses(String c14n) throws Exception {
        assertValid(signer.archive(signer.sign(), c14n, true, signer.archiveTsaKeys.getPrivate()));
    }

    @Test
    void archiveTimeStampWithoutObjectsInImprintFails() throws Exception {
        Map<String, byte[]> files = signer.archive(signer.sign(), XadesAlgorithms.EXC_C14N, false, signer.archiveTsaKeys.getPrivate());

        assertArchiveTimeStampFails(files, crlWithoutRevocations(signer.root.getSubjectX500Principal()), Detail.ARCHIVE_MESSAGE_IMPRINT);
    }

    @Test
    void archiveTimeStampWithTamperedSignatureFails() throws Exception {
        Map<String, byte[]> files = signer.archive(signer.sign(), XadesAlgorithms.EXC_C14N, true, TestCertificates.keyPair().getPrivate());

        assertArchiveTimeStampFails(files, crlWithoutRevocations(signer.root.getSubjectX500Principal()), Detail.TIMESTAMP_SIGNATURE);
    }

    @Test
    void archiveTimeStampWithRevokedTsaCertificateFails() throws Exception {
        Map<String, byte[]> files = signer.archive(signer.sign(), XadesAlgorithms.EXC_C14N, true, signer.archiveTsaKeys.getPrivate());
        X509CRL crl = crlWithoutRevocations(signer.root.getSubjectX500Principal());
        X509CRLEntry entry = mock(X509CRLEntry.class);
        when(entry.getRevocationDate()).thenReturn(new Date());
        when(crl.getRevokedCertificate(signer.archiveTsa)).thenReturn(entry);

        assertArchiveTimeStampFails(files, crl, Detail.CERTIFICATE_REVOKED);
    }

    // Profile 4.5 for the archive token too: a correct SHA-1 imprint is still rejected.
    @Test
    void archiveTimeStampWithSha1ImprintFails() throws Exception {
        Map<String, byte[]> files = signer.archive(signer.sign(), XadesAlgorithms.EXC_C14N, true, signer.archiveTsaKeys.getPrivate(), "SHA-1",
            TSPAlgorithms.SHA1);

        assertArchiveTimeStampFails(files, crlWithoutRevocations(signer.root.getSubjectX500Principal()), Detail.TIMESTAMP_DIGEST_NOT_ALLOWED);
    }

    @Test
    void archiveTimeStampThatIsNotATokenFails() throws Exception {
        Map<String, byte[]> files = signer.archive(signer.sign(), XadesAlgorithms.EXC_C14N, true, signer.archiveTsaKeys.getPrivate());
        files.put(AsiceUtil.SIGNATURE_FILE, text(files.get(AsiceUtil.SIGNATURE_FILE)).replaceFirst(
            "(<xadesv141:ArchiveTimeStamp[^>]*><ds:CanonicalizationMethod [^>]*/><xades:EncapsulatedTimeStamp>)[^<]*", "$1AAAA")
            .getBytes(StandardCharsets.UTF_8));

        assertArchiveTimeStampFails(files, crlWithoutRevocations(signer.root.getSubjectX500Principal()), Detail.TIMESTAMP_NOT_PARSED);
    }

    // RFC 3161 2.3 for the archive token too: the signing certificate has no extended key usage.
    @Test
    void archiveTimeStampFromCertificateWithoutTimeStampingUsageFails() throws Exception {
        Map<String, byte[]> files = timeStampFromSigningCertificate(signer.archive(signer.sign(), XadesAlgorithms.EXC_C14N, true,
            signer.archiveTsaKeys.getPrivate()), "(<xadesv141:ArchiveTimeStamp[^>]*><ds:CanonicalizationMethod [^>]*/><xades:EncapsulatedTimeStamp>)");

        assertArchiveTimeStampFails(files, crlWithoutRevocations(signer.root.getSubjectX500Principal()), Detail.TSA_EXTENDED_KEY_USAGE);
    }

    // TimeStampToken.validate(): the TSA certificate must be valid at the time-stamp time. This token claims a time before
    // the certificate was issued.
    @Test
    void archiveTimeStampFromBeforeTsaCertificateFails() throws Exception {
        Date beforeCertificate = Date.from(signer.archiveTsa.getNotBefore().toInstant().minus(Duration.ofDays(1)));
        Map<String, byte[]> files = replaceTimeStamp(signer.archive(signer.sign(), XadesAlgorithms.EXC_C14N, true,
            signer.archiveTsaKeys.getPrivate()), "(<xadesv141:ArchiveTimeStamp[^>]*><ds:CanonicalizationMethod [^>]*/><xades:EncapsulatedTimeStamp>)",
            (algorithm, digest) -> TestCertificates.timestamp(algorithm, digest, signer.archiveTsaKeys.getPrivate(), signer.archiveTsa,
                beforeCertificate));

        assertArchiveTimeStampFails(files, crlWithoutRevocations(signer.root.getSubjectX500Principal()), Detail.TIMESTAMP_SIGNATURE);
    }

    // Profile 4.4.5.5: xadesv141:TimeStampValidationData is supported (here empty, which the XAdES 1.4.1 schema allows).
    @Test
    void timeStampValidationDataIsAllowed() throws Exception {
        Map<String, byte[]> files = signer.sign();
        files.put(AsiceUtil.SIGNATURE_FILE, text(files.get(AsiceUtil.SIGNATURE_FILE)).replaceFirst("</xades:SignatureTimeStamp>",
            "$0<xadesv141:TimeStampValidationData xmlns:xadesv141=\"" + XadesConstants.NS_XADES_141 + "\" Id=\"validationData\"/>")
            .getBytes(StandardCharsets.UTF_8));

        assertValid(files);
    }

    // The error is reported for the archive time-stamp and marks its token, not the xades:SignatureTimeStamp.
    private void assertArchiveTimeStampFails(Map<String, byte[]> files, X509CRL crl, Detail detail) throws Exception {
        doReturn(crl).when(crlClient).download(any());
        trustGeneratedRoot();

        AttributeException exception = assertThrows(AttributeException.class,
            () -> validationService.validateSignature(container("archive.asice", zip(files))));

        Node node = exception.getNode();
        while (node != null && !"ArchiveTimeStamp".equals(node.getLocalName())) {
            node = node.getParentNode();
        }
        Node archive = node;
        assertAll(
            () -> assertEquals("xadesv141:ArchiveTimeStamp", exception.getAttribute(), messages.error(exception)),
            () -> assertEquals(detail, exception.getDetail(), messages.error(exception)),
            () -> assertNotNull(archive, "the error does not mark the xadesv141:ArchiveTimeStamp")
        );
    }

    @Test
    void pssSignatureWithRsaEncryptionCertificatePasses() throws Exception {
        assertValid(signer.sign(signer.signerKeys.getPrivate(), signer.signer, pssMethod(XadesAlgorithms.SHA512, XadesAlgorithms.SHA384, 40),
            pss(XadesAlgorithms.SHA512, XadesAlgorithms.SHA384, 40)));
    }

    // Certificate parameters (hash, MGF1 hash, minimum salt length; null hash = RSASSA-PSS key without parameters) and the
    // RSAPSSParams of the signature.
    static Stream<Arguments> suitablePssParameters() {
        return Stream.of(
            arguments("same parameters", NISTObjectIdentifiers.id_sha256, NISTObjectIdentifiers.id_sha256, 32,
                XadesAlgorithms.SHA256, XadesAlgorithms.SHA256, 32),
            arguments("longer salt than the minimum", NISTObjectIdentifiers.id_sha512, NISTObjectIdentifiers.id_sha512, 20,
                XadesAlgorithms.SHA512, XadesAlgorithms.SHA512, 64),
            arguments("key without parameters", null, null, 0, XadesAlgorithms.SHA384, XadesAlgorithms.SHA256, 48)
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("suitablePssParameters")
    void pssSignatureWithSuitablePssCertificatePasses(String name, ASN1ObjectIdentifier hash, ASN1ObjectIdentifier mgfHash, int minSalt,
        String digest, String mgfDigest, int salt) throws Exception {
        X509Certificate certificate = signer.issuePss(PSS_SIGNER, signer.signerKeys.getPublic(), hash, mgfHash, minSalt);

        assertValid(signer.sign(signer.signerKeys.getPrivate(), certificate, pssMethod(digest, mgfDigest, salt), pss(digest, mgfDigest, salt)));
    }

    static Stream<Arguments> unsuitablePssParameters() {
        return Stream.of(
            arguments("other hash", NISTObjectIdentifiers.id_sha512, NISTObjectIdentifiers.id_sha256, 32,
                XadesAlgorithms.SHA256, XadesAlgorithms.SHA256, 32, Detail.PSS_PARAMETER_MISMATCH, "SHA-512"),
            arguments("other MGF1 hash", NISTObjectIdentifiers.id_sha256, NISTObjectIdentifiers.id_sha512, 32,
                XadesAlgorithms.SHA256, XadesAlgorithms.SHA256, 32, Detail.PSS_PARAMETER_MISMATCH, "MaskGenerationFunction"),
            arguments("shorter salt than the minimum", NISTObjectIdentifiers.id_sha256, NISTObjectIdentifiers.id_sha256, 64,
                XadesAlgorithms.SHA256, XadesAlgorithms.SHA256, 32, Detail.PSS_SALT_TOO_SHORT, "aspoň 64")
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("unsuitablePssParameters")
    void pssSignatureWithUnsuitablePssCertificateFails(String name, ASN1ObjectIdentifier hash, ASN1ObjectIdentifier mgfHash, int minSalt,
        String digest, String mgfDigest, int salt, Detail detail, String expectedText) throws Exception {
        X509Certificate certificate = signer.issuePss(PSS_SIGNER, signer.signerKeys.getPublic(), hash, mgfHash, minSalt);
        Map<String, byte[]> files = signer.sign(signer.signerKeys.getPrivate(), certificate, pssMethod(digest, mgfDigest, salt),
            pss(digest, mgfDigest, salt));
        doReturn(crlWithoutRevocations(signer.root.getSubjectX500Principal())).when(crlClient).download(any());
        trustGeneratedRoot();

        AttributeException exception = assertThrows(AttributeException.class,
            () -> validationService.validateSignature(container("pss.asice", zip(files))));

        assertAll(
            () -> assertEquals("dsm:RSAPSSParams", exception.getAttribute(), messages.error(exception)),
            () -> assertEquals(detail, exception.getDetail(), messages.error(exception)),
            () -> assertTrue(messages.error(exception).contains(expectedText), messages.error(exception))
        );
    }

    // Only ds:DigestMethod is given, so MGF1 uses the same hash and the salt length is the hash length (RFC 6931).
    @Test
    void pssSignatureWithDefaultParametersPasses() throws Exception {
        String method = "<ds:SignatureMethod Algorithm=\"" + XadesAlgorithms.RSA_PSS + "\"><dsm:RSAPSSParams xmlns:dsm=\""
            + XadesConstants.NS_DSM + "\"><ds:DigestMethod Algorithm=\"" + XadesAlgorithms.SHA512 + "\"/></dsm:RSAPSSParams></ds:SignatureMethod>";

        assertValid(signer.sign(signer.signerKeys.getPrivate(), signer.signer, method, pss(XadesAlgorithms.SHA512, XadesAlgorithms.SHA512, 64)));
    }

    // Empty RSAPSSParams mean SHA-256, which the SHA-512 certificate does not allow; the missing ds:DigestMethod marks its parent.
    @Test
    void pssSignatureWithDefaultParametersAndPssCertificateFails() throws Exception {
        X509Certificate certificate = signer.issuePss(PSS_SIGNER, signer.signerKeys.getPublic(), NISTObjectIdentifiers.id_sha512,
            NISTObjectIdentifiers.id_sha512, 64);
        String method = "<ds:SignatureMethod Algorithm=\"" + XadesAlgorithms.RSA_PSS + "\"><dsm:RSAPSSParams xmlns:dsm=\""
            + XadesConstants.NS_DSM + "\"/></ds:SignatureMethod>";
        Map<String, byte[]> files = signer.sign(signer.signerKeys.getPrivate(), certificate, method,
            pss(XadesAlgorithms.SHA256, XadesAlgorithms.SHA256, 32));
        doReturn(crlWithoutRevocations(signer.root.getSubjectX500Principal())).when(crlClient).download(any());
        trustGeneratedRoot();

        AttributeException exception = assertThrows(AttributeException.class,
            () -> validationService.validateSignature(container("pss.asice", zip(files))));

        assertAll(
            () -> assertEquals("dsm:RSAPSSParams", exception.getAttribute(), messages.error(exception)),
            () -> assertEquals(Detail.PSS_PARAMETER_MISMATCH, exception.getDetail(), messages.error(exception)),
            () -> assertEquals("RSAPSSParams", exception.getNode() == null ? null : exception.getNode().getLocalName())
        );
    }

    // A signature value made with a 1024-bit key is shorter than the 2048-bit key of the certificate. The JDK does not
    // return false for it but throws "Bad signature length".
    @Test
    void signatureValueOfWrongLengthIsNotVerified() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        Map<String, byte[]> files = signer.sign(generator.generateKeyPair().getPrivate(), signer.signer, TestSigner.RSA_SHA256,
            Signature.getInstance("SHA256withRSA"));

        assertGeneratedContainerFails(files, crlWithoutRevocations(signer.root.getSubjectX500Principal()), "ds:SignatureValue",
            Detail.SIGNATURE_VALUE_ERROR);
    }

    private void assertValid(Map<String, byte[]> files) throws Exception {
        doReturn(crlWithoutRevocations(signer.root.getSubjectX500Principal())).when(crlClient).download(any());
        trustGeneratedRoot();

        List<FileResult> results = validationService.validate(List.of(container("generated.asice", zip(files))));

        assertNull(results.get(0).error(), results.get(0).error());
    }

    // TestSigner certificates and CRLs come from its generated root, so these tests trust that root instead of the DITEC CA.
    private void trustGeneratedRoot() {
        doReturn(signer.root).when(trustAnchor).certificate();
    }

    private static UnaryOperator<Map<String, byte[]>> signatureMethod(String element) {
        return signature(xml -> xml.replaceFirst("<ds:SignatureMethod [^>]*/>", element));
    }

    private static String pssMethod(String digest, String mgfDigest, int saltLength) {
        return "<ds:SignatureMethod Algorithm=\"" + XadesAlgorithms.RSA_PSS + "\"><dsm:RSAPSSParams xmlns:dsm=\"" + XadesConstants.NS_DSM + "\">"
            + "<ds:DigestMethod Algorithm=\"" + digest + "\"/><dsm:MaskGenerationFunction Algorithm=\"" + XadesConstants.NS_DSM + "MGF1\">"
            + "<ds:DigestMethod Algorithm=\"" + mgfDigest + "\"/></dsm:MaskGenerationFunction><dsm:SaltLength>" + saltLength
            + "</dsm:SaltLength><dsm:TrailerField>1</dsm:TrailerField></dsm:RSAPSSParams></ds:SignatureMethod>";
    }

    // RSASSA-PSS signer for the digest URIs of pssMethod.
    private static Signature pss(String digest, String mgfDigest, int saltLength) throws Exception {
        Signature signature = Signature.getInstance("RSASSA-PSS");
        signature.setParameter(new PSSParameterSpec(XadesAlgorithms.DIGEST_METHODS.get(digest), "MGF1",
            new MGF1ParameterSpec(XadesAlgorithms.DIGEST_METHODS.get(mgfDigest)), saltLength, 1));
        return signature;
    }

    @Test
    void secondSignatureFileWithSameIdsFails() throws Exception {
        doReturn(crlWithoutRevocations(signingCertificate("13X-T.asice").getIssuerX500Principal())).when(crlClient).download(any());
        Map<String, byte[]> files = AsiceUtil.open(new ByteArrayInputStream(sampleBytes("13X-T.asice")));
        files.put("META-INF/signatures2.xml", files.get(AsiceUtil.SIGNATURE_FILE));

        AttributeException exception = assertThrows(AttributeException.class,
            () -> validationService.validateSignature(container("two.asice", zip(files))));

        assertAll(
            () -> assertEquals(Detail.DUPLICATE_ID, exception.getDetail()),
            () -> assertEquals("META-INF/signatures2.xml", exception.getFile())
        );
    }

    // Two signature files over the same data object, each with its own Ids.
    @Test
    void containerWithTwoSignatureFilesPasses() throws Exception {
        Map<String, byte[]> files = signer.sign();
        files.put("META-INF/signatures2.xml", signer.secondSignature());

        assertValid(files);
    }

    static Stream<Arguments> sampleMarks() {
        return Stream.of(
            arguments("01X-T.asice", Mark.ATTRIBUTE, "asic:XAdESSignatures", "xmlns:asic", "http://uri.etsi.org/02918/v2.1.2#"),
            arguments("02X-T.asice", Mark.ATTRIBUTE, "ds:SignatureProperties", "xmlns:xzep",
                "http://www.ditec.sk/ep/signature_formats/xades_zepbp/v5.0"),
            arguments("03X-T.asice", Mark.ATTRIBUTE, "ds:SignatureMethod", "Algorithm",
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha255"),
            arguments("04X-T.asice", Mark.ATTRIBUTE, "ds:CanonicalizationMethod", "Algorithm",
                "http://www.w3.org/TR/2001/REC-xml-c14n-20120315"),
            arguments("05X-T.asice", Mark.TEXT, "ds:DigestValue", null, "JDbDRw9Zmb5+C93dYZE6YJFdPdq9ilNmWf69XupUap4="),
            arguments("06X-T.asice", Mark.TEXT, "ds:DigestValue", null, "xM5PV45568fMP/7UrZ6Rb4OyfwiAyWrOpMou+UjbOPM="),
            arguments("07X-T.asice", Mark.TAG, "Signature", null, "Signature"),
            arguments("08X-T.asice", Mark.TAG, "ds:SignatureValue", null, "ds:SignatureValue"),
            arguments("09X-T.asice", Mark.TEXT, "ds:X509SerialNumber", null, "2"),
            arguments("10X-T.asice", Mark.TEXT, "ds:DigestValue", null, "X32L2a3TJG+G5zvwHD3OBzqLQ19YJBO8aKZJpe7S3cA="),
            arguments("11X-T.asice", Mark.ATTRIBUTE, "ds:Reference", "URI", "object_1.txt"),
            arguments("12X-T.asice", Mark.TEXT, "xades:EncapsulatedTimeStamp", null, null),
            arguments("13X-T.asice", Mark.TEXT, "ds:X509Certificate", null, null)
        );
    }

    @ParameterizedTest(name = "{0} marks {1} of {2}")
    @MethodSource("sampleMarks")
    void errorLocationMarksOnlyWrongValue(String sample, Mark mark, String element, String attribute, String value)
        throws Exception {
        FileResult result = validationService.validate(List.of(container(sample, sampleBytes(sample)))).get(0);

        Location location = result.location();
        Element node = locate(location);
        String marked = switch (location.mark()) {
            case ATTRIBUTE -> node.getAttribute(location.attribute());
            case TEXT -> node.getTextContent().trim();
            case TAG -> node.getNodeName();
        };

        assertAll(
            () -> assertEquals(AsiceUtil.SIGNATURE_FILE, location.file()),
            () -> assertEquals(mark, location.mark()),
            () -> assertEquals(element, node.getNodeName()),
            () -> assertEquals(attribute, location.attribute()),
            () -> assertTrue(value == null ? StringUtils.isNotBlank(marked) : value.equals(marked), marked)
        );
    }

    static Stream<Arguments> editedSignatureMarks() {
        return Stream.of(
            arguments("wrong prefix marks the tag, not the correct xmlns:ds", "10X-T.asice",
                (UnaryOperator<String>) xml -> xml.replace("<xzep:SignatureVersion>", "<ds:SignatureVersion>")
                    .replace("</xzep:SignatureVersion>", "</ds:SignatureVersion>"),
                Mark.TAG, "ds:SignatureVersion", null),
            arguments("CDATA value is marked as text", "09X-T.asice",
                (UnaryOperator<String>) xml -> xml.replace("<ds:X509SerialNumber>2</ds:X509SerialNumber>",
                    "<ds:X509SerialNumber><![CDATA[2]]></ds:X509SerialNumber>"),
                Mark.TEXT, "ds:X509SerialNumber", null),
            arguments("mixed content marks the tag", "10X-T.asice",
                (UnaryOperator<String>) xml -> xml.replaceFirst("</ds:X509SubjectName>", "<x/></ds:X509SubjectName>")
                    .replaceFirst("<ds:X509SubjectName>", "<ds:X509SubjectName>CN=wrong,"),
                Mark.TAG, "ds:X509SubjectName", null),
            arguments("element order error marks the misplaced element", "10X-T.asice", SIGNING_TIME_AFTER_CERTIFICATE,
                Mark.TAG, "xades:SigningTime", null)
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("editedSignatureMarks")
    void editedSignatureMarksWrongNode(String name, String sample, UnaryOperator<String> change, Mark mark, String element,
        String attribute) throws Exception {
        Map<String, byte[]> files = AsiceUtil.open(new ByteArrayInputStream(sampleBytes(sample)));
        String xml = new String(files.get(AsiceUtil.SIGNATURE_FILE), StandardCharsets.UTF_8);
        String changed = change.apply(xml);
        assertTrue(!changed.equals(xml), "change did not apply");
        files.put(AsiceUtil.SIGNATURE_FILE, changed.getBytes(StandardCharsets.UTF_8));

        Location location = validationService.validate(List.of(container("edited.asice", zip(files)))).get(0).location();

        assertAll(
            () -> assertEquals(mark, location.mark()),
            () -> assertEquals(element, locate(location).getNodeName()),
            () -> assertEquals(attribute, location.attribute())
        );
    }

    static Stream<Arguments> otherFileMarks() {
        return Stream.of(
            arguments("manifest attribute", manifest(xml -> xml.replace("manifest:full-path=\"object_0.txt\"",
                    "manifest:full-path=\"object_0.txt\" manifest:size=\"5\"")),
                AsiceUtil.MANIFEST_FILE, Mark.ATTRIBUTE, "manifest:file-entry", "manifest:size"),
            arguments("Id in XML data", dataObject(XadesConstants.MIME_XML_CONTAINER, xmlContainer("UTF-8",
                    "<xdc:XMLData><a Id=\"signatureId\"/></xdc:XMLData>")),
                "object_0.txt", Mark.ATTRIBUTE, "a", "Id"),
            arguments("xdc prefix in XML data", dataObject(XadesConstants.MIME_XML_CONTAINER, xmlContainer("UTF-8",
                    "<xdc:XMLData><a/></xdc:XMLData><c:UsedSchemasEmbedded xmlns:c=\"" + XadesConstants.NS_XDC + "\"/>")),
                "object_0.txt", Mark.TAG, "c:UsedSchemasEmbedded", null),
            arguments("XMLData error marks the wrong element", xmlDataObject(xdc("<a xmlns=\"urn:test\"><c/></a>", XSD, XHTML)),
                "object_0.txt", Mark.TAG, "c", null),
            arguments("script in XSLT output marks the literal element", xmlDataObject(xdc(DATA, XSD, "HTML",
                    xslt("html", "<html><body><script>alert(1)</script></body></html>"))),
                "object_0.txt", Mark.TAG, "script", null),
            arguments("wrong media destination marks the attribute", xmlDataObject(xdc(DATA, XSD, "PDF", xslt("html", HTML))),
                "object_0.txt", Mark.ATTRIBUTE, "xdc:UsedPresentationSchemaEmbedded", "MediaDestinationTypeDescription")
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("otherFileMarks")
    void errorInOtherFileMarksThatFile(String name, UnaryOperator<Map<String, byte[]>> change, String file, Mark mark, String element,
        String attribute) throws Exception {
        Map<String, byte[]> files = change.apply(AsiceUtil.open(new ByteArrayInputStream(sampleBytes("10X-T.asice"))));

        Location location = validationService.validate(List.of(container("edited.asice", zip(files)))).get(0).location();

        assertAll(
            () -> assertEquals(file, location.file()),
            () -> assertEquals(mark, location.mark()),
            () -> assertEquals(element, locate(location).getNodeName()),
            () -> assertEquals(attribute, location.attribute())
        );
    }

    @Test
    void stylesheetAndSchemaDoNotFetchExternalResources() throws Exception {
        AtomicInteger hits = new AtomicInteger();
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", exchange -> {
            hits.incrementAndGet();
            byte[] body = "<x/>".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        try {
            String base = "http://" + server.getAddress().getHostString() + ":" + server.getAddress().getPort() + "/";
            String importXslt = "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"" + XadesConstants.NS_XSL + "\"><xsl:import href=\"" + base
                + "a.xsl\"/><xsl:template match=\"/\"><p/></xsl:template></xsl:stylesheet>";
            Map<String, Detail> cases = Map.of(
                xdc(DATA, XSD, "HTML", importXslt), Detail.XSLT_EXTERNAL_REFERENCE,
                xdc(DATA, XSD, "HTML", xslt("html", "<p><xsl:value-of select=\"document('" + base + "d.xml')\"/></p>")),
                Detail.XSLT_EXTERNAL_REFERENCE,
                xdc(DATA, XSD.replace("elementFormDefault=\"qualified\">", "elementFormDefault=\"qualified\"><xs:import namespace=\"urn:other\" "
                    + "schemaLocation=\"" + base + "s.xsd\"/>"), XHTML), Detail.XSD_NOT_COMPILED,
                xdc(DATA, XSD.replace("elementFormDefault=\"qualified\">", "elementFormDefault=\"qualified\"><xs:include schemaLocation=\""
                    + base + "i.xsd\"/>"), XHTML), Detail.XSD_NOT_COMPILED);
            for (Map.Entry<String, Detail> testCase : cases.entrySet()) {
                Map<String, byte[]> files = xmlDataObject(testCase.getKey())
                    .apply(AsiceUtil.open(new ByteArrayInputStream(sampleBytes("10X-T.asice"))));
                AttributeException exception = assertThrows(AttributeException.class,
                    () -> validationService.validateSignature(container("external.asice", zip(files))));
                assertEquals(testCase.getValue(), exception.getDetail(), messages.error(exception));
            }
            XsltConverter.XsltException converterError = assertThrows(XsltConverter.XsltException.class,
                () -> XsltConverter.transform(document(importXslt), document(DATA)));
            assertEquals(XsltConverter.Reason.EXTERNAL_REFERENCE, converterError.getReason());
            assertEquals(0, hits.get(), "the validator fetched an external resource");

            HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create(base)).build(), HttpResponse.BodyHandlers.discarding());
            assertEquals(1, hits.get(), "the test server did not count a direct request");
        } finally {
            server.stop(0);
        }
    }

    private static Document document(String xml) throws Exception {
        return XmlConverter.toDocument(xml.getBytes(StandardCharsets.UTF_8));
    }

    private static Element locate(Location location) throws Exception {
        Document document = DocumentBuilderFactory.newInstance().newDocumentBuilder()
            .parse(new ByteArrayInputStream(location.content().getBytes(StandardCharsets.UTF_8)));
        return (Element) XPathFactory.newInstance().newXPath().evaluate(location.path(), document, XPathConstants.NODE);
    }

    @Test
    void crlFromOtherIssuerIsNotAccepted() throws Exception {
        doReturn(crlWithoutRevocations(new X500Principal("CN=Other CA"))).when(crlClient).download(any());

        AttributeException exception = assertThrows(AttributeException.class,
            () -> validationService.validateSignature(container("13X-T.asice", sampleBytes("13X-T.asice"))));

        assertAll(
            () -> assertEquals(Detail.CRL_OTHER_ISSUER, exception.getDetail())
        );
    }

    // The certificate copies the name of the trusted root, but another key signed it.
    @Test
    void signingCertificateFromForgedIssuerIsNotTrusted() throws Exception {
        KeyPair forger = TestCertificates.keyPair();
        X509Certificate forged = TestCertificates.certificate("CN=Forged Signer,C=SK", signer.signerKeys.getPublic(), TestSigner.ROOT,
            forger.getPrivate());
        Map<String, byte[]> files = signer.sign(signer.signerKeys.getPrivate(), forged, TestSigner.RSA_SHA256,
            Signature.getInstance("SHA256withRSA"));

        assertGeneratedContainerFails(files, crlWithoutRevocations(signer.root.getSubjectX500Principal()), "ds:X509Certificate",
            Detail.CERTIFICATE_NOT_TRUSTED);
    }

    @Test
    void timeStampFromForgedTsaIsNotTrusted() throws Exception {
        KeyPair forger = TestCertificates.keyPair();
        X509Certificate forgedTsa = TestCertificates.timeStampingCertificate("CN=Forged TSA,C=SK", forger.getPublic(), TestSigner.ROOT,
            forger.getPrivate());
        Map<String, byte[]> files = signer.sign(signer.signerKeys.getPrivate(), signer.signer, TestSigner.RSA_SHA256,
            Signature.getInstance("SHA256withRSA"), forger.getPrivate(), forgedTsa);

        assertGeneratedContainerFails(files, crlWithoutRevocations(signer.root.getSubjectX500Principal()), "xades:EncapsulatedTimeStamp", Detail.CERTIFICATE_NOT_TRUSTED);
    }

    // RFC 3161 2.3: only a certificate with a critical extended key usage that is only id-kp-timeStamping may sign
    // time-stamps. The signing certificate is issued by the trusted root but has no extended key usage.
    @Test
    void signatureTimeStampFromCertificateWithoutTimeStampingUsageFails() throws Exception {
        Map<String, byte[]> files = timeStampFromSigningCertificate(signer.sign(),
            "(<xades:SignatureTimeStamp[^>]*><xades:EncapsulatedTimeStamp>)");
        doReturn(crlWithoutRevocations(signer.root.getSubjectX500Principal())).when(crlClient).download(any());
        trustGeneratedRoot();

        AttributeException exception = assertThrows(AttributeException.class,
            () -> validationService.validateSignature(container("generated.asice", zip(files))));

        Node node = exception.getNode();
        assertAll(
            () -> assertEquals("xades:EncapsulatedTimeStamp", exception.getAttribute(), messages.error(exception)),
            () -> assertEquals(Detail.TSA_EXTENDED_KEY_USAGE, exception.getDetail(), messages.error(exception)),
            () -> assertEquals(Node.TEXT_NODE, node.getNodeType()),
            () -> assertEquals("EncapsulatedTimeStamp", node.getParentNode().getLocalName()),
            () -> assertEquals("SignatureTimeStamp", node.getParentNode().getParentNode().getLocalName())
        );
    }

    // Replaces the token after the prefix with a token over the same imprint, signed with the signing certificate.
    private static Map<String, byte[]> timeStampFromSigningCertificate(Map<String, byte[]> files, String prefix) throws Exception {
        return replaceTimeStamp(files, prefix, (algorithm, digest) -> TestCertificates.timestampFromAnyCertificate(algorithm, digest,
            signer.signerKeys.getPrivate(), signer.signer));
    }

    // Replaces the token after the prefix with the token that newToken makes from the imprint hash OID and digest of the old one.
    private static Map<String, byte[]> replaceTimeStamp(Map<String, byte[]> files, String prefix,
        FailableBiFunction<ASN1ObjectIdentifier, byte[], byte[], Exception> newToken) throws Exception {
        String xml = text(files.get(AsiceUtil.SIGNATURE_FILE));
        Matcher matcher = Pattern.compile(prefix + "([^<]*)").matcher(xml);
        assertTrue(matcher.find(), prefix);
        TimeStampTokenInfo info = TimestampConverter.toToken(Base64Converter.decode(matcher.group(2))).getTimeStampInfo();
        String token = Base64Converter.encode(newToken.apply(info.getMessageImprintAlgOID(), info.getMessageImprintDigest()));
        files.put(AsiceUtil.SIGNATURE_FILE, (xml.substring(0, matcher.start(2)) + token + xml.substring(matcher.end(2)))
            .getBytes(StandardCharsets.UTF_8));
        return files;
    }

    // Profile 4.4.5.3: a CRL of the issuer of the signing certificate, signed with the issuer key, is enough revocation data.
    @Test
    void revocationValuesWithIssuerCrlPass() throws Exception {
        Map<String, byte[]> files = signer.sign();
        files.put(AsiceUtil.SIGNATURE_FILE, text(files.get(AsiceUtil.SIGNATURE_FILE)).replace("</xades:SignatureTimeStamp>",
            "</xades:SignatureTimeStamp><xades:RevocationValues Id=\"rv\"><xades:CRLValues><xades:EncapsulatedCRLValue>"
                + Base64Converter.encode(TestCertificates.crl(TestSigner.ROOT, signer.rootKeys.getPrivate()))
                + "</xades:EncapsulatedCRLValue></xades:CRLValues></xades:RevocationValues>").getBytes(StandardCharsets.UTF_8));

        assertValid(files);
    }

    // Profile 4.5: the MessageImprint hash of a time-stamp token is a 4.5 digest algorithm. This token has a correct SHA-1 imprint.
    @Test
    void signatureTimeStampWithSha1ImprintFails() throws Exception {
        Map<String, byte[]> files = signer.sign();
        String xml = text(files.get(AsiceUtil.SIGNATURE_FILE));
        Element signatureValue = (Element) document(xml).getElementsByTagNameNS(XadesConstants.NS_DS, "SignatureValue").item(0);
        byte[] imprint = MessageDigest.getInstance("SHA-1").digest(CanonicalizationConverter.canonicalize(XadesAlgorithms.C14N, signatureValue));
        String token = Base64Converter.encode(TestCertificates.timestamp(TSPAlgorithms.SHA1, imprint, signer.tsaKeys.getPrivate(), signer.tsa));
        files.put(AsiceUtil.SIGNATURE_FILE, xml.replaceFirst("(<xades:SignatureTimeStamp[^>]*><xades:EncapsulatedTimeStamp>)[^<]*",
            "$1" + Matcher.quoteReplacement(token)).getBytes(StandardCharsets.UTF_8));

        assertGeneratedContainerFails(files, crlWithoutRevocations(signer.root.getSubjectX500Principal()), "MessageImprint",
            Detail.TIMESTAMP_DIGEST_NOT_ALLOWED);
    }

    // Step 3a checks the signing certificate at the time-stamp time. This token is dated a day before the certificate.
    @Test
    void signingCertificateNotValidAtTimeStampTimeFails() throws Exception {
        Date genTime = Date.from(signer.signer.getNotBefore().toInstant().minus(Duration.ofDays(1)));
        Map<String, byte[]> files = replaceTimeStamp(signer.sign(), "(<xades:SignatureTimeStamp[^>]*><xades:EncapsulatedTimeStamp>)",
            (algorithm, digest) -> TestCertificates.timestamp(algorithm, digest, signer.tsaKeys.getPrivate(), signer.tsa, genTime));

        assertGeneratedContainerFails(files, crlWithoutRevocations(signer.root.getSubjectX500Principal()), "ds:X509Certificate",
            Detail.CERTIFICATE_NOT_VALID);
    }

    @Test
    void signatureTimeStampWithoutTsaCertificateFails() throws Exception {
        Map<String, byte[]> files = replaceTimeStamp(signer.sign(), "(<xades:SignatureTimeStamp[^>]*><xades:EncapsulatedTimeStamp>)",
            (algorithm, digest) -> TestCertificates.timestampWithoutCertificate(algorithm, digest, signer.tsaKeys.getPrivate(), signer.tsa));

        assertGeneratedContainerFails(files, crlWithoutRevocations(signer.root.getSubjectX500Principal()), "xades:EncapsulatedTimeStamp",
            Detail.TSA_CERTIFICATE_MISSING);
    }

    @Test
    void crlSignedByOtherKeyIsNotAccepted() throws Exception {
        X509CRL crl = CertificateConverter.toCrl(TestCertificates.crl(TestSigner.ROOT, TestCertificates.keyPair().getPrivate()));

        assertGeneratedContainerFails(signer.sign(), crl, "CRL", Detail.CRL_SIGNATURE);
    }

    // A real CRL signed by the trusted root: its signature passes and only its date fails.
    @Test
    void expiredCrlIsNotAccepted() throws Exception {
        Instant now = Instant.now();
        X509CRL crl = CertificateConverter.toCrl(TestCertificates.crl(TestSigner.ROOT, signer.rootKeys.getPrivate(),
            now.minus(Duration.ofDays(2)), now.minus(Duration.ofDays(1))));

        assertGeneratedContainerFails(signer.sign(), crl, "CRL", Detail.CRL_EXPIRED);
    }

    // A CRL that passed its checks serves the next containers too.
    @Test
    void crlIsDownloadedOnceForTwoContainers() throws Exception {
        doReturn(crlWithoutRevocations(signer.root.getSubjectX500Principal())).when(crlClient).download(any());
        trustGeneratedRoot();
        byte[] zip = zip(signer.sign());

        List<FileResult> results = validationService.validate(List.of(container("first.asice", zip), container("second.asice", zip)));

        assertAll(
            () -> assertNull(results.get(0).error(), results.get(0).error()),
            () -> assertNull(results.get(1).error(), results.get(1).error()),
            () -> verify(crlClient, times(1)).download(any())
        );
    }

    // A CRL that fails its checks is not kept, so the next container downloads the CRL again.
    @Test
    void crlThatFailsItsChecksIsDownloadedAgain() throws Exception {
        X509CRL forged = CertificateConverter.toCrl(TestCertificates.crl(TestSigner.ROOT, TestCertificates.keyPair().getPrivate()));
        doReturn(forged, crlWithoutRevocations(signer.root.getSubjectX500Principal())).when(crlClient).download(any());
        trustGeneratedRoot();
        byte[] zip = zip(signer.sign());

        List<FileResult> results = validationService.validate(List.of(container("first.asice", zip), container("second.asice", zip)));

        assertAll(
            () -> assertTrue(Strings.CS.contains(results.get(0).error(), "Podpis CRL"), results.get(0).error()),
            () -> assertNull(results.get(1).error(), results.get(1).error()),
            () -> verify(crlClient, times(2)).download(any())
        );
    }

    // A kept CRL is used only until its nextUpdate.
    @Test
    void keptCrlAfterItsNextUpdateIsDownloadedAgain() throws Exception {
        AtomicReference<Date> nextUpdate = new AtomicReference<>(Date.from(Instant.now().plus(Duration.ofDays(1))));
        X509CRL first = crlWithoutRevocations(signer.root.getSubjectX500Principal());
        when(first.getNextUpdate()).thenAnswer(invocation -> nextUpdate.get());
        doReturn(first, crlWithoutRevocations(signer.root.getSubjectX500Principal())).when(crlClient).download(any());
        trustGeneratedRoot();
        byte[] zip = zip(signer.sign());

        FileResult before = validationService.validate(List.of(container("first.asice", zip))).get(0);
        nextUpdate.set(Date.from(Instant.now().minusSeconds(1)));
        FileResult after = validationService.validate(List.of(container("second.asice", zip))).get(0);

        assertAll(
            () -> assertNull(before.error(), before.error()),
            () -> assertNull(after.error(), after.error()),
            () -> verify(crlClient, times(2)).download(any())
        );
    }

    @Test
    void failedCrlDownloadIsReported() throws Exception {
        doThrow(new IOException("Connection refused")).when(crlClient).download(any());
        trustGeneratedRoot();
        byte[] zip = zip(signer.sign());

        AttributeException exception = assertThrows(AttributeException.class,
            () -> validationService.validateSignature(container("generated.asice", zip)));

        assertAll(
            () -> assertEquals("CRL", exception.getAttribute(), messages.error(exception)),
            () -> assertEquals(Detail.CRL_DOWNLOAD, exception.getDetail(), messages.error(exception)),
            () -> assertTrue(messages.error(exception).contains("Connection refused"), messages.error(exception))
        );
    }

    private void assertGeneratedContainerFails(Map<String, byte[]> files, X509CRL crl, String attribute, Detail detail)
        throws Exception {
        doReturn(crl).when(crlClient).download(any());
        trustGeneratedRoot();

        AttributeException exception = assertThrows(AttributeException.class,
            () -> validationService.validateSignature(container("generated.asice", zip(files))));

        assertAll(
            () -> assertEquals(attribute, exception.getAttribute(), messages.error(exception)),
            () -> assertEquals(detail, exception.getDetail(), messages.error(exception))
        );
    }

    // Names from the upload cannot add a log line. Besides CR and LF, U+2028 and NEL (U+0085) are line breaks in some log viewers.
    @Test
    @ExtendWith(OutputCaptureExtension.class)
    void namesWithLineBreaksAreLoggedOnOneLine(CapturedOutput output) throws IOException {
        Map<String, byte[]> files = AsiceUtil.open(new ByteArrayInputStream(sampleBytes("10X-T.asice")));
        files.put("META-INF/signatures\nFORGED\u2028entry\u0085.xml", files.get(AsiceUtil.SIGNATURE_FILE));

        validationService.validate(List.of(container("a.asice\r\nFORGED upload.asice", zip(files))));

        assertAll(
            () -> assertTrue(output.getOut().lines().noneMatch(line -> line.startsWith("FORGED")), output.getOut()),
            () -> assertTrue(output.getOut().contains("a.asice??FORGED upload.asice: invalid, META-INF/signatures?FORGED?entry?.xml"),
                output.getOut())
        );
    }

    @Test
    void duplicateZipEntryIsRejected() throws IOException {
        Map<String, byte[]> files = AsiceUtil.open(new ByteArrayInputStream(sampleBytes("10X-T.asice")));
        files.put("object_1.txt", "b".getBytes(StandardCharsets.UTF_8));
        String zip = new String(zip(files), StandardCharsets.ISO_8859_1).replace("object_1.txt", "object_0.txt");

        AttributeException exception = assertThrows(AttributeException.class,
            () -> validationService.validateSignature(container("dup.asice", zip.getBytes(StandardCharsets.ISO_8859_1))));

        assertEquals(Detail.DUPLICATE_ENTRY, exception.getDetail());
    }

    @Test
    void zipBombIsRejected() throws IOException {
        Map<String, byte[]> files = AsiceUtil.open(new ByteArrayInputStream(sampleBytes("10X-T.asice")));
        files.put("big.bin", new byte[101 * 1024 * 1024]);
        byte[] zip = zip(files);

        AttributeException exception = assertThrows(AttributeException.class,
            () -> validationService.validateSignature(container("big.asice", zip)));

        assertEquals(Detail.CONTAINER_TOO_LARGE, exception.getDetail());
    }

    // 20 MB of zeros (the upload limit) and the other files are over the unpacked limit.
    @Test
    void containerOverUnpackedLimitIsRejected() throws IOException {
        Map<String, byte[]> files = AsiceUtil.open(new ByteArrayInputStream(sampleBytes("10X-T.asice")));
        files.put("big.bin", new byte[20 * 1024 * 1024]);
        byte[] zip = zip(files);

        AttributeException exception = assertThrows(AttributeException.class, () -> AsiceUtil.open(new ByteArrayInputStream(zip)));

        assertEquals("Súbor: je príliš veľký. Rozbalený obsah kontajnera je väčší ako 20 MB.", messages.error(exception));
    }

    // Fails while the container is read, before the file is parsed.
    @ParameterizedTest
    @ValueSource(strings = {AsiceUtil.SIGNATURE_FILE, AsiceUtil.MANIFEST_FILE})
    void xmlFileLargerThanXmlLimitFailsWhileReading(String name) throws IOException {
        Map<String, byte[]> files = AsiceUtil.open(new ByteArrayInputStream(sampleBytes("10X-T.asice")));
        files.put(name, ("<a>" + " ".repeat(XmlConverter.MAX_SIZE) + "</a>").getBytes(StandardCharsets.UTF_8));
        byte[] zip = zip(files);

        AttributeException exception = assertThrows(AttributeException.class, () -> AsiceUtil.open(new ByteArrayInputStream(zip)));

        assertAll(
            () -> assertEquals(name, exception.getAttribute(), messages.error(exception)),
            () -> assertEquals(Detail.XML_TOO_LARGE, exception.getDetail(), messages.error(exception))
        );
    }

    // With a canonicalization transform, the digest of a data object parses the file outside AsiceUtil.parse, so
    // XmlConverter has the XML limit too.
    @Test
    void transformOfDataObjectLargerThanXmlLimitIsNotParsed() throws Exception {
        doReturn(crlWithoutRevocations(signingCertificate("10X-T.asice").getIssuerX500Principal())).when(crlClient).download(any());
        Map<String, byte[]> files = AsiceUtil.open(new ByteArrayInputStream(sampleBytes("10X-T.asice")));
        String transforms = "<ds:Transforms><ds:Transform Algorithm=\"" + XadesAlgorithms.C14N + "\" /></ds:Transforms>";
        put(files, AsiceUtil.SIGNATURE_FILE, text(files.get(AsiceUtil.SIGNATURE_FILE))
            .replace("URI=\"object_0.txt\">", "URI=\"object_0.txt\">" + transforms).getBytes(StandardCharsets.UTF_8));
        put(files, "object_0.txt", ("<a>" + "x".repeat(XmlConverter.MAX_SIZE) + "</a>").getBytes(StandardCharsets.UTF_8));

        AttributeException exception = assertThrows(AttributeException.class,
            () -> validationService.validateSignature(container("transformed.asice", zip(files))));

        assertAll(
            () -> assertEquals(Detail.DIGEST_NOT_COMPUTED, exception.getDetail(), messages.error(exception)),
            () -> assertTrue(messages.error(exception).contains("XML is larger than 1 MB"), messages.error(exception))
        );
    }

    // Tasks that wait on a latch hold every XsltConverter thread, so the transformation is rejected. A stylesheet of an
    // earlier test may still hold a thread after its time limit, so the loop waits until all the threads are ours.
    @Test
    void xsltWithAllThreadsBusyFails() throws Exception {
        ExecutorService executor = (ExecutorService) ReflectionTestUtils.getField(XsltConverter.class, "EXECUTOR");
        Map<String, byte[]> files = xmlDataObject(xdc(DATA, XSD, XHTML))
            .apply(AsiceUtil.open(new ByteArrayInputStream(sampleBytes("10X-T.asice"))));
        CountDownLatch release = new CountDownLatch(1);
        List<Future<?>> held = new ArrayList<>();
        Instant deadline = Instant.now().plus(Duration.ofMinutes(2));
        try {
            while (held.size() < XsltConverter.MAX_THREADS) {
                try {
                    held.add(executor.submit(() -> release.await(1, TimeUnit.MINUTES)));
                } catch (RejectedExecutionException e) {
                    assertTrue(Instant.now().isBefore(deadline), "The XSLT threads did not become free");
                    Thread.sleep(100);
                }
            }

            AttributeException exception = assertThrows(AttributeException.class,
                () -> validationService.validateSignature(container("busy.asice", zip(files))));

            assertAll(
                () -> assertEquals("xdc:UsedPresentationSchemaEmbedded", exception.getAttribute(), messages.error(exception)),
                () -> assertEquals(Detail.XSLT_BUSY, exception.getDetail(), messages.error(exception))
            );
        } finally {
            release.countDown();
            for (Future<?> future : held) {
                future.get(10, TimeUnit.SECONDS);
            }
        }
    }

    // Control for the tests below: the generated container stored by hand, with a central directory that matches.
    @Test
    void storedZipWithMatchingCentralDirectoryPasses() throws Exception {
        doReturn(crlWithoutRevocations(signer.root.getSubjectX500Principal())).when(crlClient).download(any());
        trustGeneratedRoot();
        byte[] zip = storedZip(signer.sign(), Map.of(), UnaryOperator.identity());

        List<FileResult> results = validationService.validate(List.of(container("stored.asice", zip)));

        assertNull(results.get(0).error(), results.get(0).error());
    }

    // The attack from the review: a second local header for object_0.txt hides in an extra field of the manifest, and
    // the central directory points to it. ZipInputStream reads the signed text, unzip the forged one.
    @Test
    void centralDirectoryWithOtherContentIsRejected() throws Exception {
        byte[] forged = "This text was never signed.\n".getBytes(StandardCharsets.UTF_8);
        byte[] hidden = localEntry("object_0.txt", forged, new byte[0]);
        byte[] extra = littleEndian(4 + hidden.length).putShort((short) 0xCAFE).putShort((short) hidden.length).put(hidden).array();
        byte[] zip = storedZip(signer.sign(), Map.of(AsiceUtil.MANIFEST_FILE, extra), entries -> {
            int manifest = entries.stream().filter(entry -> AsiceUtil.MANIFEST_FILE.equals(entry.name())).findFirst().orElseThrow().offset();
            int offset = manifest + LOCAL_HEADER_LENGTH + AsiceUtil.MANIFEST_FILE.length() + 4;
            return entries.stream()
                .map(entry -> "object_0.txt".equals(entry.name()) ? new CentralEntry(entry.name(), forged, ZipEntry.STORED, offset) : entry)
                .toList();
        });

        AttributeException exception = generatedZipFails(zip);

        assertAll(
            () -> assertEquals(Detail.ZIP_DIRECTORY_MISMATCH, exception.getDetail(), messages.error(exception)),
            () -> assertEquals("object_0.txt", exception.getArgs()[0], messages.error(exception))
        );
    }

    // The entries are mimetype, object_0.txt, META-INF/signatures.xml and META-INF/manifest.xml.
    static Stream<Arguments> centralDirectoryChanges() {
        return Stream.of(
            arguments("entry missing", (UnaryOperator<List<CentralEntry>>) entries -> entries.subList(0, entries.size() - 1),
                AsiceUtil.MANIFEST_FILE),
            arguments("entry added", (UnaryOperator<List<CentralEntry>>) entries -> Stream.concat(entries.stream(),
                    Stream.of(new CentralEntry("extra.txt", entries.get(1).content(), ZipEntry.STORED, entries.get(1).offset()))).toList(),
                "extra.txt"),
            arguments("entries in other order", (UnaryOperator<List<CentralEntry>>) entries -> List.of(entries.get(0), entries.get(1),
                    entries.get(3), entries.get(2)),
                AsiceUtil.SIGNATURE_FILE),
            arguments("other compression method", (UnaryOperator<List<CentralEntry>>) entries -> entries.stream()
                    .map(entry -> new CentralEntry(entry.name(), entry.content(),
                        "object_0.txt".equals(entry.name()) ? ZipEntry.DEFLATED : entry.method(), entry.offset()))
                    .toList(),
                "object_0.txt")
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("centralDirectoryChanges")
    void centralDirectoryThatDiffersIsRejected(String name, UnaryOperator<List<CentralEntry>> change, String entry) throws Exception {
        AttributeException exception = generatedZipFails(storedZip(signer.sign(), Map.of(), change));

        assertAll(
            () -> assertEquals(Detail.ZIP_DIRECTORY_MISMATCH, exception.getDetail(), messages.error(exception)),
            () -> assertEquals(entry, exception.getArgs()[0], messages.error(exception))
        );
    }

    // ZipFile would allocate tables for the 10 million entries that the ZIP64 end record claims, so it does not open it.
    @Test
    void zip64EndRecordIsRejected() throws Exception {
        AttributeException exception = generatedZipFails(withZip64End(storedZip(signer.sign(), Map.of(), UnaryOperator.identity()),
            10_000_000L));

        assertEquals(Detail.CONTAINER_NOT_ZIP, exception.getDetail(), messages.error(exception));
    }

    // The generated container is valid, so only the ZIP can fail.
    private AttributeException generatedZipFails(byte[] zip) throws Exception {
        doReturn(crlWithoutRevocations(signer.root.getSubjectX500Principal())).when(crlClient).download(any());
        trustGeneratedRoot();
        return assertThrows(AttributeException.class, () -> validationService.validateSignature(container("forged.asice", zip)));
    }

    private static X509Certificate signingCertificate(String sample) throws Exception {
        Map<String, byte[]> files = AsiceUtil.open(new ByteArrayInputStream(sampleBytes(sample)));
        String xml = text(files.get(AsiceUtil.SIGNATURE_FILE));
        String base64 = StringUtils.substringBetween(xml, "<ds:X509Certificate>", "</ds:X509Certificate>");
        return CertificateConverter.toCertificate(Base64Converter.decode(base64));
    }

    // A mock: its verify() accepts any key, and it is valid for one more day.
    private static X509CRL crlWithoutRevocations(X500Principal issuer) {
        X509CRL crl = mock(X509CRL.class);
        when(crl.getIssuerX500Principal()).thenReturn(issuer);
        when(crl.getNextUpdate()).thenReturn(Date.from(Instant.now().plus(Duration.ofDays(1))));
        return crl;
    }

    private static UnaryOperator<Map<String, byte[]>> signature(UnaryOperator<String> change) {
        return files -> put(files, AsiceUtil.SIGNATURE_FILE, change.apply(text(files.get(AsiceUtil.SIGNATURE_FILE))).getBytes(StandardCharsets.UTF_8));
    }

    private static UnaryOperator<Map<String, byte[]>> manifest(UnaryOperator<String> change) {
        return files -> put(files, AsiceUtil.MANIFEST_FILE, change.apply(text(files.get(AsiceUtil.MANIFEST_FILE))).getBytes(StandardCharsets.UTF_8));
    }

    private static UnaryOperator<Map<String, byte[]>> unsignedProperties(String elements) {
        return signature(xml -> xml.replace("</xades:SignatureTimeStamp>", "</xades:SignatureTimeStamp>" + elements));
    }

    private static UnaryOperator<Map<String, byte[]>> signaturePolicy(String identifier, String digestMethod) {
        return signature(xml -> xml.replace("</xades:SigningCertificate>", "</xades:SigningCertificate>"
            + "<xades:SignaturePolicyIdentifier><xades:SignaturePolicyId><xades:SigPolicyId><xades:Identifier>" + identifier
            + "</xades:Identifier></xades:SigPolicyId><xades:SigPolicyHash><ds:DigestMethod Algorithm=\"" + digestMethod + "\"/>"
            + "<ds:DigestValue>AAAA</ds:DigestValue></xades:SigPolicyHash></xades:SignaturePolicyId></xades:SignaturePolicyIdentifier>"));
    }

    // Turns object_0.txt into a data object of another type: content, xades:MimeType and manifest media-type.
    private static UnaryOperator<Map<String, byte[]>> dataObject(String mimeType, byte[] content) {
        UnaryOperator<Map<String, byte[]>> mime = signature(xml -> xml.replace("text/plain; charset=UTF-8</xades:MimeType>",
            mimeType + "</xades:MimeType>"));
        UnaryOperator<Map<String, byte[]>> manifest = manifest(xml -> xml.replace("manifest:media-type=\"text/plain; charset=UTF-8\"",
            "manifest:media-type=\"" + mimeType + "\""));
        return files -> put(manifest.apply(mime.apply(files)), "object_0.txt", content);
    }

    // Renames a data object: the ZIP entry and manifest:full-path get name, ds:Reference/@URI gets uri.
    private static UnaryOperator<Map<String, byte[]>> renamedFile(String oldName, String name, String uri) {
        UnaryOperator<Map<String, byte[]>> reference = signature(xml -> xml.replace("URI=\"" + oldName + "\"", "URI=\"" + uri + "\""));
        UnaryOperator<Map<String, byte[]>> entry = manifest(xml -> xml.replace("manifest:full-path=\"" + oldName + "\"",
            "manifest:full-path=\"" + name + "\""));
        return files -> {
            byte[] content = files.remove(oldName);
            return put(entry.apply(reference.apply(files)), name, content);
        };
    }

    private static byte[] xmlContainer(String encoding, String content) {
        return ("<?xml version=\"1.0\" encoding=\"" + encoding + "\"?><xdc:XMLDataContainer xmlns:xdc=\"" + XadesConstants.NS_XDC + "\">"
            + content + "</xdc:XMLDataContainer>").getBytes(StandardCharsets.UTF_8);
    }

    private static UnaryOperator<Map<String, byte[]>> xmlDataObject(String content) {
        return dataObject(XadesConstants.MIME_XML_CONTAINER, xmlContainer("UTF-8", content));
    }

    // An XMLDataContainer in the D.Signer layout: XML data, an embedded XSD and one embedded XSLT.
    private static String xdc(String data, String xsd, String mediaDestination, String xslt) {
        return "<xdc:XMLData Identifier=\"urn:test\" Version=\"1.0\" ContentType=\"application/xml; charset=UTF-8\">" + data
            + "</xdc:XMLData><xdc:UsedSchemasEmbedded><xdc:UsedXSDEmbedded>" + xsd + "</xdc:UsedXSDEmbedded>"
            + presentation(mediaDestination, xslt) + "</xdc:UsedSchemasEmbedded>";
    }

    private static String xdc(String data, String xsd, String mediaDestination) {
        return xdc(data, xsd, mediaDestination, xslt("xml", HTML));
    }

    private static String presentation(String mediaDestination, String xslt) {
        return "<xdc:UsedPresentationSchemaEmbedded ContentType=\"application/xslt+xml\""
            + (mediaDestination == null ? "" : " MediaDestinationTypeDescription=\"" + mediaDestination + "\"")
            + " Language=\"SK\">" + xslt + "</xdc:UsedPresentationSchemaEmbedded>";
    }

    private static String xslt(String method, String root) {
        return xslt(method, root, "");
    }

    private static String xslt(String method, String root, String templates) {
        return "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"" + XadesConstants.NS_XSL + "\" xmlns:t=\"urn:test\" exclude-result-prefixes=\"t\">"
            + "<xsl:output method=\"" + method + "\"/><xsl:template match=\"/\">" + root + "</xsl:template>" + templates + "</xsl:stylesheet>";
    }

    private static byte[] pdf(String body) {
        return pdf(PDF_METADATA, "", "", PDFA_PART_1, body);
    }

    // A PDF 1.4 with a classic xref table: the catalog (object 1, plus catalogEntries), the page tree (2), an XMP metadata
    // stream (3, plus metadataEntries) whose rdf:Description has descriptionAttributes and description, and body (4).
    private static byte[] pdf(String catalogEntries, String metadataEntries, String descriptionAttributes, String description,
        String body) {
        String xmp = "<?xpacket begin=\"\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?><x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\""
            + "http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description rdf:about=\"\" xmlns:pdfaid=\"" + PdfUtil.NS_PDFAID + "\""
            + descriptionAttributes + ">" + description + "</rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end=\"w\"?>";
        List<String> objects = List.of("<< /Type /Catalog /Pages 2 0 R" + catalogEntries + " >>", "<< /Type /Pages /Kids [] /Count 0 >>",
            "<< /Type /Metadata /Subtype /XML /Length " + xmp.length() + metadataEntries + " >>\nstream\n" + xmp + "\nendstream", body);
        StringBuilder pdf = new StringBuilder("%PDF-1.4\n");
        StringBuilder xref = new StringBuilder("xref\n0 " + (objects.size() + 1) + "\n0000000000 65535 f \n");
        for (int i = 0; i < objects.size(); i++) {
            xref.append(String.format("%010d 00000 n \n", pdf.length()));
            pdf.append(i + 1).append(" 0 obj\n").append(objects.get(i)).append("\nendobj\n");
        }
        int start = pdf.length();
        pdf.append(xref).append("trailer\n<< /Size ").append(objects.size() + 1).append(" /Root 1 0 R >>\nstartxref\n").append(start)
            .append("\n%%EOF\n");
        return pdf.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    private static String otherRootCertificate() {
        try {
            return Base64Converter.encode(TestCertificates.selfSigned("CN=Other Root CA").getEncoded());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // An OCSP response about the signing certificate of sample 10 (its issuer is the DITEC Test CA).
    private static String ocspResponse() throws Exception {
        return Base64Converter.encode(TestCertificates.ocspResponse(signingCertificate("10X-T.asice"), new TrustAnchorUtil().certificate(),
            TestCertificates.keyPair().getPrivate()));
    }

    private static String otherOcspResponse() throws Exception {
        X509Certificate issuer = TestCertificates.selfSigned("CN=Test CA");
        return Base64Converter.encode(TestCertificates.ocspResponse(issuer, issuer, TestCertificates.keyPair().getPrivate()));
    }

    // A CRL with the issuer name of the sample 10 signing certificate, signed by a generated key, not by the DITEC Test CA.
    private static String forgedIssuerCrl() throws Exception {
        X500Name issuer = X500Name.getInstance(signingCertificate("10X-T.asice").getIssuerX500Principal().getEncoded());
        Instant now = Instant.now();
        return Base64Converter.encode(TestCertificates.crl(issuer, TestCertificates.keyPair().getPrivate(), now, now.plus(Duration.ofDays(1))));
    }

    private static Map<String, byte[]> put(Map<String, byte[]> files, String name, byte[] content) {
        files.put(name, content);
        return files;
    }

    private static String text(byte[] data) {
        return new String(data, StandardCharsets.UTF_8);
    }

    @Test
    void containerWithoutMimetype() throws IOException {
        Map<String, byte[]> files = AsiceUtil.open(new ByteArrayInputStream(sampleBytes("10X-T.asice")));
        files.remove(AsiceUtil.MIMETYPE_FILE);

        AttributeException exception = assertThrows(AttributeException.class,
            () -> validationService.validateSignature(container("broken.asice", zip(files))));

        assertEquals("mimetype: nie je zadaný. Kontajner neobsahuje súbor mimetype.", messages.error(exception));
    }

    // ETSI TS 102 918, A.1: mimetype is the first ZIP entry and is not compressed.
    static Stream<Arguments> mimetypeEntries() {
        return Stream.of(
            arguments("mimetype not first", false, ZipEntry.STORED, Detail.MIMETYPE_NOT_FIRST),
            arguments("mimetype deflated", true, ZipEntry.DEFLATED, Detail.MIMETYPE_COMPRESSED)
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("mimetypeEntries")
    void mimetypeEntryBreaksContainerRule(String name, boolean mimetypeFirst, int method, Detail detail) throws IOException {
        Map<String, byte[]> files = AsiceUtil.open(new ByteArrayInputStream(sampleBytes("10X-T.asice")));

        AttributeException exception = assertThrows(AttributeException.class,
            () -> validationService.validateSignature(container("broken.asice", zip(files, mimetypeFirst, method))));

        assertAll(
            () -> assertEquals(AsiceUtil.MIMETYPE_FILE, exception.getAttribute(), messages.error(exception)),
            () -> assertEquals(detail, exception.getDetail(), messages.error(exception))
        );
    }

    @Test
    void notZipFile() {
        AttributeException exception = assertThrows(AttributeException.class,
            () -> validationService.validateSignature(container("text.asice", "hello".getBytes(StandardCharsets.UTF_8))));

        assertEquals("Súbor: nie je správny. Súbor nie je platný ZIP kontajner.", messages.error(exception));
    }

    @Test
    void everyDetailAndStateHasText() {
        for (Detail detail : Detail.values()) {
            String text = messages.text(detail.key(), "a", "b", "c");
            assertTrue(!text.isBlank() && !text.contains("{"), detail.name() + ": " + text);
        }
        for (State state : State.values()) {
            assertTrue(!messages.text(state.key()).isBlank(), state.name());
        }
    }

    private static byte[] sampleBytes(String sample) throws IOException {
        return new ClassPathResource("samples/" + sample).getContentAsByteArray();
    }

    private static MockMultipartFile container(String name, byte[] content) {
        return new MockMultipartFile("file", name, AsiceUtil.MIMETYPE, content);
    }

    private static byte[] zip(Map<String, byte[]> files) throws IOException {
        return zip(files, true, ZipEntry.STORED);
    }

    // ETSI TS 102 918, A.1: mimetype (when present) is the first entry and stored. The other files are deflated.
    private static byte[] zip(Map<String, byte[]> files, boolean mimetypeFirst, int mimetypeMethod) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] mimetype = files.get(AsiceUtil.MIMETYPE_FILE);
        try (ZipOutputStream zip = new ZipOutputStream(out)) {
            if (mimetype != null && mimetypeFirst) {
                putMimetype(zip, mimetype, mimetypeMethod);
            }
            for (Map.Entry<String, byte[]> file : files.entrySet()) {
                if (!AsiceUtil.MIMETYPE_FILE.equals(file.getKey())) {
                    zip.putNextEntry(new ZipEntry(file.getKey()));
                    zip.write(file.getValue());
                    zip.closeEntry();
                }
            }
            if (mimetype != null && !mimetypeFirst) {
                putMimetype(zip, mimetype, mimetypeMethod);
            }
        }
        return out.toByteArray();
    }

    // A STORED entry needs its size and CRC before the data is written.
    private static void putMimetype(ZipOutputStream zip, byte[] content, int method) throws IOException {
        ZipEntry entry = new ZipEntry(AsiceUtil.MIMETYPE_FILE);
        entry.setMethod(method);
        if (method == ZipEntry.STORED) {
            CRC32 crc = new CRC32();
            crc.update(content);
            entry.setSize(content.length);
            entry.setCompressedSize(content.length);
            entry.setCrc(crc.getValue());
        }
        zip.putNextEntry(entry);
        zip.write(content);
        zip.closeEntry();
    }

    // A central directory record: file name, content (for the CRC and sizes), compression method, local header offset.
    private record CentralEntry(String name, byte[] content, int method, int offset) {}

    // A ZIP written by hand, with every file stored after its local header (extra field from extras). change gets the
    // records that match the local headers and returns the central directory to write, so a test can make it differ.
    private static byte[] storedZip(Map<String, byte[]> files, Map<String, byte[]> extras, UnaryOperator<List<CentralEntry>> change) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        List<CentralEntry> entries = new ArrayList<>();
        for (Map.Entry<String, byte[]> file : files.entrySet()) {
            entries.add(new CentralEntry(file.getKey(), file.getValue(), ZipEntry.STORED, out.size()));
            out.writeBytes(localEntry(file.getKey(), file.getValue(), extras.getOrDefault(file.getKey(), new byte[0])));
        }
        int start = out.size();
        List<CentralEntry> central = change.apply(entries);
        for (CentralEntry entry : central) {
            byte[] name = entry.name().getBytes(StandardCharsets.UTF_8);
            out.writeBytes(littleEndian(46 + name.length).putInt(0x02014b50).putShort((short) 20).putShort((short) 20).putShort((short) 0)
                .putShort((short) entry.method()).putShort((short) 0).putShort(DOS_DATE).putInt(crc(entry.content()))
                .putInt(entry.content().length).putInt(entry.content().length).putShort((short) name.length).putInt(0)
                .putShort((short) 0).putShort((short) 0).putInt(0).putInt(entry.offset()).put(name).array());
        }
        out.writeBytes(littleEndian(22).putInt(0x06054b50).putInt(0).putShort((short) central.size()).putShort((short) central.size())
            .putInt(out.size() - start).putInt(start).putShort((short) 0).array());
        return out.toByteArray();
    }

    // A local header of a stored file, followed by the file.
    private static byte[] localEntry(String name, byte[] content, byte[] extra) {
        byte[] bytes = name.getBytes(StandardCharsets.UTF_8);
        return littleEndian(LOCAL_HEADER_LENGTH + bytes.length + extra.length + content.length).putInt(0x04034b50).putShort((short) 20)
            .putShort((short) 0).putShort((short) ZipEntry.STORED).putShort((short) 0).putShort(DOS_DATE).putInt(crc(content))
            .putInt(content.length).putInt(content.length).putShort((short) bytes.length).putShort((short) extra.length)
            .put(bytes).put(extra).put(content).array();
    }

    // Replaces the end record by a ZIP64 end record that claims count entries, its locator and an end record with the
    // ZIP64 markers, as a ZIP with more than 65535 entries has them.
    private static byte[] withZip64End(byte[] zip, long count) {
        int end = zip.length - 22;
        ByteBuffer record = ByteBuffer.wrap(zip).order(ByteOrder.LITTLE_ENDIAN);
        int size = record.getInt(end + 12);
        int offset = record.getInt(end + 16);
        return littleEndian(end + 56 + 20 + 22).put(zip, 0, end)
            .putInt(0x06064b50).putLong(44).putShort((short) 45).putShort((short) 45).putInt(0).putInt(0).putLong(count).putLong(count)
            .putLong(size).putLong(offset)
            .putInt(0x07064b50).putInt(0).putLong(end).putInt(1)
            .putInt(0x06054b50).putInt(0).putShort((short) 0xFFFF).putShort((short) 0xFFFF).putInt(size).putInt(offset).putShort((short) 0)
            .array();
    }

    private static ByteBuffer littleEndian(int size) {
        return ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
    }

    private static int crc(byte[] content) {
        CRC32 crc = new CRC32();
        crc.update(content);
        return (int) crc.getValue();
    }
}
