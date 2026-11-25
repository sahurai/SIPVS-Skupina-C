package sk.fiit.sipvs.validator.utils;

import java.util.Map;
import java.util.Set;

public final class XadesConstants {

    public static final String NS_DS = "http://www.w3.org/2000/09/xmldsig#";
    public static final String NS_DSM = "http://www.w3.org/2007/05/xmldsig-more#";
    public static final String NS_XADES = "http://uri.etsi.org/01903/v1.3.2#";
    public static final String NS_XADES_141 = "http://uri.etsi.org/01903/v1.4.1#";
    public static final String NS_ASIC = "http://uri.etsi.org/02918/v1.2.1#";
    public static final String NS_XZEP = "http://www.ditec.sk/ep/signature_formats/xades_zepbp/v1.0";
    public static final String NS_XDC = "http://data.gov.sk/def/container/xmldatacontainer+xml/1.0";
    public static final String NS_MANIFEST = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";
    public static final String NS_XMLNS = "http://www.w3.org/2000/xmlns/";
    public static final String NS_XSL = "http://www.w3.org/1999/XSL/Transform";

    public static final String ID = "Id";
    public static final String URI = "URI";
    public static final String ALGORITHM = "Algorithm";
    public static final String TYPE = "Type";
    public static final String TARGET = "Target";
    public static final String HASH = "#";

    // Local names of elements that are looked up with XmlUtil.first.
    public static final String SIGNATURE = "Signature";
    public static final String SIGNATURE_VERSION = "SignatureVersion";
    public static final String SIGNATURE_PROPERTIES = "SignatureProperties";
    public static final String X509_CERTIFICATE = "X509Certificate";
    public static final String QUALIFYING_PROPERTIES = "QualifyingProperties";

    public static final Map<String, String> PREFIXES = Map.of(
        NS_DS, "ds",
        NS_XADES, "xades",
        NS_XADES_141, "xadesv141",
        NS_XZEP, "xzep",
        NS_ASIC, "asic",
        NS_XDC, "xdc",
        NS_DSM, "dsm");

    public static final String TYPE_KEY_INFO = "http://www.w3.org/2000/09/xmldsig#Object";
    public static final String TYPE_SIGNATURE_PROPERTIES = "http://www.w3.org/2000/09/xmldsig#SignatureProperties";
    public static final String TYPE_SIGNED_PROPERTIES = "http://uri.etsi.org/01903#SignedProperties";

    public static final String MIME_XML_CONTAINER = "application/vnd.gov.sk.xmldatacontainer+xml; charset=UTF-8";
    public static final String MIME_PNG = "image/png";
    public static final String MIME_PDF = "application/pdf";
    public static final String MIME_TXT = "text/plain; charset=UTF-8";
    public static final String MIME_SIGNATURE_PART = "application/xml";
    public static final Set<String> DATA_OBJECT_MIME_TYPES = Set.of(MIME_XML_CONTAINER, MIME_PNG, MIME_PDF, MIME_TXT);

    public static final Set<String> SIGNATURE_CHILDREN = Set.of("SignedInfo", "SignatureValue", "KeyInfo", "Object");
    public static final Set<String> QUALIFYING_PROPERTIES_CHILDREN = Set.of("SignedProperties", "UnsignedProperties");
    public static final Set<String> SIGNED_PROPERTIES_CHILDREN = Set.of("SignedSignatureProperties", "SignedDataObjectProperties");
    public static final Set<String> SIGNED_SIGNATURE_PROPERTIES_CHILDREN =
        Set.of("SigningTime", "SigningCertificate", "SignaturePolicyIdentifier");
    public static final Set<String> SIGNED_DATA_OBJECT_PROPERTIES_CHILDREN = Set.of("DataObjectFormat");
    public static final Set<String> UNSIGNED_PROPERTIES_CHILDREN = Set.of("UnsignedSignatureProperties");
    public static final Map<String, String> UNSIGNED_SIGNATURE_PROPERTIES_CHILDREN = Map.of(
        "SignatureTimeStamp", NS_XADES,
        "CertificateValues", NS_XADES,
        "RevocationValues", NS_XADES,
        "TimeStampValidationData", NS_XADES_141,
        "ArchiveTimeStamp", NS_XADES_141);
    public static final Set<String> X509_DATA_CHILDREN = Set.of("X509Certificate", "X509IssuerSerial", "X509SubjectName");

    public static final String CRL_URL = "https://testpki.ditec.sk/CertGen2/Data/qes/DITEC%20Test%20CA%20SHA256%20RSA/Crls/DITEC%20Test%20CA%20SHA256%20RSA.crl";

    private XadesConstants() {}
}
