package sk.fiit.sipvs.validator.services.steps;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.springframework.stereotype.Service;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import sk.fiit.sipvs.validator.enums.Detail;
import sk.fiit.sipvs.validator.enums.State;
import sk.fiit.sipvs.validator.utils.CertificateUtil;
import sk.fiit.sipvs.validator.utils.SchemaUtil;
import sk.fiit.sipvs.validator.utils.XadesConstants;
import sk.fiit.sipvs.validator.utils.XmlUtil;

import static sk.fiit.sipvs.validator.utils.ValidationUtil.checkChildren;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.checkCount;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.decode;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.error;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.filePath;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.parseCertificate;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.requireId;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.required;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.requiredText;
import static sk.fiit.sipvs.validator.utils.XadesConstants.HASH;
import static sk.fiit.sipvs.validator.utils.XadesConstants.ID;
import static sk.fiit.sipvs.validator.utils.XadesConstants.NS_DS;
import static sk.fiit.sipvs.validator.utils.XadesConstants.NS_XADES;
import static sk.fiit.sipvs.validator.utils.XadesConstants.NS_XZEP;
import static sk.fiit.sipvs.validator.utils.XadesConstants.SIGNATURE_PROPERTIES;
import static sk.fiit.sipvs.validator.utils.XadesConstants.TARGET;
import static sk.fiit.sipvs.validator.utils.XadesConstants.TYPE;
import static sk.fiit.sipvs.validator.utils.XadesConstants.URI;

@Service
public class SignatureStructureValidator {

    public void validate(SignatureContext ctx) {
        checkSignatureId(ctx);
        checkSignatureValueId(ctx);
        checkSignedInfoReferences(ctx);
        checkReferenceAttributes(ctx);
        checkKeyInfo(ctx);
        checkSignatureProperties(ctx);
        checkDocumentReferences(ctx);
        checkBase64Values(ctx);
        checkSignatureStructure(ctx);
        checkX509Data(ctx);
        checkProductInfos(ctx);
        checkObjectCount(ctx);
        checkInternalReferences(ctx);
        checkSignaturePropertySchema(ctx);
    }

    private void checkSignatureId(SignatureContext ctx) {
        requireId(ctx.signature, "ds:Signature");
    }

    private void checkSignatureValueId(SignatureContext ctx) {
        Element value = XmlUtil.child(ctx.signature, NS_DS, "SignatureValue");
        if (value == null) {
            throw error(ctx.signature, "ds:SignatureValue", State.NOT_PROVIDED, Detail.ELEMENT_MISSING,
                "ds:SignatureValue");
        }
        requireId(value, "ds:SignatureValue");
    }

    private void checkSignedInfoReferences(SignatureContext ctx) {
        List<Element> typed = typedReferences(ctx);
        for (Element reference : ctx.references()) {
            if (!typed.contains(reference) && reference.hasAttribute(TYPE)) {
                throw error(XmlUtil.attributeNode(reference, TYPE), "ds:Reference/@Type", State.NOT_CORRECT, Detail.REFERENCE_UNEXPECTED_TYPE,
                    reference.getAttribute(URI), reference.getAttribute(TYPE));
            }
        }
    }

    private void checkReferenceAttributes(SignatureContext ctx) {
        for (Element reference : ctx.references()) {
            requireId(reference, "ds:Reference");
            if (StringUtils.isBlank(reference.getAttribute(URI))) {
                throw error(reference, "ds:Reference/@URI", State.NOT_PROVIDED, Detail.ATTRIBUTE_MISSING,
                    "ds:Reference", URI);
            }
        }
    }

    private void checkKeyInfo(SignatureContext ctx) {
        Element keyInfo = XmlUtil.child(ctx.signature, NS_DS, "KeyInfo");
        if (keyInfo == null) {
            throw error(ctx.signature, "ds:KeyInfo", State.NOT_PROVIDED, Detail.ELEMENT_MISSING, "ds:KeyInfo");
        }
        requireId(keyInfo, "ds:KeyInfo");
        Element x509Data = required(keyInfo, NS_DS, "ds:X509Data");
        Element certificateElement = required(x509Data, NS_DS, "ds:X509Certificate");
        Element issuerSerial = required(x509Data, NS_DS, "ds:X509IssuerSerial");
        Element subjectName = required(x509Data, NS_DS, "ds:X509SubjectName");

        ctx.certificate = parseCertificate(certificateElement, "ds:X509Certificate");
        checkIssuerSerial(issuerSerial, ctx.certificate, "ds:X509IssuerSerial");
        String subject = XmlUtil.text(subjectName);
        if (!CertificateUtil.sameName(ctx.certificate.getSubjectX500Principal(), subject)) {
            throw error(XmlUtil.textNode(subjectName), "ds:X509SubjectName", State.NOT_CORRECT, Detail.NAME_MISMATCH,
                "ds:X509SubjectName", subject, ctx.certificate.getSubjectX500Principal().getName());
        }
    }

    private void checkSignatureProperties(SignatureContext ctx) {
        Element properties = XmlUtil.first(ctx.signature, NS_DS, SIGNATURE_PROPERTIES);
        if (properties == null) {
            throw error(ctx.signature, "ds:SignatureProperties", State.NOT_PROVIDED, Detail.ELEMENT_MISSING,
                "ds:SignatureProperties");
        }
        requireId(properties, "ds:SignatureProperties");
        List<Element> items = XmlUtil.children(properties, NS_DS, "SignatureProperty");
        String target = HASH + ctx.signature.getAttribute(ID);
        boolean hasVersion = false;
        boolean hasProductInfos = false;
        for (Element item : items) {
            if (!target.equals(item.getAttribute(TARGET))) {
                throw error(XmlUtil.attributeNode(item, TARGET), "ds:SignatureProperty/@Target", State.NOT_CORRECT, Detail.PROPERTY_TARGET,
                    item.getAttribute(TARGET), target);
            }
            hasVersion |= XmlUtil.child(item, NS_XZEP, "SignatureVersion") != null;
            hasProductInfos |= XmlUtil.child(item, NS_XZEP, "ProductInfos") != null;
        }
        if (items.size() != 2 || !hasVersion || !hasProductInfos) {
            throw error(properties, "ds:SignatureProperty", State.NOT_CORRECT, Detail.SIGNATURE_PROPERTIES_CONTENT);
        }
    }

    private void checkDocumentReferences(SignatureContext ctx) {
        for (Element reference : ctx.fileReferences()) {
            String uri = filePath(reference);
            if (!ctx.container.files.containsKey(uri)) {
                throw error(XmlUtil.attributeNode(reference, URI), "ds:Reference/@URI", State.NOT_CORRECT, Detail.REFERENCE_FILE_MISSING, uri);
            }
            if (StringUtils.isEmpty(ctx.mimeType(reference))) {
                throw error(reference, "xades:MimeType", State.NOT_PROVIDED, Detail.MIME_TYPE_MISSING, uri);
            }
        }
    }

    private void checkBase64Values(SignatureContext ctx) {
        for (Element reference : ctx.references()) {
            decode(required(reference, NS_DS, "ds:DigestValue"), "ds:DigestValue");
        }
        decode(XmlUtil.child(ctx.signature, NS_DS, "SignatureValue"), "ds:SignatureValue");
    }

    private void checkSignatureStructure(SignatureContext ctx) {
        checkChildren(ctx.signature, child -> XmlUtil.is(child, NS_DS, child.getLocalName())
            && XadesConstants.SIGNATURE_CHILDREN.contains(child.getLocalName()));
        for (String name : List.of("SignedInfo", "SignatureValue", "KeyInfo")) {
            checkCount(ctx.signature, XmlUtil.children(ctx.signature, NS_DS, name), "ds:" + name);
        }
        checkOwnObject(ctx, NS_DS, "ds:SignatureProperties");
        checkOwnObject(ctx, NS_XADES, "xades:QualifyingProperties");
    }

    private void checkX509Data(SignatureContext ctx) {
        Element keyInfo = XmlUtil.child(ctx.signature, NS_DS, "KeyInfo");
        checkChildren(keyInfo, child -> XmlUtil.is(child, NS_DS, "X509Data"));
        checkCount(keyInfo, XmlUtil.children(keyInfo, NS_DS, "X509Data"), "ds:X509Data");
        Element x509Data = XmlUtil.child(keyInfo, NS_DS, "X509Data");
        checkChildren(x509Data, child -> XmlUtil.is(child, NS_DS, child.getLocalName())
            && XadesConstants.X509_DATA_CHILDREN.contains(child.getLocalName()));
        for (String name : XadesConstants.X509_DATA_CHILDREN) {
            checkCount(x509Data, XmlUtil.children(x509Data, NS_DS, name), "ds:" + name);
        }
    }

    private void checkProductInfos(SignatureContext ctx) {
        for (Element productInfo : XmlUtil.descendants(ctx.signature, NS_XZEP, "ProductInfo")) {
            requiredText(productInfo, NS_XZEP, "xzep:ProductName");
            requiredText(productInfo, NS_XZEP, "xzep:ProductVersion");
        }
        for (Element productInfos : XmlUtil.descendants(ctx.signature, NS_XZEP, "ProductInfos")) {
            if (XmlUtil.children(productInfos, NS_XZEP, "ProductInfo").isEmpty()) {
                throw error(productInfos, "xzep:ProductInfo", State.NOT_PROVIDED, Detail.ELEMENT_MISSING, "xzep:ProductInfo");
            }
        }
    }

    private void checkObjectCount(SignatureContext ctx) {
        List<Element> objects = XmlUtil.children(ctx.signature, NS_DS, "Object");
        Node signatureProperties = XmlUtil.first(ctx.signature, NS_DS, SIGNATURE_PROPERTIES).getParentNode();
        Node qualifyingProperties = ctx.qualifyingProperties().getParentNode();
        for (Element object : objects) {
            if (object != signatureProperties && object != qualifyingProperties) {
                throw error(object, "ds:Object", State.NOT_CORRECT, Detail.OBJECT_COUNT, objects.size());
            }
        }
    }

    private void checkInternalReferences(SignatureContext ctx) {
        List<Element> typed = typedReferences(ctx);
        for (Element reference : ctx.references()) {
            String uri = reference.getAttribute(URI);
            if (!typed.contains(reference) && Strings.CS.startsWith(uri, HASH)) {
                throw error(XmlUtil.attributeNode(reference, URI), "ds:Reference/@URI", State.NOT_CORRECT,
                    Detail.REFERENCE_INTERNAL, uri);
            }
        }
    }

    private void checkSignaturePropertySchema(SignatureContext ctx) {
        Element properties = XmlUtil.first(ctx.signature, NS_DS, SIGNATURE_PROPERTIES);
        for (Element property : XmlUtil.children(properties, NS_DS, "SignatureProperty")) {
            for (Element child : XmlUtil.children(property)) {
                List<SchemaUtil.SchemaError> errors = SchemaUtil.validate(SchemaUtil.xzepSchema(), child);
                if (!errors.isEmpty()) {
                    Element element = errors.get(0).element();
                    throw error(element, element.getTagName(), State.NOT_CORRECT, Detail.XZEP_SCHEMA_INVALID, child.getTagName(),
                        errors.get(0).message());
                }
            }
        }
    }

    private static void checkIssuerSerial(Element issuerSerial, X509Certificate certificate, String attribute) {
        Element issuerElement = required(issuerSerial, NS_DS, "ds:X509IssuerName");
        String issuerName = XmlUtil.text(issuerElement);
        Element serialElement = required(issuerSerial, NS_DS, "ds:X509SerialNumber");
        String serialText = XmlUtil.text(serialElement);
        BigInteger serialNumber = CertificateUtil.serialNumber(serialText);
        if (serialNumber == null) {
            throw error(XmlUtil.textNode(serialElement), attribute, State.NOT_CORRECT, Detail.SERIAL_NOT_NUMBER, serialText);
        }
        if (!certificate.getSerialNumber().equals(serialNumber)) {
            throw error(XmlUtil.textNode(serialElement), attribute, State.NOT_CORRECT, Detail.SERIAL_MISMATCH,
                serialNumber, certificate.getSerialNumber());
        }
        if (!CertificateUtil.sameName(certificate.getIssuerX500Principal(), issuerName)) {
            throw error(XmlUtil.textNode(issuerElement), attribute, State.NOT_CORRECT, Detail.NAME_MISMATCH,
                "ds:X509IssuerName", issuerName, certificate.getIssuerX500Principal().getName());
        }
    }

    private static List<Element> typedReferences(SignatureContext ctx) {
        return List.of(
            typedReference(ctx, NS_DS, "ds:KeyInfo", XadesConstants.TYPE_KEY_INFO),
            typedReference(ctx, NS_DS, "ds:SignatureProperties", XadesConstants.TYPE_SIGNATURE_PROPERTIES),
            typedReference(ctx, NS_XADES, "xades:SignedProperties", XadesConstants.TYPE_SIGNED_PROPERTIES));
    }

    private static Element typedReference(SignatureContext ctx, String ns, String name, String type) {
        Element target = XmlUtil.first(ctx.signature, ns, StringUtils.substringAfter(name, ":"));
        if (target == null) {
            throw error(ctx.signature, name, State.NOT_PROVIDED, Detail.ELEMENT_MISSING, name);
        }
        requireId(target, name);
        String uri = HASH + target.getAttribute(ID);
        Element reference = ctx.references().stream()
            .filter(r -> uri.equals(r.getAttribute(URI)))
            .findFirst()
            .orElseThrow(() -> error(ctx.signedInfo(), "ds:Reference " + name, State.NOT_PROVIDED,
                Detail.REFERENCE_MISSING, name + " (" + uri + ")"));
        if (!type.equals(reference.getAttribute(TYPE))) {
            throw error(XmlUtil.attributeNode(reference, TYPE), "ds:Reference/@Type", State.NOT_CORRECT, Detail.REFERENCE_TYPE,
                uri, reference.getAttribute(TYPE), type);
        }
        return reference;
    }

    private static void checkOwnObject(SignatureContext ctx, String ns, String name) {
        List<Element> found = XmlUtil.descendants(ctx.signature, ns, StringUtils.substringAfter(name, ":"));
        checkCount(ctx.signature, found, name);
        Element element = found.get(0);
        Node parent = element.getParentNode();
        if (!(parent instanceof Element object) || !XmlUtil.is(object, NS_DS, "Object")
            || object.getParentNode() != ctx.signature || XmlUtil.children(object).size() != 1) {
            throw error(element, name, State.NOT_CORRECT, Detail.ELEMENT_NOT_IN_OWN_OBJECT, name);
        }
    }
}
