package sk.fiit.sipvs.validator.services.steps;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

import org.apache.commons.lang3.Strings;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import sk.fiit.sipvs.validator.converters.CanonicalizationConverter;
import sk.fiit.sipvs.validator.enums.Detail;
import sk.fiit.sipvs.validator.enums.State;
import sk.fiit.sipvs.validator.utils.XmlUtil;

import static sk.fiit.sipvs.validator.utils.ValidationUtil.error;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.filePath;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.transforms;
import static sk.fiit.sipvs.validator.utils.XadesConstants.ALGORITHM;
import static sk.fiit.sipvs.validator.utils.XadesConstants.HASH;
import static sk.fiit.sipvs.validator.utils.XadesConstants.ID;
import static sk.fiit.sipvs.validator.utils.XadesConstants.NS_DS;
import static sk.fiit.sipvs.validator.utils.XadesConstants.NS_XADES;
import static sk.fiit.sipvs.validator.utils.XadesConstants.QUALIFYING_PROPERTIES;
import static sk.fiit.sipvs.validator.utils.XadesConstants.URI;

public final class SignatureContext {

    final Container container;
    final String fileName;
    final byte[] bytes;
    final Document document;
    final Element signature;
    X509Certificate certificate;
    List<X509Certificate> certificateValues = List.of();
    List<X509CRL> crlValues = List.of();
    List<OCSPResp> ocspValues = List.of();

    public SignatureContext(Container container, String fileName, byte[] bytes, Document document, Element signature) {
        this.container = container;
        this.fileName = fileName;
        this.bytes = bytes;
        this.document = document;
        this.signature = signature;
    }

    Element signedInfo() {
        Element signedInfo = XmlUtil.child(signature, NS_DS, "SignedInfo");
        if (signedInfo == null) {
            throw error(signature, "ds:SignedInfo", State.NOT_PROVIDED, Detail.ELEMENT_MISSING, "ds:SignedInfo");
        }
        return signedInfo;
    }

    List<Element> references() {
        return XmlUtil.children(signedInfo(), NS_DS, "Reference");
    }

    List<Element> fileReferences() {
        return references().stream().filter(reference -> !Strings.CS.startsWith(reference.getAttribute(URI), HASH)).toList();
    }

    Element qualifyingProperties() {
        return XmlUtil.first(signature, NS_XADES, QUALIFYING_PROPERTIES);
    }

    Element signedSignatureProperties() {
        Element signedProperties = XmlUtil.child(qualifyingProperties(), NS_XADES, "SignedProperties");
        return XmlUtil.child(signedProperties, NS_XADES, "SignedSignatureProperties");
    }

    Element unsignedSignatureProperties() {
        Element unsigned = XmlUtil.child(qualifyingProperties(), NS_XADES, "UnsignedProperties");
        return XmlUtil.child(unsigned, NS_XADES, "UnsignedSignatureProperties");
    }

    List<Element> dataObjectFormats() {
        return XmlUtil.descendants(qualifyingProperties(), NS_XADES, "DataObjectFormat");
    }

    String mimeType(Element reference) {
        return XmlUtil.text(mimeTypeElement(reference));
    }

    Element mimeTypeElement(Element reference) {
        String objectReference = HASH + reference.getAttribute(ID);
        return dataObjectFormats().stream()
            .filter(format -> objectReference.equals(format.getAttribute("ObjectReference")))
            .map(format -> XmlUtil.child(format, NS_XADES, "MimeType"))
            .filter(Objects::nonNull)
            .findFirst()
            .orElse(null);
    }

    byte[] referencedData(Element reference, String nodeSetC14n) throws Exception {
        String uri = reference.getAttribute(URI);
        List<String> algorithms = transforms(reference).stream().map(transform -> transform.getAttribute(ALGORITHM)).toList();
        byte[] data;
        int next = 0;
        if (Strings.CS.startsWith(uri, HASH)) {
            Element target = document.getElementById(Strings.CS.removeStart(uri, HASH));
            data = CanonicalizationConverter.canonicalize(algorithms.isEmpty() ? nodeSetC14n : algorithms.get(next++), target);
        } else {
            data = container.files.get(filePath(reference));
        }
        for (String algorithm : algorithms.subList(next, algorithms.size())) {
            data = CanonicalizationConverter.canonicalize(algorithm, data);
        }
        return data;
    }
}
