package sk.fiit.sipvs.validator.services.steps;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.springframework.stereotype.Service;
import org.w3c.dom.Element;
import sk.fiit.sipvs.validator.enums.Detail;
import sk.fiit.sipvs.validator.enums.State;
import sk.fiit.sipvs.validator.utils.DataObjectUtil;
import sk.fiit.sipvs.validator.utils.XadesConstants;
import sk.fiit.sipvs.validator.utils.XmlUtil;

import static sk.fiit.sipvs.validator.utils.ValidationUtil.checkNamespace;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.error;
import static sk.fiit.sipvs.validator.utils.XadesConstants.ID;
import static sk.fiit.sipvs.validator.utils.XadesConstants.NS_DS;
import static sk.fiit.sipvs.validator.utils.XadesConstants.NS_XADES;
import static sk.fiit.sipvs.validator.utils.XadesConstants.NS_XZEP;
import static sk.fiit.sipvs.validator.utils.XadesConstants.SIGNATURE_PROPERTIES;
import static sk.fiit.sipvs.validator.utils.XadesConstants.SIGNATURE_VERSION;

@Service
public class ProfileValidator {

    public void validate(SignatureContext ctx) {
        checkSignatureVersion(ctx);
        checkDsNamespace(ctx);
        checkAsicNamespace(ctx);
        checkRoot(ctx);
        checkEncoding(ctx);
        checkPrefixes(ctx);
        checkUniqueIds(ctx);
        checkNamespaceDeclarations(ctx);
    }

    private void checkSignatureVersion(SignatureContext ctx) {
        Element version = XmlUtil.first(ctx.signature, "*", SIGNATURE_VERSION);
        if (version == null) {
            throw error(ctx.signature, "xzep:SignatureVersion", State.NOT_PROVIDED, Detail.ELEMENT_MISSING,
                "xzep:SignatureVersion");
        }
        checkNamespace(version, "xzep:SignatureVersion", NS_XZEP);
        String value = XmlUtil.text(version);
        if (!NS_XZEP.equals(value)) {
            throw error(XmlUtil.textNode(version), "xzep:SignatureVersion", State.NOT_CORRECT, Detail.WRONG_VALUE, value, NS_XZEP);
        }
    }

    private void checkDsNamespace(SignatureContext ctx) {
        Element signature = ctx.signature;
        checkNamespace(signature, "xmlns:ds", NS_DS);
        if (!signature.hasAttributeNS(XadesConstants.NS_XMLNS, "ds")) {
            throw error(signature, "xmlns:ds", State.NOT_PROVIDED, Detail.ATTRIBUTE_MISSING, "ds:Signature", "xmlns:ds");
        }
        String value = signature.getAttributeNS(XadesConstants.NS_XMLNS, "ds");
        if (!NS_DS.equals(value)) {
            throw error(XmlUtil.attributeNode(signature, "xmlns:ds"), "xmlns:ds", State.NOT_CORRECT, Detail.WRONG_VALUE, value, NS_DS);
        }
    }

    private void checkAsicNamespace(SignatureContext ctx) {
        Element root = ctx.document.getDocumentElement();
        if (!root.hasAttributeNS(XadesConstants.NS_XMLNS, "asic")) {
            throw error(root, "xmlns:asic", State.NOT_PROVIDED, Detail.ATTRIBUTE_MISSING, root.getTagName(), "xmlns:asic");
        }
        String value = root.getAttributeNS(XadesConstants.NS_XMLNS, "asic");
        if (!XadesConstants.NS_ASIC.equals(value)) {
            throw error(XmlUtil.attributeNode(root, "xmlns:asic"), "xmlns:asic", State.NOT_CORRECT, Detail.WRONG_VALUE, value, XadesConstants.NS_ASIC);
        }
        checkNamespace(root, "xmlns:asic", XadesConstants.NS_ASIC);
    }

    private void checkRoot(SignatureContext ctx) {
        Element root = ctx.document.getDocumentElement();
        if (!Strings.CS.equals("XAdESSignatures", root.getLocalName())) {
            throw error(root, "asic:XAdESSignatures", State.NOT_CORRECT, Detail.WRONG_ROOT, root.getTagName(),
                "asic:XAdESSignatures");
        }
    }

    private void checkEncoding(SignatureContext ctx) {
        String encoding = ctx.document.getXmlEncoding();
        if (encoding != null && !Strings.CI.equals(StandardCharsets.UTF_8.name(), encoding)) {
            throw error(ctx.document.getDocumentElement(), ctx.fileName, State.NOT_CORRECT, Detail.WRONG_ENCODING,
                ctx.fileName, encoding);
        }
        if (!DataObjectUtil.isUtf8(ctx.bytes)) {
            throw error(ctx.document.getDocumentElement(), ctx.fileName, State.NOT_CORRECT, Detail.NOT_UTF8, ctx.fileName);
        }
    }

    private void checkPrefixes(SignatureContext ctx) {
        List<Element> elements = new ArrayList<>();
        elements.add(ctx.document.getDocumentElement());
        elements.add(ctx.signature);
        elements.addAll(XmlUtil.descendants(ctx.signature, "*", "*"));
        for (Element element : elements) {
            String namespace = element.getNamespaceURI();
            String expected = namespace == null ? null : XadesConstants.PREFIXES.get(namespace);
            if (expected != null && element.getPrefix() == null) {
                throw error(element, "xmlns:" + expected, State.NOT_PROVIDED, Detail.NO_PREFIX,
                    element.getTagName(), expected);
            }
            if (expected != null && !expected.equals(element.getPrefix())) {
                throw error(element, "xmlns:" + expected, State.NOT_CORRECT, Detail.WRONG_PREFIX,
                    element.getTagName(), element.getPrefix(), expected);
            }
        }
    }

    private void checkUniqueIds(SignatureContext ctx) {
        Set<String> seen = new HashSet<>(ctx.container.ids);
        for (Element element : XmlUtil.descendants(ctx.document.getDocumentElement(), "*", "*")) {
            String id = element.getAttribute(ID);
            if (StringUtils.isNotEmpty(id) && !seen.add(id)) {
                throw error(XmlUtil.attributeNode(element, ID), "Id", State.NOT_CORRECT, Detail.DUPLICATE_ID, id);
            }
        }
    }

    private void checkNamespaceDeclarations(SignatureContext ctx) {
        checkDeclaration(XmlUtil.first(ctx.signature, NS_DS, SIGNATURE_PROPERTIES), "xzep", NS_XZEP);
        checkDeclaration(ctx.qualifyingProperties(), "xades", NS_XADES);
    }

    private static void checkDeclaration(Element element, String prefix, String expected) {
        if (element == null) {
            return;
        }
        String attribute = "xmlns:" + prefix;
        if (!element.hasAttributeNS(XadesConstants.NS_XMLNS, prefix)) {
            throw error(element, attribute, State.NOT_PROVIDED, Detail.ATTRIBUTE_MISSING, element.getTagName(), attribute);
        }
        String value = element.getAttributeNS(XadesConstants.NS_XMLNS, prefix);
        if (!expected.equals(value)) {
            throw error(XmlUtil.attributeNode(element, attribute), attribute, State.NOT_CORRECT, Detail.WRONG_VALUE, value, expected);
        }
    }
}
