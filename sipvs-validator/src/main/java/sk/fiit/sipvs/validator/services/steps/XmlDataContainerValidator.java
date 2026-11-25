package sk.fiit.sipvs.validator.services.steps;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import javax.xml.validation.Schema;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;
import org.xml.sax.SAXException;
import sk.fiit.sipvs.validator.converters.XmlConverter;
import sk.fiit.sipvs.validator.converters.XsltConverter;
import sk.fiit.sipvs.validator.enums.Detail;
import sk.fiit.sipvs.validator.enums.State;
import sk.fiit.sipvs.validator.exceptions.AttributeException;
import sk.fiit.sipvs.validator.utils.DataObjectUtil;
import sk.fiit.sipvs.validator.utils.SchemaUtil;
import sk.fiit.sipvs.validator.utils.XadesConstants;
import sk.fiit.sipvs.validator.utils.XmlUtil;

import static sk.fiit.sipvs.validator.utils.ValidationUtil.checkNamespace;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.error;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.required;
import static sk.fiit.sipvs.validator.utils.XadesConstants.NS_DS;
import static sk.fiit.sipvs.validator.utils.XadesConstants.SIGNATURE;

@Service
public class XmlDataContainerValidator {

    private static final String XDC = "xdc";
    private static final String MEDIA_DESTINATION = "MediaDestinationTypeDescription";
    private static final String MEDIA_TXT = "TXT";
    private static final List<String> MEDIA_DESTINATION_TYPES = List.of(MEDIA_TXT, "HTML", "XHTML");
    private static final Set<String> XSLT_IMPORTS = Set.of("import", "include");

    void checkXmlContainer(Container container, String uri, byte[] data) {
        if (!DataObjectUtil.isUtf8(data)) {
            throw new AttributeException(uri, State.NOT_CORRECT, Detail.NOT_UTF8, uri);
        }
        String content = XmlConverter.toText(data);
        try {
            Document document = container.xml(uri);
            Element root = document.getDocumentElement();
            if (!Strings.CS.equals("XMLDataContainer", root.getLocalName())) {
                throw error(root, uri, State.NOT_CORRECT, Detail.WRONG_ROOT, root.getTagName(), "xdc:XMLDataContainer");
            }
            checkNamespace(root, uri, XadesConstants.NS_XDC);
            if (!Strings.CS.equals("xdc", root.getPrefix())) {
                throw error(root, uri, State.NOT_CORRECT, Detail.WRONG_PREFIX, root.getTagName(), root.getPrefix(), "xdc");
            }
            required(root, XadesConstants.NS_XDC, "xdc:XMLData");
            Element nested = XmlUtil.first(root, NS_DS, SIGNATURE);
            if (nested != null) {
                throw error(nested, uri, State.NOT_CORRECT, Detail.NESTED_SIGNATURE, uri);
            }
            for (Element element : XmlUtil.descendants(root, XadesConstants.NS_XDC, "*")) {
                if (element.getPrefix() == null) {
                    throw error(element, uri, State.NOT_PROVIDED, Detail.NO_PREFIX, element.getTagName(), XDC);
                }
                if (!XDC.equals(element.getPrefix())) {
                    throw error(element, uri, State.NOT_CORRECT, Detail.WRONG_PREFIX, element.getTagName(), element.getPrefix(), XDC);
                }
            }
            String encoding = document.getXmlEncoding();
            if (encoding != null && !Strings.CI.equals(StandardCharsets.UTF_8.name(), encoding)) {
                throw error(root, uri, State.NOT_CORRECT, Detail.WRONG_ENCODING, uri, encoding);
            }
        } catch (AttributeException e) {
            throw e.in(uri, content);
        }
    }

    void checkXmlContainerContent(Element root) {
        Element data = embeddedElement(required(root, XadesConstants.NS_XDC, "xdc:XMLData"));
        Element schemas = XmlUtil.child(root, XadesConstants.NS_XDC, "UsedSchemasEmbedded");
        List<Element> xsds = embeddedSchemas(root, schemas, "UsedXSDEmbedded", "UsedXSDReference");
        checkXmlData(data, xsds);
        for (Element presentation : embeddedSchemas(root, schemas, "UsedPresentationSchemaEmbedded", "UsedPresentationSchemaReference")) {
            checkPresentationSchema(presentation, data);
        }
    }

    private static List<Element> embeddedSchemas(Element root, Element schemas, String name, String referenceName) {
        List<Element> found = XmlUtil.children(schemas, XadesConstants.NS_XDC, name);
        if (found.isEmpty()) {
            List<Element> references = XmlUtil.descendants(root, XadesConstants.NS_XDC, referenceName);
            String referenced = references.stream()
                .map(reference -> StringUtils.defaultIfBlank(XmlUtil.text(reference), reference.getTagName()))
                .collect(Collectors.joining(", "));
            Node node = references.isEmpty() ? Objects.requireNonNullElse(schemas, root) : references.get(0);
            throw error(node, XDC + ":" + name, State.NOT_PROVIDED, Detail.SCHEMA_NOT_EMBEDDED, XDC + ":" + name,
                StringUtils.defaultIfEmpty(referenced, "-"));
        }
        return found;
    }

    private static void checkXmlData(Element data, List<Element> xsds) {
        List<Element> schemas = xsds.stream().map(XmlDataContainerValidator::embeddedElement).toList();
        Schema schema;
        try {
            schema = SchemaUtil.compile(schemas.stream().map(XmlConverter::toDocument).toList());
        } catch (SAXException e) {
            throw error(schemas.get(0), "xdc:UsedXSDEmbedded", State.NOT_CORRECT, Detail.XSD_NOT_COMPILED, e.getMessage());
        }
        List<SchemaUtil.SchemaError> errors = SchemaUtil.validate(schema, data);
        if (!errors.isEmpty()) {
            throw error(errors.get(0).element(), "xdc:XMLData", State.NOT_CORRECT, Detail.XML_DATA_INVALID, errors.get(0).message());
        }
    }

    private static void checkPresentationSchema(Element presentation, Element data) {
        String attribute = presentation.getTagName();
        if (!presentation.hasAttribute(MEDIA_DESTINATION)) {
            throw error(presentation, MEDIA_DESTINATION, State.NOT_PROVIDED, Detail.ATTRIBUTE_MISSING, attribute, MEDIA_DESTINATION);
        }
        String type = presentation.getAttribute(MEDIA_DESTINATION);
        if (!MEDIA_DESTINATION_TYPES.contains(type)) {
            throw error(XmlUtil.attributeNode(presentation, MEDIA_DESTINATION), MEDIA_DESTINATION, State.NOT_CORRECT, Detail.WRONG_VALUE,
                type, String.join(", ", MEDIA_DESTINATION_TYPES));
        }
        Element stylesheet = embeddedElement(presentation);
        for (Element element : XmlUtil.descendants(stylesheet, XadesConstants.NS_XSL, "*")) {
            if (XSLT_IMPORTS.contains(element.getLocalName())) {
                throw error(element, element.getTagName(), State.NOT_CORRECT, Detail.XSLT_EXTERNAL_REFERENCE, element.getAttribute("href"));
            }
        }
        String output;
        try {
            output = XsltConverter.transform(XmlConverter.toDocument(stylesheet), XmlConverter.toDocument(data));
        } catch (XsltConverter.XsltException e) {
            throw switch (e.getReason()) {
                case EXTERNAL_REFERENCE -> error(stylesheet, attribute, State.NOT_CORRECT, Detail.XSLT_EXTERNAL_REFERENCE, e.getValue());
                case TOO_LARGE -> error(stylesheet, attribute, State.TOO_LARGE, Detail.XSLT_OUTPUT_TOO_LARGE, e.getValue());
                case TIMEOUT -> error(stylesheet, attribute, State.NOT_CORRECT, Detail.XSLT_TIMEOUT, e.getValue());
                case BUSY -> error(stylesheet, attribute, State.NOT_AVAILABLE, Detail.XSLT_BUSY, e.getValue());
                case FAILED -> error(stylesheet, attribute, State.NOT_CORRECT, Detail.XSLT_FAILED, e.getValue());
            };
        }
        if (MEDIA_TXT.equals(type)) {
            int invalid = DataObjectUtil.firstInvalidXmlChar(output);
            if (invalid >= 0) {
                throw error(stylesheet, attribute, State.NOT_CORRECT, Detail.XSLT_OUTPUT_INVALID_CHAR,
                    DataObjectUtil.codePointHex(invalid));
            }
            return;
        }
        String tag = DataObjectUtil.forbiddenHtmlTag(output);
        if (tag != null) {
            throw error(forbiddenTagSource(stylesheet, tag), attribute, State.NOT_CORRECT, Detail.FORBIDDEN_HTML_TAG, type, tag);
        }
    }
    private static Element forbiddenTagSource(Element stylesheet, String tag) {
        for (Element element : XmlUtil.descendants(stylesheet, "*", "*")) {
            boolean literal = !XadesConstants.NS_XSL.equals(element.getNamespaceURI()) && Strings.CI.equals(tag, element.getLocalName());
            boolean created = XmlUtil.is(element, XadesConstants.NS_XSL, "element")
                && Strings.CI.equals(tag, StringUtils.substringAfterLast(":" + element.getAttribute("name"), ":"));
            if (literal || created) {
                return element;
            }
        }
        return stylesheet;
    }

    private static Element embeddedElement(Element parent) {
        List<Element> elements = XmlUtil.children(parent);
        Text text = null;
        StringBuilder content = new StringBuilder();
        for (Node node = parent.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (node instanceof Text part && StringUtils.isNotBlank(part.getData())) {
                text = text == null ? part : text;
                content.append(part.getData());
            }
        }
        if (elements.size() != 1 || text != null) {
            Node node = text != null ? text : elements.size() > 1 ? elements.get(1) : parent;
            throw error(node, parent.getTagName(), State.NOT_CORRECT, Detail.EMBEDDED_CONTENT, parent.getTagName(), elements.size(),
                StringUtils.strip(content.toString()).length());
        }
        return elements.get(0);
    }
}
