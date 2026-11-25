package sk.fiit.sipvs.validator.converters;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSInput;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

public final class XmlConverter {

    public static final int MAX_SIZE_MB = 1;
    public static final int MAX_SIZE = MAX_SIZE_MB * 1024 * 1024;
    private static final int MAX_ELEMENT_DEPTH = 1000;
    private static final String MAX_ELEMENT_DEPTH_PROPERTY = "jdk.xml.maxElementDepth";

    private XmlConverter() {}

    public static Document toDocument(byte[] xml) throws ParserConfigurationException, SAXException, IOException {
        if (xml.length > MAX_SIZE) {
            throw new IOException("XML is larger than " + MAX_SIZE_MB + " MB");
        }
        return builder().parse(new ByteArrayInputStream(xml));
    }

    public static Document toDocument(Element element) {
        Document copy = newDocument();
        Element root = (Element) copy.importNode(element, true);
        for (Node node = element.getParentNode(); node instanceof Element ancestor; node = node.getParentNode()) {
            NamedNodeMap attributes = ancestor.getAttributes();
            for (int i = 0; i < attributes.getLength(); i++) {
                Attr attr = (Attr) attributes.item(i);
                boolean declaration = XMLConstants.XMLNS_ATTRIBUTE_NS_URI.equals(attr.getNamespaceURI());
                if (declaration && !root.hasAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, attr.getLocalName())) {
                    root.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, attr.getName(), attr.getValue());
                }
            }
        }
        copy.appendChild(root);
        return copy;
    }

    public static LSInput lsInput() {
        return ((DOMImplementationLS) newDocument().getImplementation()).createLSInput();
    }

    public static String toText(byte[] data) {
        return new String(data, StandardCharsets.UTF_8);
    }

    private static Document newDocument() {
        try {
            return builder().newDocument();
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException(e);
        }
    }

    private static DocumentBuilder builder() throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setAttribute(MAX_ELEMENT_DEPTH_PROPERTY, MAX_ELEMENT_DEPTH);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.setErrorHandler(new DefaultHandler());
        return builder;
    }
}
