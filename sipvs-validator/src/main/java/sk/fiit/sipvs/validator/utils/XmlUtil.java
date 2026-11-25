package sk.fiit.sipvs.validator.utils;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

public final class XmlUtil {

    private static final String XMLNS = "xmlns";

    private XmlUtil() {}

    public static Element first(Element parent, String ns, String localName) {
        List<Element> found = descendants(parent, ns, localName);
        return found.isEmpty() ? null : found.get(0);
    }

    public static List<Element> descendants(Element parent, String ns, String localName) {
        List<Element> result = new ArrayList<>();
        if (parent == null) {
            return result;
        }
        NodeList nodes = parent.getElementsByTagNameNS(ns, localName);
        for (int i = 0; i < nodes.getLength(); i++) {
            result.add((Element) nodes.item(i));
        }
        return result;
    }

    public static List<Element> children(Element parent) {
        List<Element> result = new ArrayList<>();
        if (parent == null) {
            return result;
        }
        for (Node node = parent.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (node instanceof Element element) {
                result.add(element);
            }
        }
        return result;
    }

    public static List<Element> children(Element parent, String ns, String localName) {
        return children(parent).stream().filter(child -> is(child, ns, localName)).toList();
    }

    public static Element child(Element parent, String ns, String localName) {
        List<Element> found = children(parent, ns, localName);
        return found.isEmpty() ? null : found.get(0);
    }

    public static boolean is(Element element, String ns, String localName) {
        return element != null && Strings.CS.equals(ns, element.getNamespaceURI())
            && Strings.CS.equals(localName, element.getLocalName());
    }

    public static String text(Element element) {
        return element == null ? StringUtils.EMPTY : StringUtils.trimToEmpty(element.getTextContent());
    }

    public static String attribute(Element element, String name) {
        return element == null ? StringUtils.EMPTY : element.getAttribute(name);
    }

    public static Node attributeNode(Element element, String name) {
        Attr attr = element.getAttributeNode(name);
        return attr == null ? element : attr;
    }

    public static Node textNode(Element element) {
        if (!children(element).isEmpty()) {
            return element;
        }
        for (Node node = element.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (node instanceof Text text && StringUtils.isNotBlank(text.getData())) {
                return text;
            }
        }
        return element;
    }

    public static Node namespaceDeclaration(Element element) {
        String name = element.getPrefix() == null ? XMLNS : XMLNS + ":" + element.getPrefix();
        for (Node current = element; current instanceof Element ancestor; current = current.getParentNode()) {
            Attr attr = ancestor.getAttributeNode(name);
            if (attr != null) {
                return attr;
            }
        }
        return element;
    }

    public static String path(Node node) {
        Node current = node instanceof Attr attr ? attr.getOwnerElement() : node;
        if (current instanceof Text) {
            current = current.getParentNode();
        }
        Deque<String> steps = new ArrayDeque<>();
        while (current != null && current.getNodeType() == Node.ELEMENT_NODE) {
            steps.push("/*[" + position(current) + "]");
            current = current.getParentNode();
        }
        return String.join(StringUtils.EMPTY, steps);
    }

    private static int position(Node node) {
        int position = 1;
        for (Node sibling = node.getPreviousSibling(); sibling != null; sibling = sibling.getPreviousSibling()) {
            if (sibling.getNodeType() == Node.ELEMENT_NODE) {
                position++;
            }
        }
        return position;
    }
}
