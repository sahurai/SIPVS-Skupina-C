package sk.fiit.sipvs.validator.utils;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import sk.fiit.sipvs.validator.converters.Base64Converter;
import sk.fiit.sipvs.validator.converters.CertificateConverter;
import sk.fiit.sipvs.validator.converters.UriConverter;
import sk.fiit.sipvs.validator.enums.Detail;
import sk.fiit.sipvs.validator.enums.State;
import sk.fiit.sipvs.validator.exceptions.AttributeException;

import static sk.fiit.sipvs.validator.utils.XadesConstants.ALGORITHM;
import static sk.fiit.sipvs.validator.utils.XadesConstants.ID;
import static sk.fiit.sipvs.validator.utils.XadesConstants.NS_DS;
import static sk.fiit.sipvs.validator.utils.XadesConstants.URI;

public final class ValidationUtil {

    private static final Pattern CONTROL_CHARS = Pattern.compile("[\\p{Cc}\\u2028\\u2029]");
    private static final String CONTROL_CHAR_REPLACEMENT = "?";

    private ValidationUtil() {}

    public static String allowedMimeTypes() {
        return XadesConstants.DATA_OBJECT_MIME_TYPES.stream().sorted().collect(Collectors.joining(", "));
    }

    public static void checkChildren(Element parent, Predicate<Element> allowed) {
        for (Element child : XmlUtil.children(parent)) {
            if (!allowed.test(child)) {
                throw error(child, child.getTagName(), State.NOT_CORRECT, Detail.ELEMENT_NOT_ALLOWED,
                    child.getTagName(), parent.getTagName());
            }
        }
    }

    public static void checkCount(Element parent, List<Element> found, String name) {
        if (found.isEmpty()) {
            throw error(parent, name, State.NOT_PROVIDED, Detail.ELEMENT_MISSING, name);
        }
        if (found.size() > 1) {
            throw error(found.get(1), name, State.NOT_CORRECT, Detail.ELEMENT_COUNT, name, found.size());
        }
    }

    public static void checkNamespace(Element element, String attribute, String expected) {
        String namespace = element.getNamespaceURI();
        if (namespace == null) {
            throw error(element, attribute, State.NOT_PROVIDED, Detail.NO_NAMESPACE, element.getTagName(), expected);
        }
        if (!expected.equals(namespace)) {
            boolean rightPrefix = Strings.CS.equals(XadesConstants.PREFIXES.get(expected), element.getPrefix());
            throw error(rightPrefix ? XmlUtil.namespaceDeclaration(element) : element, attribute, State.NOT_CORRECT, Detail.WRONG_NAMESPACE, element.getTagName(),
                namespace, expected);
        }
    }

    public static void checkAlgorithm(Element parent, Element element, String name, Set<String> supported) {
        if (element == null) {
            throw error(parent, name, State.NOT_PROVIDED, Detail.ELEMENT_MISSING, name);
        }
        String algorithm = element.getAttribute(ALGORITHM);
        if (!supported.contains(algorithm)) {
            throw error(XmlUtil.attributeNode(element, ALGORITHM), name, State.NOT_CORRECT, Detail.UNSUPPORTED_ALGORITHM, algorithm);
        }
    }

    public static List<Element> transforms(Element reference) {
        return XmlUtil.children(XmlUtil.child(reference, NS_DS, "Transforms"), NS_DS, "Transform");
    }

    public static Element required(Element parent, String ns, String name) {
        Element element = XmlUtil.child(parent, ns, StringUtils.substringAfter(name, ":"));
        if (element == null) {
            throw error(parent, name, State.NOT_PROVIDED, Detail.ELEMENT_MISSING, name);
        }
        return element;
    }

    public static Element requiredText(Element parent, String ns, String name) {
        Element element = required(parent, ns, name);
        if (StringUtils.isBlank(element.getTextContent())) {
            throw error(element, name, State.EMPTY, Detail.EMPTY_VALUE, name);
        }
        return element;
    }

    public static void requireId(Element element, String name) {
        if (StringUtils.isBlank(element.getAttribute(ID))) {
            throw error(element, name + "/@Id", State.NOT_PROVIDED, Detail.ATTRIBUTE_MISSING, name, ID);
        }
    }

    public static X509Certificate parseCertificate(Element element, String attribute) {
        try {
            return CertificateConverter.toCertificate(decode(element, attribute));
        } catch (CertificateException e) {
            throw error(XmlUtil.textNode(element), attribute, State.NOT_CORRECT, Detail.CERTIFICATE_NOT_PARSED, element.getTagName());
        }
    }

    public static byte[] decode(Element element, String attribute) {
        if (element == null) {
            throw new AttributeException(attribute, State.NOT_PROVIDED, Detail.ELEMENT_MISSING, attribute);
        }
        String text = XmlUtil.text(element);
        if (text.isEmpty()) {
            throw error(element, attribute, State.EMPTY, Detail.EMPTY_VALUE, element.getTagName());
        }
        try {
            return Base64Converter.decode(text);
        } catch (IllegalArgumentException e) {
            throw error(XmlUtil.textNode(element), attribute, State.NOT_CORRECT, Detail.NOT_BASE64, element.getTagName());
        }
    }

    public static String filePath(Element reference) {
        return UriConverter.decode(reference.getAttribute(URI));
    }

    public static AttributeException error(Node node, String attribute, State state, Detail detail,
        Object... args) {
        return new AttributeException(attribute, state, detail, args).at(node);
    }

    public static String safe(String text) {
        return CONTROL_CHARS.matcher(StringUtils.defaultString(text)).replaceAll(CONTROL_CHAR_REPLACEMENT);
    }
}
