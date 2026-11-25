package sk.fiit.sipvs.validator.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.xml.XMLConstants;
import javax.xml.transform.Source;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.apache.commons.lang3.StringUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import sk.fiit.sipvs.validator.converters.XmlConverter;

public final class SchemaUtil {

    private static final String SCHEMAS = "schemas/";
    private static final String DTD_TYPE = "http://www.w3.org/TR/REC-xml";
    private static final String CURRENT_ELEMENT = "http://apache.org/xml/properties/dom/current-element-node";
    private static final Map<String, String> BUNDLED = Map.of(
        XadesConstants.NS_DS, "xmldsig-core-schema.xsd",
        XadesConstants.NS_XADES, "XAdES01903v132-201601.xsd",
        XadesConstants.NS_XADES_141, "XAdES01903v141-201601.xsd",
        XadesConstants.NS_ASIC, "en_31916201v010101.xsd",
        XadesConstants.NS_DSM, "rfc6931-rsapss.xsd");

    private static final String XZEP_SCHEMA = "xades-zepbp-xzep.xsd";

    private static Schema signatureSchema;
    private static Schema xzepSchema;

    private SchemaUtil() {}

    public record SchemaError(Element element, String message) {}

    public static synchronized Schema signatureSchema() {
        if (signatureSchema == null) {
            SchemaFactory factory = factory();
            factory.setResourceResolver(bundledResolver());
            factory.setErrorHandler(new FailingHandler(false));
            try {
                signatureSchema = factory.newSchema(new Source[] {bundled(XadesConstants.NS_ASIC), bundled(XadesConstants.NS_XADES_141),
                    bundled(XadesConstants.NS_DSM)});
            } catch (SAXException e) {
                throw new IllegalStateException("Bundled signature schemas do not compile", e);
            }
        }
        return signatureSchema;
    }

    public static synchronized Schema xzepSchema() {
        if (xzepSchema == null) {
            SchemaFactory factory = factory();
            factory.setErrorHandler(new FailingHandler(false));
            try {
                xzepSchema = factory.newSchema(new StreamSource(resource(XZEP_SCHEMA), XZEP_SCHEMA));
            } catch (SAXException e) {
                throw new IllegalStateException("Bundled xzep schema does not compile", e);
            }
        }
        return xzepSchema;
    }

    public static Schema compile(List<Document> schemas) throws SAXException {
        SchemaFactory factory = factory();
        factory.setErrorHandler(new FailingHandler(true));
        return factory.newSchema(schemas.stream().map(DOMSource::new).toArray(Source[]::new));
    }

    public static List<SchemaError> validate(Schema schema, Node node) {
        Validator validator = schema.newValidator();
        List<SchemaError> errors = new ArrayList<>();
        Element root = node instanceof Document document ? document.getDocumentElement() : (Element) node;
        try {
            validator.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, StringUtils.EMPTY);
            validator.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, StringUtils.EMPTY);
            validator.setErrorHandler(new ErrorHandler() {
                @Override
                public void warning(SAXParseException e) {}

                @Override
                public void error(SAXParseException e) throws SAXException {
                    Object current = validator.getProperty(CURRENT_ELEMENT);
                    errors.add(new SchemaError(current instanceof Element element ? element : root, e.getMessage()));
                }

                @Override
                public void fatalError(SAXParseException e) throws SAXException {
                    error(e);
                }
            });
            validator.validate(new DOMSource(node));
        } catch (SAXException e) {
            errors.add(new SchemaError(root, e.getMessage()));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return errors;
    }

    private static SchemaFactory factory() {
        SchemaFactory factory = SchemaFactory.newDefaultInstance();
        try {
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, StringUtils.EMPTY);
            factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, StringUtils.EMPTY);
        } catch (SAXException e) {
            throw new IllegalStateException(e);
        }
        return factory;
    }

    private static LSResourceResolver bundledResolver() {
        return (type, namespace, publicId, systemId, base) -> {
            if (DTD_TYPE.equals(type)) {
                return input(systemId, new StringReader(StringUtils.EMPTY), null);
            }
            String file = namespace == null ? null : BUNDLED.get(namespace);
            return file == null ? null : input(systemId, null, resource(file));
        };
    }

    private static StreamSource bundled(String namespace) {
        String file = BUNDLED.get(namespace);
        URL url = SchemaUtil.class.getClassLoader().getResource(SCHEMAS + file);
        return new StreamSource(resource(file), url == null ? file : url.toExternalForm());
    }

    private static InputStream resource(String file) {
        InputStream in = SchemaUtil.class.getClassLoader().getResourceAsStream(SCHEMAS + file);
        if (in == null) {
            throw new IllegalStateException("Missing bundled schema " + file);
        }
        return in;
    }

    private static LSInput input(String systemId, StringReader reader, InputStream stream) {
        LSInput input = XmlConverter.lsInput();
        input.setSystemId(systemId);
        input.setCharacterStream(reader);
        input.setByteStream(stream);
        return input;
    }

    private record FailingHandler(boolean strict) implements ErrorHandler {

        @Override
        public void warning(SAXParseException e) throws SAXException {
            if (strict) {
                throw e;
            }
        }

        @Override
        public void error(SAXParseException e) throws SAXException {
            throw e;
        }

        @Override
        public void fatalError(SAXParseException e) throws SAXException {
            throw e;
        }
    }
}
