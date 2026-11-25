package sk.fiit.sipvs.validator.converters;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

public final class CanonicalizationConverter {

    static {
        Init.init();
    }

    private CanonicalizationConverter() {}

    public static byte[] canonicalize(String algorithm, Element element) throws XMLSecurityException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Canonicalizer.getInstance(algorithm).canonicalizeSubtree(element, out);
        return out.toByteArray();
    }

    public static byte[] canonicalize(String algorithm, byte[] xml)
        throws XMLSecurityException, IOException, ParserConfigurationException, SAXException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Canonicalizer.getInstance(algorithm).canonicalizeSubtree(XmlConverter.toDocument(xml), out);
        return out.toByteArray();
    }
}
