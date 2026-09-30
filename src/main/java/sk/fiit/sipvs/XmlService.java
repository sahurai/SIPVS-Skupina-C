package sk.fiit.sipvs;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

@Service
public class XmlService {

    public static final String NS = "urn:mladost:ubytovaci-protokol:1.0";

    private final Path xsd;
    private final Path xsl;
    private final Path xml;
    private final Path html;

    public XmlService(@Value("${protokol.xsd}") String xsd, @Value("${protokol.xsl}") String xsl,
                      @Value("${protokol.xml}") String xml, @Value("${protokol.html}") String html) {
        this.xsd = Path.of(xsd);
        this.xsl = Path.of(xsl);
        this.xml = Path.of(xml);
        this.html = Path.of(html);
    }

    public Path xmlSubor() {
        return xml;
    }

    public Path htmlSubor() {
        return html;
    }

    public Path ulozXml(Protokol p) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().newDocument();

        Element root = doc.createElementNS(NS, "ubytovaciProtokol");
        doc.appendChild(root);

        Element student = child(root, "student");
        student.setAttribute("univerzitneId", p.univerzitneId());
        text(student, "meno", p.meno());
        text(student, "priezvisko", p.priezvisko());
        text(student, "datumNarodenia", p.datumNarodenia());
        text(student, "statnaPrislusnost", p.statnaPrislusnost());
        text(student, "fakulta", p.fakulta());
        text(student, "rocnik", p.rocnik());
        optional(student, "telefon", p.telefon());
        optional(student, "email", p.email());
        if (p.fotografia() != null && p.fotografia().data() != null && !p.fotografia().data().isBlank()) {
            text(student, "fotografia", p.fotografia().data()).setAttribute("typ", p.fotografia().typ());
        }
        optional(student, "zakonnyZastupca", p.zakonnyZastupca());

        Element adresa = child(root, "adresa");
        text(adresa, "ulica", p.adresa().ulica());
        text(adresa, "cislo", p.adresa().cislo());
        text(adresa, "mesto", p.adresa().mesto());
        text(adresa, "psc", p.adresa().psc());
        text(adresa, "stat", p.adresa().stat());

        if (p.spotrebice() != null && !p.spotrebice().isEmpty()) {
            Element spotrebice = child(root, "spotrebice");
            int celkovyPrikon = 0;
            for (Protokol.Spotrebic s : p.spotrebice()) {
                Element spotrebic = child(spotrebice, "spotrebic");
                spotrebic.setAttribute("typ", s.typ());
                text(spotrebic, "znacka", s.znacka());
                text(spotrebic, "serioveCislo", s.serioveCislo());
                text(spotrebic, "prikon", s.prikon());
                celkovyPrikon += s.prikon();
            }
            // The server calculates the total. It does not trust the value from the browser.
            text(spotrebice, "celkovyPrikon", celkovyPrikon);
        }

        Element potvrdenie = child(root, "potvrdenie");
        text(potvrdenie, "suhlas", p.suhlas());
        text(potvrdenie, "datumVyplnenia", p.datumVyplnenia());

        Files.createDirectories(xml.toAbsolutePath().getParent());
        Transformer t = TransformerFactory.newInstance().newTransformer();
        t.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        t.setOutputProperty(OutputKeys.INDENT, "yes");
        t.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
        try (OutputStream out = Files.newOutputStream(xml)) {
            t.transform(new DOMSource(doc), new StreamResult(out));
        }
        return xml;
    }

    public List<String> overXml() throws Exception {
        requireXml();
        List<String> chyby = new ArrayList<>();
        Validator validator = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI)
                .newSchema(xsd.toFile())
                .newValidator();
        // Collect all errors. Stop only when the document is not well-formed.
        validator.setErrorHandler(new ErrorHandler() {
            @Override
            public void warning(SAXParseException e) {
                chyby.add(popis("Varovanie", e));
            }

            @Override
            public void error(SAXParseException e) {
                chyby.add(popis("Chyba", e));
            }

            @Override
            public void fatalError(SAXParseException e) throws SAXException {
                chyby.add(popis("Fatálna chyba", e));
                throw e;
            }
        });
        try {
            validator.validate(new StreamSource(xml.toFile()));
        } catch (SAXParseException e) {
            // The handler has already recorded this error.
        }
        return chyby;
    }

    public Path transformujXml() throws Exception {
        requireXml();
        TransformerFactory tf = TransformerFactory.newInstance();
        tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        Transformer t = tf.newTransformer(new StreamSource(xsl.toFile()));
        Files.createDirectories(html.toAbsolutePath().getParent());
        t.transform(new StreamSource(xml.toFile()), new StreamResult(html.toFile()));
        return html;
    }

    void requireXml() {
        if (!Files.exists(xml)) {
            throw new IllegalStateException("Súbor " + xml + " neexistuje. Najprv stlačte Ulož XML.");
        }
    }

    private static Element child(Element parent, String name) {
        Element e = parent.getOwnerDocument().createElementNS(NS, name);
        parent.appendChild(e);
        return e;
    }

    private static Element text(Element parent, String name, Object value) {
        Element e = child(parent, name);
        e.setTextContent(value == null ? "" : value.toString());
        return e;
    }

    private static void optional(Element parent, String name, String value) {
        if (value != null && !value.isBlank()) {
            text(parent, name, value.trim());
        }
    }

    private static String popis(String druh, SAXParseException e) {
        return druh + " [riadok " + e.getLineNumber() + ", stĺpec " + e.getColumnNumber() + "]: " + e.getMessage();
    }
}
