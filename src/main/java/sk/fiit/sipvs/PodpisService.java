package sk.fiit.sipvs;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.regex.Pattern;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.stream.StreamSource;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;

import com.openhtmltopdf.outputdevice.helper.BaseRendererBuilder.FontStyle;
import com.openhtmltopdf.pdfboxout.PdfRendererBuilder;

@Service
public class PodpisService {

    public static final String IDENTIFIKATOR = "urn:mladost:ubytovaci-protokol";
    public static final String VERZIA = "1.0";

    private static final Pattern XML_DEKLARACIA = Pattern.compile("^\\uFEFF?\\s*<\\?xml[^>]*\\?>\\s*");
    private static final String FONT = "Liberation Serif";

    private final XmlService xml;
    private final Path xsd;
    private final Path xsl;
    private final Path pdf;
    private final Path asice;

    public PodpisService(XmlService xml, @Value("${protokol.xsd}") String xsd, @Value("${protokol.xsl}") String xsl,
                         @Value("${protokol.pdf}") String pdf, @Value("${protokol.asice}") String asice) {
        this.xml = xml;
        this.xsd = Path.of(xsd);
        this.xsl = Path.of(xsl);
        this.pdf = Path.of(pdf);
        this.asice = Path.of(asice);
    }

    public record Vstupy(String xml, String xsd, String xsl, String pdf,
                         String identifikator, String verzia, String formatUri, String xsdUri, String xslUri) {
    }

    public Path pdfSubor() {
        return pdf;
    }

    public Path asiceSubor() {
        return asice;
    }

    public Vstupy vstupy() throws Exception {
        xml.requireXml();
        return new Vstupy(
                bezDeklaracie(xml.xmlSubor()),
                bezDeklaracie(xsd),
                bezDeklaracie(xsl),
                Base64.getEncoder().encodeToString(vytvorPdf()),
                IDENTIFIKATOR,
                VERZIA,
                XmlService.NS,
                XmlService.NS + "#xsd",
                XmlService.NS + "#xsl");
    }

    public byte[] vytvorPdf() throws Exception {
        xml.requireXml();
        TransformerFactory tf = TransformerFactory.newInstance();
        tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document html = dbf.newDocumentBuilder().newDocument();
        tf.newTransformer(new StreamSource(xsl.toFile()))
                .transform(new StreamSource(xml.xmlSubor().toFile()), new DOMResult(html));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PdfRendererBuilder b = new PdfRendererBuilder();
        b.useFastMode();
        b.usePdfAConformance(PdfRendererBuilder.PdfAConformance.PDFA_1_B);
        b.useColorProfile(zdroj("/sRGB.icc").readAllBytes());
        b.useFont(() -> zdroj("/fonts/LiberationSerif-Regular.ttf"), FONT, 400, FontStyle.NORMAL, true);
        b.useFont(() -> zdroj("/fonts/LiberationSerif-Bold.ttf"), FONT, 700, FontStyle.NORMAL, true);
        b.useFont(() -> zdroj("/fonts/LiberationSerif-Italic.ttf"), FONT, 400, FontStyle.ITALIC, true);
        b.useFont(() -> zdroj("/fonts/LiberationSerif-BoldItalic.ttf"), FONT, 700, FontStyle.ITALIC, true);
        b.withW3cDocument(html, null);
        b.toStream(out);
        b.run();

        Files.createDirectories(pdf.toAbsolutePath().getParent());
        Files.write(pdf, out.toByteArray());
        return out.toByteArray();
    }

    public Path ulozAsice(String base64) throws Exception {
        if (base64 == null || base64.isBlank()) {
            throw new IllegalArgumentException("Podpisovač nevrátil žiadne dáta.");
        }
        byte[] data = Base64.getMimeDecoder().decode(base64);
        if (data.length < 4 || data[0] != 'P' || data[1] != 'K') {
            throw new IllegalArgumentException("Výstup podpisovača nie je ZIP (ASiC) kontajner.");
        }
        Files.createDirectories(asice.toAbsolutePath().getParent());
        Files.write(asice, data);
        return asice;
    }

    private static String bezDeklaracie(Path subor) throws Exception {
        String text = Files.readString(subor, StandardCharsets.UTF_8);
        return XML_DEKLARACIA.matcher(text).replaceFirst("");
    }

    private InputStream zdroj(String cesta) {
        InputStream in = getClass().getResourceAsStream(cesta);
        if (in == null) {
            throw new IllegalStateException("Chýba zdroj " + cesta);
        }
        return in;
    }
}
