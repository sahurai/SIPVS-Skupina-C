package sk.fiit.sipvs;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.color.ColorSpace;
import java.awt.color.ICC_Profile;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;

import javax.imageio.ImageIO;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.stream.StreamSource;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

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
        List<String> chyby = xml.overXml();
        if (!chyby.isEmpty()) {
            throw new IllegalStateException("XML nie je platné voči XSD, preto ho nemožno podpísať. " + chyby.get(0));
        }
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
        bezPriehladnosti(html);

        // PDF/A-1 rules checked by D.Signer: the ICC profile must be version 2 (the JDK sRGB is 2.4),
        // and the fonts are embedded whole, because the subsets have a wrong CIDSet.
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PdfRendererBuilder b = new PdfRendererBuilder();
        b.useFastMode();
        b.usePdfAConformance(PdfRendererBuilder.PdfAConformance.PDFA_1_B);
        b.useColorProfile(ICC_Profile.getInstance(ColorSpace.CS_sRGB).getData());
        b.useFont(() -> zdroj("/fonts/LiberationSerif-Regular.ttf"), FONT, 400, FontStyle.NORMAL, false);
        b.useFont(() -> zdroj("/fonts/LiberationSerif-Bold.ttf"), FONT, 700, FontStyle.NORMAL, false);
        b.useFont(() -> zdroj("/fonts/LiberationSerif-Italic.ttf"), FONT, 400, FontStyle.ITALIC, false);
        b.useFont(() -> zdroj("/fonts/LiberationSerif-BoldItalic.ttf"), FONT, 700, FontStyle.ITALIC, false);
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

    // PDF/A-1 forbids transparency. Draw each embedded image on white and store it as an opaque PNG.
    private static void bezPriehladnosti(Document html) throws Exception {
        NodeList obrazky = html.getElementsByTagNameNS("*", "img");
        for (int i = 0; i < obrazky.getLength(); i++) {
            Element img = (Element) obrazky.item(i);
            String src = img.getAttribute("src");
            int ciarka = src.indexOf(',');
            if (!src.startsWith("data:") || ciarka < 0) {
                continue;
            }
            BufferedImage povodny = ImageIO.read(new ByteArrayInputStream(
                    Base64.getMimeDecoder().decode(src.substring(ciarka + 1))));
            if (povodny == null) {
                continue;
            }
            BufferedImage rgb = new BufferedImage(povodny.getWidth(), povodny.getHeight(), BufferedImage.TYPE_INT_RGB);
            Graphics2D g = rgb.createGraphics();
            g.setColor(Color.WHITE);
            g.fillRect(0, 0, rgb.getWidth(), rgb.getHeight());
            g.drawImage(povodny, 0, 0, null);
            g.dispose();
            ByteArrayOutputStream png = new ByteArrayOutputStream();
            ImageIO.write(rgb, "png", png);
            img.setAttribute("src", "data:image/png;base64," + Base64.getEncoder().encodeToString(png.toByteArray()));
        }
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
