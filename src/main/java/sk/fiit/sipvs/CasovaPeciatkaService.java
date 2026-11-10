package sk.fiit.sipvs;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.xml.XMLConstants;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.xml.parsers.DocumentBuilderFactory;

import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Part 3: extends the XAdES-BES signature in the ASiC-E container to XAdES-T.
 *
 * The service takes the whole ds:SignatureValue element (start tag, content and end tag), canonicalizes it,
 * hashes it with SHA-256 and sends the hash to the time-stamp authority (RFC 3161). The time-stamp token from
 * the answer is stored in ds:Signature/ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/
 * xades:UnsignedSignatureProperties/xades:SignatureTimeStamp/xades:EncapsulatedTimeStamp.
 * The result is a new container, the original one stays unchanged. Inside the new container the original
 * signatures.xml is not parsed and written again: the new XML is inserted into the original text, so every other
 * character of the file stays the same.
 *
 * The RFC 3161 request and response are handled with Bouncy Castle (bcpkix).
 */
@Service
public class CasovaPeciatkaService {

    static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    static final String XADES = "http://uri.etsi.org/01903/v1.3.2#";
    private static final String PODPISY = "META-INF/signatures.xml";
    private static final String MIMETYPE = "mimetype";
    private static final byte[] SHA256_ALG = {0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
            0x02, 0x01, 0x05, 0x00};

    private final PodpisService podpis;
    private final String tsaUrl;
    private final Path vystup;
    private final Duration limit;
    private final HttpClient http;

    public CasovaPeciatkaService(PodpisService podpis, @Value("${protokol.tsa.url:}") String tsaUrl,
                                 @Value("${protokol.asice-t}") String vystup,
                                 @Value("${protokol.tsa.timeout-sekundy:30}") int limitSekundy,
                                 @Value("${protokol.tsa.dovera-kazdemu-certifikatu:false}") boolean doveraKazdemu) {
        this.podpis = podpis;
        this.tsaUrl = tsaUrl == null ? "" : tsaUrl.trim();
        this.vystup = Path.of(vystup);
        this.limit = Duration.ofSeconds(limitSekundy);
        HttpClient.Builder b = HttpClient.newBuilder().connectTimeout(limit).followRedirects(HttpClient.Redirect.NORMAL);
        if (doveraKazdemu) {
            b.sslContext(sslBezKontroly());
        }
        this.http = b.build();
    }

    // The same as the C# sample (ServerCertificateValidationCallback returns true). Only for the test TSA.
    private static SSLContext sslBezKontroly() {
        try {
            TrustManager vsetkym = new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] c, String t) {
                }

                public void checkServerTrusted(X509Certificate[] c, String t) {
                }

                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            };
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{vsetkym}, new SecureRandom());
            return ctx;
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public record Vysledok(Path subor, Instant cas, String tsa) {
    }

    // data/protokol-t.tsq and data/protokol-t.tsr: the standard file types of an RFC 3161 request and response.
    private Path subor(String pripona) {
        String meno = vystup.getFileName().toString();
        int bodka = meno.lastIndexOf('.');
        return vystup.resolveSibling((bodka < 0 ? meno : meno.substring(0, bodka)) + pripona);
    }

    public Path vystupSubor() {
        return vystup;
    }

    /** Adds the time stamp to the container made by the signing step. */
    public Vysledok pridaj() throws Exception {
        if (tsaUrl.isEmpty()) {
            throw new IllegalStateException("Nie je nastavená adresa časovej pečiatky. "
                    + "Nastavte protokol.tsa.url v application.properties.");
        }
        Path vstup = podpis.asiceSubor();
        if (!Files.isRegularFile(vstup)) {
            throw new IllegalStateException("Najprv podpíšte dokument. Kontajner " + vstup + " neexistuje.");
        }
        return pridaj(Files.readAllBytes(vstup));
    }

    private Vysledok pridaj(byte[] asice) throws Exception {
        Map<String, byte[]> subory = precitajZip(asice);
        byte[] podpisyXml = subory.get(PODPISY);
        if (podpisyXml == null) {
            throw new IllegalStateException("Kontajner neobsahuje " + PODPISY + ".");
        }

        Document doc = nacitaj(podpisyXml);
        Element podpis = prvy(doc.getDocumentElement(), DS, "Signature");
        Element hodnota = prvy(podpis, DS, "SignatureValue");
        Element qp = prvy(podpis, XADES, "QualifyingProperties");
        if (prvyAleboNull(qp, XADES, "SignatureTimeStamp") != null) {
            throw new IllegalStateException("Podpis už obsahuje časovú pečiatku.");
        }
        Element signedInfo = prvy(podpis, DS, "SignedInfo");
        String c14n = prvy(signedInfo, DS, "CanonicalizationMethod").getAttribute("Algorithm");

        // The time stamp covers the whole ds:SignatureValue element, not only its text.
        byte[] kanonicky = kanonizuj(hodnota, c14n);
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(kanonicky);

        // Time-stamp request with Bouncy Castle: SHA-256 imprint, nonce, certificates requested.
        TimeStampRequestGenerator generator = new TimeStampRequestGenerator();
        generator.setCertReq(true);
        TimeStampRequest dotaz = generator.generate(TSPAlgorithms.SHA256, hash, new BigInteger(63, new SecureRandom()));
        Files.createDirectories(vystup.toAbsolutePath().getParent());
        Files.write(subor(".tsq"), dotaz.getEncoded());      // the request, as sent to the TSA
        byte[] odpoved = poslat(dotaz.getEncoded());
        Files.write(subor(".tsr"), odpoved);                 // the answer, as received (also when it is invalid)

        TimeStampResponse odpovedTsa = new TimeStampResponse(odpoved);
        try {
            odpovedTsa.validate(dotaz);   // status, hash, nonce and policy of the answer
        } catch (org.bouncycastle.tsp.TSPException e) {
            throw new IllegalStateException("Odpoveď servera časovej pečiatky nie je platná: " + e.getMessage(), e);
        }
        TimeStampToken token = odpovedTsa.getTimeStampToken();
        if (token == null) {
            throw new IllegalStateException("Odpoveď servera časovej pečiatky neobsahuje token (stav "
                    + odpovedTsa.getStatus() + ": " + odpovedTsa.getStatusString() + ").");
        }

        String id = podpis.getAttribute("Id");
        String vlozene = noveCasti(qp, hodnota, id.isEmpty() ? "signature" : id, c14n, token.getEncoded());
        subory.put(PODPISY, vlozKXml(podpisyXml, qp, vlozene));
        Files.createDirectories(vystup.toAbsolutePath().getParent());
        Files.write(vystup, zapisZip(subory));
        return new Vysledok(vystup, token.getTimeStampInfo().getGenTime().toInstant(), tsaUrl);
    }

    // ---------- XML ----------

    private static Document nacitaj(byte[] xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xml));
    }

    private static Element prvyAleboNull(Element koren, String ns, String meno) {
        NodeList l = koren.getElementsByTagNameNS(ns, meno);
        return l.getLength() == 0 ? null : (Element) l.item(0);
    }

    private static Element prvy(Element koren, String ns, String meno) {
        Element e = prvyAleboNull(koren, ns, meno);
        if (e == null) {
            throw new IllegalStateException("V podpise chýba element " + meno + ".");
        }
        return e;
    }

    private static final String C14N_10 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    private static final String C14N_10_COMMENTS = C14N_10 + "#WithComments";
    private static final String C14N_11 = "http://www.w3.org/2006/12/xml-c14n11";
    private static final String C14N_EXC = "http://www.w3.org/2001/10/xml-exc-c14n#";
    private static final String C14N_EXC_COMMENTS = C14N_EXC + "WithComments";

    /**
     * Canonical form of ds:SignatureValue together with its start and end tag, as a signature verifier sees it.
     * The element has only text inside, so the canonical form is built directly: the start tag with the namespaces
     * and attributes in the canonical order, the escaped text, the end tag.
     */
    static byte[] kanonizuj(Element el, String algoritmus) {
        boolean exclusive = algoritmus.equals(C14N_EXC) || algoritmus.equals(C14N_EXC_COMMENTS);
        if (!exclusive && !algoritmus.equals(C14N_10) && !algoritmus.equals(C14N_10_COMMENTS)
                && !algoritmus.equals(C14N_11)) {
            throw new IllegalStateException("Nepodporovaný kanonizačný algoritmus: " + algoritmus);
        }
        for (Node n = el.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n.getNodeType() != Node.TEXT_NODE && n.getNodeType() != Node.CDATA_SECTION_NODE) {
                throw new IllegalStateException("ds:SignatureValue má obsahovať iba text.");
            }
        }

        // Namespace declarations in scope for the element: the nearest declaration of a prefix wins.
        java.util.TreeMap<String, String> ns = new java.util.TreeMap<>();
        java.util.Set<String> videne = new java.util.HashSet<>();
        for (Node n = el; n instanceof Element; n = n.getParentNode()) {
            org.w3c.dom.NamedNodeMap at = n.getAttributes();
            for (int i = 0; i < at.getLength(); i++) {
                Node a = at.item(i);
                String meno = a.getNodeName();
                String prefix = meno.equals("xmlns") ? "" : meno.startsWith("xmlns:") ? meno.substring(6) : null;
                if (prefix != null && videne.add(prefix) && !(a.getNodeValue().isEmpty())) {
                    ns.put(prefix, a.getNodeValue());
                }
            }
        }
        if (exclusive) {
            // Only the namespaces the element and its attributes use visibly.
            java.util.Set<String> pouzite = new java.util.HashSet<>();
            pouzite.add(el.getPrefix() == null ? "" : el.getPrefix());
            org.w3c.dom.NamedNodeMap at = el.getAttributes();
            for (int i = 0; i < at.getLength(); i++) {
                String pf = at.item(i).getPrefix();
                if (pf != null && !pf.equals("xmlns")) {
                    pouzite.add(pf);
                }
            }
            ns.keySet().retainAll(pouzite);
        }

        StringBuilder sb = new StringBuilder("<").append(el.getNodeName());
        ns.forEach((p, u) -> sb.append(p.isEmpty() ? " xmlns=\"" : " xmlns:" + p + "=\"").append(escAttr(u)).append('"'));
        java.util.TreeMap<String, String> atributy = new java.util.TreeMap<>();
        org.w3c.dom.NamedNodeMap at = el.getAttributes();
        for (int i = 0; i < at.getLength(); i++) {
            Node a = at.item(i);
            String meno = a.getNodeName();
            if (meno.equals("xmlns") || meno.startsWith("xmlns:")) {
                continue;
            }
            // Sorted by namespace URI first (empty for no namespace), then by the local name.
            String kluc = (a.getNamespaceURI() == null ? "" : a.getNamespaceURI()) + "\u0000" + a.getLocalName();
            atributy.put(kluc, " " + meno + "=\"" + escAttr(a.getNodeValue()) + "\"");
        }
        atributy.values().forEach(sb::append);
        sb.append('>').append(escText(el.getTextContent())).append("</").append(el.getNodeName()).append('>');
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String escText(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\r", "&#xD;");
    }

    private static String escAttr(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace("\"", "&quot;").replace("\t", "&#x9;")
                .replace("\n", "&#xA;").replace("\r", "&#xD;");
    }

    /**
     * The new XML as text, with the prefixes the file already uses (xades and ds are declared on
     * QualifyingProperties). It has no line breaks or indentation, so the text of the old parts is not touched.
     */
    private static String noveCasti(Element qp, Element signatureValue, String prefix, String c14n, byte[] token) {
        String x = qp.getPrefix() == null ? "" : qp.getPrefix() + ":";
        String d = signatureValue.getPrefix() == null ? "" : signatureValue.getPrefix() + ":";
        String b64 = Base64.getEncoder().encodeToString(token);
        String timeStamp = "<" + x + "SignatureTimeStamp Id=\"" + prefix + "SignatureTimeStamp\">"
                + "<" + d + "CanonicalizationMethod Algorithm=\"" + c14n + "\"/>"
                + "<" + x + "EncapsulatedTimeStamp Id=\"" + prefix + "EncapsulatedTimeStamp\">" + b64
                + "</" + x + "EncapsulatedTimeStamp>"
                + "</" + x + "SignatureTimeStamp>";
        Element usp = prvyAleboNull(qp, XADES, "UnsignedSignatureProperties");
        if (usp != null) {
            return timeStamp;                       // goes into the existing UnsignedSignatureProperties
        }
        String vnutri = "<" + x + "UnsignedSignatureProperties>" + timeStamp + "</" + x + "UnsignedSignatureProperties>";
        if (prvyAleboNull(qp, XADES, "UnsignedProperties") != null) {
            return vnutri;                          // goes into the existing UnsignedProperties
        }
        return "<" + x + "UnsignedProperties Id=\"" + prefix + "UnsignedProperties\">" + vnutri
                + "</" + x + "UnsignedProperties>";
    }

    /** Inserts the text before the end tag of the parent element. The rest of the file stays byte for byte the same. */
    private static byte[] vlozKXml(byte[] povodne, Element qp, String vlozene) {
        Element rodic = prvyAleboNull(qp, XADES, "UnsignedSignatureProperties");
        if (rodic == null) {
            rodic = prvyAleboNull(qp, XADES, "UnsignedProperties");
        }
        if (rodic == null) {
            rodic = qp;
        }
        String koniec = "</" + rodic.getTagName() + ">";
        String text = new String(povodne, StandardCharsets.UTF_8);
        int pozicia = text.indexOf(koniec);
        if (pozicia < 0 || pozicia != text.lastIndexOf(koniec)) {
            throw new IllegalStateException("V " + PODPISY + " sa nepodarilo nájsť jednoznačné miesto pre časovú pečiatku.");
        }
        return (text.substring(0, pozicia) + vlozene + text.substring(pozicia)).getBytes(StandardCharsets.UTF_8);
    }

    // ---------- ZIP ----------

    private static Map<String, byte[]> precitajZip(byte[] data) throws IOException {
        Map<String, byte[]> m = new LinkedHashMap<>();
        try (ZipInputStream zin = new ZipInputStream(new ByteArrayInputStream(data), StandardCharsets.UTF_8)) {
            for (ZipEntry e; (e = zin.getNextEntry()) != null; ) {
                if (!e.isDirectory()) {
                    m.put(e.getName(), zin.readAllBytes());
                }
            }
        }
        return m;
    }

    // The ASiC rule: "mimetype" is the first entry and it is stored without compression.
    private static byte[] zapisZip(Map<String, byte[]> subory) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ZipOutputStream zout = new ZipOutputStream(out, StandardCharsets.UTF_8)) {
            byte[] mime = subory.get(MIMETYPE);
            if (mime != null) {
                ZipEntry e = new ZipEntry(MIMETYPE);
                e.setMethod(ZipEntry.STORED);
                e.setSize(mime.length);
                e.setCompressedSize(mime.length);
                CRC32 crc = new CRC32();
                crc.update(mime);
                e.setCrc(crc.getValue());
                zout.putNextEntry(e);
                zout.write(mime);
                zout.closeEntry();
            }
            for (Map.Entry<String, byte[]> s : subory.entrySet()) {
                if (s.getKey().equals(MIMETYPE)) {
                    continue;
                }
                zout.putNextEntry(new ZipEntry(s.getKey()));
                zout.write(s.getValue());
                zout.closeEntry();
            }
        }
        return out.toByteArray();
    }

    // ---------- RFC 3161 ----------

    private static final String TS_REPLY_MIME_TYPE = "application/timestamp-reply";

    private byte[] poslat(byte[] dotaz) throws Exception {
        HttpRequest rq = HttpRequest.newBuilder(URI.create(tsaUrl)).timeout(limit)
                .header("Content-Type", "application/timestamp-query")
                .POST(HttpRequest.BodyPublishers.ofByteArray(dotaz)).build();
        HttpResponse<byte[]> res;
        try {
            res = http.send(rq, HttpResponse.BodyHandlers.ofByteArray());
        } catch (IOException e) {
            throw new IllegalStateException("Server časovej pečiatky je nedostupný (" + tsaUrl + "): "
                    + (e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName()), e);
        }
        if (res.statusCode() != 200) {
            throw new IllegalStateException("Server časovej pečiatky vrátil HTTP " + res.statusCode() + ".");
        }
        String typ = res.headers().firstValue("Content-Type").orElse("");
        if (!typ.split(";")[0].trim().equalsIgnoreCase(TS_REPLY_MIME_TYPE)) {
            throw new IllegalStateException("Nesprávny MIME typ odpovede servera časovej pečiatky: " + typ);
        }
        return res.body();
    }
}
