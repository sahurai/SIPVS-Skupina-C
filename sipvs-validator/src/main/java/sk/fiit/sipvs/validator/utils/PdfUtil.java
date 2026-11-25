package sk.fiit.sipvs.validator.utils;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public final class PdfUtil {

    public static final String NS_PDFAID = "http://www.aiim.org/pdfa/ns/id/";

    private static final String PART = "part";
    private static final String OBJ = "obj";
    private static final String END_OBJ = "endobj";
    private static final String END_STREAM = "endstream";
    private static final String START_XREF_KEYWORD = "startxref";
    private static final Pattern START_XREF = Pattern.compile("startxref\\s+(\\d{1,9})");
    private static final Pattern XREF = Pattern.compile("\\s*xref\\s+");
    private static final Pattern SUBSECTION = Pattern.compile("(\\d{1,9}) (\\d{1,9})\\s+");
    private static final Pattern ENTRY = Pattern.compile("(\\d{10}) (\\d{5}) ([nf])\\s{1,2}");
    private static final Pattern TRAILER = Pattern.compile("\\s*trailer\\s*<<");
    private static final Pattern ROOT = Pattern.compile("/Root\\s+(\\d{1,9})\\s+(\\d{1,5})\\s+R");
    private static final Pattern PREV = Pattern.compile("/Prev\\s+(\\d{1,9})");
    private static final Pattern OBJECT = Pattern.compile("\\s*(\\d{1,9})\\s+(\\d{1,5})\\s+obj\\b");
    private static final Pattern CATALOG = Pattern.compile("/Type\\s*/Catalog\\b");
    private static final Pattern METADATA = Pattern.compile("/Metadata\\s+(\\d{1,9})\\s+(\\d{1,5})\\s+R");
    private static final Pattern STREAM = Pattern.compile(">>\\s*stream\\r?\\n");
    private static final Pattern FILTER = Pattern.compile("/Filter\\s*(/[^\\s/<>\\[\\]()]+|\\[[^\\]]*\\])");

    private PdfUtil() {}

    public record Metadata(String filter, byte[] xmp) {}

    public static final class PdfException extends Exception {

        public PdfException(String missing) {
            super(missing);
        }
    }

    public static Metadata catalogMetadata(byte[] data) throws PdfException {
        String pdf = new String(data, StandardCharsets.ISO_8859_1);
        Map<Integer, Integer> offsets = new HashMap<>();
        int[] root = null;
        Set<Integer> visited = new HashSet<>();
        Integer xref = lastStartXref(pdf);
        while (xref != null && visited.add(xref)) {
            String trailer = readXref(pdf, xref, offsets);
            Matcher rootRef = ROOT.matcher(trailer);
            if (root == null && rootRef.find()) {
                root = new int[] {Integer.parseInt(rootRef.group(1)), Integer.parseInt(rootRef.group(2))};
            }
            Matcher prev = PREV.matcher(trailer);
            xref = prev.find() ? Integer.valueOf(prev.group(1)) : null;
        }
        if (root == null) {
            throw new PdfException("trailer /Root");
        }
        int catalogStart = objectStart(pdf, offsets, root);
        String catalog = pdf.substring(catalogStart, endOf(pdf, END_OBJ, catalogStart, root));
        if (!CATALOG.matcher(catalog).find()) {
            throw new PdfException(name(root) + " /Type /Catalog");
        }
        Matcher metadataRef = METADATA.matcher(catalog);
        if (!metadataRef.find()) {
            throw new PdfException("/Metadata");
        }
        int[] metadata = {Integer.parseInt(metadataRef.group(1)), Integer.parseInt(metadataRef.group(2))};
        int start = objectStart(pdf, offsets, metadata);
        Matcher stream = STREAM.matcher(pdf).region(start, endOf(pdf, END_OBJ, start, metadata));
        if (!stream.find()) {
            throw new PdfException(name(metadata) + " stream");
        }
        Matcher filter = FILTER.matcher(pdf.substring(start, stream.start()));
        String content = pdf.substring(stream.end(), endOf(pdf, END_STREAM, stream.end(), metadata));
        return new Metadata(filter.find() ? filter.group(1) : null, content.getBytes(StandardCharsets.ISO_8859_1));
    }

    public static String pdfaPart(Document xmp) {
        Element root = xmp.getDocumentElement();
        List<Element> elements = new ArrayList<>();
        elements.add(root);
        elements.addAll(XmlUtil.descendants(root, "*", "*"));
        for (Element element : elements) {
            if (element.hasAttributeNS(NS_PDFAID, PART)) {
                return element.getAttributeNS(NS_PDFAID, PART);
            }
            if (XmlUtil.is(element, NS_PDFAID, PART)) {
                return XmlUtil.text(element);
            }
        }
        return null;
    }

    private static Integer lastStartXref(String pdf) throws PdfException {
        Matcher matcher = START_XREF.matcher(pdf);
        Integer offset = null;
        while (matcher.find()) {
            offset = Integer.valueOf(matcher.group(1));
        }
        if (offset == null) {
            throw new PdfException("startxref");
        }
        return offset;
    }

    private static String readXref(String pdf, int offset, Map<Integer, Integer> offsets) throws PdfException {
        Matcher xref = XREF.matcher(pdf);
        if (offset >= pdf.length() || !xref.region(offset, pdf.length()).lookingAt()) {
            throw new PdfException("xref " + offset);
        }
        int position = xref.end();
        Matcher trailer = TRAILER.matcher(pdf);
        while (!trailer.region(position, pdf.length()).lookingAt()) {
            Matcher subsection = SUBSECTION.matcher(pdf).region(position, pdf.length());
            if (!subsection.lookingAt()) {
                throw new PdfException("xref " + offset);
            }
            int first = Integer.parseInt(subsection.group(1));
            int count = Integer.parseInt(subsection.group(2));
            position = subsection.end();
            Matcher entry = ENTRY.matcher(pdf);
            for (int i = 0; i < count; i++) {
                if (!entry.region(position, pdf.length()).lookingAt()) {
                    throw new PdfException("xref " + offset);
                }
                long objectOffset = Long.parseLong(entry.group(1));
                boolean inUse = "n".equals(entry.group(3)) && objectOffset < pdf.length();
                offsets.putIfAbsent(first + i, inUse ? (int) objectOffset : -1);
                position = entry.end();
            }
        }
        int end = pdf.indexOf(START_XREF_KEYWORD, trailer.end());
        return pdf.substring(trailer.end(), end < 0 ? pdf.length() : end);
    }

    private static int objectStart(String pdf, Map<Integer, Integer> offsets, int[] object) throws PdfException {
        Integer offset = offsets.get(object[0]);
        if (offset == null || offset < 0) {
            throw new PdfException(name(object));
        }
        Matcher header = OBJECT.matcher(pdf).region(offset, pdf.length());
        if (!header.lookingAt() || Integer.parseInt(header.group(1)) != object[0] || Integer.parseInt(header.group(2)) != object[1]) {
            throw new PdfException(name(object));
        }
        return header.end();
    }

    private static int endOf(String pdf, String keyword, int from, int[] object) throws PdfException {
        int end = pdf.indexOf(keyword, from);
        if (end < 0) {
            throw new PdfException(name(object) + StringUtils.SPACE + keyword);
        }
        return end;
    }

    private static String name(int[] object) {
        return object[0] + StringUtils.SPACE + object[1] + StringUtils.SPACE + OBJ;
    }
}
