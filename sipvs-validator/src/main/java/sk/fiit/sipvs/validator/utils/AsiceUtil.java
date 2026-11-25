package sk.fiit.sipvs.validator.utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import sk.fiit.sipvs.validator.converters.XmlConverter;
import sk.fiit.sipvs.validator.enums.Detail;
import sk.fiit.sipvs.validator.enums.State;
import sk.fiit.sipvs.validator.exceptions.AttributeException;

import static sk.fiit.sipvs.validator.utils.ValidationUtil.safe;

public final class AsiceUtil {

    public static final String MIMETYPE_FILE = "mimetype";
    public static final String MIMETYPE = "application/vnd.etsi.asic-e+zip";
    public static final String META_INF = "META-INF/";
    public static final String SIGNATURE_FILE = "META-INF/signatures.xml";
    public static final String MANIFEST_FILE = "META-INF/manifest.xml";
    public static final String MANIFEST_ROOT_ENTRY = "/";

    private static final Pattern SIGNATURE_FILES = Pattern.compile("META-INF/signatures\\d*\\.xml");
    private static final String SIGNATURE_FILE_PREFIX = "META-INF/signatures";
    private static final String XML_EXTENSION = ".xml";
    private static final String FULL_PATH = "full-path";
    private static final String MEDIA_TYPE = "media-type";
    private static final Set<String> FILE_ENTRY_ATTRIBUTES = Set.of(FULL_PATH, MEDIA_TYPE);
    private static final int MAX_UNPACKED_MB = 20;
    private static final long MAX_UNPACKED_SIZE = MAX_UNPACKED_MB * 1024L * 1024L;
    private static final byte[] ZIP_SIGNATURE = {'P', 'K', 3, 4};
    private static final byte[] END_SIGNATURE = {'P', 'K', 5, 6};
    private static final int END_RECORD_LENGTH = 22;
    private static final int END_TOTAL_OFFSET = 10;
    private static final String DEFLATED = "DEFLATED";
    private static final String STORED = "STORED";
    private static final String CONTAINER = "container";

    private static final Logger log = LoggerFactory.getLogger(AsiceUtil.class);

    private AsiceUtil() {}

    public static Map<String, byte[]> open(InputStream container) throws IOException {
        return open(CONTAINER, container);
    }

    public static Map<String, byte[]> open(String name, InputStream container) throws IOException {
        byte[] bytes = container.readAllBytes();
        if (!startsWithZipSignature(bytes)) {
            throw new AttributeException("file", State.NOT_CORRECT, Detail.CONTAINER_NOT_ZIP);
        }
        List<ZipEntry> entries = new ArrayList<>();
        Map<String, byte[]> files = readEntries(name, bytes, entries);
        if (MapUtils.isEmpty(files)) {
            throw new AttributeException("file", State.EMPTY, Detail.CONTAINER_EMPTY);
        }
        checkCentralDirectory(bytes, entries, files);
        checkMimetype(files);
        checkMimetypeEntry(bytes);
        return files;
    }

    public static List<String> signatureFiles(Map<String, byte[]> files) {
        List<String> names = files.keySet().stream().filter(name -> SIGNATURE_FILES.matcher(name).matches()).sorted().toList();
        if (names.isEmpty()) {
            throw new AttributeException(SIGNATURE_FILE, State.NOT_PROVIDED, Detail.FILE_MISSING, SIGNATURE_FILE);
        }
        for (String name : files.keySet()) {
            if (Strings.CS.startsWith(name, SIGNATURE_FILE_PREFIX) && Strings.CS.endsWith(name, XML_EXTENSION)
                && !SIGNATURE_FILES.matcher(name).matches()) {
                throw new AttributeException(name, State.NOT_CORRECT, Detail.SIGNATURE_FILE_NAME, name);
            }
        }
        return names;
    }

    public static Document parseSignatureFile(String name, byte[] xml) {
        Document document = parse(name, xml);
        for (Element element : XmlUtil.descendants(document.getDocumentElement(), "*", "*")) {
            if (element.hasAttribute("Id")) {
                element.setIdAttribute("Id", true);
            }
        }
        return document;
    }

    public static Document parseManifest(Map<String, byte[]> files) {
        byte[] manifest = files.get(MANIFEST_FILE);
        if (manifest == null) {
            throw new AttributeException(MANIFEST_FILE, State.NOT_PROVIDED, Detail.FILE_MISSING, MANIFEST_FILE);
        }
        return parse(MANIFEST_FILE, manifest);
    }

    public static Map<String, String> manifestEntries(Document manifest) {
        Map<String, String> entries = new LinkedHashMap<>();
        Element root = manifest.getDocumentElement();
        for (Element entry : XmlUtil.descendants(root, XadesConstants.NS_MANIFEST, "file-entry")) {
            String path = entry.getAttributeNS(XadesConstants.NS_MANIFEST, FULL_PATH);
            if (!MANIFEST_ROOT_ENTRY.equals(path)) {
                entries.put(path, entry.getAttributeNS(XadesConstants.NS_MANIFEST, MEDIA_TYPE));
            }
        }
        return entries;
    }

    public static Attr manifestPathAttribute(Document manifest, String path) {
        Element root = manifest.getDocumentElement();
        return XmlUtil.descendants(root, XadesConstants.NS_MANIFEST, "file-entry").stream()
            .filter(entry -> path.equals(entry.getAttributeNS(XadesConstants.NS_MANIFEST, FULL_PATH)))
            .map(entry -> entry.getAttributeNodeNS(XadesConstants.NS_MANIFEST, FULL_PATH))
            .findFirst()
            .orElse(null);
    }

    public static void checkManifestAttributes(Map<String, byte[]> files, Document document) {
        byte[] manifest = files.get(MANIFEST_FILE);
        Element root = document.getDocumentElement();
        List<Element> entries = XmlUtil.descendants(root, XadesConstants.NS_MANIFEST, "file-entry");
        for (Element entry : entries) {
            NamedNodeMap attributes = entry.getAttributes();
            for (int i = 0; i < attributes.getLength(); i++) {
                Attr attribute = (Attr) attributes.item(i);
                boolean allowed = XadesConstants.NS_XMLNS.equals(attribute.getNamespaceURI())
                    || (XadesConstants.NS_MANIFEST.equals(attribute.getNamespaceURI())
                    && FILE_ENTRY_ATTRIBUTES.contains(attribute.getLocalName()));
                if (!allowed) {
                    throw new AttributeException(MANIFEST_FILE, State.NOT_CORRECT, Detail.MANIFEST_ATTRIBUTE,
                        entry.getAttributeNS(XadesConstants.NS_MANIFEST, FULL_PATH), attribute.getName())
                        .at(attribute).in(MANIFEST_FILE, XmlConverter.toText(manifest));
                }
            }
        }
        Set<String> paths = new HashSet<>();
        for (Element entry : entries) {
            String path = entry.getAttributeNS(XadesConstants.NS_MANIFEST, FULL_PATH);
            if (!paths.add(path)) {
                throw new AttributeException(MANIFEST_FILE, State.NOT_CORRECT, Detail.MANIFEST_DUPLICATE_ENTRY, path)
                    .at(entry.getAttributeNodeNS(XadesConstants.NS_MANIFEST, FULL_PATH)).in(MANIFEST_FILE, XmlConverter.toText(manifest));
            }
        }
    }

    public static void checkManifestEncoding(Map<String, byte[]> files, Document document) {
        byte[] manifest = files.get(MANIFEST_FILE);
        String encoding = document.getXmlEncoding();
        if (encoding != null && !Strings.CI.equals(StandardCharsets.UTF_8.name(), encoding)) {
            throw new AttributeException(MANIFEST_FILE, State.NOT_CORRECT, Detail.WRONG_ENCODING, MANIFEST_FILE, encoding)
                .at(document.getDocumentElement()).in(MANIFEST_FILE, XmlConverter.toText(manifest));
        }
        if (!DataObjectUtil.isUtf8(manifest)) {
            throw new AttributeException(MANIFEST_FILE, State.NOT_CORRECT, Detail.NOT_UTF8, MANIFEST_FILE)
                .at(document.getDocumentElement()).in(MANIFEST_FILE, XmlConverter.toText(manifest));
        }
    }

    public static Document parse(String name, byte[] xml) {
        if (xml.length > XmlConverter.MAX_SIZE) {
            throw new AttributeException(name, State.TOO_LARGE, Detail.XML_TOO_LARGE, name, XmlConverter.MAX_SIZE_MB);
        }
        try {
            return XmlConverter.toDocument(xml);
        } catch (Exception e) {
            throw new AttributeException(name, State.NOT_CORRECT, Detail.XML_NOT_WELL_FORMED, name, e.getMessage())
                .in(name, XmlConverter.toText(xml));
        }
    }

    private static boolean startsWithZipSignature(byte[] bytes) {
        return bytes.length >= ZIP_SIGNATURE.length
            && Arrays.equals(ArrayUtils.subarray(bytes, 0, ZIP_SIGNATURE.length), ZIP_SIGNATURE);
    }

    private static Map<String, byte[]> readEntries(String name, byte[] bytes, List<ZipEntry> entries) {
        Map<String, byte[]> files = new LinkedHashMap<>();
        long total = 0;
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(bytes))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                entries.add(entry);
                if (entry.isDirectory()) {
                    continue;
                }
                boolean xml = isXmlFile(entry.getName());
                long limit = Math.min(MAX_UNPACKED_SIZE - total, xml ? XmlConverter.MAX_SIZE : MAX_UNPACKED_SIZE);
                byte[] content = zip.readNBytes((int) limit + 1);
                total += content.length;
                logEntry(name, entry, content.length);
                if (xml && content.length > XmlConverter.MAX_SIZE) {
                    throw new AttributeException(entry.getName(), State.TOO_LARGE, Detail.XML_TOO_LARGE, entry.getName(),
                        XmlConverter.MAX_SIZE_MB);
                }
                if (total > MAX_UNPACKED_SIZE) {
                    throw new AttributeException("file", State.TOO_LARGE, Detail.CONTAINER_TOO_LARGE, MAX_UNPACKED_MB);
                }
                if (files.put(entry.getName(), content) != null) {
                    throw new AttributeException("file", State.NOT_CORRECT, Detail.DUPLICATE_ENTRY, entry.getName());
                }
            }
        } catch (IOException | IllegalArgumentException e) {
            throw new AttributeException("file", State.NOT_CORRECT, Detail.CONTAINER_NOT_ZIP);
        }
        log.info("{}: {} file(s), {} B unpacked", safe(name), files.size(), total);
        return files;
    }

    private static void logEntry(String name, ZipEntry entry, int size) {
        String method = switch (entry.getMethod()) {
            case ZipEntry.STORED -> STORED;
            case ZipEntry.DEFLATED -> DEFLATED;
            default -> String.valueOf(entry.getMethod());
        };
        log.info("{}: {} ({} B, {})", safe(name), safe(entry.getName()), size, method);
    }

    private static boolean isXmlFile(String name) {
        return SIGNATURE_FILES.matcher(name).matches() || MANIFEST_FILE.equals(name);
    }

    private static void checkCentralDirectory(byte[] bytes, List<ZipEntry> entries, Map<String, byte[]> files) throws IOException {
        if (hasZip64EntryCount(bytes)) {
            throw new AttributeException("file", State.NOT_CORRECT, Detail.CONTAINER_NOT_ZIP);
        }
        Path temp = Files.createTempFile(CONTAINER, null);
        try {
            Files.write(temp, bytes);
            try (ZipFile zip = new ZipFile(temp.toFile())) {
                List<? extends ZipEntry> central = zip.stream().toList();
                for (int i = 0; i < Math.max(entries.size(), central.size()); i++) {
                    ZipEntry local = i < entries.size() ? entries.get(i) : null;
                    ZipEntry listed = i < central.size() ? central.get(i) : null;
                    if (local == null || listed == null || !Strings.CS.equals(local.getName(), listed.getName())
                        || local.getMethod() != listed.getMethod()) {
                        throw directoryMismatch(local == null ? listed.getName() : local.getName());
                    }
                }
                for (ZipEntry entry : central) {
                    if (!entry.isDirectory() && !sameContent(zip, entry, files.get(entry.getName()))) {
                        throw directoryMismatch(entry.getName());
                    }
                }
            } catch (ZipException | IllegalArgumentException e) {
                throw new AttributeException("file", State.NOT_CORRECT, Detail.CONTAINER_NOT_ZIP);
            }
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    private static boolean hasZip64EntryCount(byte[] bytes) {
        for (int i = 0; i + END_RECORD_LENGTH <= bytes.length; i++) {
            if (Arrays.equals(bytes, i, i + END_SIGNATURE.length, END_SIGNATURE, 0, END_SIGNATURE.length)
                && bytes[i + END_TOTAL_OFFSET] == (byte) 0xFF && bytes[i + END_TOTAL_OFFSET + 1] == (byte) 0xFF) {
                return true;
            }
        }
        return false;
    }

    private static boolean sameContent(ZipFile zip, ZipEntry entry, byte[] content) throws IOException {
        try (InputStream in = zip.getInputStream(entry)) {
            return Arrays.equals(content, in.readNBytes(content.length + 1));
        }
    }

    private static AttributeException directoryMismatch(String entry) {
        return new AttributeException("file", State.NOT_CORRECT, Detail.ZIP_DIRECTORY_MISMATCH, entry);
    }

    private static void checkMimetype(Map<String, byte[]> files) {
        byte[] mimetype = files.get(MIMETYPE_FILE);
        if (mimetype == null) {
            throw new AttributeException(MIMETYPE_FILE, State.NOT_PROVIDED, Detail.FILE_MISSING, MIMETYPE_FILE);
        }
        String value = StringUtils.trim(new String(mimetype, StandardCharsets.US_ASCII));
        if (!MIMETYPE.equals(value)) {
            throw new AttributeException(MIMETYPE_FILE, State.NOT_CORRECT, Detail.WRONG_VALUE, value, MIMETYPE);
        }
        byte[] expected = MIMETYPE.getBytes(StandardCharsets.US_ASCII);
        if (!Arrays.equals(expected, mimetype)) {
            throw new AttributeException(MIMETYPE_FILE, State.NOT_CORRECT, Detail.MIMETYPE_NOT_EXACT, mimetype.length, MIMETYPE,
                expected.length);
        }
    }

    private static void checkMimetypeEntry(byte[] bytes) {
        ZipEntry first;
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(bytes))) {
            first = zip.getNextEntry();
        } catch (IOException | IllegalArgumentException e) {
            throw new AttributeException("file", State.NOT_CORRECT, Detail.CONTAINER_NOT_ZIP);
        }
        if (!MIMETYPE_FILE.equals(first.getName())) {
            throw new AttributeException(MIMETYPE_FILE, State.NOT_CORRECT, Detail.MIMETYPE_NOT_FIRST, first.getName());
        }
        if (first.getMethod() != ZipEntry.STORED) {
            throw new AttributeException(MIMETYPE_FILE, State.NOT_CORRECT, Detail.MIMETYPE_COMPRESSED,
                first.getMethod() == ZipEntry.DEFLATED ? DEFLATED : first.getMethod());
        }
    }
}
