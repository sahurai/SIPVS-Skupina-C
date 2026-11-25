package sk.fiit.sipvs.validator.services.steps;

import java.awt.Dimension;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import sk.fiit.sipvs.validator.converters.XmlConverter;
import sk.fiit.sipvs.validator.enums.Detail;
import sk.fiit.sipvs.validator.enums.State;
import sk.fiit.sipvs.validator.exceptions.AttributeException;
import sk.fiit.sipvs.validator.utils.AsiceUtil;
import sk.fiit.sipvs.validator.utils.DataObjectUtil;
import sk.fiit.sipvs.validator.utils.PdfUtil;
import sk.fiit.sipvs.validator.utils.XadesConstants;
import sk.fiit.sipvs.validator.utils.XmlUtil;

import static sk.fiit.sipvs.validator.utils.ValidationUtil.allowedMimeTypes;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.error;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.filePath;
import static sk.fiit.sipvs.validator.utils.XadesConstants.ID;
import static sk.fiit.sipvs.validator.utils.XadesConstants.URI;

@Service
public class DataObjectValidator {

    private static final String PDF_VERSION = "1.4";
    private static final long MAX_PNG_PIXELS = 50_000_000L;
    private static final int MAX_PNG_DECODED_MB = 64;
    private static final long MB = 1024L * 1024L;

    private final XmlDataContainerValidator xmlDataContainerValidator;

    public DataObjectValidator(XmlDataContainerValidator xmlDataContainerValidator) {
        this.xmlDataContainerValidator = xmlDataContainerValidator;
    }

    public void validate(SignatureContext ctx) {
        checkDataObjects(ctx);
        checkManifest(ctx);
        checkDataObjectIds(ctx);
        checkXmlContainerContents(ctx);
        AsiceUtil.checkManifestEncoding(ctx.container.files, ctx.container.manifest());
    }

    private void checkDataObjects(SignatureContext ctx) {
        for (Element reference : ctx.fileReferences()) {
            String uri = filePath(reference);
            if (Strings.CS.startsWith(uri, AsiceUtil.META_INF)) {
                throw error(XmlUtil.attributeNode(reference, URI), "ds:Reference/@URI", State.NOT_CORRECT, Detail.FILE_IN_META_INF, uri);
            }
            try {
                checkDataObject(ctx.container, uri, ctx.mimeType(reference));
            } catch (AttributeException e) {
                throw e.getFile() == null ? e.at(XmlUtil.attributeNode(reference, URI)) : e;
            }
        }
    }

    private void checkManifest(SignatureContext ctx) {
        Map<String, String> entries = AsiceUtil.manifestEntries(ctx.container.manifest());
        for (Element reference : ctx.fileReferences()) {
            String uri = filePath(reference);
            Element mimeTypeElement = ctx.mimeTypeElement(reference);
            String mimeType = XmlUtil.text(mimeTypeElement);
            if (!entries.containsKey(uri)) {
                throw error(XmlUtil.attributeNode(reference, URI), AsiceUtil.MANIFEST_FILE, State.NOT_CORRECT, Detail.MANIFEST_ENTRY_MISSING, uri);
            }
            if (!Strings.CS.equals(mimeType, entries.get(uri))) {
                throw error(XmlUtil.textNode(mimeTypeElement), AsiceUtil.MANIFEST_FILE, State.NOT_CORRECT, Detail.MANIFEST_MEDIA_TYPE,
                    uri, entries.get(uri), mimeType);
            }
        }
        for (String path : entries.keySet()) {
            if (!ctx.container.signedFiles.contains(path)) {
                throw new AttributeException(AsiceUtil.MANIFEST_FILE, State.NOT_CORRECT, Detail.MANIFEST_EXTRA_ENTRY, path)
                    .at(AsiceUtil.manifestPathAttribute(ctx.container.manifest(), path))
                    .in(AsiceUtil.MANIFEST_FILE, XmlConverter.toText(ctx.container.files.get(AsiceUtil.MANIFEST_FILE)));
            }
        }
        AsiceUtil.checkManifestAttributes(ctx.container.files, ctx.container.manifest());
    }

    private void checkDataObjectIds(SignatureContext ctx) {
        Set<String> uris = new LinkedHashSet<>();
        for (Element reference : ctx.fileReferences()) {
            if (XadesConstants.MIME_XML_CONTAINER.equals(ctx.mimeType(reference))) {
                uris.add(filePath(reference));
            }
        }
        Set<String> seen = new HashSet<>(ctx.container.allSignatureIds);
        ctx.container.dataObjectIds.forEach((uri, ids) -> {
            if (!uris.contains(uri)) {
                seen.addAll(ids);
            }
        });
        for (String uri : uris) {
            byte[] data = ctx.container.files.get(uri);
            Element root = ctx.container.xml(uri).getDocumentElement();
            List<Element> elements = new ArrayList<>();
            elements.add(root);
            elements.addAll(XmlUtil.descendants(root, "*", "*"));
            Set<String> ids = new HashSet<>();
            for (Element element : elements) {
                String id = element.getAttribute(ID);
                if (StringUtils.isEmpty(id)) {
                    continue;
                }
                if (!seen.add(id)) {
                    throw error(XmlUtil.attributeNode(element, ID), "Id", State.NOT_CORRECT, Detail.DUPLICATE_ID, id)
                        .in(uri, XmlConverter.toText(data));
                }
                ids.add(id);
            }
            ctx.container.dataObjectIds.put(uri, ids);
        }
    }

    private void checkXmlContainerContents(SignatureContext ctx) {
        for (Element reference : ctx.fileReferences()) {
            if (!XadesConstants.MIME_XML_CONTAINER.equals(ctx.mimeType(reference))) {
                continue;
            }
            String uri = filePath(reference);
            byte[] data = ctx.container.files.get(uri);
            try {
                xmlDataContainerValidator.checkXmlContainerContent(ctx.container.xml(uri).getDocumentElement());
            } catch (AttributeException e) {
                throw e.in(uri, XmlConverter.toText(data));
            }
        }
    }

    private void checkDataObject(Container container, String uri, String mimeType) {
        byte[] data = container.files.get(uri);
        switch (mimeType) {
            case XadesConstants.MIME_TXT -> checkText(uri, data);
            case XadesConstants.MIME_PNG -> {
                if (!DataObjectUtil.isPng(data)) {
                    throw new AttributeException(uri, State.NOT_CORRECT, Detail.NOT_PNG, uri);
                }
                Dimension size = DataObjectUtil.imageSize(data);
                if (size != null && (long) size.width * size.height > MAX_PNG_PIXELS) {
                    throw new AttributeException(uri, State.TOO_LARGE, Detail.PNG_TOO_LARGE, uri, size.width + " x " + size.height,
                        MAX_PNG_PIXELS);
                }
                long decoded = DataObjectUtil.pngDecodedSize(data);
                if (decoded > MAX_PNG_DECODED_MB * MB) {
                    throw new AttributeException(uri, State.TOO_LARGE, Detail.PNG_DECODED_TOO_LARGE, uri,
                        (long) Math.ceil((double) decoded / MB), MAX_PNG_DECODED_MB);
                }
                if (!DataObjectUtil.isReadableImage(data)) {
                    throw new AttributeException(uri, State.NOT_CORRECT, Detail.PNG_NOT_READABLE, uri);
                }
            }
            case XadesConstants.MIME_PDF -> checkPdf(uri, data);
            case XadesConstants.MIME_XML_CONTAINER -> xmlDataContainerValidator.checkXmlContainer(container, uri, data);
            default -> throw new AttributeException(uri, State.NOT_CORRECT, Detail.MIME_TYPE_NOT_ALLOWED, uri, mimeType,
                allowedMimeTypes());
        }
    }

    private static void checkText(String uri, byte[] data) {
        if (!DataObjectUtil.isUtf8(data)) {
            throw new AttributeException(uri, State.NOT_CORRECT, Detail.NOT_UTF8, uri);
        }
        int invalid = DataObjectUtil.firstInvalidXmlChar(XmlConverter.toText(data));
        if (invalid >= 0) {
            throw new AttributeException(uri, State.NOT_CORRECT, Detail.INVALID_CHAR, uri,
                DataObjectUtil.codePointHex(invalid));
        }
    }

    private static void checkPdf(String uri, byte[] data) {
        String version = DataObjectUtil.pdfVersion(data);
        if (version == null) {
            throw new AttributeException(uri, State.NOT_CORRECT, Detail.NOT_PDF, uri);
        }
        if (!PDF_VERSION.equals(version)) {
            throw new AttributeException(uri, State.NOT_CORRECT, Detail.PDF_VERSION, uri, version);
        }
        checkPdfaPart(uri, data);
        String signature = DataObjectUtil.pdfSignature(data);
        if (signature != null) {
            throw new AttributeException(uri, State.NOT_CORRECT, Detail.NESTED_PDF_SIGNATURE, uri, signature);
        }
    }

    private static void checkPdfaPart(String uri, byte[] data) {
        PdfUtil.Metadata metadata;
        try {
            metadata = PdfUtil.catalogMetadata(data);
        } catch (PdfUtil.PdfException e) {
            throw new AttributeException(uri, State.NOT_PROVIDED, Detail.PDF_METADATA_MISSING, uri, e.getMessage());
        }
        if (metadata.filter() != null) {
            throw new AttributeException(uri, State.NOT_CORRECT, Detail.PDF_METADATA_FILTERED, uri, metadata.filter());
        }
        Document xmp;
        try {
            xmp = XmlConverter.toDocument(metadata.xmp());
        } catch (Exception e) {
            throw new AttributeException(uri, State.NOT_CORRECT, Detail.PDF_METADATA_NOT_XML, uri, e.getMessage());
        }
        String part = PdfUtil.pdfaPart(xmp);
        if (part == null) {
            throw new AttributeException(uri, State.NOT_CORRECT, Detail.NOT_PDFA, uri);
        }
        if (!Strings.CS.equals("1", StringUtils.strip(part))) {
            throw new AttributeException(uri, State.NOT_CORRECT, Detail.PDFA_PART, uri, part);
        }
    }
}
