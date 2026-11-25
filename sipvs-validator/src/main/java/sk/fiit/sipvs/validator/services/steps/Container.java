package sk.fiit.sipvs.validator.services.steps;

import java.security.cert.X509CRL;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang3.Strings;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import sk.fiit.sipvs.validator.utils.AsiceUtil;
import sk.fiit.sipvs.validator.utils.SchemaUtil;
import sk.fiit.sipvs.validator.utils.XmlUtil;

import static sk.fiit.sipvs.validator.utils.ValidationUtil.filePath;
import static sk.fiit.sipvs.validator.utils.XadesConstants.HASH;
import static sk.fiit.sipvs.validator.utils.XadesConstants.ID;
import static sk.fiit.sipvs.validator.utils.XadesConstants.NS_DS;
import static sk.fiit.sipvs.validator.utils.XadesConstants.URI;

public final class Container {

    final Map<String, byte[]> files;
    final Set<String> signedFiles = new HashSet<>();
    final Set<String> ids = new HashSet<>();
    final Set<String> allSignatureIds = new HashSet<>();
    final Map<String, Set<String>> dataObjectIds = new HashMap<>();
    private final Map<String, List<SchemaUtil.SchemaError>> schemaErrors = new HashMap<>();
    X509CRL crl;
    private Document manifest;

    public Container(Map<String, byte[]> files) {
        this.files = files;
        for (String name : AsiceUtil.signatureFiles(files)) {
            collectSignedFiles(name);
        }
    }

    public void addIds(Document document) {
        ids.addAll(ids(document));
    }

    private void collectSignedFiles(String name) {
        Document document = AsiceUtil.parse(name, files.get(name));
        allSignatureIds.addAll(ids(document));
        for (Element reference : XmlUtil.descendants(document.getDocumentElement(), NS_DS, "Reference")) {
            if (!Strings.CS.startsWith(reference.getAttribute(URI), HASH)) {
                signedFiles.add(filePath(reference));
            }
        }
    }

    List<SchemaUtil.SchemaError> schemaErrors(String fileName, Document document) {
        return schemaErrors.computeIfAbsent(fileName, name -> SchemaUtil.validate(SchemaUtil.signatureSchema(), document));
    }

    Document manifest() {
        if (manifest == null) {
            manifest = AsiceUtil.parseManifest(files);
        }
        return manifest;
    }

    Document xml(String path) {
        return AsiceUtil.parse(path, files.get(path));
    }

    private static Set<String> ids(Document document) {
        Set<String> ids = new HashSet<>();
        for (Element element : XmlUtil.descendants(document.getDocumentElement(), "*", "*")) {
            if (element.hasAttribute(ID)) {
                ids.add(element.getAttribute(ID));
            }
        }
        return ids;
    }
}
