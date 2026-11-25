package sk.fiit.sipvs.validator.services;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Semaphore;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;
import sk.fiit.sipvs.validator.converters.XmlConverter;
import sk.fiit.sipvs.validator.dto.FileResult;
import sk.fiit.sipvs.validator.dto.Location;
import sk.fiit.sipvs.validator.enums.Detail;
import sk.fiit.sipvs.validator.enums.Mark;
import sk.fiit.sipvs.validator.enums.State;
import sk.fiit.sipvs.validator.exceptions.AttributeException;
import sk.fiit.sipvs.validator.services.steps.AlgorithmValidator;
import sk.fiit.sipvs.validator.services.steps.Container;
import sk.fiit.sipvs.validator.services.steps.CoreValidator;
import sk.fiit.sipvs.validator.services.steps.DataObjectValidator;
import sk.fiit.sipvs.validator.services.steps.ProfileValidator;
import sk.fiit.sipvs.validator.services.steps.QualifyingPropertiesValidator;
import sk.fiit.sipvs.validator.services.steps.SignatureContext;
import sk.fiit.sipvs.validator.services.steps.SignatureStructureValidator;
import sk.fiit.sipvs.validator.services.steps.SigningCertificateValidator;
import sk.fiit.sipvs.validator.services.steps.TimestampValidator;
import sk.fiit.sipvs.validator.utils.AsiceUtil;
import sk.fiit.sipvs.validator.utils.MessageUtil;
import sk.fiit.sipvs.validator.utils.XmlUtil;

import static sk.fiit.sipvs.validator.utils.ValidationUtil.error;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.safe;

@Service
public class ValidationService {

    private static final Logger log = LoggerFactory.getLogger(ValidationService.class);

    public static final int MAX_VALIDATIONS = 4;

    private static final String ASICE_EXTENSION = ".asice";

    private final MessageUtil messages;
    private final ProfileValidator profileValidator;
    private final AlgorithmValidator algorithmValidator;
    private final SignatureStructureValidator signatureStructureValidator;
    private final QualifyingPropertiesValidator qualifyingPropertiesValidator;
    private final DataObjectValidator dataObjectValidator;
    private final SigningCertificateValidator signingCertificateValidator;
    private final TimestampValidator timestampValidator;
    private final CoreValidator coreValidator;
    private final Semaphore validations = new Semaphore(MAX_VALIDATIONS);

    public ValidationService(MessageUtil messages, ProfileValidator profileValidator, AlgorithmValidator algorithmValidator,
        SignatureStructureValidator signatureStructureValidator, QualifyingPropertiesValidator qualifyingPropertiesValidator,
        DataObjectValidator dataObjectValidator, SigningCertificateValidator signingCertificateValidator,
        TimestampValidator timestampValidator, CoreValidator coreValidator) {
        this.messages = messages;
        this.profileValidator = profileValidator;
        this.algorithmValidator = algorithmValidator;
        this.signatureStructureValidator = signatureStructureValidator;
        this.qualifyingPropertiesValidator = qualifyingPropertiesValidator;
        this.dataObjectValidator = dataObjectValidator;
        this.signingCertificateValidator = signingCertificateValidator;
        this.timestampValidator = timestampValidator;
        this.coreValidator = coreValidator;
    }

    public List<FileResult> validate(List<MultipartFile> files) {
        if (CollectionUtils.isEmpty(files)) {
            throw new AttributeException("file", State.NOT_PROVIDED);
        }
        return files.stream().map(this::validateFile).toList();
    }

    private FileResult validateFile(MultipartFile file) {
        String name = StringUtils.defaultString(file.getOriginalFilename());
        if (file.isEmpty()) {
            log.warn("{}: file is empty", safe(name));
            return FileResult.error(name, messages.error(name, State.EMPTY));
        }
        if (!Strings.CI.endsWith(name, ASICE_EXTENSION)) {
            log.warn("{}: not an .asice file", safe(name));
            return FileResult.error(name, messages.error(name, State.NOT_CORRECT));
        }
        if (!validations.tryAcquire()) {
            log.warn("{}: {} validations already run", safe(name), MAX_VALIDATIONS);
            return FileResult.error(name, messages.error(new AttributeException("file", State.NOT_AVAILABLE, Detail.VALIDATION_BUSY,
                MAX_VALIDATIONS)));
        }
        try {
            validateSignature(file);
        } catch (AttributeException e) {
            log.warn("{}: invalid, {}", safe(name), safe(e.getMessage()));
            return FileResult.error(name, messages.error(e), location(e));
        } catch (RuntimeException | Error e) {
            log.error("{}: unexpected error", safe(name), e);
            return FileResult.error(name, messages.text("error.unexpected"));
        } finally {
            validations.release();
        }
        log.info("{}: valid", safe(name));
        return FileResult.ok(name, file.getSize());
    }

    private static Location location(AttributeException e) {
        if (e.getFile() == null) {
            return null;
        }
        Node node = e.getNode();
        String attribute = node instanceof Attr attr ? attr.getName() : null;
        return new Location(e.getFile(), StringUtils.stripToNull(XmlUtil.path(node)), mark(node), attribute, e.getContent());
    }

    private static Mark mark(Node node) {
        if (node instanceof Attr) {
            return Mark.ATTRIBUTE;
        }
        if (node instanceof Text) {
            return Mark.TEXT;
        }
        return node == null ? null : Mark.TAG;
    }

    public void validateSignature(MultipartFile file) {
        log.debug("Validating {}", safe(file.getOriginalFilename()));
        Map<String, byte[]> files = openContainer(file);
        Container container = new Container(files);
        for (String name : AsiceUtil.signatureFiles(files)) {
            byte[] bytes = files.get(name);
            try {
                validateSignatureFile(container, name, bytes);
            } catch (AttributeException e) {
                throw e.in(name, XmlConverter.toText(bytes));
            }
        }
    }

    private void validateSignatureFile(Container container, String name, byte[] bytes) {
        Document document = AsiceUtil.parseSignatureFile(name, bytes);
        List<Element> signatures = XmlUtil.children(document.getDocumentElement()).stream()
            .filter(element -> Strings.CS.equals("Signature", element.getLocalName()))
            .toList();
        if (signatures.isEmpty()) {
            throw error(document.getDocumentElement(), "ds:Signature", State.NOT_PROVIDED, Detail.ELEMENT_MISSING,
                "ds:Signature");
        }
        for (Element signature : signatures) {
            validateOneSignature(new SignatureContext(container, name, bytes, document, signature));
        }
        container.addIds(document);
    }

    private void validateOneSignature(SignatureContext ctx) {
        log.debug("Checking signature profile");
        profileValidator.validate(ctx);
        log.debug("Checking XML Signature elements");
        algorithmValidator.validate(ctx);
        signatureStructureValidator.validate(ctx);
        qualifyingPropertiesValidator.validate(ctx);
        dataObjectValidator.validate(ctx);
        List<TimeStampToken> timestamps = timestampValidator.readTimestamps(ctx);
        log.debug("Checking signing certificate");
        signingCertificateValidator.validate(ctx, timestamps.get(0));
        log.debug("Checking timestamps");
        timestampValidator.validate(ctx, timestamps);
        log.debug("Checking reference digests and the signature value");
        coreValidator.validate(ctx);
    }

    private static Map<String, byte[]> openContainer(MultipartFile file) {
        try (InputStream in = file.getInputStream()) {
            return AsiceUtil.open(file.getOriginalFilename(), in);
        } catch (IOException e) {
            throw new AttributeException("file", State.NOT_CORRECT, Detail.CONTAINER_NOT_ZIP);
        }
    }
}
