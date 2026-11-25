package sk.fiit.sipvs.validator.services.steps;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.interfaces.RSAKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import org.apache.commons.lang3.Strings;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.w3c.dom.Element;
import sk.fiit.sipvs.validator.converters.Base64Converter;
import sk.fiit.sipvs.validator.converters.CanonicalizationConverter;
import sk.fiit.sipvs.validator.enums.Detail;
import sk.fiit.sipvs.validator.enums.State;
import sk.fiit.sipvs.validator.exceptions.AttributeException;
import sk.fiit.sipvs.validator.utils.CryptoUtil;
import sk.fiit.sipvs.validator.utils.XadesAlgorithms;
import sk.fiit.sipvs.validator.utils.XadesConstants;
import sk.fiit.sipvs.validator.utils.XmlUtil;

import static sk.fiit.sipvs.validator.utils.ValidationUtil.decode;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.error;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.safe;
import static sk.fiit.sipvs.validator.utils.XadesConstants.ALGORITHM;
import static sk.fiit.sipvs.validator.utils.XadesConstants.NS_DS;
import static sk.fiit.sipvs.validator.utils.XadesConstants.URI;

@Service
public class CoreValidator {

    private static final Logger log = LoggerFactory.getLogger(CoreValidator.class);

    public void validate(SignatureContext ctx) {
        checkReferenceDigests(ctx);
        checkSignatureValue(ctx);
    }

    private void checkReferenceDigests(SignatureContext ctx) {
        for (Element reference : ctx.references()) {
            String uri = reference.getAttribute(URI);
            Element digestValue = XmlUtil.child(reference, NS_DS, "DigestValue");
            byte[] digest;
            try {
                String digestMethod = XmlUtil.child(reference, NS_DS, "DigestMethod").getAttribute(ALGORITHM);
                digest = CryptoUtil.digest(digestMethod, ctx.referencedData(reference, XadesAlgorithms.C14N));
            } catch (AttributeException e) {
                throw e;
            } catch (Exception e) {
                log.debug("Cannot compute digest of {}: {}", safe(uri), safe(ExceptionUtils.getRootCauseMessage(e)));
                throw error(XmlUtil.attributeNode(reference, URI), "ds:DigestValue", State.NOT_CORRECT, Detail.DIGEST_NOT_COMPUTED, uri,
                    ExceptionUtils.getRootCauseMessage(e));
            }
            if (!MessageDigest.isEqual(digest, decode(digestValue, "ds:DigestValue"))) {
                throw error(XmlUtil.textNode(digestValue), "ds:DigestValue", State.NOT_CORRECT, Detail.DIGEST_MISMATCH,
                    uri, Base64Converter.encode(digest), XmlUtil.text(digestValue));
            }
            log.debug("Digest of {} matches", safe(uri));
        }
    }

    private void checkSignatureValue(SignatureContext ctx) {
        Element signedInfo = ctx.signedInfo();
        String c14n = XmlUtil.child(signedInfo, NS_DS, "CanonicalizationMethod").getAttribute(ALGORITHM);
        Element signatureMethod = XmlUtil.child(signedInfo, NS_DS, "SignatureMethod");
        Element signatureValue = XmlUtil.child(ctx.signature, NS_DS, "SignatureValue");
        byte[] value = decode(signatureValue, "ds:SignatureValue");
        boolean valid;
        try {
            byte[] data = CanonicalizationConverter.canonicalize(c14n, signedInfo);
            if (XadesAlgorithms.RSA_PSS.equals(signatureMethod.getAttribute(ALGORITHM))) {
                checkPssKeyParameters(ctx, signatureMethod);
            }
            valid = CryptoUtil.verify(signatureMethod, ctx.certificate.getPublicKey(), data, value);
        } catch (AttributeException e) {
            throw e;
        } catch (Exception e) {
            log.debug("Cannot verify ds:SignatureValue: {}", safe(ExceptionUtils.getRootCauseMessage(e)));
            throw error(XmlUtil.textNode(signatureValue), "ds:SignatureValue", State.NOT_CORRECT, Detail.SIGNATURE_VALUE_ERROR,
                ExceptionUtils.getRootCauseMessage(e));
        }
        if (!valid) {
            throw error(XmlUtil.textNode(signatureValue), "ds:SignatureValue", State.NOT_CORRECT, Detail.SIGNATURE_VALUE_INVALID);
        }
    }

    private static void checkPssKeyParameters(SignatureContext ctx, Element signatureMethod) throws GeneralSecurityException {
        if (!(ctx.certificate.getPublicKey() instanceof RSAKey key) || !(key.getParams() instanceof PSSParameterSpec required)) {
            return;
        }
        PSSParameterSpec used = CryptoUtil.pssParameters(signatureMethod);
        Element params = XmlUtil.child(signatureMethod, XadesConstants.NS_DSM, "RSAPSSParams");
        Element mgf = XmlUtil.child(params, XadesConstants.NS_DSM, "MaskGenerationFunction");
        checkPssParameter(params, XmlUtil.child(params, NS_DS, "DigestMethod"), "ds:DigestMethod", used.getDigestAlgorithm(),
            required.getDigestAlgorithm());
        checkPssParameter(mgf == null ? params : mgf, XmlUtil.child(mgf, NS_DS, "DigestMethod"), "dsm:MaskGenerationFunction/ds:DigestMethod",
            mgfDigest(used), mgfDigest(required));
        if (used.getSaltLength() < required.getSaltLength()) {
            Element salt = XmlUtil.child(params, XadesConstants.NS_DSM, "SaltLength");
            throw error(salt == null ? params : XmlUtil.textNode(salt), "dsm:RSAPSSParams", State.NOT_CORRECT, Detail.PSS_SALT_TOO_SHORT,
                used.getSaltLength(), required.getSaltLength());
        }
    }

    private static void checkPssParameter(Element parent, Element digestMethod, String name, String used, String required) {
        if (!Strings.CI.equals(used, required)) {
            throw error(digestMethod == null ? parent : XmlUtil.attributeNode(digestMethod, ALGORITHM), "dsm:RSAPSSParams",
                State.NOT_CORRECT, Detail.PSS_PARAMETER_MISMATCH, name, used, required);
        }
    }

    private static String mgfDigest(PSSParameterSpec spec) {
        return spec.getMGFParameters() instanceof MGF1ParameterSpec mgf ? mgf.getDigestAlgorithm() : spec.getMGFAlgorithm();
    }
}
