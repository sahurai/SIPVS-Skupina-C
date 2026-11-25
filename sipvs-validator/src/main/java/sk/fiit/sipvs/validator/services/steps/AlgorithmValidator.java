package sk.fiit.sipvs.validator.services.steps;

import java.util.Set;

import org.springframework.stereotype.Service;
import org.w3c.dom.Element;
import sk.fiit.sipvs.validator.enums.Detail;
import sk.fiit.sipvs.validator.enums.State;
import sk.fiit.sipvs.validator.utils.XadesAlgorithms;
import sk.fiit.sipvs.validator.utils.XadesConstants;
import sk.fiit.sipvs.validator.utils.XmlUtil;

import static sk.fiit.sipvs.validator.utils.ValidationUtil.checkAlgorithm;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.error;
import static sk.fiit.sipvs.validator.utils.ValidationUtil.transforms;
import static sk.fiit.sipvs.validator.utils.XadesConstants.ALGORITHM;
import static sk.fiit.sipvs.validator.utils.XadesConstants.NS_DS;
import static sk.fiit.sipvs.validator.utils.XadesConstants.URI;

@Service
public class AlgorithmValidator {

    public void validate(SignatureContext ctx) {
        checkSignatureAndCanonicalizationMethod(ctx);
        checkPssAlgorithms(ctx);
        checkTransformsAndDigestMethods(ctx);
    }

    private void checkSignatureAndCanonicalizationMethod(SignatureContext ctx) {
        Element signedInfo = ctx.signedInfo();
        Element signatureMethod = XmlUtil.child(signedInfo, NS_DS, "SignatureMethod");
        checkAlgorithm(signedInfo, signatureMethod, "ds:SignatureMethod", XadesAlgorithms.SIGNATURE_METHODS.keySet());
        if (XadesAlgorithms.RSA_PSS.equals(signatureMethod.getAttribute(ALGORITHM))
            && XmlUtil.child(signatureMethod, XadesConstants.NS_DSM, "RSAPSSParams") == null) {
            throw error(signatureMethod, "ds:SignatureMethod", State.NOT_PROVIDED, Detail.ELEMENT_MISSING,
                "dsm:RSAPSSParams");
        }
        checkAlgorithm(signedInfo, XmlUtil.child(signedInfo, NS_DS, "CanonicalizationMethod"), "ds:CanonicalizationMethod",
            XadesAlgorithms.CANONICALIZATION_METHODS);
    }

    private void checkPssAlgorithms(SignatureContext ctx) {
        Element signatureMethod = XmlUtil.child(ctx.signedInfo(), NS_DS, "SignatureMethod");
        Element params = XmlUtil.child(signatureMethod, XadesConstants.NS_DSM, "RSAPSSParams");
        Element digestMethod = XmlUtil.child(params, NS_DS, "DigestMethod");
        if (digestMethod != null) {
            checkAlgorithm(params, digestMethod, "ds:DigestMethod", XadesAlgorithms.DIGEST_METHODS.keySet());
        }
        Element mgf = XmlUtil.child(params, XadesConstants.NS_DSM, "MaskGenerationFunction");
        if (mgf != null && mgf.hasAttribute(ALGORITHM)) {
            checkAlgorithm(params, mgf, "dsm:MaskGenerationFunction", Set.of(XadesAlgorithms.MGF1));
        }
        Element mgfDigestMethod = XmlUtil.child(mgf, NS_DS, "DigestMethod");
        if (mgfDigestMethod != null) {
            checkAlgorithm(mgf, mgfDigestMethod, "ds:DigestMethod", XadesAlgorithms.DIGEST_METHODS.keySet());
        }
    }

    private void checkTransformsAndDigestMethods(SignatureContext ctx) {
        for (Element reference : ctx.references()) {
            String uri = reference.getAttribute(URI);
            for (Element transform : transforms(reference)) {
                checkReferenceAlgorithm(reference, transform, "ds:Transforms", uri, XadesAlgorithms.TRANSFORMS);
            }
            checkReferenceAlgorithm(reference, XmlUtil.child(reference, NS_DS, "DigestMethod"), "ds:DigestMethod", uri,
                XadesAlgorithms.DIGEST_METHODS.keySet());
        }
    }

    private static void checkReferenceAlgorithm(Element reference, Element element, String name, String uri,
        Set<String> supported) {
        if (element == null) {
            throw error(reference, name, State.NOT_PROVIDED, Detail.ELEMENT_MISSING, name);
        }
        String algorithm = element.getAttribute(ALGORITHM);
        if (!supported.contains(algorithm)) {
            throw error(XmlUtil.attributeNode(element, ALGORITHM), name, State.NOT_CORRECT, Detail.UNSUPPORTED_ALGORITHM_IN_REFERENCE, algorithm, uri);
        }
    }
}
