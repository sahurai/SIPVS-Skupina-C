package sk.fiit.sipvs.validator.utils;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.w3c.dom.Element;

import static sk.fiit.sipvs.validator.utils.XadesConstants.ALGORITHM;

public final class CryptoUtil {

    private CryptoUtil() {}

    public static byte[] digest(String digestMethod, byte[] data) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance(XadesAlgorithms.DIGEST_METHODS.get(digestMethod)).digest(data);
    }

    public static boolean verify(Element signatureMethod, PublicKey key, byte[] data, byte[] value)
        throws GeneralSecurityException {
        String algorithm = signatureMethod.getAttribute(ALGORITHM);
        Signature verifier = Signature.getInstance(XadesAlgorithms.SIGNATURE_METHODS.get(algorithm));
        if (XadesAlgorithms.RSA_PSS.equals(algorithm)) {
            verifier.setParameter(pssParameters(signatureMethod));
        }
        verifier.initVerify(key);
        verifier.update(data);
        return verifier.verify(value);
    }

    public static PSSParameterSpec pssParameters(Element signatureMethod) throws NoSuchAlgorithmException {
        Element params = XmlUtil.child(signatureMethod, XadesConstants.NS_DSM, "RSAPSSParams");
        String digestUri = digestUri(XmlUtil.child(params, XadesConstants.NS_DS, "DigestMethod"), XadesAlgorithms.SHA256);
        Element mgf = XmlUtil.child(params, XadesConstants.NS_DSM, "MaskGenerationFunction");
        String digest = XadesAlgorithms.DIGEST_METHODS.get(digestUri);
        String mgfDigest = XadesAlgorithms.DIGEST_METHODS.get(digestUri(XmlUtil.child(mgf, XadesConstants.NS_DS, "DigestMethod"), digestUri));
        int defaultSalt = MessageDigest.getInstance(digest).getDigestLength();
        int salt = NumberUtils.toInt(XmlUtil.text(XmlUtil.child(params, XadesConstants.NS_DSM, "SaltLength")), defaultSalt);
        int trailer = NumberUtils.toInt(XmlUtil.text(XmlUtil.child(params, XadesConstants.NS_DSM, "TrailerField")), 1);
        return new PSSParameterSpec(digest, "MGF1", new MGF1ParameterSpec(mgfDigest), salt, trailer);
    }

    private static String digestUri(Element digestMethod, String defaultUri) {
        return StringUtils.defaultIfBlank(XmlUtil.attribute(digestMethod, ALGORITHM), defaultUri);
    }
}
