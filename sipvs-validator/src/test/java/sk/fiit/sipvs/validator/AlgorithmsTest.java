package sk.fiit.sipvs.validator;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.security.MessageDigest;
import java.security.Signature;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.junit.jupiter.api.Test;
import sk.fiit.sipvs.validator.utils.XadesAlgorithms;

class AlgorithmsTest {

    @Test
    void everySignatureMethodHasJcaImplementation() {
        XadesAlgorithms.SIGNATURE_METHODS.values().forEach(name -> assertDoesNotThrow(() -> Signature.getInstance(name), name));
    }

    @Test
    void everyDigestMethodHasJcaImplementation() {
        XadesAlgorithms.DIGEST_METHODS.values().forEach(name -> assertDoesNotThrow(() -> MessageDigest.getInstance(name), name));
    }

    @Test
    void everyCanonicalizationMethodIsSupported() {
        Init.init();
        XadesAlgorithms.CANONICALIZATION_METHODS.forEach(uri -> assertDoesNotThrow(() -> Canonicalizer.getInstance(uri), uri));
    }
}
