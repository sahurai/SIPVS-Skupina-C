package sk.fiit.sipvs.validator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.xml.sax.SAXParseException;
import sk.fiit.sipvs.validator.converters.CanonicalizationConverter;
import sk.fiit.sipvs.validator.utils.XadesAlgorithms;

class CanonicalizationConverterTest {

    @Test
    void fileIsCanonicalized() throws Exception {
        byte[] xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- c --><a xmlns=\"urn:a\" b=\"2\" a=\"1\"><e/><![CDATA[x<y]]></a>"
            .getBytes(StandardCharsets.UTF_8);

        assertEquals("<a xmlns=\"urn:a\" a=\"1\" b=\"2\"><e></e>x&lt;y</a>",
            new String(CanonicalizationConverter.canonicalize(XadesAlgorithms.C14N, xml), StandardCharsets.UTF_8));
    }

    // A file reference with a canonicalization transform is parsed with the same depth limit as other XML.
    @Test
    void deeplyNestedFileIsNotParsed() {
        byte[] xml = ("<a>".repeat(20000) + "</a>".repeat(20000)).getBytes(StandardCharsets.UTF_8);

        assertThrows(SAXParseException.class, () -> CanonicalizationConverter.canonicalize(XadesAlgorithms.C14N, xml));
    }
}
