package sk.fiit.sipvs.validator;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import sk.fiit.sipvs.validator.converters.UriConverter;

class UriConverterTest {

    // A '+' stays a '+' (RFC 3986 is not form encoding). A bad escape or bytes that are not UTF-8 keep the raw value.
    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "my%20zmluva.pdf | my zmluva.pdf",
        "%C5%BEiados%C5%A5.pdf | žiadosť.pdf",
        "a+b.txt | a+b.txt",
        "plain.txt | plain.txt",
        "100%.txt | 100%.txt",
        "%zz.txt | %zz.txt",
        "%FF.txt | %FF.txt"
    })
    void decodesPercentEscapes(String uri, String expected) {
        assertEquals(expected, UriConverter.decode(uri));
    }
}
