package sk.fiit.sipvs.validator.converters;

import java.util.Base64;

import org.apache.commons.lang3.StringUtils;

public final class Base64Converter {

    private Base64Converter() {}

    public static byte[] decode(String text) {
        return Base64.getDecoder().decode(StringUtils.deleteWhitespace(text));
    }

    public static String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }
}
