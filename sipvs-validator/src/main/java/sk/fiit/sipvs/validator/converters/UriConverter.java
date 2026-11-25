package sk.fiit.sipvs.validator.converters;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;

import org.apache.commons.lang3.StringUtils;

public final class UriConverter {

    private static final char PERCENT = '%';

    private UriConverter() {}

    public static String decode(String uri) {
        if (!StringUtils.contains(uri, PERCENT)) {
            return uri;
        }
        byte[] raw = uri.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        for (int i = 0; i < raw.length; i++) {
            if (raw[i] != PERCENT) {
                bytes.write(raw[i]);
                continue;
            }
            int high = i + 2 < raw.length ? Character.digit(raw[i + 1], 16) : -1;
            int low = i + 2 < raw.length ? Character.digit(raw[i + 2], 16) : -1;
            if (high < 0 || low < 0) {
                return uri;
            }
            bytes.write(high << 4 | low);
            i += 2;
        }
        try {
            return StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes.toByteArray())).toString();
        } catch (CharacterCodingException e) {
            return uri;
        }
    }
}
