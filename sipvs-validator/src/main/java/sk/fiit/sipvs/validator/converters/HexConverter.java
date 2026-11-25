package sk.fiit.sipvs.validator.converters;

import java.util.HexFormat;

public final class HexConverter {

    private HexConverter() {}

    public static String encode(byte[] data) {
        return HexFormat.of().formatHex(data);
    }
}
