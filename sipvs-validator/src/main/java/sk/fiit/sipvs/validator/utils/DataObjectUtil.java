package sk.fiit.sipvs.validator.utils;

import java.awt.Dimension;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;
import javax.imageio.stream.MemoryCacheImageInputStream;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;

public final class DataObjectUtil {

    private static final byte[] PNG_SIGNATURE = {(byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};
    private static final int IHDR_OFFSET = PNG_SIGNATURE.length;
    private static final int IHDR_HEADER = 8;
    private static final int IHDR_LENGTH = 13;
    private static final byte[] IHDR = {'I', 'H', 'D', 'R'};
    private static final Pattern PDF_VERSION = Pattern.compile("^%PDF-(\\d\\.\\d)");
    private static final Pattern PDF_SIGNATURE = Pattern.compile("(/ByteRange|/Type\\s*/Sig)(?![^\\s()<>\\[\\]{}/%])");
    private static final Pattern FORBIDDEN_HTML_TAG = Pattern.compile(
        "<(?:[\\w.-]+:)?(applet|script|iframe|link|object)(?=[\\s/>])", Pattern.CASE_INSENSITIVE);

    private DataObjectUtil() {}

    public static boolean isUtf8(byte[] data) {
        try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(data));
            return true;
        } catch (CharacterCodingException e) {
            return false;
        }
    }

    public static int firstInvalidXmlChar(String text) {
        return text.codePoints().filter(c -> !isXmlChar(c)).findFirst().orElse(-1);
    }

    public static String codePointHex(int codePoint) {
        return StringUtils.leftPad(Integer.toHexString(codePoint).toUpperCase(Locale.ROOT), 4, '0');
    }

    public static boolean isPng(byte[] data) {
        return data.length >= PNG_SIGNATURE.length
            && Arrays.equals(ArrayUtils.subarray(data, 0, PNG_SIGNATURE.length), PNG_SIGNATURE);
    }

    public static Dimension imageSize(byte[] data) {
        try (ImageInputStream input = new MemoryCacheImageInputStream(new ByteArrayInputStream(data))) {
            Iterator<ImageReader> readers = ImageIO.getImageReaders(input);
            if (!readers.hasNext()) {
                return null;
            }
            ImageReader reader = readers.next();
            try {
                reader.setInput(input, true, true);
                return new Dimension(reader.getWidth(0), reader.getHeight(0));
            } finally {
                reader.dispose();
            }
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    public static long pngDecodedSize(byte[] data) {
        if (!isPng(data) || data.length < IHDR_OFFSET + IHDR_HEADER + IHDR_LENGTH) {
            return -1;
        }
        ByteBuffer header = ByteBuffer.wrap(data);
        if (header.getInt(IHDR_OFFSET) != IHDR_LENGTH
            || !Arrays.equals(data, IHDR_OFFSET + 4, IHDR_OFFSET + IHDR_HEADER, IHDR, 0, IHDR.length)) {
            return -1;
        }
        int samples = switch (data[IHDR_OFFSET + 17]) {
            case 0, 4 -> 2;
            case 2, 6 -> 4;
            case 3 -> 1;
            default -> -1;
        };
        if (samples < 0) {
            return -1;
        }
        double width = Integer.toUnsignedLong(header.getInt(IHDR_OFFSET + 8));
        double height = Integer.toUnsignedLong(header.getInt(IHDR_OFFSET + 12));
        int bytesPerSample = data[IHDR_OFFSET + 16] == 16 ? 2 : 1;
        return (long) (width * height * samples * bytesPerSample);
    }

    public static boolean isReadableImage(byte[] data) {
        try {
            return ImageIO.read(new ByteArrayInputStream(data)) != null;
        } catch (IOException | RuntimeException e) {
            return false;
        }
    }

    public static String pdfVersion(byte[] data) {
        Matcher matcher = PDF_VERSION.matcher(latin1(data, 16));
        return matcher.find() ? matcher.group(1) : null;
    }

    public static String pdfSignature(byte[] data) {
        Matcher matcher = PDF_SIGNATURE.matcher(latin1(data, data.length));
        return matcher.find() ? StringUtils.normalizeSpace(matcher.group()) : null;
    }

    public static String forbiddenHtmlTag(String html) {
        Matcher matcher = FORBIDDEN_HTML_TAG.matcher(html);
        return matcher.find() ? matcher.group(1).toLowerCase(Locale.ROOT) : null;
    }

    private static String latin1(byte[] data, int length) {
        return new String(data, 0, Math.min(length, data.length), StandardCharsets.ISO_8859_1);
    }

    private static boolean isXmlChar(int c) {
        return c == 0x9 || c == 0xA || c == 0xD
            || (c >= 0x20 && c <= 0xD7FF)
            || (c >= 0xE000 && c <= 0xFFFD)
            || (c >= 0x10000 && c <= 0x10FFFF);
    }
}
