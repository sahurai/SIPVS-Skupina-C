package sk.fiit.sipvs.validator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.Dimension;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.zip.CRC32;

import javax.imageio.ImageIO;

import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.Test;
import sk.fiit.sipvs.validator.utils.DataObjectUtil;

class DataObjectUtilTest {

    private static final byte[] PNG_SIGNATURE = {(byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};

    @Test
    void pdfSignatureDictionaryIsFound() {
        assertEquals("/ByteRange", DataObjectUtil.pdfSignature(bytes("<< /ByteRange [0 10 20 30] >>")));
        assertEquals("/Type /Sig", DataObjectUtil.pdfSignature(bytes("<</Type /Sig/Filter/Adobe.PPKLite>>")));
        assertEquals("/Type/Sig", DataObjectUtil.pdfSignature(bytes("<</Type/Sig>>")));
        assertEquals("/Type /Sig", DataObjectUtil.pdfSignature(bytes("<</Type\n/Sig>>")));
    }

    @Test
    void otherPdfNamesAreNotSignatures() {
        assertNull(DataObjectUtil.pdfSignature(bytes("<</Type /SigFieldLock /Action /All>>")));
        assertNull(DataObjectUtil.pdfSignature(bytes("<</Type /SigRef>>")));
        assertNull(DataObjectUtil.pdfSignature(bytes("<</Type /Page /Contents 4 0 R>>")));
    }

    @Test
    void forbiddenHtmlTagIsFoundInAnyCaseAndPrefix() {
        assertEquals("script", DataObjectUtil.forbiddenHtmlTag("<p>x</p><script>alert(1)</script>"));
        assertEquals("link", DataObjectUtil.forbiddenHtmlTag("<LINK rel=\"stylesheet\" href=\"a.css\">"));
        assertEquals("script", DataObjectUtil.forbiddenHtmlTag("<h:script/>"));
        assertEquals("iframe", DataObjectUtil.forbiddenHtmlTag("<iframe\nsrc=\"x\"></iframe>"));
        assertEquals("object", DataObjectUtil.forbiddenHtmlTag("<object data=\"x\">"));
        assertEquals("applet", DataObjectUtil.forbiddenHtmlTag("<applet code=\"x\">"));
    }

    @Test
    void allowedHtmlTagsAreNotForbidden() {
        assertNull(DataObjectUtil.forbiddenHtmlTag("<ul><li>a</li></ul><scripts/><objects/><p>&lt;script&gt;</p>"));
    }

    @Test
    void controlCharacterIsNotXmlChar() {
        assertEquals(0x1, DataObjectUtil.firstInvalidXmlChar("ab\u0001c"));
        assertEquals(-1, DataObjectUtil.firstInvalidXmlChar("ab\tc\n"));
    }

    @Test
    void realPngIsReadable() throws IOException {
        assertTrue(DataObjectUtil.isReadableImage(png()));
    }

    @Test
    void pngSignatureWithOtherDataIsNotReadable() {
        assertFalse(DataObjectUtil.isReadableImage(ArrayUtils.addAll(PNG_SIGNATURE, bytes("not an image"))));
    }

    @Test
    void imageSizeIsReadFromHeaderOnly() {
        assertEquals(new Dimension(46000, 46000), DataObjectUtil.imageSize(pngHeader(46000, 46000)));
        assertNull(DataObjectUtil.imageSize(bytes("not an image")));
    }

    // Width x height x samples x bytes per sample, with an alpha sample for gray and RGB (in case of tRNS).
    @Test
    void pngDecodedSizeIsEstimatedFromHeaderOnly() {
        assertEquals(7000L * 7000 * 4 * 2, DataObjectUtil.pngDecodedSize(pngHeader(7000, 7000, 16, 6)));
        assertEquals(100L * 50 * 4, DataObjectUtil.pngDecodedSize(pngHeader(100, 50, 8, 2)));
        assertEquals(100L * 50 * 2 * 2, DataObjectUtil.pngDecodedSize(pngHeader(100, 50, 16, 0)));
        assertEquals(100L * 50 * 2, DataObjectUtil.pngDecodedSize(pngHeader(100, 50, 8, 4)));
        assertEquals(100L * 50, DataObjectUtil.pngDecodedSize(pngHeader(100, 50, 4, 3)));
        assertEquals(Long.MAX_VALUE, DataObjectUtil.pngDecodedSize(pngHeader(-1, -1, 16, 6)));
        assertEquals(-1, DataObjectUtil.pngDecodedSize(pngHeader(100, 50, 8, 5)));
        assertEquals(-1, DataObjectUtil.pngDecodedSize(ArrayUtils.addAll(PNG_SIGNATURE, bytes("the first chunk is not IHDR"))));
    }

    static byte[] png() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(new BufferedImage(2, 2, BufferedImage.TYPE_INT_RGB), "png", out);
        return out.toByteArray();
    }

    // The PNG signature and an IHDR chunk (8-bit RGB) without any pixel data.
    static byte[] pngHeader(int width, int height) {
        return pngHeader(width, height, 8, 2);
    }

    static byte[] pngHeader(int width, int height, int bitDepth, int colorType) {
        byte[] ihdr = ByteBuffer.allocate(17).put(bytes("IHDR")).putInt(width).putInt(height)
            .put(new byte[] {(byte) bitDepth, (byte) colorType, 0, 0, 0}).array();
        CRC32 crc = new CRC32();
        crc.update(ihdr);
        return ByteBuffer.allocate(PNG_SIGNATURE.length + 25).put(PNG_SIGNATURE).putInt(13).put(ihdr).putInt((int) crc.getValue()).array();
    }

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.ISO_8859_1);
    }
}
