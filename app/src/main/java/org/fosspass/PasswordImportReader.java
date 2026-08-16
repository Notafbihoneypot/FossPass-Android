package org.fosspass;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

final class PasswordImportReader {
    static final int MAX_IMPORT_BYTES = 20 * 1024 * 1024;

    private PasswordImportReader() {}

    static byte[] readBytes(InputStream input, int maxBytes) throws IOException {
        if (maxBytes < 1) throw new IllegalArgumentException("Import size limit must be positive");
        WipingBuffer output = new WipingBuffer(Math.min(maxBytes, 8192));
        byte[] chunk = new byte[8192];
        int total = 0;
        try {
            int read;
            while ((read = input.read(chunk)) != -1) {
                if (read > maxBytes - total) {
                    throw new IllegalArgumentException(
                            "Import file exceeds " + maxBytes + "-byte safety limit");
                }
                output.write(chunk, 0, read);
                total += read;
            }
            return output.toByteArray();
        } finally {
            Arrays.fill(chunk, (byte) 0);
            output.wipe();
        }
    }

    static String decodeUtf8(byte[] bytes) throws IOException {
        return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString();
    }

    static String readUtf8(InputStream input, int maxBytes) throws IOException {
        byte[] bytes = readBytes(input, maxBytes);
        try {
            return decodeUtf8(bytes);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    private static final class WipingBuffer extends ByteArrayOutputStream {
        WipingBuffer(int size) { super(size); }
        byte[] buffer() { return buf; }
        void wipe() { Arrays.fill(buf, (byte) 0); }
    }
}
