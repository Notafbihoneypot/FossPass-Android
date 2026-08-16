package org.fosspass;

final class PasswordImportFileType {
    private static final byte[] KEEPASS_MAGIC = new byte[]{
            0x03, (byte) 0xd9, (byte) 0xa2, (byte) 0x9a
    };

    private PasswordImportFileType() {}

    static boolean isKeePassDatabase(byte[] bytes) {
        if (bytes == null || bytes.length < KEEPASS_MAGIC.length) return false;
        for (int i = 0; i < KEEPASS_MAGIC.length; i++) {
            if (bytes[i] != KEEPASS_MAGIC[i]) return false;
        }
        return true;
    }

    static String[] supportedMimeTypes() {
        return new String[]{
                "text/csv",
                "application/json",
                "text/xml",
                "application/xml",
                "text/plain",
                "application/x-keepass2",
                "application/octet-stream"
        };
    }
}
