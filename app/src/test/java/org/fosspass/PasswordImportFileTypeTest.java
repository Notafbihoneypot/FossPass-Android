package org.fosspass;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import org.junit.Test;

public class PasswordImportFileTypeTest {
    @Test
    public void recognizesKeePassKdbAndKdbxMagic() {
        assertTrue(PasswordImportFileType.isKeePassDatabase(new byte[]{0x03, (byte) 0xd9, (byte) 0xa2, (byte) 0x9a, 0x67, (byte) 0xfb, 0x4b, (byte) 0xb5}));
        assertTrue(PasswordImportFileType.isKeePassDatabase(new byte[]{0x03, (byte) 0xd9, (byte) 0xa2, (byte) 0x9a, 0x65, (byte) 0xfb, 0x4b, (byte) 0xb5}));
        assertFalse(PasswordImportFileType.isKeePassDatabase("<KeePassFile>".getBytes()));
    }

    @Test
    public void advertisesKeePassMimeTypesToAndroidDocumentPicker() {
        assertTrue(Arrays.asList(PasswordImportFileType.supportedMimeTypes()).contains("application/x-keepass2"));
        assertTrue(Arrays.asList(PasswordImportFileType.supportedMimeTypes()).contains("application/octet-stream"));
        assertTrue(Arrays.asList(PasswordImportFileType.supportedMimeTypes()).contains("application/xml"));
    }
}
