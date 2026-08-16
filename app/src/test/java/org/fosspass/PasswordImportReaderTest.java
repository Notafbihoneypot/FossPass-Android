package org.fosspass;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import org.junit.Test;

public class PasswordImportReaderTest {
    @Test
    public void rejectsImportLargerThanConfiguredLimit() throws Exception {
        byte[] input = "123456".getBytes(StandardCharsets.UTF_8);
        try {
            PasswordImportReader.readUtf8(new ByteArrayInputStream(input), 5);
            fail("Expected oversized import to be rejected");
        } catch (IllegalArgumentException expected) {
            assertEquals("Import file exceeds 5-byte safety limit", expected.getMessage());
        }
    }

    @Test(expected = CharacterCodingException.class)
    public void rejectsInvalidUtf8InsteadOfReplacingSecretBytes() throws Exception {
        byte[] invalidUtf8 = {(byte) 0xC3, 0x28};
        PasswordImportReader.readUtf8(new ByteArrayInputStream(invalidUtf8), 10);
    }
}
