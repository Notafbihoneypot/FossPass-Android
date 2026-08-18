package org.fosspass;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.io.File;
import org.junit.Test;

public class AndroidVaultStorageTest {
    @Test
    public void internalModeUsesPrivateAppFilesDirectory() {
        File selected = AndroidVaultStorage.selectVaultDirectory(
                new File("/private/files"), new File("/device/app-files"), "internal");
        assertEquals(new File("/private/files/main.vault"), selected);
    }

    @Test
    public void deviceModeUsesAppScopedDeviceStorage() {
        File selected = AndroidVaultStorage.selectVaultDirectory(
                new File("/private/files"), new File("/device/app-files"), "device");
        assertEquals(new File("/device/app-files/FossPass/main.vault"), selected);
    }

    @Test
    public void deviceModeFailsClosedWhenDeviceStorageIsUnavailable() {
        assertThrows(IllegalStateException.class, () ->
                AndroidVaultStorage.selectVaultDirectory(
                        new File("/private/files"), null, "device"));
    }

    @Test
    public void explicitPickerChoicesMapToSupportedStorageModes() {
        assertEquals(AndroidVaultStorage.INTERNAL, AndroidVaultStorage.modeForChoice(0));
        assertEquals(AndroidVaultStorage.DEVICE, AndroidVaultStorage.modeForChoice(1));
        assertThrows(IllegalArgumentException.class, () -> AndroidVaultStorage.modeForChoice(2));
    }

    @Test
    public void currentStorageModeMapsBackToPickerSelection() {
        assertEquals(0, AndroidVaultStorage.choiceForMode(AndroidVaultStorage.INTERNAL));
        assertEquals(1, AndroidVaultStorage.choiceForMode(AndroidVaultStorage.DEVICE));
        assertThrows(IllegalArgumentException.class,
                () -> AndroidVaultStorage.choiceForMode("arbitrary-path"));
    }

    @Test
    public void unknownModeIsRejected() {
        assertThrows(IllegalArgumentException.class, () ->
                AndroidVaultStorage.selectVaultDirectory(
                        new File("/private/files"), new File("/device/app-files"), "../unsafe"));
    }
}
