package org.fosspass;

import java.io.File;

final class AndroidVaultStorage {
    static final String INTERNAL = "internal";
    static final String DEVICE = "device";

    private AndroidVaultStorage() {}

    static String modeForChoice(int choice) {
        if (choice == 0) return INTERNAL;
        if (choice == 1) return DEVICE;
        throw new IllegalArgumentException("Unknown vault storage choice");
    }

    static int choiceForMode(String mode) {
        if (INTERNAL.equals(mode)) return 0;
        if (DEVICE.equals(mode)) return 1;
        throw new IllegalArgumentException("Unknown vault storage mode");
    }

    static File selectVaultDirectory(File internalFilesDir, File externalFilesDir, String mode) {
        if (internalFilesDir == null) throw new IllegalStateException("Private app storage unavailable");
        if (INTERNAL.equals(mode)) return new File(internalFilesDir, "main.vault");
        if (DEVICE.equals(mode)) {
            if (externalFilesDir == null) throw new IllegalStateException("Device app storage unavailable");
            return new File(new File(externalFilesDir, "FossPass"), "main.vault");
        }
        throw new IllegalArgumentException("Unknown vault storage mode");
    }
}
