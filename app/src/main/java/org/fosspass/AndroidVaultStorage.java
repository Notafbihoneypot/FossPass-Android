package org.fosspass;

import java.io.File;

final class AndroidVaultStorage {
    static final String INTERNAL = "internal";
    static final String DEVICE = "device";

    private AndroidVaultStorage() {}

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
