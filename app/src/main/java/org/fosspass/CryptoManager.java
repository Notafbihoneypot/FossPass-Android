package org.fosspass;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class CryptoManager {
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String MASTER_KEY_ALIAS = "FossPassMasterKey";

    private final KeyStore keyStore;

    public CryptoManager() throws Exception {
        keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
    }

    public void generateMasterKey(Context context) throws Exception {
        if (keyStore.containsAlias(MASTER_KEY_ALIAS)) return;

        KeyGenerator keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);

        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                MASTER_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG);
        } else {
            // Fallback for older versions
            builder.setUserAuthenticationValidityDurationSeconds(-1); // -1 means every use requires auth
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            if (context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
                builder.setIsStrongBoxBacked(true);
            }
        }

        keyGenerator.init(builder.build());
        keyGenerator.generateKey();
    }

    public byte[] encrypt(byte[] data, byte[] iv) throws Exception {
        SecretKey key = (SecretKey) keyStore.getKey(MASTER_KEY_ALIAS, null);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(data);
    }

    public byte[] decrypt(byte[] encryptedData, byte[] iv) throws Exception {
        SecretKey key = (SecretKey) keyStore.getKey(MASTER_KEY_ALIAS, null);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(encryptedData);
    }
}
