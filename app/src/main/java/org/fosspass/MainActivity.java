package org.fosspass;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PersistableBundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.provider.Settings;
import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.util.Base64;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

import com.google.android.gms.fido.Fido;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAssertionResponse;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAttestationResponse;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorErrorResponse;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.common.BitMatrix;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.xml.parsers.DocumentBuilderFactory;

import org.json.JSONArray;
import org.json.JSONObject;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

// UniFFI Imports
import uniffi.fosspass_core.*;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "FossPass";
    private static final int BG_TOP = Color.rgb(6, 11, 17);
    private static final int BG_BOTTOM = Color.rgb(2, 6, 10);
    private static final int PANEL = Color.rgb(15, 23, 32);
    private static final int PANEL_2 = Color.rgb(24, 34, 45);
    private static final int TEXT = Color.rgb(244, 247, 248);
    private static final int MUTED = Color.rgb(148, 163, 184);
    private static final int GREEN = Color.rgb(142, 227, 74);
    private static final int CYAN = Color.rgb(79, 209, 197);
    private static final int RED = Color.rgb(255, 90, 90);
    private static final int CLIPBOARD_CLEAR_MS = 30_000;
    private static final long EXTERNAL_FLOW_TIMEOUT_MS = 120_000L;
    private static final long FIDO_SECRET_TIMEOUT_MS = 60_000L;
    private static final long QR_ANIMATION_MS = 1_200L;
    private static final int QR_FRAME_CHUNK_CHARS = 600;
    private static final int SINGLE_QR_MAX_CHARS = 1_800;
    private static final int REQ_QR_SCAN = 2401;
    private static final int REQ_IMPORT_PASSWORDS = 2402;
    private static final int REQ_EXPORT_PASSWORDS = 2403;
    private static final int REQ_FIDO_REGISTER = 2501;
    private static final int REQ_FIDO_ASSERT = 2502;
    private static final String PREF_FIDO_ENABLED = "fido_enabled";
    private static final String PREF_FIDO_CREDENTIAL = "fido_credential_id";
    private static final String PREF_FIDO_PUBLIC_KEY = "fido_public_key";
    private static final String PREF_FIDO_COUNTER = "fido_counter";
    private static final String PREF_FIDO_USER_ID = "fido_user_id";
    private static final String PREF_UNLOCK_FAILURES = "unlock_failures";
    private static final String PREF_UNLOCK_BLOCKED_UNTIL = "unlock_blocked_until";
    private static final String PREF_VAULT_STORAGE = "vault_storage";

    static {
        try {
            System.loadLibrary("fosspass_core");
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Native library fosspass_core not found. Make sure Rust build succeeded.", e);
        }
    }

    private final Handler handler = new Handler(Looper.getMainLooper());
    private final ExecutorService ioExecutor = Executors.newSingleThreadExecutor();
    private final List<PublicEntry> entries = new ArrayList<>();
    
    private SharedPreferences securePrefs;
    private UnlockedVault rustVault = null;
    private boolean strongBoxBacked = false;
    private String strongBoxStatus = "StrongBox pending";
    private String status = "No vault loaded";
    private String selectedId = null;
    private String vaultPath;
    private String pendingExportFormat = "csv";
    private String pendingSyncPassphrase = "";
    private String lastBundleJson = "";
    private String pendingEncryptedQrBundle = "";
    private long pendingEncryptedQrExpiresAtMs;
    private List<String> qrExportFrames = new ArrayList<>();
    private int qrExportIndex = 0;
    private Runnable qrExportAnimation;
    private boolean pendingCreateVault = false;
    private long pendingUnlockToken = LifecycleOperationGuard.INVALID_TOKEN;
    private long pendingFidoRegistrationToken = LifecycleOperationGuard.INVALID_TOKEN;
    private final LifecycleOperationGuard operationGuard = new LifecycleOperationGuard();
    private final ExternalFlowState externalFlow = new ExternalFlowState();
    private final FidoPendingSecrets fidoSecrets = new FidoPendingSecrets();

    private final BroadcastReceiver screenOffReceiver = new BroadcastReceiver() {
        @Override public void onReceive(Context context, Intent intent) {
            if (Intent.ACTION_SCREEN_OFF.equals(intent.getAction())) lock();
        }
    };

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        
        if (initSecurePrefs()) {
            applyVaultStorageSelection();
            renderUnlock();
        } else renderFatalSecurityError();
    }

    @Override protected void onStart() {
        super.onStart();
        registerReceiver(screenOffReceiver, new IntentFilter(Intent.ACTION_SCREEN_OFF));
    }

    @Override protected void onStop() {
        super.onStop();
        try { unregisterReceiver(screenOffReceiver); } catch (IllegalArgumentException ignored) {}
        lockForBackgroundTransition();
    }

    private void lockForBackgroundTransition() {
        long now = android.os.SystemClock.elapsedRealtime();
        ExternalFlowState.Type flow = externalFlow.current(now);
        boolean validFido = ExternalFlowState.mayRetainFidoSecrets(flow)
                && fidoSecrets.hasPending(now)
                && ((flow == ExternalFlowState.Type.FIDO_ASSERTION
                    && operationGuard.isCurrent(pendingUnlockToken, LifecycleOperationGuard.Kind.UNLOCK))
                    || (flow == ExternalFlowState.Type.FIDO_REGISTRATION
                    && operationGuard.isCurrent(pendingFidoRegistrationToken,
                            LifecycleOperationGuard.Kind.FIDO_REGISTRATION)));
        if (validFido) {
            // Keep only the typed, expiring FIDO continuation; lock all live vault/UI state.
            VaultSession.clear();
            clearUnlockedState(true);
        } else if (flow == ExternalFlowState.Type.AUTOFILL_HANDOFF) {
            operationGuard.invalidate();
            fidoSecrets.clear(FidoPendingSecrets.CleanupReason.ON_STOP);
            clearUnlockedState(false);
        } else {
            lock();
        }
    }

    @Override public void onTrimMemory(int level) {
        super.onTrimMemory(level);
        if (level >= android.content.ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN) {
            lockForBackgroundTransition();
        }
    }

    @Override protected void onDestroy() {
        operationGuard.destroy();
        fidoSecrets.clear(FidoPendingSecrets.CleanupReason.DESTRUCTION);
        externalFlow.clear();
        VaultSession.clear();
        pendingEncryptedQrBundle = "";
        pendingEncryptedQrExpiresAtMs = 0L;
        rustVault = null;
        entries.clear();
        handler.removeCallbacksAndMessages(null);
        ioExecutor.shutdownNow();
        super.onDestroy();
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_QR_SCAN && resultCode == RESULT_OK && data != null) {
            String scanned = data.getStringExtra(QrScannerActivity.EXTRA_QR_VALUE);
            if (QrSyncSupport.isStagedAndroidBundle(scanned)) {
                pendingEncryptedQrBundle = scanned;
                pendingEncryptedQrExpiresAtMs = android.os.SystemClock.elapsedRealtime()
                        + EXTERNAL_FLOW_TIMEOUT_MS;
                externalFlow.clear();
                status = "Encrypted QR captured; unlock and re-enter the sync passphrase to import";
                if (securePrefs != null) renderUnlock();
                toast("QR captured securely. Unlock to finish import.");
            } else {
                toast("Unsupported or incomplete Android sync QR");
            }
            return;
        }
        ExternalFlowState.Type expectedFlow = flowForRequest(requestCode);
        if (expectedFlow != ExternalFlowState.Type.NONE
                && !externalFlow.consume(expectedFlow, android.os.SystemClock.elapsedRealtime())) {
            if (requestCode == REQ_FIDO_REGISTER || requestCode == REQ_FIDO_ASSERT) {
                fidoSecrets.clear(FidoPendingSecrets.CleanupReason.INVALID_RESULT);
                operationGuard.invalidate();
                pendingUnlockToken = LifecycleOperationGuard.INVALID_TOKEN;
                pendingFidoRegistrationToken = LifecycleOperationGuard.INVALID_TOKEN;
                toast("Hardware-key result expired; retry unlock or enrollment");
            } else {
                toast("Vault locked while away; unlock and retry this action");
            }
            return;
        }
        if (resultCode != RESULT_OK || data == null) {
            if (requestCode == REQ_FIDO_REGISTER || requestCode == REQ_FIDO_ASSERT) {
                fidoSecrets.clear(FidoPendingSecrets.CleanupReason.CANCELLATION);
                operationGuard.invalidate();
                pendingUnlockToken = LifecycleOperationGuard.INVALID_TOKEN;
                pendingFidoRegistrationToken = LifecycleOperationGuard.INVALID_TOKEN;
                toast("Hardware-key operation cancelled");
            }
            return;
        }
        if (requestCode == REQ_FIDO_REGISTER) {
            handleFidoRegistrationResult(data);
        } else if (requestCode == REQ_FIDO_ASSERT) {
            handleFidoAssertionResult(data);
        } else if (requestCode == REQ_IMPORT_PASSWORDS && data.getData() != null) {
            importPasswordFile(data.getData());
        } else if (requestCode == REQ_EXPORT_PASSWORDS && data.getData() != null) {
            exportPasswordFile(data.getData(), pendingExportFormat);
        }
    }

    private ExternalFlowState.Type flowForRequest(int requestCode) {
        if (requestCode == REQ_FIDO_REGISTER) return ExternalFlowState.Type.FIDO_REGISTRATION;
        if (requestCode == REQ_FIDO_ASSERT) return ExternalFlowState.Type.FIDO_ASSERTION;
        if (requestCode == REQ_QR_SCAN) return ExternalFlowState.Type.QR_SCAN;
        if (requestCode == REQ_IMPORT_PASSWORDS) return ExternalFlowState.Type.DOCUMENT_IMPORT;
        if (requestCode == REQ_EXPORT_PASSWORDS) return ExternalFlowState.Type.DOCUMENT_EXPORT;
        if (requestCode == 2601) return ExternalFlowState.Type.AUTOFILL_SETTINGS;
        return ExternalFlowState.Type.NONE;
    }

    private boolean initSecurePrefs() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                        MasterKey.DEFAULT_MASTER_KEY_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setKeySize(256)
                        .setIsStrongBoxBacked(true)
                        .build();
                MasterKey strongKey = new MasterKey.Builder(this).setKeyGenParameterSpec(spec).build();
                securePrefs = EncryptedSharedPreferences.create(this, "fosspass_strongbox", strongKey,
                        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM);
                strongBoxBacked = verifyStrongBoxKey(MasterKey.DEFAULT_MASTER_KEY_ALIAS);
                if (!strongBoxBacked) throw new SecurityException("StrongBox key was not hardware verified");
                strongBoxStatus = "StrongBox-backed key verified";
                return true;
            } catch (Exception e) {
                Log.w(TAG, "StrongBox not available: " + e.getMessage());
            }
        }
        try {
            MasterKey key = new MasterKey.Builder(this).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build();
            securePrefs = EncryptedSharedPreferences.create(this, "fosspass_secure", key,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM);
            strongBoxStatus = "Encrypted Android Keystore active";
            return true;
        } catch (Exception e) {
            Log.e(TAG, "EncryptedSharedPreferences failed", e);
            securePrefs = null;
            strongBoxStatus = "Secure storage unavailable";
            return false;
        }
    }

    private void applyVaultStorageSelection() {
        String mode = securePrefs.getString(PREF_VAULT_STORAGE, AndroidVaultStorage.INTERNAL);
        try {
            File directory = AndroidVaultStorage.selectVaultDirectory(
                    getFilesDir(), getExternalFilesDir(null), mode);
            vaultPath = directory.getAbsolutePath();
            status = AndroidVaultStorage.DEVICE.equals(mode)
                    ? "Encrypted database uses app-scoped device storage"
                    : "Encrypted database uses private internal storage";
        } catch (RuntimeException e) {
            vaultPath = null;
            status = "Selected database storage is unavailable";
            Log.e(TAG, "Vault storage selection failed", e);
        }
    }

    private String selectedStorageMode() {
        return securePrefs.getString(PREF_VAULT_STORAGE, AndroidVaultStorage.INTERNAL);
    }

    private void showVaultStoragePicker() {
        String[] locations = {
                "Private internal storage (recommended)",
                "App-scoped device storage"
        };
        int[] selected = {AndroidVaultStorage.choiceForMode(selectedStorageMode())};
        new AlertDialog.Builder(this)
                .setTitle("Choose database location")
                .setSingleChoiceItems(locations, selected[0],
                        (dialog, which) -> selected[0] = which)
                .setPositiveButton("Use Location", (dialog, which) -> {
                    String mode = AndroidVaultStorage.modeForChoice(selected[0]);
                    securePrefs.edit().putString(PREF_VAULT_STORAGE, mode).apply();
                    applyVaultStorageSelection();
                    renderUnlock();
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private boolean verifyStrongBoxKey(String alias) throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        SecretKey key = (SecretKey) store.getKey(alias, null);
        if (key == null) return false;
        SecretKeyFactory factory = SecretKeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore");
        KeyInfo info = (KeyInfo) factory.getKeySpec(key, KeyInfo.class);
        if (!info.isInsideSecureHardware()) return false;
        return Build.VERSION.SDK_INT < Build.VERSION_CODES.S
                || info.getSecurityLevel() == KeyProperties.SECURITY_LEVEL_STRONGBOX;
    }

    private void renderFatalSecurityError() {
        LinearLayout outer = new LinearLayout(this);
        outer.setOrientation(LinearLayout.VERTICAL);
        outer.setGravity(Gravity.CENTER);
        outer.setPadding(dp(24), dp(24), dp(24), dp(24));
        outer.setBackground(gradient(BG_TOP, BG_BOTTOM, 0));
        LinearLayout card = glassCard(24);
        card.addView(text("FossPass locked for safety", 24, RED, true));
        card.addView(text("Encrypted Android Keystore storage could not be initialized. No plaintext fallback was opened. Restart after repairing the device keystore.", 14, TEXT, false));
        outer.addView(card, new LinearLayout.LayoutParams(-1, -2));
        setContentView(outer);
    }

    private void renderUnlock() {
        LinearLayout outer = new LinearLayout(this);
        outer.setOrientation(LinearLayout.VERTICAL);
        outer.setGravity(Gravity.CENTER);
        outer.setPadding(dp(22), dp(22), dp(22), dp(22));
        outer.setBackground(gradient(BG_TOP, BG_BOTTOM, 0));

        LinearLayout card = glassCard(28);
        card.setPadding(dp(24), dp(26), dp(24), dp(24));
        card.addView(pill(strongBoxStatus, strongBoxBacked ? GREEN : CYAN));

        TextView title = text("FossPass", 38, TEXT, true);
        title.setGravity(Gravity.CENTER_HORIZONTAL);
        card.addView(title);
        TextView sub = text("Argon2id + XChaCha20 Hardened Vault", 15, MUTED, false);
        sub.setGravity(Gravity.CENTER_HORIZONTAL);
        card.addView(sub);

        boolean deviceStorage = AndroidVaultStorage.DEVICE.equals(selectedStorageMode());
        card.addView(infoBox("Encrypted database location",
                deviceStorage
                        ? "App-scoped device storage. The vault remains encrypted, but ciphertext may be visible to a connected computer or privileged apps. Each location is a separate vault; switching does not copy data."
                        : "Private internal app storage (recommended). Android sandboxing and vault encryption both protect the database. Each location is a separate vault; switching does not copy data."));
        Button storage = button("Choose Database Location", false);
        card.addView(storage);

        EditText pass = input("Master password", "", true);
        card.addView(label("Master password"));
        card.addView(pass);

        LinearLayout row = row();
        Button create = button("Create Vault", true);
        Button open = button("Unlock", false);
        row.addView(create, weight());
        row.addView(open, weight());
        card.addView(row);

        card.addView(infoBox("Security Hardware", securePrefs.getBoolean(PREF_FIDO_ENABLED, false)
                ? "FIDO2 hardware key required after the master password. Assertions are verified offline with the enrolled public key."
                : "Android BIOMETRIC_STRONG protects unlock. Enroll a USB/NFC/BLE FIDO2 key from Import / Export after unlocking."));

        create.setOnClickListener(v -> handleUnlock(pass, true));
        open.setOnClickListener(v -> handleUnlock(pass, false));
        storage.setOnClickListener(v -> showVaultStoragePicker());

        outer.addView(card, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));
        setContentView(outer);
    }

    private void handleUnlock(EditText pass, boolean create) {
        if (vaultPath == null) {
            toast("Selected database storage is unavailable; choose private internal storage");
            return;
        }
        long waitMs = remainingUnlockDelayMs();
        if (waitMs > 0) {
            toast("Too many failed attempts; retry in " + ((waitMs + 999L) / 1_000L) + "s");
            return;
        }
        String p = pass.getText().toString();
        if (p.isEmpty()) { toast("Enter password"); return; }
        pass.setText("");
        long token = operationGuard.beginExclusive(LifecycleOperationGuard.Kind.UNLOCK);
        if (token == LifecycleOperationGuard.INVALID_TOKEN) {
            toast("Unlock already in progress");
            return;
        }
        pendingUnlockToken = token;
        if (!create && securePrefs.getBoolean(PREF_FIDO_ENABLED, false)) {
            pendingCreateVault = false;
            beginFidoAssertion(p, token);
            return;
        }
        showBiometricPrompt(() -> finishPasswordUnlock(p, create, token), () -> {
            operationGuard.invalidate();
            pendingUnlockToken = LifecycleOperationGuard.INVALID_TOKEN;
        });
    }

    private void finishPasswordUnlock(String password, boolean create, long token) {
        executeIo(() -> {
            try {
                if (!operationGuard.isCurrent(token, LifecycleOperationGuard.Kind.UNLOCK)) return;
                if (create) Fosspass_coreKt.initVault(vaultPath, password);
                UnlockedVault unlocked = Fosspass_coreKt.unlockVault(vaultPath, password);
                handler.post(() -> {
                    if (!operationGuard.completeIfCurrent(token, LifecycleOperationGuard.Kind.UNLOCK)) return;
                    pendingUnlockToken = LifecycleOperationGuard.INVALID_TOKEN;
                    rustVault = unlocked;
                    resetUnlockThrottle();
                    status = create ? "Vault Created" : "Unlocked";
                    loadEntries();
                });
            } catch (Exception e) {
                Log.e(TAG, "Unlock failed", e);
                handler.post(() -> {
                    if (!operationGuard.completeIfCurrent(token, LifecycleOperationGuard.Kind.UNLOCK)) return;
                    pendingUnlockToken = LifecycleOperationGuard.INVALID_TOKEN;
                    recordUnlockFailure();
                    toast("Unlock failed");
                });
            }
        });
    }

    private long remainingUnlockDelayMs() {
        if (securePrefs == null) return Long.MAX_VALUE;
        return UnlockThrottle.remainingMs(
                securePrefs.getLong(PREF_UNLOCK_BLOCKED_UNTIL, 0L),
                System.currentTimeMillis());
    }

    private void recordUnlockFailure() {
        if (securePrefs == null) return;
        UnlockThrottle.State state = UnlockThrottle.recordFailure(
                securePrefs.getInt(PREF_UNLOCK_FAILURES, 0),
                securePrefs.getLong(PREF_UNLOCK_BLOCKED_UNTIL, 0L),
                System.currentTimeMillis());
        securePrefs.edit()
                .putInt(PREF_UNLOCK_FAILURES, state.failures)
                .putLong(PREF_UNLOCK_BLOCKED_UNTIL, state.blockedUntilMs)
                .apply();
    }

    private void resetUnlockThrottle() {
        if (securePrefs != null) securePrefs.edit()
                .remove(PREF_UNLOCK_FAILURES)
                .remove(PREF_UNLOCK_BLOCKED_UNTIL)
                .apply();
    }

    private void loadEntries() {
        UnlockedVault vault = rustVault;
        long generation = operationGuard.captureGeneration();
        if (vault == null || generation == LifecycleOperationGuard.INVALID_TOKEN) return;
        executeIo(() -> {
            try {
                if (!operationGuard.isGenerationCurrent(generation)) return;
                List<PublicEntry> list = vault.listEntries();
                handler.post(() -> {
                    if (!operationGuard.isGenerationCurrent(generation) || rustVault != vault) return;
                    entries.clear();
                    entries.addAll(list);
                    if (!entries.isEmpty() && selectedId == null) selectedId = entries.get(0).getEntryId();
                    long now = android.os.SystemClock.elapsedRealtime();
                    boolean hasStagedQr = !pendingEncryptedQrBundle.isEmpty()
                            && now < pendingEncryptedQrExpiresAtMs;
                    if (hasStagedQr) {
                        lastBundleJson = pendingEncryptedQrBundle;
                        pendingEncryptedQrBundle = "";
                        pendingEncryptedQrExpiresAtMs = 0L;
                        status = "QR ready; enter the offline sync passphrase and import";
                        renderShell();
                        showQrPanel();
                    } else {
                        pendingEncryptedQrBundle = "";
                        pendingEncryptedQrExpiresAtMs = 0L;
                        renderShell();
                    }
                });
            } catch (Exception e) {
                Log.e(TAG, "Load failed", e);
                handler.post(() -> {
                    if (operationGuard.isGenerationCurrent(generation)) toast("Load failed");
                });
            }
        });
    }

    private void renderShell() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackground(gradient(BG_TOP, BG_BOTTOM, 0));

        LinearLayout top = new LinearLayout(this);
        top.setOrientation(LinearLayout.VERTICAL);
        top.setPadding(dp(18), dp(16), dp(18), dp(12));
        top.setBackground(gradient(Color.rgb(13, 20, 29), Color.rgb(7, 13, 20), 18));
        LinearLayout titleRow = row();
        titleRow.addView(text("FossPass", 28, TEXT, true), new LinearLayout.LayoutParams(0, -2, 1));
        titleRow.addView(pill("Rust Core", GREEN));
        titleRow.addView(pill(securePrefs.getBoolean(PREF_FIDO_ENABLED, false) ? "FIDO2 required" : "Biometric", CYAN));
        top.addView(titleRow);
        top.addView(text(status, 12, MUTED, false));
        root.addView(top);

        LinearLayout actions = new LinearLayout(this);
        actions.setOrientation(LinearLayout.VERTICAL);
        actions.setPadding(dp(10), dp(10), dp(10), dp(6));
        LinearLayout primaryActions = row();
        LinearLayout secondaryActions = row();
        Button add = button("+ New", true);
        Button qr = button("Sync", false);
        Button transfer = button("Import / Export", false);
        Button autofill = button("Autofill 30s", false);
        Button lockBtn = button("Lock", false);
        primaryActions.addView(add, weight());
        primaryActions.addView(qr, weight());
        secondaryActions.addView(transfer, weight());
        secondaryActions.addView(autofill, weight());
        secondaryActions.addView(lockBtn, weight());
        actions.addView(primaryActions);
        actions.addView(secondaryActions);
        root.addView(actions);

        ScrollView scroll = new ScrollView(this);
        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(dp(14), dp(8), dp(14), dp(24));
        body.addView(text("Vault Entries", 22, TEXT, true));
        
        for (PublicEntry e : entries) body.addView(entryRow(e));
        PublicEntry selected = selectedEntry();
        if (selected != null) body.addView(detailCard(selected));

        scroll.addView(body);
        root.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        setContentView(root);

        add.setOnClickListener(v -> showAddDialog());
        qr.setOnClickListener(v -> showQrPanel());
        transfer.setOnClickListener(v -> showImportExportPanel());
        autofill.setOnClickListener(v -> lockForAutofillHandoff());
        lockBtn.setOnClickListener(v -> lock());
    }

    private View entryRow(PublicEntry e) {
        LinearLayout item = glassCard(20);
        item.setOrientation(LinearLayout.HORIZONTAL);
        item.setGravity(Gravity.CENTER_VERTICAL);
        item.setPadding(dp(14), dp(12), dp(14), dp(12));
        String title = e.getTitle();
        TextView avatar = text(title.isEmpty() ? "?" : title.substring(0, 1).toUpperCase(Locale.ROOT), 18, Color.rgb(7, 16, 6), true);
        avatar.setGravity(Gravity.CENTER);
        avatar.setBackground(gradient(TEXT, Color.rgb(209, 250, 229), 14));
        item.addView(avatar, new LinearLayout.LayoutParams(dp(44), dp(44)));
        LinearLayout mid = new LinearLayout(this);
        mid.setOrientation(LinearLayout.VERTICAL);
        mid.setPadding(dp(12), 0, dp(8), 0);
        mid.addView(text(title, 17, TEXT, true));
        mid.addView(text(e.getUsername().isEmpty() ? "secure note" : e.getUsername(), 13, MUTED, false));
        item.addView(mid, new LinearLayout.LayoutParams(0, -2, 1));
        item.addView(text(e.getFavorite() ? "★" : "☆", 22, GREEN, false));
        item.setOnClickListener(v -> { selectedId = e.getEntryId(); renderShell(); });
        return item;
    }

    private View detailCard(PublicEntry e) {
        LinearLayout d = glassCard(24);
        d.setPadding(dp(16), dp(16), dp(16), dp(16));
        d.addView(text(e.getTitle(), 25, TEXT, true));
        d.addView(text("Revision " + e.getRevision() + " · " + e.getUpdatedAt(), 12, MUTED, false));
        d.addView(secretLine("Username", e.getUsername()));
        d.addView(secretLine("Password", "••••••••••••••••", e.getPassword()));
        d.addView(secretLine("URL", e.getUrl()));
        d.addView(label("Notes"));
        d.addView(text(e.getNotes().isEmpty() ? "No notes" : e.getNotes(), 14, TEXT, false));
        Button del = button("Delete", false);
        del.setTextColor(RED);
        d.addView(del);
        del.setOnClickListener(v -> {
            UnlockedVault vault = rustVault;
            long generation = operationGuard.captureGeneration();
            if (vault == null || generation == LifecycleOperationGuard.INVALID_TOKEN) return;
            executeIo(() -> {
                try {
                    if (!operationGuard.isGenerationCurrent(generation)) return;
                    vault.deleteEntry(e.getEntryId());
                    handler.post(() -> {
                        if (!operationGuard.isGenerationCurrent(generation) || rustVault != vault) return;
                        selectedId = null;
                        loadEntries();
                    });
                } catch (Exception ignored) {}
            });
        });
        return d;
    }

    private View secretLine(String label, String shown) { return secretLine(label, shown, shown); }
    private View secretLine(String labelText, String shown, String copyValue) {
        LinearLayout r = row();
        r.setPadding(0, dp(8), 0, dp(8));
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.addView(label(labelText));
        col.addView(text(shown, 15, TEXT, false));
        r.addView(col, new LinearLayout.LayoutParams(0, -2, 1));
        Button copy = button("Copy", false);
        r.addView(copy);
        copy.setOnClickListener(v -> copySecret(copyValue));
        return r;
    }

    private void showAddDialog() {
        LinearLayout form = dialogForm();
        EditText title = input("Title", "", false);
        EditText user = input("User", "", false);
        EditText pass = input("Pass", "", false);
        form.addView(label("Title")); form.addView(title);
        form.addView(label("User")); form.addView(user);
        form.addView(label("Pass")); form.addView(pass);
        new AlertDialog.Builder(this).setTitle("New Entry").setView(form)
                .setPositiveButton("Save", (d, w) -> {
                    UnlockedVault vault = rustVault;
                    long generation = operationGuard.captureGeneration();
                    String entryTitle = title.getText().toString();
                    String entryUser = user.getText().toString();
                    String entryPassword = pass.getText().toString();
                    if (vault == null || generation == LifecycleOperationGuard.INVALID_TOKEN) return;
                    executeIo(() -> {
                        try {
                            if (!operationGuard.isGenerationCurrent(generation)) return;
                            vault.addEntry(new AddEntryRequest(entryTitle, entryUser, entryPassword, "", ""));
                            handler.post(() -> {
                                if (operationGuard.isGenerationCurrent(generation) && rustVault == vault) loadEntries();
                            });
                        } catch (Exception e) {
                            Log.e(TAG, "Save failed", e);
                        }
                    });
                }).show();
    }

    private void showImportExportPanel() {
        LinearLayout form = dialogForm();
        form.addView(infoBox("Migration Center", "Imports KeePass KDB/KDBX databases and XML exports, Bitwarden JSON/CSV, 1Password CSV, Chrome/Firefox CSV, LastPass CSV, Dashlane CSV, NordPass CSV, and Proton Pass CSV. KeePass key files are not supported yet. Plaintext export files should be imported only in your intended compartment and deleted securely afterward."));
        Button importFile = button("Import file", true);
        Button exportCsv = button("Export CSV", false);
        Button exportJson = button("Export JSON", false);
        Button changePassword = button("Change Master Password", false);
        Button hwSetup = button("Configure Hardware Key", false);
        Button enableAutofill = button("Enable Android Autofill", false);
        form.addView(importFile);
        form.addView(exportCsv);
        form.addView(exportJson);
        form.addView(changePassword);
        form.addView(hwSetup);
        form.addView(enableAutofill);
        AlertDialog dialog = new AlertDialog.Builder(this).setTitle("Security & Transfer").setView(form).setNegativeButton("Close", null).show();
        importFile.setOnClickListener(v -> launchPasswordImport());
        exportCsv.setOnClickListener(v -> launchPasswordExport("csv"));
        exportJson.setOnClickListener(v -> launchPasswordExport("json"));
        changePassword.setOnClickListener(v -> showChangeMasterPasswordDialog());
        hwSetup.setOnClickListener(v -> showHardwareSetupInfo());
        enableAutofill.setOnClickListener(v -> requestAutofillService());
    }

    private void requestAutofillService() {
        Intent intent = new Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE,
                Uri.parse("package:" + getPackageName()));
        externalFlow.begin(ExternalFlowState.Type.AUTOFILL_SETTINGS,
                android.os.SystemClock.elapsedRealtime(), EXTERNAL_FLOW_TIMEOUT_MS);
        startActivityForResult(intent, 2601);
    }

    private void showChangeMasterPasswordDialog() {
        if (rustVault == null) { toast("Unlock the vault first"); return; }
        LinearLayout form = dialogForm();
        form.addView(infoBox("Re-encrypt vault", "This changes the real vault encryption key. Keep the app open until the operation finishes. A current-password check is required."));
        EditText current = input("Current master password", "", true);
        EditText next = input("New master password", "", true);
        EditText confirm = input("Confirm new master password", "", true);
        TextView strengthText = text("Strength: Very weak (0/100)", 13, RED, true);
        TextView guidance = text("Use at least 12 characters; a unique multi-word passphrase is recommended.", 12, MUTED, false);
        ProgressBar strengthBar = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        strengthBar.setMax(100);
        strengthBar.setProgress(0);
        strengthBar.setProgressTintList(android.content.res.ColorStateList.valueOf(RED));

        form.addView(label("Current master password"));
        form.addView(current);
        form.addView(label("New master password"));
        form.addView(next);
        form.addView(strengthText);
        form.addView(strengthBar, new LinearLayout.LayoutParams(-1, dp(12)));
        form.addView(guidance);
        form.addView(label("Confirm new master password"));
        form.addView(confirm);

        next.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {
                PasswordStrength.Result result = PasswordStrength.evaluate(s.toString());
                int color = result.score < 25 ? RED : result.score < 65 ? Color.rgb(245, 158, 11) : result.score < 80 ? CYAN : GREEN;
                strengthText.setText(getString(R.string.strength_format, result.label, result.score));
                strengthText.setTextColor(color);
                strengthBar.setProgress(result.score);
                strengthBar.setProgressTintList(android.content.res.ColorStateList.valueOf(color));
                guidance.setText(result.guidance);
            }
            @Override public void afterTextChanged(Editable s) {}
        });

        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("Change Master Password")
                .setView(form)
                .setPositiveButton("Change Password", null)
                .setNegativeButton("Cancel", null)
                .create();
        dialog.setOnShowListener(ignored -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            String currentValue = current.getText().toString();
            String newValue = next.getText().toString();
            PasswordStrength.Result result = PasswordStrength.evaluate(newValue);
            if (currentValue.isEmpty()) { toast("Enter the current master password"); return; }
            if (newValue.length() < 12 || result.score < 45) { toast("Use a Fair or stronger password with at least 12 characters"); return; }
            if (!newValue.equals(confirm.getText().toString())) { toast("New passwords do not match"); return; }
            if (currentValue.equals(newValue)) { toast("New password must be different"); return; }

            long token = operationGuard.beginExclusive(LifecycleOperationGuard.Kind.REKEY);
            if (token == LifecycleOperationGuard.INVALID_TOKEN) { toast("Another security operation is pending"); return; }
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(false);
            status = "Re-encrypting vault…";
            executeIo(() -> {
                try {
                    if (!operationGuard.isCurrent(token, LifecycleOperationGuard.Kind.REKEY)) return;
                    UnlockedVault changed = Fosspass_coreKt.changeMasterPassword(vaultPath, currentValue, newValue);
                    handler.post(() -> {
                        if (!operationGuard.completeIfCurrent(token, LifecycleOperationGuard.Kind.REKEY)) return;
                        rustVault = changed;
                        current.setText(""); next.setText(""); confirm.setText("");
                        status = "Master password changed; vault re-encrypted";
                        dialog.dismiss();
                        loadEntries();
                        toast("Master password changed");
                    });
                } catch (Exception e) {
                    Log.e(TAG, "Master password change failed", e);
                    handler.post(() -> {
                        if (!operationGuard.completeIfCurrent(token, LifecycleOperationGuard.Kind.REKEY)) return;
                        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(true);
                        toast("Password change failed: check the current password");
                    });
                }
            });
        }));
        dialog.show();
    }

    private void showHardwareSetupInfo() {
        boolean enabled = securePrefs.getBoolean(PREF_FIDO_ENABLED, false);
        AlertDialog.Builder builder = new AlertDialog.Builder(this)
                .setTitle(enabled ? "Hardware key enabled" : "Enroll FIDO2 hardware key")
                .setMessage(enabled
                        ? "A cryptographically verified FIDO2 roaming authenticator is required after your master password. You can replace it or disable the requirement."
                        : "Enroll a USB/NFC/BLE FIDO2 security key. FossPass stores only its credential ID and public key; every unlock verifies a fresh signed challenge offline.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton(enabled ? "Replace key" : "Enroll key", (d, w) -> beginFidoRegistration());
        if (enabled) {
            builder.setNeutralButton("Disable", (d, w) -> new AlertDialog.Builder(this)
                    .setTitle("Disable hardware key?")
                    .setMessage("Future unlocks will fall back to Android biometric authentication.")
                    .setNegativeButton("Cancel", null)
                    .setPositiveButton("Disable", (d2, w2) -> {
                        securePrefs.edit()
                                .remove(PREF_FIDO_ENABLED)
                                .remove(PREF_FIDO_CREDENTIAL)
                                .remove(PREF_FIDO_PUBLIC_KEY)
                                .remove(PREF_FIDO_COUNTER)
                                .apply();
                        status = "FIDO2 hardware key disabled";
                        renderShell();
                    }).show());
        }
        builder.show();
    }

    private void beginFidoRegistration() {
        if (rustVault == null) { toast("Unlock the vault before enrolling a key"); return; }
        long token = operationGuard.beginExclusive(LifecycleOperationGuard.Kind.FIDO_REGISTRATION);
        if (token == LifecycleOperationGuard.INVALID_TOKEN) { toast("Another security operation is pending"); return; }
        pendingFidoRegistrationToken = token;
        byte[] challenge = Fido2HardwareKey.challenge();
        fidoSecrets.setRegistration(challenge, android.os.SystemClock.elapsedRealtime(), FIDO_SECRET_TIMEOUT_MS);
        byte[] userId;
        String savedUserId = securePrefs.getString(PREF_FIDO_USER_ID, null);
        if (savedUserId == null) {
            userId = new byte[32];
            new SecureRandom().nextBytes(userId);
            securePrefs.edit().putString(PREF_FIDO_USER_ID, Base64.encodeToString(userId, Base64.NO_WRAP)).apply();
        } else {
            userId = Base64.decode(savedUserId, Base64.DEFAULT);
        }
        Fido.getFido2ApiClient(this)
                .getRegisterPendingIntent(Fido2HardwareKey.registrationOptions(challenge, userId))
                .addOnSuccessListener(pendingIntent -> {
                    if (operationGuard.isCurrent(token, LifecycleOperationGuard.Kind.FIDO_REGISTRATION))
                        launchFidoIntent(pendingIntent, REQ_FIDO_REGISTER);
                })
                .addOnFailureListener(e -> {
                    if (!operationGuard.completeIfCurrent(token,
                            LifecycleOperationGuard.Kind.FIDO_REGISTRATION)) return;
                    fidoSecrets.clear(FidoPendingSecrets.CleanupReason.API_FAILURE);
                    pendingFidoRegistrationToken = LifecycleOperationGuard.INVALID_TOKEN;
                    toast("FIDO2 enrollment unavailable: " + e.getMessage());
                });
        Arrays.fill(challenge, (byte) 0);
    }

    private void beginFidoAssertion(String password, long token) {
        try {
            String encodedId = securePrefs.getString(PREF_FIDO_CREDENTIAL, null);
            if (encodedId == null) throw new IllegalStateException("No hardware credential is enrolled");
            byte[] credentialId = Base64.decode(encodedId, Base64.DEFAULT);
            byte[] challenge = Fido2HardwareKey.challenge();
            char[] passwordChars = password.toCharArray();
            fidoSecrets.setAssertion(passwordChars, challenge,
                    android.os.SystemClock.elapsedRealtime(), FIDO_SECRET_TIMEOUT_MS);
            Arrays.fill(passwordChars, '\0');
            Fido.getFido2ApiClient(this)
                    .getSignPendingIntent(Fido2HardwareKey.assertionOptions(challenge, credentialId))
                    .addOnSuccessListener(pendingIntent -> {
                        if (operationGuard.isCurrent(token, LifecycleOperationGuard.Kind.UNLOCK))
                            launchFidoIntent(pendingIntent, REQ_FIDO_ASSERT);
                    })
                    .addOnFailureListener(e -> {
                        if (!operationGuard.completeIfCurrent(token,
                                LifecycleOperationGuard.Kind.UNLOCK)) return;
                        fidoSecrets.clear(FidoPendingSecrets.CleanupReason.API_FAILURE);
                        pendingUnlockToken = LifecycleOperationGuard.INVALID_TOKEN;
                        toast("FIDO2 authentication unavailable: " + e.getMessage());
                    });
            Arrays.fill(challenge, (byte) 0);
        } catch (Exception e) {
            fidoSecrets.clear(FidoPendingSecrets.CleanupReason.API_FAILURE);
            operationGuard.invalidate();
            pendingUnlockToken = LifecycleOperationGuard.INVALID_TOKEN;
            toast("Hardware-key setup is invalid: " + e.getMessage());
        }
    }

    private void launchFidoIntent(PendingIntent pendingIntent, int requestCode) {
        try {
            ExternalFlowState.Type type = requestCode == REQ_FIDO_ASSERT
                    ? ExternalFlowState.Type.FIDO_ASSERTION : ExternalFlowState.Type.FIDO_REGISTRATION;
            externalFlow.begin(type, android.os.SystemClock.elapsedRealtime(), EXTERNAL_FLOW_TIMEOUT_MS);
            startIntentSenderForResult(pendingIntent.getIntentSender(), requestCode, null, 0, 0, 0);
            long token = requestCode == REQ_FIDO_ASSERT ? pendingUnlockToken : pendingFidoRegistrationToken;
            LifecycleOperationGuard.Kind kind = requestCode == REQ_FIDO_ASSERT
                    ? LifecycleOperationGuard.Kind.UNLOCK : LifecycleOperationGuard.Kind.FIDO_REGISTRATION;
            handler.postDelayed(() -> expireFidoContinuation(token, kind), FIDO_SECRET_TIMEOUT_MS);
        } catch (Exception e) {
            externalFlow.clear();
            fidoSecrets.clear(FidoPendingSecrets.CleanupReason.LAUNCH_FAILURE);
            operationGuard.invalidate();
            pendingUnlockToken = LifecycleOperationGuard.INVALID_TOKEN;
            pendingFidoRegistrationToken = LifecycleOperationGuard.INVALID_TOKEN;
            toast("Could not open hardware-key prompt: " + e.getMessage());
        }
    }

    private void expireFidoContinuation(long token, LifecycleOperationGuard.Kind kind) {
        if (!operationGuard.isCurrent(token, kind)) return;
        if (fidoSecrets.hasPending(android.os.SystemClock.elapsedRealtime())) return;
        operationGuard.invalidate();
        pendingUnlockToken = LifecycleOperationGuard.INVALID_TOKEN;
        pendingFidoRegistrationToken = LifecycleOperationGuard.INVALID_TOKEN;
        externalFlow.clear();
        VaultSession.clear();
    }

    private void handleFidoRegistrationResult(Intent data) {
        byte[] challenge = null;
        try {
            challenge = fidoSecrets.challenge(android.os.SystemClock.elapsedRealtime());
            if (challenge == null || !operationGuard.completeIfCurrent(pendingFidoRegistrationToken,
                    LifecycleOperationGuard.Kind.FIDO_REGISTRATION)) throw new SecurityException("Enrollment request expired");
            throwIfFidoError(data);
            byte[] responseBytes = data.getByteArrayExtra(Fido.FIDO2_KEY_RESPONSE_EXTRA);
            if (responseBytes == null) throw new SecurityException("Missing FIDO2 registration response");
            AuthenticatorAttestationResponse response = AuthenticatorAttestationResponse.deserializeFromBytes(responseBytes);
            Fido2HardwareKey.verifyRegistration(challenge, response.getClientDataJSON(), response.getAttestationObject());
            PublicKey publicKey = Fido2HardwareKey.extractEs256PublicKey(response.getAttestationObject());
            securePrefs.edit()
                    .putBoolean(PREF_FIDO_ENABLED, true)
                    .putString(PREF_FIDO_CREDENTIAL, Base64.encodeToString(response.getKeyHandle(), Base64.NO_WRAP))
                    .putString(PREF_FIDO_PUBLIC_KEY, Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP))
                    .putLong(PREF_FIDO_COUNTER, 0)
                    .apply();
            status = "FIDO2 hardware key enrolled; vault remains locked";
            renderUnlock();
            toast("Hardware key enrolled; unlock again to continue");
        } catch (Exception e) {
            Log.e(TAG, "FIDO2 registration rejected", e);
            toast("Hardware-key enrollment failed: " + e.getMessage());
        } finally {
            if (challenge != null) Arrays.fill(challenge, (byte) 0);
            fidoSecrets.clear(FidoPendingSecrets.CleanupReason.INVALID_RESULT);
            pendingFidoRegistrationToken = LifecycleOperationGuard.INVALID_TOKEN;
        }
    }

    private void handleFidoAssertionResult(Intent data) {
        char[] password = null;
        byte[] challenge = null;
        try {
            challenge = fidoSecrets.challenge(android.os.SystemClock.elapsedRealtime());
            if (challenge == null || !operationGuard.isCurrent(pendingUnlockToken,
                    LifecycleOperationGuard.Kind.UNLOCK)) throw new SecurityException("Unlock request expired");
            throwIfFidoError(data);
            byte[] responseBytes = data.getByteArrayExtra(Fido.FIDO2_KEY_RESPONSE_EXTRA);
            if (responseBytes == null) throw new SecurityException("Missing FIDO2 assertion response");
            AuthenticatorAssertionResponse response = AuthenticatorAssertionResponse.deserializeFromBytes(responseBytes);
            byte[] expectedId = Base64.decode(securePrefs.getString(PREF_FIDO_CREDENTIAL, ""), Base64.DEFAULT);
            if (!java.security.MessageDigest.isEqual(expectedId, response.getKeyHandle())) {
                throw new SecurityException("Unexpected hardware credential");
            }
            byte[] encodedKey = Base64.decode(securePrefs.getString(PREF_FIDO_PUBLIC_KEY, ""), Base64.DEFAULT);
            PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(encodedKey));
            long oldCounter = securePrefs.getLong(PREF_FIDO_COUNTER, 0);
            long counter = Fido2HardwareKey.verifyAssertion(publicKey, challenge,
                    response.getClientDataJSON(), response.getAuthenticatorData(), response.getSignature(),
                    Fido2HardwareKey.RP_ID, oldCounter);
            securePrefs.edit().putLong(PREF_FIDO_COUNTER, counter).apply();
            password = fidoSecrets.consumeAssertion(android.os.SystemClock.elapsedRealtime());
            if (password == null) throw new SecurityException("Unlock request expired");
            String unlockPassword = new String(password);
            finishPasswordUnlock(unlockPassword, pendingCreateVault, pendingUnlockToken);
        } catch (Exception e) {
            fidoSecrets.clear(FidoPendingSecrets.CleanupReason.INVALID_RESULT);
            operationGuard.invalidate();
            pendingUnlockToken = LifecycleOperationGuard.INVALID_TOKEN;
            recordUnlockFailure();
            Log.e(TAG, "FIDO2 assertion rejected", e);
            toast("Hardware-key authentication failed: " + e.getMessage());
        } finally {
            if (password != null) Arrays.fill(password, '\0');
            if (challenge != null) Arrays.fill(challenge, (byte) 0);
        }
    }

    private void throwIfFidoError(Intent data) {
        byte[] errorBytes = data.getByteArrayExtra(Fido.FIDO2_KEY_ERROR_EXTRA);
        if (errorBytes != null) {
            AuthenticatorErrorResponse error = AuthenticatorErrorResponse.deserializeFromBytes(errorBytes);
            throw new SecurityException(error.getErrorMessage());
        }
    }

    private void launchPasswordImport() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        intent.putExtra(Intent.EXTRA_MIME_TYPES, PasswordImportFileType.supportedMimeTypes());
        externalFlow.begin(ExternalFlowState.Type.DOCUMENT_IMPORT,
                android.os.SystemClock.elapsedRealtime(), EXTERNAL_FLOW_TIMEOUT_MS);
        startActivityForResult(intent, REQ_IMPORT_PASSWORDS);
    }

    private void launchPasswordExport(String format) {
        pendingExportFormat = format;
        String name = "fosspass-export." + format;
        String mime = format.equals("csv") ? "text/csv" : "application/json";
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType(mime);
        intent.putExtra(Intent.EXTRA_TITLE, name);
        externalFlow.begin(ExternalFlowState.Type.DOCUMENT_EXPORT,
                android.os.SystemClock.elapsedRealtime(), EXTERNAL_FLOW_TIMEOUT_MS);
        startActivityForResult(intent, REQ_EXPORT_PASSWORDS);
    }

    private void importPasswordFile(Uri uri) {
        if (rustVault == null) { toast("Vault locked while choosing file; unlock and retry"); return; }
        long token = operationGuard.beginExclusive(LifecycleOperationGuard.Kind.IMPORT);
        if (token == LifecycleOperationGuard.INVALID_TOKEN) { toast("Another security operation is pending"); return; }
        executeIo(() -> {
            byte[] bytes = null;
            try {
                if (!operationGuard.isCurrent(token, LifecycleOperationGuard.Kind.IMPORT)) return;
                try (InputStream in = getContentResolver().openInputStream(uri)) {
                    if (in == null) throw new IllegalStateException("Could not open file");
                    bytes = PasswordImportReader.readBytes(in, PasswordImportReader.MAX_IMPORT_BYTES);
                }
                if (PasswordImportFileType.isKeePassDatabase(bytes)) {
                    byte[] keepassBytes = bytes;
                    bytes = null;
                    handler.post(() -> {
                        if (operationGuard.isCurrent(token, LifecycleOperationGuard.Kind.IMPORT))
                            showKeePassPasswordDialog(keepassBytes, token);
                        else Arrays.fill(keepassBytes, (byte) 0);
                    });
                    return;
                }
                String content = PasswordImportReader.decodeUtf8(bytes);
                importParsedEntries(PasswordImportParser.parse(content), token);
            } catch (Exception e) {
                Log.e(TAG, "Import failed", e);
                handler.post(() -> {
                    if (operationGuard.completeIfCurrent(token, LifecycleOperationGuard.Kind.IMPORT))
                        toast("Import failed: " + e.getMessage());
                });
            } finally {
                if (bytes != null) Arrays.fill(bytes, (byte) 0);
            }
        });
    }

    private void showKeePassPasswordDialog(byte[] databaseBytes, long token) {
        LinearLayout form = dialogForm();
        form.addView(infoBox("KeePass database", "Enter the password for this KDB/KDBX database. KeePass key files are not supported yet."));
        EditText password = input("KeePass database password", "", true);
        form.addView(password);
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("Unlock KeePass import")
                .setView(form)
                .setPositiveButton("Import", null)
                .setNegativeButton("Cancel", (d, w) -> {
                    Arrays.fill(databaseBytes, (byte) 0);
                    operationGuard.completeIfCurrent(token, LifecycleOperationGuard.Kind.IMPORT);
                })
                .create();
        dialog.setOnCancelListener(d -> {
            Arrays.fill(databaseBytes, (byte) 0);
            operationGuard.completeIfCurrent(token, LifecycleOperationGuard.Kind.IMPORT);
        });
        dialog.setOnShowListener(ignored -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            String databasePassword = password.getText().toString();
            password.setText("");
            dialog.dismiss();
            executeIo(() -> {
                try {
                    if (!operationGuard.isCurrent(token, LifecycleOperationGuard.Kind.IMPORT)) return;
                    List<AddEntryRequest> requests = Fosspass_coreKt.parseKeepassDatabase(databaseBytes, databasePassword);
                    List<PasswordImportParser.ImportedEntry> parsedEntries = new ArrayList<>();
                    for (AddEntryRequest request : requests) {
                        parsedEntries.add(new PasswordImportParser.ImportedEntry(
                                request.getTitle(), request.getUsername(), request.getPassword(),
                                request.getUrl(), request.getNotes()));
                    }
                    importParsedEntries(parsedEntries, token);
                } catch (Exception e) {
                    Log.e(TAG, "KeePass import failed", e);
                    handler.post(() -> {
                        if (operationGuard.completeIfCurrent(token, LifecycleOperationGuard.Kind.IMPORT))
                            toast("KeePass import failed: " + e.getMessage());
                    });
                } finally {
                    Arrays.fill(databaseBytes, (byte) 0);
                }
            });
        }));
        dialog.show();
    }

    private void importParsedEntries(List<PasswordImportParser.ImportedEntry> parsedEntries, long token) throws Exception {
        if (!operationGuard.isCurrent(token, LifecycleOperationGuard.Kind.IMPORT) || rustVault == null) return;
        List<PasswordImportParser.ImportedEntry> existingEntries = new ArrayList<>();
        for (PublicEntry entry : rustVault.listEntries()) {
            existingEntries.add(new PasswordImportParser.ImportedEntry(
                    entry.getTitle(), entry.getUsername(), entry.getPassword(),
                    entry.getUrl(), entry.getNotes()));
        }
        PasswordImportPlanner.Plan plan = PasswordImportPlanner.plan(existingEntries, parsedEntries);
        List<AddEntryRequest> importRequests = new ArrayList<>();
        for (PasswordImportParser.ImportedEntry entry : plan.entriesToImport) {
            importRequests.add(new AddEntryRequest(
                    entry.title, entry.username, entry.password, entry.url, entry.notes));
        }
        int imported = rustVault.addEntries(importRequests);
        int skipped = plan.exactDuplicatesSkipped;
        int reused = plan.reusedPasswordsDetected;
        handler.post(() -> {
            if (!operationGuard.completeIfCurrent(token, LifecycleOperationGuard.Kind.IMPORT)) return;
            status = "Imported " + imported + " entries · skipped " + skipped + " exact duplicates"
                    + (reused > 0 ? " · warning: " + reused + " reused passwords" : "");
            loadEntries();
        });
    }

    private void exportPasswordFile(Uri uri, String format) {
        UnlockedVault vault = rustVault;
        long generation = operationGuard.captureGeneration();
        if (vault == null || generation == LifecycleOperationGuard.INVALID_TOKEN) {
            toast("Vault locked while choosing export location; unlock and retry");
            return;
        }
        executeIo(() -> {
            try {
                if (!operationGuard.isGenerationCurrent(generation)) return;
                List<PublicEntry> snapshot = vault.listEntries();
                String content = format.equals("json") ? exportJson(snapshot) : exportCsv(snapshot);
                try (OutputStream out = getContentResolver().openOutputStream(uri, "wt")) {
                    if (out == null) throw new IllegalStateException("Could not create file");
                    out.write(content.getBytes(StandardCharsets.UTF_8));
                }
                handler.post(() -> {
                    if (!operationGuard.isGenerationCurrent(generation) || rustVault != vault) return;
                    status = "Exported " + snapshot.size() + " entries as " + format.toUpperCase(Locale.ROOT);
                    renderShell();
                });
            } catch (Exception e) {
                Log.e(TAG, "Export failed", e);
                handler.post(() -> {
                    if (operationGuard.isGenerationCurrent(generation))
                        toast("Export failed: " + e.getMessage());
                });
            }
        });
    }

    private int importJson(String content) throws Exception {
        JSONArray array;
        String trimmed = content.trim();
        if (trimmed.startsWith("[")) array = new JSONArray(trimmed);
        else {
            JSONObject root = new JSONObject(trimmed);
            // Bitwarden JSON export support
            array = root.optJSONArray("items");
            if (array == null) array = root.optJSONArray("entries");
            if (array == null) throw new IllegalArgumentException("Unsupported JSON format");
        }
        int count = 0;
        for (int i = 0; i < array.length(); i++) {
            JSONObject o = array.getJSONObject(i);
            String title = o.optString("name", o.optString("title", "Imported"));
            String username = "";
            String password = "";
            String url = "";
            String notes = o.optString("notes", "");

            if (o.has("login")) {
                JSONObject login = o.optJSONObject("login");
                if (login != null) {
                    username = login.optString("username", "");
                    password = login.optString("password", "");
                    JSONArray uris = login.optJSONArray("uris");
                    if (uris != null && uris.length() > 0) {
                        url = uris.optJSONObject(0).optString("uri", "");
                    }
                }
            } else {
                username = o.optString("username", o.optString("user", ""));
                password = o.optString("password", "");
                url = o.optString("url", o.optString("website", ""));
            }
            
            addImportedEntry(title, username, password, url, notes);
            count++;
        }
        return count;
    }

    private int importCsv(String content) throws Exception {
        List<List<String>> rows = parseCsv(content);
        if (rows.isEmpty()) return 0;
        List<String> header = rows.get(0);
        
        // Bitwarden, 1Password, Chrome, and generic mappings
        int title = csvColumn(header, "name", "title", "service");
        int user = csvColumn(header, "username", "user", "login", "login_username");
        int pass = csvColumn(header, "password", "pass", "login_password");
        int url = csvColumn(header, "url", "website", "uri", "login_uri");
        int notes = csvColumn(header, "notes", "note", "extra");
        
        int count = 0;
        for (int i = 1; i < rows.size(); i++) {
            List<String> r = rows.get(i);
            if (r.size() < 1 || (r.size() == 1 && r.get(0).trim().isEmpty())) continue;
            addImportedEntry(csvValue(r, title, "Imported"), csvValue(r, user, ""), csvValue(r, pass, ""), csvValue(r, url, ""), csvValue(r, notes, ""));
            count++;
        }
        return count;
    }

    private int importKeePassXml(String content) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        NodeList entryNodes = factory.newDocumentBuilder().parse(new java.io.ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8))).getElementsByTagName("Entry");
        int count = 0;
        for (int i = 0; i < entryNodes.getLength(); i++) {
            Element entry = (Element) entryNodes.item(i);
            java.util.HashMap<String, String> values = new java.util.HashMap<>();
            NodeList strings = entry.getElementsByTagName("String");
            for (int j = 0; j < strings.getLength(); j++) {
                Element string = (Element) strings.item(j);
                String key = childText(string, "Key");
                String value = childText(string, "Value");
                values.put(key, value);
            }
            addImportedEntry(values.getOrDefault("Title", "Imported"), values.getOrDefault("UserName", ""), values.getOrDefault("Password", ""), values.getOrDefault("URL", ""), values.getOrDefault("Notes", ""));
            count++;
        }
        return count;
    }

    private void addImportedEntry(String title, String username, String password, String url, String notes) throws Exception {
        rustVault.addEntry(new AddEntryRequest(title, username, password, url, notes));
    }

    private String exportJson(List<PublicEntry> list) throws Exception {
        JSONArray array = new JSONArray();
        for (PublicEntry e : list) {
            JSONObject o = new JSONObject();
            o.put("title", e.getTitle()); o.put("username", e.getUsername()); o.put("password", e.getPassword()); o.put("url", e.getUrl()); o.put("notes", e.getNotes());
            array.put(o);
        }
        return array.toString(2);
    }

    private String exportCsv(List<PublicEntry> list) {
        StringBuilder out = new StringBuilder("title,username,password,url,notes\n");
        for (PublicEntry e : list) out.append(csvEscape(e.getTitle())).append(',').append(csvEscape(e.getUsername())).append(',').append(csvEscape(e.getPassword())).append(',').append(csvEscape(e.getUrl())).append(',').append(csvEscape(e.getNotes())).append('\n');
        return out.toString();
    }

    private static String childText(Element parent, String tag) { NodeList nodes = parent.getElementsByTagName(tag); return nodes.getLength() == 0 ? "" : nodes.item(0).getTextContent(); }
    private static int csvColumn(List<String> header, String... names) { for (int i = 0; i < header.size(); i++) for (String name : names) if (header.get(i).trim().equalsIgnoreCase(name)) return i; return -1; }
    private static String csvValue(List<String> row, int index, String fallback) { return index >= 0 && index < row.size() ? row.get(index) : fallback; }
    private static String csvEscape(String value) { String v = value == null ? "" : value; return "\"" + v.replace("\"", "\"\"") + "\""; }

    private static List<List<String>> parseCsv(String text) {
        List<List<String>> rows = new ArrayList<>(); List<String> row = new ArrayList<>(); StringBuilder field = new StringBuilder(); boolean quoted = false;
        for (int i = 0; i < text.length(); i++) { char c = text.charAt(i); if (quoted) { if (c == '\"' && i + 1 < text.length() && text.charAt(i + 1) == '\"') { field.append('\"'); i++; } else if (c == '\"') quoted = false; else field.append(c); } else if (c == '\"') quoted = true; else if (c == ',') { row.add(field.toString()); field.setLength(0); } else if (c == '\n') { row.add(field.toString()); field.setLength(0); rows.add(row); row = new ArrayList<>(); } else if (c != '\r') field.append(c); }
        row.add(field.toString()); if (!(row.size() == 1 && row.get(0).isEmpty())) rows.add(row); return rows;
    }

    private void showQrPanel() {
        stopQrExportAnimation();
        LinearLayout form = dialogForm();
        form.addView(infoBox("Easy encrypted sync", "Small transfers use one QR. Large vaults use one automatically changing tile: point the other camera once and hold still; do not scan each frame manually."));
        Button scan = button("Scan QR", false);
        form.addView(scan);
        EditText syncPass = input("Sync Passphrase", pendingSyncPassphrase, true);
        form.addView(label("Sync Passphrase"));
        form.addView(syncPass);
        ImageView qr = new ImageView(this);
        qr.setPadding(0, dp(12), 0, dp(12));
        form.addView(qr, new LinearLayout.LayoutParams(-1, dp(300)));
        TextView frameStatus = text("Export creates one QR when the encrypted vault fits.", 12, MUTED, false);
        frameStatus.setGravity(Gravity.CENTER_HORIZONTAL);
        form.addView(frameStatus);
        LinearLayout frameNavigation = row();
        Button previousFrame = button("Previous frame", false);
        Button nextFrame = button("Next frame", false);
        frameNavigation.addView(previousFrame, weight());
        frameNavigation.addView(nextFrame, weight());
        form.addView(frameNavigation);
        if (!qrExportFrames.isEmpty()) showQrExportFrame(qr, frameStatus);
        
        EditText bundle = input("Raw JSON / Scanned data", lastBundleJson, false);
        bundle.setSingleLine(false);
        bundle.setMinLines(3);
        form.addView(label("Raw JSON / Scanned data"));
        form.addView(bundle);

        AlertDialog dialog = new AlertDialog.Builder(this).setTitle("QR Sync").setView(form)
                .setPositiveButton("Import", null)
                .setNegativeButton("Close", null)
                .setNeutralButton("Export", null).create();
        
        dialog.setOnShowListener(d -> {
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener(v -> {
                String passphrase = syncPass.getText().toString();
                if (passphrase.length() < 8) {
                    toast("Use an 8+ character offline sync passphrase");
                    return;
                }
                UnlockedVault vault = rustVault;
                long generation = operationGuard.captureGeneration();
                if (vault == null || generation == LifecycleOperationGuard.INVALID_TOKEN) return;
                executeIo(() -> {
                    try {
                        if (!operationGuard.isGenerationCurrent(generation)) return;
                        String b = vault.exportAndroidCompatibleBundle(passphrase, "fosspass-qr-sync-v1");
                        List<String> frames;
                        if (b.length() <= SINGLE_QR_MAX_CHARS) {
                            frames = new ArrayList<>();
                            frames.add(b);
                        } else {
                            frames = QrSyncSupport.splitAndroidBundle(
                                    b, QR_FRAME_CHUNK_CHARS, UUID.randomUUID().toString());
                        }
                        handler.post(() -> {
                            if (!operationGuard.isGenerationCurrent(generation) || rustVault != vault) return;
                            try {
                                lastBundleJson = b;
                                qrExportFrames = frames;
                                qrExportIndex = 0;
                                bundle.setText(b);
                                showQrExportFrame(qr, frameStatus);
                                startQrExportAnimation(qr, frameStatus);
                                toast(frames.size() == 1
                                        ? "Single encrypted QR ready — scan once"
                                        : "One-scan transfer ready — hold the other camera on this tile");
                            } catch (Exception e) {
                                Log.e(TAG, "QR generate failed", e);
                                toast("QR generation failed: " + e.getMessage());
                            }
                        });
                    } catch (Exception e) {
                        Log.e(TAG, "Export failed", e);
                        handler.post(() -> {
                            if (operationGuard.isGenerationCurrent(generation)) toast("Export failed");
                        });
                    }
                });
            });

            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
                String pass = syncPass.getText().toString();
                String data;
                try {
                    data = QrSyncSupport.requireCompleteAndroidBundle(bundle.getText().toString());
                } catch (IllegalArgumentException error) {
                    toast(error.getMessage());
                    return;
                }
                if (pass.isEmpty()) { toast("Need sync passphrase"); return; }
                UnlockedVault vault = rustVault;
                long generation = operationGuard.captureGeneration();
                if (vault == null || generation == LifecycleOperationGuard.INVALID_TOKEN) return;
                executeIo(() -> {
                    try {
                        if (!operationGuard.isGenerationCurrent(generation)) return;
                        ImportReport report = vault.importAndroidCompatibleBundle(data, pass);

                        handler.post(() -> {
                            if (!operationGuard.isGenerationCurrent(generation) || rustVault != vault) return;
                            toast("Imported " + report.getImportedEntries() + " entries");
                            dialog.dismiss();
                            loadEntries();
                        });
                    } catch (Exception e) {
                        Log.e(TAG, "QR Import failed", e);
                        handler.post(() -> {
                            if (operationGuard.isGenerationCurrent(generation))
                                toast("Import failed: " + e.getMessage());
                        });
                    }
                });
            });
        });
        
        previousFrame.setOnClickListener(v -> {
            if (qrExportFrames.isEmpty()) return;
            stopQrExportAnimation();
            qrExportIndex = (qrExportIndex - 1 + qrExportFrames.size()) % qrExportFrames.size();
            showQrExportFrame(qr, frameStatus);
        });
        nextFrame.setOnClickListener(v -> {
            if (qrExportFrames.isEmpty()) return;
            stopQrExportAnimation();
            qrExportIndex = QrSyncSupport.nextFrameIndex(qrExportIndex, qrExportFrames.size());
            showQrExportFrame(qr, frameStatus);
        });

        scan.setOnClickListener(v -> {
            pendingSyncPassphrase = "";
            dialog.dismiss();
            externalFlow.begin(ExternalFlowState.Type.QR_SCAN,
                    android.os.SystemClock.elapsedRealtime(), EXTERNAL_FLOW_TIMEOUT_MS);
            startActivityForResult(new Intent(this, QrScannerActivity.class), REQ_QR_SCAN);
            toast("Scan the code once and keep the camera pointed until import is captured");
        });
        dialog.setOnDismissListener(ignored -> stopQrExportAnimation());
        dialog.show();
    }

    private void showQrExportFrame(ImageView qr, TextView frameStatus) {
        if (qrExportFrames.isEmpty()) {
            qr.setImageDrawable(null);
            frameStatus.setText("No QR export generated yet");
            return;
        }
        qrExportIndex = Math.max(0, Math.min(qrExportIndex, qrExportFrames.size() - 1));
        try {
            qr.setImageBitmap(qrBitmap(qrExportFrames.get(qrExportIndex), 800));
            frameStatus.setText(qrExportFrames.size() == 1
                    ? "Single QR — scan once"
                    : "Automatic frame " + (qrExportIndex + 1) + " / " + qrExportFrames.size()
                            + " — keep the camera pointed here; no manual scanning");
        } catch (Exception e) {
            qr.setImageDrawable(null);
            frameStatus.setText("Could not render QR frame");
            Log.e(TAG, "QR frame render failed", e);
        }
    }

    private void startQrExportAnimation(ImageView qr, TextView frameStatus) {
        stopQrExportAnimation();
        if (qrExportFrames.size() < 2) return;
        qrExportAnimation = new Runnable() {
            @Override public void run() {
                if (qrExportFrames.size() < 2) return;
                qrExportIndex = QrSyncSupport.nextFrameIndex(qrExportIndex, qrExportFrames.size());
                showQrExportFrame(qr, frameStatus);
                handler.postDelayed(this, QR_ANIMATION_MS);
            }
        };
        handler.postDelayed(qrExportAnimation, QR_ANIMATION_MS);
    }

    private void stopQrExportAnimation() {
        if (qrExportAnimation != null) handler.removeCallbacks(qrExportAnimation);
        qrExportAnimation = null;
    }

    private void executeIo(Runnable task) {
        if (operationGuard.captureGeneration() == LifecycleOperationGuard.INVALID_TOKEN) return;
        try {
            ioExecutor.execute(task);
        } catch (RejectedExecutionException ignored) {
            // Shutdown races are expected during destruction; never report into dead UI.
        }
    }

    private void lock() {
        stopQrExportAnimation();
        operationGuard.invalidate();
        pendingUnlockToken = LifecycleOperationGuard.INVALID_TOKEN;
        pendingFidoRegistrationToken = LifecycleOperationGuard.INVALID_TOKEN;
        fidoSecrets.clear(FidoPendingSecrets.CleanupReason.CANCELLATION);
        externalFlow.clear();
        VaultSession.clear();
        clearUnlockedState(false);
    }

    private void lockForAutofillHandoff() {
        if (rustVault == null) { toast("Unlock the vault before starting autofill handoff"); return; }
        externalFlow.begin(ExternalFlowState.Type.AUTOFILL_HANDOFF,
                android.os.SystemClock.elapsedRealtime(), 30_000L);
        operationGuard.invalidate();
        fidoSecrets.clear(FidoPendingSecrets.CleanupReason.CANCELLATION);
        VaultSession.handoff(rustVault, 30_000L);
        clearUnlockedState(false);
        toast("Autofill handoff active once for 30 seconds");
    }

    private void clearUnlockedState(boolean preserveFidoContinuation) {
        rustVault = null;
        entries.clear();
        selectedId = null;
        if (!preserveFidoContinuation) {
            pendingUnlockToken = LifecycleOperationGuard.INVALID_TOKEN;
            pendingFidoRegistrationToken = LifecycleOperationGuard.INVALID_TOKEN;
        }
        pendingSyncPassphrase = "";
        lastBundleJson = "";
        qrExportFrames = new ArrayList<>();
        qrExportIndex = 0;
        clearClipboard();
        if (!isDestroyed()) {
            if (securePrefs != null) renderUnlock();
            else renderFatalSecurityError();
        }
    }

    private void copySecret(String value) {
        ClipboardManager cb = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        ClipData clip = ClipData.newPlainText("FossPass", value);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            PersistableBundle extras = new PersistableBundle();
            extras.putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true);
            clip.getDescription().setExtras(extras);
        }
        cb.setPrimaryClip(clip);
        toast("Copied (30s clear)");
        handler.removeCallbacksAndMessages("clip_clear");
        handler.postAtTime(this::clearClipboard, "clip_clear", android.os.SystemClock.uptimeMillis() + CLIPBOARD_CLEAR_MS);
    }

    private void clearClipboard() {
        try {
            ClipboardManager cb = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            if (cb != null) cb.setPrimaryClip(ClipData.newPlainText("", ""));
        } catch (Exception ignored) {}
    }

    private PublicEntry selectedEntry() {
        if (selectedId != null) for (PublicEntry e : entries) if (selectedId.equals(e.getEntryId())) return e;
        return entries.isEmpty() ? null : entries.get(0);
    }

    private void showBiometricPrompt(Runnable onSuccess, Runnable onCancelled) {
        BiometricPrompt prompt = new BiometricPrompt(this, ContextCompat.getMainExecutor(this), new BiometricPrompt.AuthenticationCallback() {
            @Override public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                onSuccess.run();
            }

            @Override public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                onCancelled.run();
            }
        });
        prompt.authenticate(new BiometricPrompt.PromptInfo.Builder().setTitle("FossPass").setNegativeButtonText("Cancel")
                .setAllowedAuthenticators(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG).build());
    }

    private LinearLayout glassCard(int radius) {
        LinearLayout l = new LinearLayout(this);
        l.setOrientation(LinearLayout.VERTICAL);
        l.setBackground(gradient(PANEL, Color.rgb(10, 16, 24), radius));
        l.setPadding(dp(14), dp(14), dp(14), dp(14));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.setMargins(0, dp(8), 0, dp(8));
        l.setLayoutParams(lp);
        return l;
    }
    private View infoBox(String title, String body) { LinearLayout l = glassCard(18); l.addView(text(title, 14, GREEN, true)); l.addView(text(body, 13, MUTED, false)); return l; }
    private LinearLayout dialogForm() { LinearLayout f = new LinearLayout(this); f.setOrientation(LinearLayout.VERTICAL); f.setPadding(dp(10), 0, dp(10), 0); return f; }
    private LinearLayout row() { LinearLayout r = new LinearLayout(this); r.setOrientation(LinearLayout.HORIZONTAL); r.setGravity(Gravity.CENTER_VERTICAL); return r; }
    private TextView text(String s, int sp, int color, boolean bold) { TextView t = new TextView(this); t.setText(s); t.setTextSize(sp); t.setTextColor(color); if (bold) t.setTypeface(Typeface.DEFAULT_BOLD); return t; }
    private TextView label(String s) { TextView t = text(s, 12, MUTED, false); t.setPadding(0, dp(12), 0, dp(5)); return t; }
    private TextView pill(String s, int color) { TextView t = text(s, 11, color, true); t.setGravity(Gravity.CENTER); t.setPadding(dp(10), dp(5), dp(10), dp(5)); t.setBackground(gradient(Color.argb(46, Color.red(color), Color.green(color), Color.blue(color)), Color.argb(18, Color.red(color), Color.green(color), Color.blue(color)), 999)); return t; }
    private EditText input(String hint, String value, boolean password) { EditText e = new EditText(this); e.setHint(hint); e.setText(value); e.setTextColor(TEXT); e.setInputType(password ? 129 : 1); e.setBackground(gradient(PANEL_2, Color.rgb(17, 25, 34), 14)); e.setPadding(dp(12), dp(9), dp(12), dp(9)); return e; }
    private Button button(String s, boolean primary) { Button b = new Button(this); b.setText(s); b.setAllCaps(false); b.setTextColor(primary ? Color.rgb(7, 16, 6) : TEXT); b.setBackground(gradient(primary ? GREEN : PANEL_2, primary ? Color.rgb(126, 211, 33) : Color.rgb(18, 28, 38), 16)); return b; }
    private GradientDrawable gradient(int a, int b, int radius) { GradientDrawable g = new GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM, new int[]{a, b}); g.setCornerRadius(dp(radius)); return g; }
    private LinearLayout.LayoutParams weight() { LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, -2, 1); lp.setMargins(dp(4), dp(4), dp(4), dp(4)); return lp; }
    private int dp(int v) { return (int) (v * getResources().getDisplayMetrics().density + 0.5f); }
    private void toast(String s) { Toast.makeText(this, s, Toast.LENGTH_SHORT).show(); }
    private Bitmap qrBitmap(String data, int size) throws Exception {
        BitMatrix matrix = new MultiFormatWriter().encode(data, BarcodeFormat.QR_CODE, size, size);
        Bitmap bmp = Bitmap.createBitmap(size, size, Bitmap.Config.RGB_565);
        for (int y = 0; y < size; y++) for (int x = 0; x < size; x++) bmp.setPixel(x, y, matrix.get(x, y) ? Color.BLACK : Color.WHITE);
        return bmp;
    }
}
