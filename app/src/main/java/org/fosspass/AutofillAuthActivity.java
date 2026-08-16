package org.fosspass;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.view.WindowManager;
import android.view.autofill.AutofillId;
import android.view.autofill.AutofillManager;
import android.view.autofill.AutofillValue;
import android.widget.RemoteViews;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import android.service.autofill.Dataset;

import uniffi.fosspass_core.PublicEntry;

/** Releases one in-memory credential only after BIOMETRIC_STRONG authentication. */
public final class AutofillAuthActivity extends AppCompatActivity {
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        View blank = new View(this);
        blank.setBackgroundColor(0xff071018);
        setContentView(blank);

        String entryId = getIntent().getStringExtra(FossPassAutofillService.EXTRA_ENTRY_ID);
        AutofillId usernameId = getIntent().getParcelableExtra(FossPassAutofillService.EXTRA_USERNAME_ID);
        AutofillId passwordId = getIntent().getParcelableExtra(FossPassAutofillService.EXTRA_PASSWORD_ID);
        if (entryId == null || (usernameId == null && passwordId == null)
                || BiometricManager.from(this).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                != BiometricManager.BIOMETRIC_SUCCESS) {
            cancel();
            return;
        }

        BiometricPrompt prompt = new BiometricPrompt(this, ContextCompat.getMainExecutor(this),
                new BiometricPrompt.AuthenticationCallback() {
                    @Override public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                        PublicEntry entry = VaultSession.find(entryId);
                        if (entry == null) { cancel(); return; }
                        RemoteViews label = new RemoteViews(getPackageName(), android.R.layout.simple_list_item_1);
                        label.setTextViewText(android.R.id.text1, entry.getTitle());
                        Dataset.Builder dataset = new Dataset.Builder(label);
                        if (usernameId != null) dataset.setValue(usernameId, AutofillValue.forText(entry.getUsername()));
                        if (passwordId != null) dataset.setValue(passwordId, AutofillValue.forText(entry.getPassword()));
                        Intent reply = new Intent();
                        reply.putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset.build());
                        setResult(RESULT_OK, reply);
                        VaultSession.clear();
                        finish();
                    }

                    @Override public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                        cancel();
                    }
                });
        prompt.authenticate(new BiometricPrompt.PromptInfo.Builder()
                .setTitle("Fill from FossPass")
                .setSubtitle("Confirm before releasing this credential")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setNegativeButtonText("Cancel")
                .build());
    }

    private void cancel() {
        VaultSession.clear();
        setResult(RESULT_CANCELED);
        finish();
    }
}
