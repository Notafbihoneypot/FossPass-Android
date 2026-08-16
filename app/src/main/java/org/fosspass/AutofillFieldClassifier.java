package org.fosspass;

import android.text.InputType;
import android.view.View;

import java.util.Locale;

final class AutofillFieldClassifier {
    enum Kind { USERNAME, PASSWORD, IGNORE }

    private AutofillFieldClassifier() {}

    static Kind classify(String[] hints, int inputType) {
        if (hints != null) {
            for (String hint : hints) {
                if (hint == null) continue;
                String normalized = hint.toLowerCase(Locale.ROOT);
                if (normalized.equals(View.AUTOFILL_HINT_PASSWORD)
                        || normalized.contains("password")) return Kind.PASSWORD;
                if (normalized.equals(View.AUTOFILL_HINT_USERNAME)
                        || normalized.equals(View.AUTOFILL_HINT_EMAIL_ADDRESS)
                        || normalized.contains("username")
                        || normalized.contains("email")) return Kind.USERNAME;
            }
        }
        int variation = inputType & InputType.TYPE_MASK_VARIATION;
        if (variation == InputType.TYPE_TEXT_VARIATION_PASSWORD
                || variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
                || variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD) return Kind.PASSWORD;
        if (variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
                || variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS) return Kind.USERNAME;
        return Kind.IGNORE;
    }
}
