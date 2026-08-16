package org.fosspass;

import static org.junit.Assert.assertEquals;

import android.text.InputType;
import android.view.View;

import org.junit.Test;

public class AutofillFieldClassifierTest {
    @Test
    public void explicitPasswordHintWins() {
        assertEquals(AutofillFieldClassifier.Kind.PASSWORD,
                AutofillFieldClassifier.classify(new String[]{View.AUTOFILL_HINT_PASSWORD}, 0));
    }

    @Test
    public void usernameAndEmailHintsAreRecognized() {
        assertEquals(AutofillFieldClassifier.Kind.USERNAME,
                AutofillFieldClassifier.classify(new String[]{View.AUTOFILL_HINT_USERNAME}, 0));
        assertEquals(AutofillFieldClassifier.Kind.USERNAME,
                AutofillFieldClassifier.classify(new String[]{View.AUTOFILL_HINT_EMAIL_ADDRESS}, 0));
    }

    @Test
    public void passwordInputTypeIsRecognizedWithoutHints() {
        assertEquals(AutofillFieldClassifier.Kind.PASSWORD,
                AutofillFieldClassifier.classify(null,
                        InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD));
    }

    @Test
    public void ordinaryTextIsIgnored() {
        assertEquals(AutofillFieldClassifier.Kind.IGNORE,
                AutofillFieldClassifier.classify(null, InputType.TYPE_CLASS_TEXT));
    }
}
