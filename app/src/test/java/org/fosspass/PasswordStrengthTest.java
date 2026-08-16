package org.fosspass;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class PasswordStrengthTest {
    @Test
    public void shortCommonPasswordIsVeryWeak() {
        PasswordStrength.Result result = PasswordStrength.evaluate("password");
        assertTrue(result.score < 25);
        assertEquals("Very weak", result.label);
    }

    @Test
    public void longMixedPasswordIsStrong() {
        PasswordStrength.Result result = PasswordStrength.evaluate("Violet-River-Quartz-2026!Orbit");
        assertTrue(result.score >= 75);
        assertTrue(result.label.equals("Strong") || result.label.equals("Very strong"));
    }

    @Test
    public void repeatedCharactersArePenalized() {
        assertTrue(PasswordStrength.evaluate("aaaaaaaaaaaaaaaaaaaa").score
                < PasswordStrength.evaluate("correct horse battery staple").score);
    }
}
