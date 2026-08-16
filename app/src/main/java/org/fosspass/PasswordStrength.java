package org.fosspass;

import java.util.Locale;

final class PasswordStrength {
    static final class Result {
        final int score;
        final String label;
        final String guidance;

        Result(int score, String label, String guidance) {
            this.score = score;
            this.label = label;
            this.guidance = guidance;
        }
    }

    private PasswordStrength() {}

    static Result evaluate(String password) {
        String value = password == null ? "" : password;
        if (value.isEmpty()) return new Result(0, "Very weak", "Use a long, unique passphrase.");

        boolean lower = false;
        boolean upper = false;
        boolean digit = false;
        boolean symbol = false;
        boolean space = false;
        int repeatedAdjacent = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isLowerCase(c)) lower = true;
            else if (Character.isUpperCase(c)) upper = true;
            else if (Character.isDigit(c)) digit = true;
            else if (Character.isWhitespace(c)) space = true;
            else symbol = true;
            if (i > 0 && c == value.charAt(i - 1)) repeatedAdjacent++;
        }

        int pool = 0;
        if (lower) pool += 26;
        if (upper) pool += 26;
        if (digit) pool += 10;
        if (symbol) pool += 33;
        if (space) pool += 1;
        double entropyBits = value.length() * (Math.log(Math.max(pool, 1)) / Math.log(2));

        String normalized = value.toLowerCase(Locale.ROOT);
        if (normalized.equals("password") || normalized.equals("password1")
                || normalized.equals("12345678") || normalized.equals("qwerty123")
                || normalized.equals("letmein") || normalized.equals("admin")) {
            entropyBits -= 40;
        }
        if (normalized.contains("123456") || normalized.contains("abcdef")
                || normalized.contains("qwerty")) entropyBits -= 20;
        entropyBits -= repeatedAdjacent * 4.0;
        if (value.length() < 12) entropyBits -= (12 - value.length()) * 4.0;
        if (pool <= 26) entropyBits -= 10;

        int score = (int) Math.round(Math.max(0, Math.min(100, entropyBits / 1.2)));
        String label;
        if (score < 25) label = "Very weak";
        else if (score < 45) label = "Weak";
        else if (score < 65) label = "Fair";
        else if (score < 80) label = "Strong";
        else label = "Very strong";

        String guidance;
        if (value.length() < 12) guidance = "Use at least 12 characters; 16+ is better.";
        else if (!(lower && upper && digit) && !space) guidance = "Add more character variety or use a longer multi-word passphrase.";
        else if (repeatedAdjacent > 2) guidance = "Avoid repeated characters.";
        else guidance = "Good length and variety. Make sure it is unique.";
        return new Result(score, label, guidance);
    }
}
