package org.fosspass;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

final class PasswordImportPlanner {
    static final class Plan {
        final List<PasswordImportParser.ImportedEntry> entriesToImport;
        final int exactDuplicatesSkipped;
        final int reusedPasswordsDetected;

        Plan(List<PasswordImportParser.ImportedEntry> entriesToImport,
             int exactDuplicatesSkipped,
             int reusedPasswordsDetected) {
            this.entriesToImport = entriesToImport;
            this.exactDuplicatesSkipped = exactDuplicatesSkipped;
            this.reusedPasswordsDetected = reusedPasswordsDetected;
        }
    }

    private PasswordImportPlanner() {}

    static Plan plan(List<PasswordImportParser.ImportedEntry> existing,
                     List<PasswordImportParser.ImportedEntry> incoming) {
        Set<EntryKey> seen = new HashSet<>();
        Set<String> seenPasswords = new HashSet<>();
        for (PasswordImportParser.ImportedEntry entry : existing) {
            seen.add(EntryKey.of(entry));
            if (!entry.password.isEmpty()) seenPasswords.add(entry.password);
        }

        List<PasswordImportParser.ImportedEntry> accepted = new ArrayList<>();
        int duplicates = 0;
        int reusedPasswords = 0;
        for (PasswordImportParser.ImportedEntry entry : incoming) {
            if (!seen.add(EntryKey.of(entry))) {
                duplicates++;
                continue;
            }
            if (!entry.password.isEmpty() && !seenPasswords.add(entry.password)) reusedPasswords++;
            accepted.add(entry);
        }
        return new Plan(accepted, duplicates, reusedPasswords);
    }

    private static final class EntryKey {
        final String title;
        final String username;
        final String password;
        final String url;
        final String notes;

        EntryKey(String title, String username, String password, String url, String notes) {
            this.title = title;
            this.username = username;
            this.password = password;
            this.url = url;
            this.notes = notes;
        }

        static EntryKey of(PasswordImportParser.ImportedEntry entry) {
            return new EntryKey(normalize(entry.title), normalize(entry.username),
                    entry.password, normalizeUrl(entry.url), normalize(entry.notes));
        }

        @Override public boolean equals(Object other) {
            if (this == other) return true;
            if (!(other instanceof EntryKey)) return false;
            EntryKey key = (EntryKey) other;
            return title.equals(key.title) && username.equals(key.username)
                    && password.equals(key.password) && url.equals(key.url) && notes.equals(key.notes);
        }

        @Override public int hashCode() {
            return Objects.hash(title, username, password, url, notes);
        }
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    private static String normalizeUrl(String value) {
        String normalized = normalize(value);
        while (normalized.endsWith("/") && normalized.length() > 1) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }
}
