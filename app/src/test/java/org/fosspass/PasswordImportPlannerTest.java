package org.fosspass;

import static org.junit.Assert.assertEquals;

import java.util.Collections;
import org.junit.Test;

public class PasswordImportPlannerTest {
    private static PasswordImportParser.ImportedEntry entry(
            String title, String username, String password, String url, String notes) {
        return new PasswordImportParser.ImportedEntry(title, username, password, url, notes);
    }

    @Test
    public void skipsExactCredentialAlreadyInVault() {
        PasswordImportPlanner.Plan plan = PasswordImportPlanner.plan(
                Collections.singletonList(entry("GitHub", "Alice", "secret", "https://github.com/", "primary")),
                Collections.singletonList(entry(" github ", "alice", "secret", "https://github.com", "primary")));

        assertEquals(0, plan.entriesToImport.size());
        assertEquals(1, plan.exactDuplicatesSkipped);
        assertEquals(0, plan.reusedPasswordsDetected);
    }

    @Test
    public void keepsDifferentAccountsButReportsPasswordReuse() {
        PasswordImportPlanner.Plan plan = PasswordImportPlanner.plan(
                Collections.singletonList(entry("GitHub", "alice", "same secret", "https://github.com", "")),
                Collections.singletonList(entry("GitLab", "alice", "same secret", "https://gitlab.com", "")));

        assertEquals(1, plan.entriesToImport.size());
        assertEquals(0, plan.exactDuplicatesSkipped);
        assertEquals(1, plan.reusedPasswordsDetected);
    }
}
