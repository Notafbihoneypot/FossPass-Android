package org.fosspass;

import static org.junit.Assert.*;

import org.junit.Test;

public class FidoPendingSecretsTest {
    @Test public void successfulAssertionConsumesPasswordAndClearsChallenge() {
        FidoPendingSecrets secrets = new FidoPendingSecrets();
        char[] source = "correct horse".toCharArray();
        byte[] challenge = new byte[] {1, 2, 3};
        secrets.setAssertion(source, challenge, 10L, 100L);
        source[0] = 'X';
        challenge[0] = 9;

        char[] password = secrets.consumeAssertion(50L);
        assertArrayEquals("correct horse".toCharArray(), password);
        assertFalse(secrets.hasPending(50L));
        java.util.Arrays.fill(password, '\0');
    }

    @Test public void cancelFailureLaunchFailureStopAndDestroyClearSecrets() {
        for (FidoPendingSecrets.CleanupReason reason : FidoPendingSecrets.CleanupReason.values()) {
            FidoPendingSecrets secrets = new FidoPendingSecrets();
            char[] password = "secret".toCharArray();
            byte[] challenge = new byte[] {4, 5};
            secrets.setAssertion(password, challenge, 0L, 100L);
            secrets.clear(reason);
            assertFalse(reason.name(), secrets.hasPending(1L));
            assertNull(reason.name(), secrets.passwordForTest());
            assertNull(reason.name(), secrets.challengeForTest());
        }
    }

    @Test public void timeoutClearsAndCannotBeConsumed() {
        FidoPendingSecrets secrets = new FidoPendingSecrets();
        secrets.setAssertion("secret".toCharArray(), new byte[] {1}, 10L, 5L);
        assertNull(secrets.consumeAssertion(16L));
        assertFalse(secrets.hasPending(16L));
        assertNull(secrets.passwordForTest());
        assertNull(secrets.challengeForTest());
    }

    @Test public void exactDeadlineIsExpiredAndLeavesCleanEmptyState() {
        FidoPendingSecrets secrets = new FidoPendingSecrets();
        secrets.setRegistration(new byte[] {7, 8}, 10L, 5L);
        assertNull(secrets.challenge(15L));
        assertNull(secrets.passwordForTest());
        assertNull(secrets.challengeForTest());
    }
}
