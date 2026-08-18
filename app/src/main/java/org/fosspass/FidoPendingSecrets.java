package org.fosspass;

import java.util.Arrays;

/** Owns and zeroizes short-lived FIDO assertion material. */
final class FidoPendingSecrets {
    enum CleanupReason { CANCELLATION, API_FAILURE, LAUNCH_FAILURE, TIMEOUT, ON_STOP, DESTRUCTION, INVALID_RESULT }

    private char[] password;
    private byte[] challenge;
    private long expiresAtMs;
    private boolean assertion;

    synchronized void setAssertion(char[] sourcePassword, byte[] sourceChallenge, long nowMs, long durationMs) {
        clear(CleanupReason.INVALID_RESULT);
        password = Arrays.copyOf(sourcePassword, sourcePassword.length);
        challenge = Arrays.copyOf(sourceChallenge, sourceChallenge.length);
        assertion = true;
        expiresAtMs = nowMs + Math.max(0L, durationMs);
    }

    synchronized void setRegistration(byte[] sourceChallenge, long nowMs, long durationMs) {
        clear(CleanupReason.INVALID_RESULT);
        challenge = Arrays.copyOf(sourceChallenge, sourceChallenge.length);
        assertion = false;
        expiresAtMs = nowMs + Math.max(0L, durationMs);
    }

    synchronized byte[] challenge(long nowMs) {
        if (!hasPending(nowMs)) return null;
        return Arrays.copyOf(challenge, challenge.length);
    }

    synchronized char[] consumeAssertion(long nowMs) {
        if (!hasPending(nowMs)) return null;
        char[] result = Arrays.copyOf(password, password.length);
        clear(CleanupReason.INVALID_RESULT);
        return result;
    }

    synchronized boolean hasPending(long nowMs) {
        if (challenge == null || (assertion && password == null) || nowMs >= expiresAtMs) {
            if (password != null || challenge != null) clear(CleanupReason.TIMEOUT);
            return false;
        }
        return true;
    }

    synchronized void clear(CleanupReason reason) {
        if (password != null) Arrays.fill(password, '\0');
        if (challenge != null) Arrays.fill(challenge, (byte) 0);
        password = null;
        challenge = null;
        assertion = false;
        expiresAtMs = 0L;
    }

    // Package-private snapshots retained solely to verify zeroization in local JVM tests.
    synchronized char[] passwordForTest() { return password == null ? null : Arrays.copyOf(password, password.length); }
    synchronized byte[] challengeForTest() { return challenge == null ? null : Arrays.copyOf(challenge, challenge.length); }
}
