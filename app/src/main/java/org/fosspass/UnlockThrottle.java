package org.fosspass;

final class UnlockThrottle {
    static final int MAX_FAILURES = 16;
    private static final long MAX_DELAY_MS = 60_000L;

    private UnlockThrottle() {}

    static State recordFailure(int currentFailures, long ignoredBlockedUntilMs, long nowMs) {
        int bounded = Math.max(0, Math.min(currentFailures, MAX_FAILURES - 1));
        int failures = bounded + 1;
        int shift = Math.min(failures, 6);
        long delayMs = Math.min(MAX_DELAY_MS, 1_000L << shift);
        return new State(failures, nowMs + delayMs);
    }

    static long remainingMs(long blockedUntilMs, long nowMs) {
        return Math.max(0L, blockedUntilMs - nowMs);
    }

    static final class State {
        final int failures;
        final long blockedUntilMs;

        State(int failures, long blockedUntilMs) {
            this.failures = failures;
            this.blockedUntilMs = blockedUntilMs;
        }
    }
}
