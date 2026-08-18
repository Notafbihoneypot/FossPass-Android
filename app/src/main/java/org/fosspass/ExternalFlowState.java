package org.fosspass;

/** A single, typed, token-bound, expiring external-Activity launch. */
final class ExternalFlowState {
    static final long INVALID_TOKEN = -1L;

    enum Type {
        NONE,
        FIDO_REGISTRATION,
        FIDO_ASSERTION,
        QR_SCAN,
        DOCUMENT_IMPORT,
        DOCUMENT_EXPORT,
        AUTOFILL_SETTINGS,
        AUTOFILL_HANDOFF
    }

    private Type type = Type.NONE;
    private long token = INVALID_TOKEN;
    private long expiresAtMs;
    private long legacyToken;

    /**
     * Begins a flow only if no unexpired flow is live. The request token must be
     * carried by the launch callback and supplied to {@link #peek} or {@link #consume}.
     */
    synchronized boolean begin(Type next, long operationToken, long nowMs, long durationMs) {
        requireTypeAndToken(next, operationToken);
        expireAt(nowMs);
        if (type != Type.NONE) return false;

        type = next;
        token = operationToken;
        long duration = Math.max(0L, durationMs);
        expiresAtMs = duration > Long.MAX_VALUE - nowMs ? Long.MAX_VALUE : nowMs + duration;
        return true;
    }

    synchronized Type current(long nowMs) {
        expireAt(nowMs);
        return type;
    }

    /** Non-consuming check that requires both the launch type and request identity. */
    synchronized boolean peek(Type expected, long operationToken, long nowMs) {
        expireAt(nowMs);
        return expected != null && expected != Type.NONE
                && operationToken != INVALID_TOKEN
                && type == expected && token == operationToken;
    }

    /** Consumes the matching launch exactly once. A mismatch leaves the live flow intact. */
    synchronized boolean consume(Type expected, long operationToken, long nowMs) {
        if (!peek(expected, operationToken, nowMs)) return false;
        clear();
        return true;
    }

    synchronized void clear() {
        type = Type.NONE;
        token = INVALID_TOKEN;
        expiresAtMs = 0L;
    }

    private void expireAt(long nowMs) {
        if (type != Type.NONE && nowMs >= expiresAtMs) clear();
    }

    private static void requireTypeAndToken(Type next, long operationToken) {
        if (next == null || next == Type.NONE) {
            throw new IllegalArgumentException("A scoped flow type is required");
        }
        if (operationToken == INVALID_TOKEN) {
            throw new IllegalArgumentException("A request token is required");
        }
    }

    /*
     * Source-compatibility bridge for the in-progress Activity migration. New code
     * must use the token-bearing API above; this bridge still provides exclusivity.
     */
    @Deprecated synchronized void begin(Type next, long nowMs, long durationMs) {
        long nextToken = ++legacyToken;
        if (nextToken == INVALID_TOKEN) nextToken = ++legacyToken;
        begin(next, nextToken, nowMs, durationMs);
    }

    @Deprecated synchronized boolean matches(Type expected, long nowMs) {
        expireAt(nowMs);
        return type == expected;
    }

    @Deprecated synchronized boolean consume(Type expected, long nowMs) {
        expireAt(nowMs);
        if (type != expected) return false;
        clear();
        return true;
    }

    static boolean mayRetainVault(Type type) {
        return type == Type.AUTOFILL_HANDOFF;
    }

    static boolean mayRetainFidoSecrets(Type type) {
        return type == Type.FIDO_ASSERTION || type == Type.FIDO_REGISTRATION;
    }

    /** External activities never keep the decrypted vault attached to the visible Activity. */
    static boolean mustLockLiveVault(Type type) {
        return true;
    }
}
