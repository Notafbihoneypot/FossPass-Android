package org.fosspass;

/** Thread-safe generation guard for asynchronous work owned by one Activity lifecycle. */
final class LifecycleOperationGuard {
    static final long INVALID_TOKEN = -1L;

    enum Kind { UNLOCK, REKEY, IMPORT, FIDO_REGISTRATION }

    @FunctionalInterface
    interface GuardedCall<T, E extends Exception> {
        T call() throws E;
    }

    /** Distinguishes a skipped call from a call that ran and legitimately returned null. */
    static final class CallResult<T> {
        private static final CallResult<?> NOT_RUN = new CallResult<>(false, null);

        private final boolean ran;
        private final T value;

        private CallResult(boolean ran, T value) {
            this.ran = ran;
            this.value = value;
        }

        static <T> CallResult<T> ran(T value) {
            return new CallResult<>(true, value);
        }

        @SuppressWarnings("unchecked")
        static <T> CallResult<T> notRun() {
            return (CallResult<T>) NOT_RUN;
        }

        boolean wasRun() {
            return ran;
        }

        T value() {
            return value;
        }
    }

    private long generation;
    private long activeToken = INVALID_TOKEN;
    private Kind activeKind;
    private boolean destroyed;

    synchronized long beginExclusive(Kind kind) {
        if (kind == null || destroyed || activeToken != INVALID_TOKEN) return INVALID_TOKEN;
        generation = nextGeneration(generation);
        activeToken = generation;
        activeKind = kind;
        return activeToken;
    }

    /** Captures this lifecycle generation for non-exclusive background/UI callbacks. */
    synchronized long captureGeneration() {
        return destroyed ? INVALID_TOKEN : generation;
    }

    synchronized boolean isGenerationCurrent(long token) {
        return !destroyed && token != INVALID_TOKEN && token == generation;
    }

    synchronized boolean isCurrent(long token, Kind kind) {
        return !destroyed && token != INVALID_TOKEN && token == activeToken && kind == activeKind;
    }

    synchronized boolean completeIfCurrent(long token, Kind kind) {
        if (!isCurrent(token, kind)) return false;
        clearActive();
        return true;
    }

    /** Invalidates only the operation identified by token; stale callbacks are harmless. */
    synchronized boolean invalidateIfCurrent(long token) {
        if (destroyed || token == INVALID_TOKEN || token != activeToken) return false;
        invalidateLocked();
        return true;
    }

    /**
     * Linearization point for a guarded mutation. The guard monitor is deliberately
     * held for the call: either the call finishes before invalidate() returns, or an
     * earlier invalidate makes this return notRun without invoking the call.
     * Exceptions from the call are propagated and do not complete the operation.
     */
    synchronized <T, E extends Exception> CallResult<T> callIfCurrent(
            long token, Kind kind, GuardedCall<T, E> call) throws E {
        if (call == null) throw new NullPointerException("call");
        if (!isCurrent(token, kind)) return CallResult.notRun();
        return CallResult.ran(call.call());
    }

    synchronized void invalidate() {
        invalidateLocked();
    }

    synchronized void destroy() {
        invalidateLocked();
        destroyed = true;
    }

    private void invalidateLocked() {
        generation = nextGeneration(generation);
        clearActive();
    }

    private void clearActive() {
        activeToken = INVALID_TOKEN;
        activeKind = null;
    }

    private static long nextGeneration(long current) {
        long next = current + 1L;
        return next == INVALID_TOKEN ? next + 1L : next;
    }
}
