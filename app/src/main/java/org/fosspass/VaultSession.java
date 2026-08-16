package org.fosspass;

import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;

import java.util.Collections;
import java.util.List;

import uniffi.fosspass_core.PublicEntry;
import uniffi.fosspass_core.UnlockedVault;

/** In-memory, process-local handoff. It never persists decrypted entries. */
final class VaultSession {
    private static final Handler MAIN = new Handler(Looper.getMainLooper());
    private static UnlockedVault vault;
    private static long expiresAtElapsedMs;
    private static long generation;

    private VaultSession() {}

    static synchronized void activate(UnlockedVault unlockedVault) {
        generation++;
        vault = unlockedVault;
        expiresAtElapsedMs = Long.MAX_VALUE;
    }

    static synchronized void handoff(UnlockedVault unlockedVault, long durationMs) {
        long ticket = ++generation;
        long boundedDuration = Math.max(0L, durationMs);
        vault = unlockedVault;
        expiresAtElapsedMs = SystemClock.elapsedRealtime() + boundedDuration;
        MAIN.postDelayed(() -> clearIfCurrent(ticket), boundedDuration);
    }

    static synchronized List<PublicEntry> entries() {
        if (!valid()) return Collections.emptyList();
        try {
            return vault.listEntries();
        } catch (Exception ignored) {
            clear();
            return Collections.emptyList();
        }
    }

    static synchronized PublicEntry find(String entryId) {
        if (!valid() || entryId == null) return null;
        try {
            for (PublicEntry entry : vault.listEntries()) {
                if (entryId.equals(entry.getEntryId())) return entry;
            }
        } catch (Exception ignored) {
            clear();
        }
        return null;
    }

    static synchronized void clear() {
        generation++;
        vault = null;
        expiresAtElapsedMs = 0L;
    }

    private static boolean valid() {
        if (vault == null || SystemClock.elapsedRealtime() > expiresAtElapsedMs) {
            clear();
            return false;
        }
        return true;
    }

    private static synchronized void clearIfCurrent(long ticket) {
        if (generation == ticket) clear();
    }
}
