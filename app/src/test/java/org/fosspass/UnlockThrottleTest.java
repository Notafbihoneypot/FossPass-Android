package org.fosspass;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class UnlockThrottleTest {
    @Test
    public void firstFailureDelaysForTwoSeconds() {
        UnlockThrottle.State state = UnlockThrottle.recordFailure(0, 0L, 10_000L);
        assertEquals(1, state.failures);
        assertEquals(12_000L, state.blockedUntilMs);
    }

    @Test
    public void delayDoublesAndCapsAtOneMinute() {
        UnlockThrottle.State state = UnlockThrottle.recordFailure(10, 0L, 10_000L);
        assertEquals(11, state.failures);
        assertEquals(70_000L, state.blockedUntilMs);
    }

    @Test
    public void remainingDelayNeverGoesNegative() {
        assertEquals(0L, UnlockThrottle.remainingMs(12_000L, 12_001L));
        assertEquals(1_500L, UnlockThrottle.remainingMs(12_000L, 10_500L));
    }

    @Test
    public void corruptPersistedFailureCountIsBounded() {
        UnlockThrottle.State state = UnlockThrottle.recordFailure(Integer.MAX_VALUE, 0L, 5_000L);
        assertTrue(state.failures <= UnlockThrottle.MAX_FAILURES);
        assertEquals(65_000L, state.blockedUntilMs);
    }
}
