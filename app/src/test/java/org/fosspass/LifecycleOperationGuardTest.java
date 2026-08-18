package org.fosspass;

import static org.junit.Assert.*;

import org.junit.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public class LifecycleOperationGuardTest {
    @Test public void invalidationRejectsInFlightCallbackAndAllowsNewUnlock() {
        LifecycleOperationGuard guard = new LifecycleOperationGuard();
        long unlock = guard.beginExclusive(LifecycleOperationGuard.Kind.UNLOCK);
        assertTrue(unlock > 0);
        assertEquals(LifecycleOperationGuard.INVALID_TOKEN,
                guard.beginExclusive(LifecycleOperationGuard.Kind.UNLOCK));

        guard.invalidate();
        assertFalse(guard.completeIfCurrent(unlock, LifecycleOperationGuard.Kind.UNLOCK));
        assertTrue(guard.beginExclusive(LifecycleOperationGuard.Kind.UNLOCK) > unlock);
    }

    @Test public void callbackCanMutateOnlyOnceForMatchingKind() {
        LifecycleOperationGuard guard = new LifecycleOperationGuard();
        long token = guard.beginExclusive(LifecycleOperationGuard.Kind.REKEY);
        assertFalse(guard.completeIfCurrent(token, LifecycleOperationGuard.Kind.IMPORT));
        assertTrue(guard.completeIfCurrent(token, LifecycleOperationGuard.Kind.REKEY));
        assertFalse(guard.completeIfCurrent(token, LifecycleOperationGuard.Kind.REKEY));
    }

    @Test public void destructionPermanentlyRejectsOperations() {
        LifecycleOperationGuard guard = new LifecycleOperationGuard();
        long token = guard.beginExclusive(LifecycleOperationGuard.Kind.IMPORT);
        guard.destroy();
        assertFalse(guard.completeIfCurrent(token, LifecycleOperationGuard.Kind.IMPORT));
        assertEquals(LifecycleOperationGuard.INVALID_TOKEN,
                guard.beginExclusive(LifecycleOperationGuard.Kind.UNLOCK));
    }

    @Test public void generationSnapshotRejectsCallbackAfterBackgroundLock() {
        LifecycleOperationGuard guard = new LifecycleOperationGuard();
        long generation = guard.captureGeneration();
        assertTrue(guard.isGenerationCurrent(generation));
        guard.invalidate();
        assertFalse(guard.isGenerationCurrent(generation));
    }

    @Test public void completionDoesNotRevalidateAnOlderGeneration() {
        LifecycleOperationGuard guard = new LifecycleOperationGuard();
        long beforeOperation = guard.captureGeneration();
        long operation = guard.beginExclusive(LifecycleOperationGuard.Kind.REKEY);
        assertFalse(guard.isGenerationCurrent(beforeOperation));
        assertTrue(guard.completeIfCurrent(operation, LifecycleOperationGuard.Kind.REKEY));
        assertFalse(guard.isGenerationCurrent(beforeOperation));
        assertTrue(guard.isGenerationCurrent(guard.captureGeneration()));
    }

    @Test public void destructionRejectsCapturedGenerationCallbacks() {
        LifecycleOperationGuard guard = new LifecycleOperationGuard();
        long generation = guard.captureGeneration();
        guard.destroy();
        assertFalse(guard.isGenerationCurrent(generation));
        assertEquals(LifecycleOperationGuard.INVALID_TOKEN, guard.captureGeneration());
    }

    @Test public void staleCallbackCannotInvalidateNewerOperation() {
        LifecycleOperationGuard guard = new LifecycleOperationGuard();
        long stale = guard.beginExclusive(LifecycleOperationGuard.Kind.UNLOCK);
        assertTrue(guard.completeIfCurrent(stale, LifecycleOperationGuard.Kind.UNLOCK));
        long current = guard.beginExclusive(LifecycleOperationGuard.Kind.REKEY);

        assertFalse(guard.invalidateIfCurrent(stale));
        assertTrue(guard.isCurrent(current, LifecycleOperationGuard.Kind.REKEY));
        assertTrue(guard.invalidateIfCurrent(current));
        assertFalse(guard.isCurrent(current, LifecycleOperationGuard.Kind.REKEY));
    }

    @Test public void staleCompletionCannotCompleteNewerSameKindOperation() {
        LifecycleOperationGuard guard = new LifecycleOperationGuard();
        long stale = guard.beginExclusive(LifecycleOperationGuard.Kind.UNLOCK);
        assertTrue(guard.completeIfCurrent(stale, LifecycleOperationGuard.Kind.UNLOCK));
        long current = guard.beginExclusive(LifecycleOperationGuard.Kind.UNLOCK);

        assertFalse(guard.completeIfCurrent(stale, LifecycleOperationGuard.Kind.UNLOCK));
        assertTrue(guard.isCurrent(current, LifecycleOperationGuard.Kind.UNLOCK));
    }

    @Test public void guardedCallFinishesBeforeConcurrentInvalidateReturns() throws Exception {
        LifecycleOperationGuard guard = new LifecycleOperationGuard();
        long token = guard.beginExclusive(LifecycleOperationGuard.Kind.IMPORT);
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch invalidated = new CountDownLatch(1);
        AtomicBoolean mutationFinished = new AtomicBoolean(false);
        AtomicReference<Throwable> threadFailure = new AtomicReference<>();

        Thread callback = new Thread(() -> {
            try {
                LifecycleOperationGuard.CallResult<String> result = guard.callIfCurrent(
                        token, LifecycleOperationGuard.Kind.IMPORT, () -> {
                            entered.countDown();
                            assertTrue(release.await(5, TimeUnit.SECONDS));
                            mutationFinished.set(true);
                            return "committed";
                        });
                assertTrue(result.wasRun());
                assertEquals("committed", result.value());
            } catch (Throwable e) {
                threadFailure.set(e);
            }
        });
        callback.start();
        assertTrue(entered.await(5, TimeUnit.SECONDS));

        Thread invalidator = new Thread(() -> {
            guard.invalidate();
            if (!mutationFinished.get()) {
                threadFailure.compareAndSet(null, new AssertionError("invalidate returned early"));
            }
            invalidated.countDown();
        });
        invalidator.start();
        assertFalse(invalidated.await(100, TimeUnit.MILLISECONDS));
        release.countDown();
        callback.join(5000);
        invalidator.join(5000);
        assertFalse(callback.isAlive());
        assertFalse(invalidator.isAlive());
        assertEquals(0L, invalidated.getCount());
        if (threadFailure.get() != null) throw new AssertionError(threadFailure.get());
    }

    @Test public void concurrentInvalidateWinningPreventsGuardedCall() throws Exception {
        LifecycleOperationGuard guard = new LifecycleOperationGuard();
        long token = guard.beginExclusive(LifecycleOperationGuard.Kind.REKEY);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch invalidated = new CountDownLatch(1);
        AtomicBoolean ran = new AtomicBoolean(false);
        AtomicReference<LifecycleOperationGuard.CallResult<String>> resultRef = new AtomicReference<>();
        AtomicReference<Throwable> threadFailure = new AtomicReference<>();

        Thread invalidator = new Thread(() -> {
            try {
                assertTrue(start.await(5, TimeUnit.SECONDS));
                guard.invalidate();
                invalidated.countDown();
            } catch (Throwable e) {
                threadFailure.set(e);
            }
        });
        Thread callback = new Thread(() -> {
            try {
                assertTrue(invalidated.await(5, TimeUnit.SECONDS));
                resultRef.set(guard.callIfCurrent(token, LifecycleOperationGuard.Kind.REKEY, () -> {
                    ran.set(true);
                    return "bad";
                }));
            } catch (Throwable e) {
                threadFailure.set(e);
            }
        });
        invalidator.start();
        callback.start();
        start.countDown();
        invalidator.join(5000);
        callback.join(5000);

        assertFalse(invalidator.isAlive());
        assertFalse(callback.isAlive());
        if (threadFailure.get() != null) throw new AssertionError(threadFailure.get());
        LifecycleOperationGuard.CallResult<String> result = resultRef.get();
        assertNotNull(result);
        assertFalse(result.wasRun());
        assertFalse(ran.get());
        assertNull(result.value());
    }

    @Test public void guardedCallPropagatesExceptionsAndRemainsCurrent() {
        LifecycleOperationGuard guard = new LifecycleOperationGuard();
        long token = guard.beginExclusive(LifecycleOperationGuard.Kind.REKEY);
        Exception expected = new Exception("native failure");
        try {
            guard.callIfCurrent(token, LifecycleOperationGuard.Kind.REKEY, () -> {
                throw expected;
            });
            fail("exception should propagate");
        } catch (Exception actual) {
            assertSame(expected, actual);
        }
        assertTrue(guard.isCurrent(token, LifecycleOperationGuard.Kind.REKEY));
    }
}
