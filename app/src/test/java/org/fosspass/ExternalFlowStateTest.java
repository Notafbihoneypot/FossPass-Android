package org.fosspass;

import static org.junit.Assert.*;

import org.junit.Test;

public class ExternalFlowStateTest {
    @Test public void flowsAreTypedTokenBoundAndExpire() {
        ExternalFlowState state = new ExternalFlowState();
        assertTrue(state.begin(ExternalFlowState.Type.FIDO_ASSERTION, 41L, 1000L, 500L));
        assertTrue(state.peek(ExternalFlowState.Type.FIDO_ASSERTION, 41L, 1499L));
        assertFalse(state.peek(ExternalFlowState.Type.DOCUMENT_IMPORT, 41L, 1200L));
        assertFalse(state.peek(ExternalFlowState.Type.FIDO_ASSERTION, 42L, 1200L));
        assertFalse(state.peek(ExternalFlowState.Type.FIDO_ASSERTION, 41L, 1501L));
        assertEquals(ExternalFlowState.Type.NONE, state.current(1501L));
    }

    @Test public void completionIsTypeAndTokenScopedAndSingleUse() {
        ExternalFlowState state = new ExternalFlowState();
        assertTrue(state.begin(ExternalFlowState.Type.QR_SCAN, 17L, 5L, 100L));
        assertFalse(state.consume(ExternalFlowState.Type.DOCUMENT_IMPORT, 17L, 6L));
        assertFalse(state.consume(ExternalFlowState.Type.QR_SCAN, 18L, 6L));
        assertTrue(state.consume(ExternalFlowState.Type.QR_SCAN, 17L, 6L));
        assertFalse(state.consume(ExternalFlowState.Type.QR_SCAN, 17L, 6L));
    }

    @Test public void liveFlowCannotBeOverwritten() {
        ExternalFlowState state = new ExternalFlowState();
        assertTrue(state.begin(ExternalFlowState.Type.QR_SCAN, 1L, 100L, 20L));
        assertFalse(state.begin(ExternalFlowState.Type.DOCUMENT_IMPORT, 2L, 101L, 20L));
        assertTrue(state.peek(ExternalFlowState.Type.QR_SCAN, 1L, 101L));
    }

    @Test public void expiredFlowDoesNotBlockAReplacement() {
        ExternalFlowState state = new ExternalFlowState();
        assertTrue(state.begin(ExternalFlowState.Type.QR_SCAN, 1L, 100L, 20L));
        assertTrue(state.begin(ExternalFlowState.Type.DOCUMENT_IMPORT, 2L, 120L, 20L));
        assertTrue(state.peek(ExternalFlowState.Type.DOCUMENT_IMPORT, 2L, 120L));
    }

    @Test public void exactDeadlineIsExpired() {
        ExternalFlowState state = new ExternalFlowState();
        assertTrue(state.begin(ExternalFlowState.Type.QR_SCAN, 9L, 100L, 20L));
        assertTrue(state.peek(ExternalFlowState.Type.QR_SCAN, 9L, 119L));
        assertFalse(state.peek(ExternalFlowState.Type.QR_SCAN, 9L, 120L));
        assertEquals(ExternalFlowState.Type.NONE, state.current(120L));
    }

    @Test public void staleResultCannotConsumeNewSameTypeFlow() {
        ExternalFlowState state = new ExternalFlowState();
        assertTrue(state.begin(ExternalFlowState.Type.FIDO_ASSERTION, 1001L, 0L, 10L));
        assertTrue(state.consume(ExternalFlowState.Type.FIDO_ASSERTION, 1001L, 1L));
        assertTrue(state.begin(ExternalFlowState.Type.FIDO_ASSERTION, 1002L, 2L, 10L));
        assertFalse(state.consume(ExternalFlowState.Type.FIDO_ASSERTION, 1001L, 3L));
        assertTrue(state.peek(ExternalFlowState.Type.FIDO_ASSERTION, 1002L, 3L));
    }

    @Test public void clearRemovesBoundFlow() {
        ExternalFlowState state = new ExternalFlowState();
        assertTrue(state.begin(ExternalFlowState.Type.DOCUMENT_EXPORT, 55L, 1L, 100L));
        state.clear();
        assertFalse(state.peek(ExternalFlowState.Type.DOCUMENT_EXPORT, 55L, 2L));
    }

    @Test public void onlyAutofillHandoffMayRetainVault() {
        for (ExternalFlowState.Type type : ExternalFlowState.Type.values()) {
            assertEquals(type == ExternalFlowState.Type.AUTOFILL_HANDOFF,
                    ExternalFlowState.mayRetainVault(type));
        }
    }

    @Test public void onlyFidoTransitionsPreservePendingFidoMaterial() {
        for (ExternalFlowState.Type type : ExternalFlowState.Type.values()) {
            boolean expected = type == ExternalFlowState.Type.FIDO_ASSERTION
                    || type == ExternalFlowState.Type.FIDO_REGISTRATION;
            assertEquals(type.name(), expected, ExternalFlowState.mayRetainFidoSecrets(type));
        }
    }

    @Test public void everyExternalTransitionLocksTheLiveVaultUi() {
        for (ExternalFlowState.Type type : ExternalFlowState.Type.values()) {
            assertTrue(type.name(), ExternalFlowState.mustLockLiveVault(type));
        }
    }
}
