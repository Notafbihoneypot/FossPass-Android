# FossPass Security Hardening Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Fix the audited FossPass Android and shared-vault security issues from highest to lowest priority, verify both Android and Qubes clients, then publish sanitized source repositories.

**Architecture:** Extract lifecycle and matching policy into testable Java helpers; keep cryptographic and import invariants in the Rust core; use generation tokens to reject stale async results; make filesystem transactions durable; generate native artifacts from source rather than publishing stale binaries. Preserve Argon2id/XChaCha20/AES-GCM parameters and fail closed.

**Tech Stack:** Java 17, Android SDK 35, Gradle 8, CameraX/ZXing, FIDO2, Rust/UniFFI, Tauri 2, Node/Vite.

---

### Task 1: Reject stale asynchronous vault operations (P0)

**Files:**
- Create: `app/src/main/java/org/fosspass/SecureOperationGate.java`
- Create: `app/src/test/java/org/fosspass/SecureOperationGateTest.java`
- Modify: `app/src/main/java/org/fosspass/MainActivity.java`

1. Write JVM tests proving a generation accepted while started is rejected after lock, stop, screen-off, destruction, or a newer operation.
2. Run the focused test and confirm RED because the gate does not exist.
3. Implement a monotonic generation gate with explicit started/stopped state and one in-flight unlock.
4. Apply the captured generation before assigning `rustVault`, activating `VaultSession`, or posting success UI from unlock/rekey/import.
5. Run focused and complete Android unit tests; commit only after GREEN.

### Task 2: Scope external flows and clear pending FIDO secrets (P0)

**Files:**
- Create or modify: `app/src/main/java/org/fosspass/ExternalFlowState.java`
- Test: `app/src/test/java/org/fosspass/ExternalFlowStateTest.java`
- Modify: `app/src/main/java/org/fosspass/MainActivity.java`
- Modify: `app/src/main/java/org/fosspass/VaultSession.java`

1. Write tests proving only an explicit, single-use autofill handoff can retain a short-lived vault session; document picker, QR, FIDO, and settings flows must not.
2. Write tests proving cancellation, API failure, launch failure, timeout, stop, destruction, and explicit lock clear challenge/password state.
3. Verify RED, implement scoped flow types and centralized terminal cleanup, then verify GREEN.
4. Ensure the successful FIDO path consumes pending state exactly once.

### Task 3: Restrict and deblock Autofill (P1)

**Files:**
- Modify: `app/src/main/java/org/fosspass/AutofillFieldClassifier.java`
- Modify: `app/src/main/java/org/fosspass/FossPassAutofillService.java`
- Modify: `app/src/main/java/org/fosspass/AutofillAuthActivity.java`
- Test: `app/src/test/java/org/fosspass/AutofillFieldClassifierTest.java`
- Create: `app/src/test/java/org/fosspass/AutofillOriginMatcherTest.java`

1. Add failing tests for normalized exact/subdomain URL matching, package associations, IDN handling, malformed URLs, and default-deny behavior.
2. Implement matched entries only; expose search-all only behind explicit authentication.
3. Move vault reads and fill response construction to an executor and honor `CancellationSignal` before and during work.
4. Verify no credential titles are returned to unrelated apps/sites.

### Task 4: Harden FIDO verification and persistence (P1)

**Files:**
- Modify: `app/src/main/java/org/fosspass/Fido2HardwareKey.java`
- Modify: `app/src/main/java/org/fosspass/MainActivity.java`
- Modify: `app/src/test/java/org/fosspass/Fido2HardwareKeyTest.java`

1. Add failing tests for missing/wrong Android APK origin, wrong challenge/type/RP hash, and counter rollback.
2. Parse `clientDataJSON` as JSON and validate the configured `android:apk-key-hash:` origin.
3. Persist accepted counters with checked synchronous `commit()` before granting access.
4. Rename UI claims from hardware-backed key to roaming FIDO credential unless attestation is actually verified.

### Task 5: Harden credential creation and deletion UX (P1)

**Files:**
- Modify: `app/src/main/java/org/fosspass/MainActivity.java`
- Test: new focused JVM policy/helper tests under `app/src/test/java/org/fosspass/`

1. Add failing policy tests for password confirmation/strength and destructive-action confirmation.
2. Make new-entry passwords masked with deliberate reveal support and no suggestions/autocorrect.
3. Separate create/unlock behavior and require confirmation plus strength for creation.
4. Require delete confirmation, disable duplicate submission, and surface failures.
5. Add biometric capability/error callbacks and a documented fallback policy.

### Task 6: Bound and consolidate imports (P1)

**Files:**
- Modify: `crates/fosspass-core/src/vault.rs`
- Modify: `crates/fosspass-core/src/lib.rs`
- Modify: `crates/fosspass-core/src/fosspass.udl`
- Regenerate: `app/src/main/java/uniffi/fosspass_core/fosspass_core.kt`
- Modify: `app/src/main/java/org/fosspass/MainActivity.java`

1. Add Rust tests for maximum KeePass entry count, recursion depth, per-field size, aggregate decoded size, and rollback.
2. Add one Rust import transaction that performs deduplication and writes once without Java and Rust independently rescanning.
3. Return a report and updated non-secret metadata; avoid the immediate third full reload.
4. Minimize full-vault immutable Java strings and require fresh authentication/warning for plaintext export.

### Task 7: Make encrypted writes crash-durable (P1)

**Files:**
- Modify: `crates/fosspass-core/src/vault.rs`
- Modify: Qubes `src-tauri/src/vault.rs`
- Test: Rust tests in both files/modules

1. Add fault-injection tests for temp write, file sync, rename, parent-directory sync, rekey stage swap, and recovery.
2. Use unique 0600 temporary files, write/flush/`sync_all`, atomic rename, and parent directory sync.
3. Make rekey recovery deterministic and replace/clear Android `VaultSession` after a successful password change.
4. Verify permissions, tamper rejection, and rollback remain intact.

### Task 8: Remove stale native-artifact and startup risks (P2)

**Files:**
- Modify: `app/build.gradle`
- Modify: `README.md`
- Modify: `.gitignore`
- Modify: CI workflows under `.github/workflows/`
- Remove: checked-in `apks/`, `app/src/main/jniLibs/`, and unused `CryptoManager.java` after proving no references

1. Add a build check that generates UniFFI bindings and native libraries from the same source commit.
2. Fail the build on missing ABI/checksum symbols and fail closed at app startup if `System.loadLibrary` fails.
3. Align documented/package ABIs; enforce release stripping and verify the release APK contents.
4. Keep binaries in signed GitHub Releases, not source history.

### Task 9: Improve large-vault scaling without plaintext indexes (P2)

**Files:**
- Modify: `app/src/main/java/org/fosspass/MainActivity.java` or replace list UI with dedicated adapter classes
- Create: RecyclerView adapter/search policy tests
- Modify: Rust core only if an authenticated encrypted metadata index is introduced

1. Add paging/filter behavior tests and performance regression fixtures for 500 and 50,000 metadata records.
2. Replace the all-views `ScrollView` with `RecyclerView/ListAdapter` and search.
3. Fetch/display secret fields only for the selected authenticated entry.
4. Do not create an unauthenticated plaintext title/domain index.

### Task 10: Final independent review, verification, and publication

**Files:**
- Both repositories and new `.github/workflows/` CI definitions

1. Run independent spec and security reviewers over each diff; fix all critical/important findings.
2. Android canonical gate: Rust tests, regenerated JNI/UniFFI, `:app:testDebugUnitTest`, `:app:lintDebug`, `:app:assembleDebug`, release APK inspection, and physical-device tests when attached.
3. Qubes gate: `npm test`, frontend build, `cargo fmt --check`, Rust tests, Clippy with warnings denied, RPM build/install/launch verification.
4. Scan tracked files/history for secrets, vaults, plaintext exports, signing keys, APKs, RPMs, and local build paths.
5. Commit verified source, authenticate GitHub, create/update the two repositories, push `main`, and read back remote commit IDs and CI status before reporting success.
