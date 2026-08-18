# FossPass Android

Offline-first encrypted Android password vault with Qubes interoperability.

Current build: `0.4.1-alpha-qr-scanner` (`versionCode 7`).

## Download

- Architecture: Android `arm64-v8a`
- Signing: debug/test key — prerelease testing only
- APK: [FossPass 0.4.1 alpha](apks/FossPass-0.4.1-alpha-qr-scanner-arm64-debug.apk)
- SHA-256: `5c5b4b2a214a6cafc367a7c8adea5621f991c98b7934f75a160b846b6bd18df1`

> This is a debug-signed alpha build. Do not treat it as a production release. A production APK must be signed with a protected release key and tested on physical devices.

## Implemented

- Rust/UniFFI vault core using Argon2id and XChaCha20-Poly1305.
- Vault create, unlock, master-password change, entries, imports, exports, and encrypted QR sync.
- One direct QR for small encrypted bundles and one automatically changing QR tile for large vaults, with live Android camera heartbeat, QR detection, haptic frame confirmation, and collection progress.
- `BIOMETRIC_STRONG`, FIDO2 roaming-key support, `FLAG_SECURE`, clipboard sensitivity metadata, and automatic clipboard clearing.
- StrongBox-backed encrypted preferences when verified; encrypted Android Keystore fallback when StrongBox is unavailable. The app fails closed if encrypted preferences cannot initialize.
- Persistent exponential unlock throttling capped at 60 seconds.
- Android Autofill Service with a 30-second in-memory handoff and a fresh `BIOMETRIC_STRONG` confirmation before one credential is released. Decrypted Autofill data is never persisted.
- Choose the encrypted database location from the unlock screen: private internal storage (recommended) or app-scoped device storage. Locations remain separate encrypted vaults and switching does not copy records.
- Password-manager imports for supported JSON, CSV, KeePass XML, and KDBX exports.
- Android backup disabled and cleartext network traffic disabled.
- No broad storage permission and no `INTERNET` permission.

## Autofill workflow

1. Open and unlock FossPass normally, including the configured FIDO2 step when enabled.
2. Open **Import / Export** and select **Enable Android Autofill** once.
3. Switch to the target app within 30 seconds.
4. Select a FossPass entry from Android Autofill and confirm biometrics.

The handoff is process-local, expires proactively after 30 seconds, is cleared after one fill, and is cleared immediately by explicit lock or screen-off.

## Build

```bash
export JAVA_HOME="$HOME/Downloads/android-studio/jbr"
export ANDROID_HOME="$HOME/Android/Sdk"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/27.2.12479018"
export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$PATH"

cd crates/fosspass-core
cargo test
cargo build --release
cargo run --bin uniffi-bindgen -- generate \
  --library target/release/libfosspass_core.so \
  --language kotlin \
  --out-dir ../../app/src/main/java
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \
  -o ../../app/src/main/jniLibs build --release
cd ../..

./gradlew clean :app:testDebugUnitTest :app:lintDebug :app:assembleDebug
```

Canonical debug APK:

`app/build/outputs/apk/debug/app-debug.apk`

Physical-device verification is still required for UI, storage switching, Autofill integration, biometrics, StrongBox, QR camera, and roaming FIDO2 behavior.

## Qubes desktop interoperability

The matching source repository is [FossPass-Qubes](https://github.com/Notafbihoneypot/FossPass-Qubes).

Both applications implement the same encrypted transfer format:

- `fosspass-qr-sync-v1` and `fosspass-vault-file-v1`
- Argon2id: 32 MiB, 2 iterations, parallelism 1
- AES-256-GCM with a random 16-byte salt and 12-byte IV

Use a separate 8+ character offline sync passphrase, not a vault master password. Transfer the encrypted JSON by QR or `.fosspass` file between Qubes and Android.
