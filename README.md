# FossPass Android

Offline-first encrypted Android password vault with Qubes interoperability.

## Current Android build

- Version: `0.3.1-alpha-import-security` (version code 5)
- Architecture: Android `arm64-v8a`
- Signing: debug/test key — prerelease testing only

[Download FossPass 0.3.1 alpha APK](apks/FossPass-0.3.1-alpha-import-security-arm64-debug.apk)

SHA-256:

```text
af9e719164ee416d83e476e4851241016f4836346f95206388b13958d023bc5c
```

Security-relevant properties of this build:

- Encrypted vault storage using Argon2id and authenticated encryption.
- Duplicate prevention for manual and imported entries.
- Fail-closed handling for tampered or corrupt vault records.
- Private internal storage by default, with optional encrypted app-scoped device storage.
- Password-manager imports for supported JSON, CSV, and KeePass XML exports.
- Android backup disabled and cleartext network traffic disabled.
- No broad storage permission and no Internet permission.

> This is a debug-signed alpha build. Do not treat it as a production release. A production APK must be signed with a protected release key and tested on physical devices.
