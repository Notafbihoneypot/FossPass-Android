use aes_gcm::{
    aead::{Aead as AesAead, KeyInit as AesKeyInit},
    Aes256Gcm, Nonce as AesNonce,
};
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{aead::OsRng, XChaCha20Poly1305, XNonce};
use chrono::Utc;
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use keepass::{
    db::{fields, GroupId, GroupRef},
    Database, DatabaseKey,
};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs,
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
use thiserror::Error;
use uuid::Uuid;
use walkdir::WalkDir;
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const VAULT_KDF_MEMORY_KIB: u32 = 32 * 1024;
const VAULT_KDF_ITERATIONS: u32 = 2;
const VAULT_KDF_PARALLELISM: u32 = 1;
const VAULT_KEY_KDF_NAME: &str = "vault-key-v1";

#[derive(Error, Debug, uniffi::Error)]
pub enum VaultError {
    #[error("I/O error: {0}")]
    Io(String),
    #[error("JSON error: {0}")]
    Json(String),
    #[error("crypto error")]
    Crypto,
    #[error("vault already exists")]
    VaultExists,
    #[error("vault not found")]
    VaultNotFound,
    #[error("invalid vault file")]
    InvalidVaultFile,
    #[error("invalid sync bundle")]
    InvalidSyncBundle,
    #[error("sync bundle replay detected")]
    SyncReplay,
    #[error("sync bundle belongs to a different vault")]
    WrongVault,
    #[error("duplicate entry")]
    DuplicateEntry,
    #[error("password import error: {0}")]
    PasswordImport(String),
}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultError::Io(e.to_string())
    }
}
impl From<serde_json::Error> for VaultError {
    fn from(e: serde_json::Error) -> Self {
        VaultError::Json(e.to_string())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    magic: String,
    format_version: u32,
    file_type: String,
    vault_id: String,
    object_id: String,
    kdf: KdfParams,
    cipher: CipherParams,
    aad: Aad,
    ciphertext: String,
}
#[derive(Debug, Serialize, Deserialize, Clone, uniffi::Record)]
pub struct KdfParams {
    pub name: String,
    pub salt: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
struct CipherParams {
    name: String,
    nonce: String,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
struct Aad {
    file_type: String,
    vault_id: String,
    object_id: String,
}
#[derive(Debug, Serialize, Deserialize)]
struct VaultMeta {
    vault_id: String,
    vault_name: String,
    created_at: String,
    updated_at: String,
    format_version: u32,
    sync_policy: SyncPolicy,
    security_profile: String,
}
#[derive(Debug, Serialize, Deserialize)]
struct SyncPolicy {
    mode: String,
    syncthing_folder_id: String,
    airgap_qr_enabled: bool,
}
#[derive(Debug, Serialize, Deserialize)]
struct LoginEntry {
    entry_id: String,
    entry_type: String,
    title: String,
    username: String,
    password: String,
    url: String,
    notes: String,
    tags: Vec<String>,
    favorite: bool,
    created_at: String,
    updated_at: String,
    updated_by_device: String,
    revision: i64,
}
#[derive(Debug, Serialize, Deserialize)]
struct Tombstone {
    entry_id: String,
    deleted_at: String,
    deleted_by_device: String,
    reason: String,
    last_known_revision: i64,
}

#[derive(uniffi::Object)]
pub struct UnlockedVault {
    root: PathBuf,
    vault_id: String,
    key: Zeroizing<[u8; 32]>,
}

#[uniffi::export]
impl UnlockedVault {
    pub fn list_entries(&self) -> Result<Vec<PublicEntry>, VaultError> {
        list_entries_internal(self)
    }
    pub fn add_entry(&self, req: AddEntryRequest) -> Result<(), VaultError> {
        add_entry_internal(self, req).map(|_| ())
    }
    pub fn add_entries(&self, requests: Vec<AddEntryRequest>) -> Result<i32, VaultError> {
        let mut duplicate_keys: HashSet<_> = list_entries_internal(self)?
            .iter()
            .map(public_duplicate_key)
            .collect();
        for request in &requests {
            if !duplicate_keys.insert(request_duplicate_key(request)) {
                return Err(VaultError::DuplicateEntry);
            }
        }

        let mut added_ids = Vec::with_capacity(requests.len());
        for request in requests {
            match write_entry_internal(self, request) {
                Ok(id) => added_ids.push(id),
                Err(error) => {
                    for id in &added_ids {
                        let _ = fs::remove_file(entry_path(&self.root, id));
                    }
                    return Err(error);
                }
            }
        }
        i32::try_from(added_ids.len()).map_err(|_| VaultError::InvalidVaultFile)
    }
    pub fn delete_entry(&self, entry_id: &str) -> Result<(), VaultError> {
        delete_entry_internal(self, entry_id)
    }
    pub fn export_android_compatible_bundle(
        &self,
        passphrase: &str,
        file_type: &str,
    ) -> Result<String, VaultError> {
        export_android_compatible_bundle_internal(self, passphrase, file_type)
    }
    pub fn import_android_compatible_bundle(
        &self,
        bundle_json: &str,
        passphrase: &str,
    ) -> Result<ImportReport, VaultError> {
        import_android_compatible_bundle_internal(self, bundle_json, passphrase)
    }
}

#[derive(Debug, Deserialize, Clone, uniffi::Record)]
pub struct AddEntryRequest {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
}

#[uniffi::export]
pub fn parse_keepass_database(
    database_bytes: Vec<u8>,
    database_password: &str,
) -> Result<Vec<AddEntryRequest>, VaultError> {
    const MAX_KEEPASS_BYTES: usize = 20 * 1024 * 1024;
    if database_bytes.is_empty() {
        return Err(VaultError::PasswordImport(
            "KeePass database is empty".into(),
        ));
    }
    if database_bytes.len() > MAX_KEEPASS_BYTES {
        return Err(VaultError::PasswordImport(
            "KeePass database exceeds 20 MiB".into(),
        ));
    }
    if !database_bytes.starts_with(&[0x03, 0xd9, 0xa2, 0x9a]) {
        return Err(VaultError::PasswordImport(
            "not a KeePass KDB/KDBX database".into(),
        ));
    }

    let database = Database::open(
        &mut Cursor::new(database_bytes),
        DatabaseKey::new().with_password(database_password),
    )
    .map_err(|_| {
        VaultError::PasswordImport(
            "KeePass database could not be opened; check its password (key files are not supported yet)"
                .into(),
        )
    })?;
    let recycle_bin = database.recycle_bin().map(|group| group.id());
    let mut entries = Vec::new();
    collect_keepass_group(database.root(), recycle_bin, &mut entries);
    if entries.is_empty() {
        return Err(VaultError::PasswordImport(
            "KeePass database contains no importable entries".into(),
        ));
    }
    Ok(entries)
}

fn collect_keepass_group(
    group: GroupRef<'_>,
    recycle_bin: Option<GroupId>,
    entries: &mut Vec<AddEntryRequest>,
) {
    if recycle_bin == Some(group.id()) {
        return;
    }
    entries.extend(group.entries().map(|entry| AddEntryRequest {
        title: entry.get(fields::TITLE).unwrap_or_default().to_string(),
        username: entry.get(fields::USERNAME).unwrap_or_default().to_string(),
        password: entry.get(fields::PASSWORD).unwrap_or_default().to_string(),
        url: entry.get(fields::URL).unwrap_or_default().to_string(),
        notes: entry.get(fields::NOTES).unwrap_or_default().to_string(),
    }));
    for child in group.groups() {
        collect_keepass_group(child, recycle_bin, entries);
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, uniffi::Record)]
pub struct PublicEntry {
    pub entry_id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub favorite: bool,
    pub updated_at: String,
    pub revision: i64,
}

#[derive(Debug, Serialize, Deserialize, uniffi::Record)]
pub struct ImportReport {
    pub bundle_id: String,
    pub imported_entries: i32,
    pub imported_tombstones: i32,
    pub conflicts: i32,
}

#[derive(Debug, Serialize, Deserialize)]
struct AndroidCompatBundle {
    r#type: String,
    #[serde(default)]
    version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    compression: Option<String>,
    salt: String,
    iv: String,
    ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AndroidCompatEntry {
    id: String,
    title: String,
    username: String,
    password: String,
    url: String,
    notes: String,
    updated_at: String,
    favorite: bool,
}

#[uniffi::export]
pub fn init_vault(vault_path: &str, master_password: &str) -> Result<(), VaultError> {
    let root = expand(vault_path);
    if root.join("vault.meta.fpass").exists() {
        return Err(VaultError::VaultExists);
    }
    secure_create_dir_all(&root)?;
    for d in ["entries", "tombstones", "devices", "bundles", "conflicts"] {
        secure_create_dir_all(&root.join(d))?
    }
    let now = now();
    let vault_id = Uuid::new_v4().to_string();
    let meta = VaultMeta {
        vault_id: vault_id.clone(),
        vault_name: "Main Vault".into(),
        created_at: now.clone(),
        updated_at: now,
        format_version: 1,
        sync_policy: SyncPolicy {
            mode: "syncthing-plus-airgap".into(),
            syncthing_folder_id: "fosspass-main".into(),
            airgap_qr_enabled: true,
        },
        security_profile: "linux-qubes-first".into(),
    };
    let env = encrypt_with_password("vault_meta", &vault_id, &vault_id, &meta, master_password)?;
    atomic_write_secure(
        root.join("vault.meta.fpass"),
        &serde_json::to_vec_pretty(&env)?,
    )?;
    Ok(())
}

#[uniffi::export]
pub fn unlock_vault(
    vault_path: &str,
    master_password: &str,
) -> Result<Arc<UnlockedVault>, VaultError> {
    let root = expand(vault_path);
    let (meta, key) = load_meta_and_key(&root, master_password)?;
    migrate_legacy_entry_filenames(&root, &meta.vault_id, &key)?;
    Ok(Arc::new(UnlockedVault {
        root,
        vault_id: meta.vault_id,
        key,
    }))
}

#[uniffi::export]
pub fn change_master_password(
    vault_path: &str,
    current_password: &str,
    new_password: &str,
) -> Result<Arc<UnlockedVault>, VaultError> {
    if new_password.is_empty() || current_password == new_password {
        return Err(VaultError::Crypto);
    }

    let root = expand(vault_path);
    let (meta, old_key) = load_meta_and_key(&root, current_password)?;
    let parent = root.parent().ok_or(VaultError::InvalidVaultFile)?;
    let token = Uuid::new_v4().to_string();
    let stage = parent.join(format!(".fosspass-rekey-{token}"));
    let backup = parent.join(format!(".fosspass-backup-{token}"));

    secure_create_dir_all(&stage)?;
    let new_meta = encrypt_with_password(
        "vault_meta",
        &meta.vault_id,
        &meta.vault_id,
        &meta,
        new_password,
    )?;
    let new_key = derive(new_password, &new_meta.kdf)?;

    let stage_result = (|| -> Result<(), VaultError> {
        for item in WalkDir::new(&root).min_depth(1).follow_links(false) {
            let item = item.map_err(|e| VaultError::Io(e.to_string()))?;
            let relative = item
                .path()
                .strip_prefix(&root)
                .map_err(|_| VaultError::InvalidVaultFile)?;
            let target = stage.join(relative);
            if item.file_type().is_symlink() {
                return Err(VaultError::InvalidVaultFile);
            }
            if item.file_type().is_dir() {
                secure_create_dir_all(&target)?;
                continue;
            }
            if relative == Path::new("vault.meta.fpass") {
                atomic_write_secure(target, &serde_json::to_vec_pretty(&new_meta)?)?;
            } else if item.path().extension().and_then(|v| v.to_str()) == Some("fpass") {
                let envelope: Envelope = serde_json::from_slice(&fs::read(item.path())?)?;
                let plain: serde_json::Value = decrypt_with_key(&envelope, &old_key)?;
                let reencrypted = encrypt_with_key(
                    &envelope.file_type,
                    &envelope.vault_id,
                    &envelope.object_id,
                    &plain,
                    &new_key,
                )?;
                atomic_write_secure(target, &serde_json::to_vec_pretty(&reencrypted)?)?;
            } else {
                if let Some(parent) = target.parent() {
                    secure_create_dir_all(parent)?;
                }
                fs::copy(item.path(), &target)?;
                #[cfg(unix)]
                fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
            }
        }
        Ok(())
    })();

    if let Err(error) = stage_result {
        let _ = fs::remove_dir_all(&stage);
        return Err(error);
    }

    fs::rename(&root, &backup)?;
    if let Err(error) = fs::rename(&stage, &root) {
        let _ = fs::rename(&backup, &root);
        let _ = fs::remove_dir_all(&stage);
        return Err(VaultError::Io(error.to_string()));
    }
    let _ = fs::remove_dir_all(&backup);

    Ok(Arc::new(UnlockedVault {
        root,
        vault_id: meta.vault_id,
        key: new_key,
    }))
}

fn same_normalized_entry(existing: &PublicEntry, incoming: &AddEntryRequest) -> bool {
    public_duplicate_key(existing) == request_duplicate_key(incoming)
}

type DuplicateKey = (String, String, String, String, String);

fn public_duplicate_key(entry: &PublicEntry) -> DuplicateKey {
    (
        normalize_duplicate_field(&entry.title),
        normalize_duplicate_field(&entry.username),
        entry.password.clone(),
        normalize_duplicate_url(&entry.url),
        normalize_duplicate_field(&entry.notes),
    )
}

fn request_duplicate_key(entry: &AddEntryRequest) -> DuplicateKey {
    (
        normalize_duplicate_field(&entry.title),
        normalize_duplicate_field(&entry.username),
        entry.password.clone(),
        normalize_duplicate_url(&entry.url),
        normalize_duplicate_field(&entry.notes),
    )
}

fn android_compat_duplicate_key(entry: &AndroidCompatEntry) -> DuplicateKey {
    (
        normalize_duplicate_field(&entry.title),
        normalize_duplicate_field(&entry.username),
        entry.password.clone(),
        normalize_duplicate_url(&entry.url),
        normalize_duplicate_field(&entry.notes),
    )
}

fn normalize_duplicate_field(value: &str) -> String {
    value.trim().to_lowercase()
}

fn normalize_duplicate_url(value: &str) -> String {
    normalize_duplicate_field(value)
        .trim_end_matches('/')
        .to_string()
}

fn add_entry_internal(
    unlocked: &UnlockedVault,
    req: AddEntryRequest,
) -> Result<String, VaultError> {
    if list_entries_internal(unlocked)?
        .iter()
        .any(|entry| same_normalized_entry(entry, &req))
    {
        return Err(VaultError::DuplicateEntry);
    }
    write_entry_internal(unlocked, req)
}

fn write_entry_internal(
    unlocked: &UnlockedVault,
    req: AddEntryRequest,
) -> Result<String, VaultError> {
    let now = now();
    let id = Uuid::new_v4().to_string();
    let entry = LoginEntry {
        entry_id: id.clone(),
        entry_type: "login".into(),
        title: req.title,
        username: req.username,
        password: req.password,
        url: req.url,
        notes: req.notes,
        tags: vec![],
        favorite: false,
        created_at: now.clone(),
        updated_at: now,
        updated_by_device: "local-linux-qubes-device".into(),
        revision: 1,
    };
    let env = encrypt_with_key("entry", &unlocked.vault_id, &id, &entry, &unlocked.key)?;
    atomic_write_secure(
        entry_path(&unlocked.root, &id),
        &serde_json::to_vec_pretty(&env)?,
    )?;
    Ok(id)
}

fn list_entries_internal(unlocked: &UnlockedVault) -> Result<Vec<PublicEntry>, VaultError> {
    let tombs = tombstones(&unlocked.root, &unlocked.key)?;
    let entries_dir = unlocked.root.join("entries");
    if !entries_dir.exists() {
        return Ok(vec![]);
    }

    let mut out = Vec::new();
    for item in WalkDir::new(entries_dir).min_depth(1).max_depth(1) {
        let item = item.map_err(|e| VaultError::Io(e.to_string()))?;
        if !item.file_type().is_file() {
            continue;
        }
        if item.path().extension().and_then(|s| s.to_str()) != Some("fpass") {
            continue;
        }
        let bytes = fs::read(item.path())?;
        let env: Envelope = serde_json::from_slice(&bytes)?;
        if env.file_type != "entry" || env.vault_id != unlocked.vault_id {
            return Err(VaultError::InvalidVaultFile);
        }
        let e: LoginEntry = decrypt_with_key(&env, &unlocked.key)?;
        if env.object_id != e.entry_id {
            return Err(VaultError::InvalidVaultFile);
        }
        if tombs.contains(&e.entry_id) {
            continue;
        }
        out.push(PublicEntry {
            entry_id: e.entry_id,
            title: e.title,
            username: e.username,
            password: e.password,
            url: e.url,
            notes: e.notes,
            favorite: e.favorite,
            updated_at: e.updated_at,
            revision: e.revision,
        })
    }
    out.sort_by_cached_key(|e| e.title.to_lowercase());
    Ok(out)
}

fn export_android_compatible_bundle_internal(
    unlocked: &UnlockedVault,
    passphrase: &str,
    file_type: &str,
) -> Result<String, VaultError> {
    if file_type != "fosspass-qr-sync-v1" && file_type != "fosspass-vault-file-v1" {
        return Err(VaultError::InvalidSyncBundle);
    }
    let entries = list_entries_internal(unlocked)?
        .into_iter()
        .map(|e| AndroidCompatEntry {
            id: e.entry_id,
            title: e.title,
            username: e.username,
            password: e.password,
            url: e.url,
            notes: e.notes,
            updated_at: e.updated_at,
            favorite: e.favorite,
        })
        .collect::<Vec<_>>();
    let plain_json = Zeroizing::new(serde_json::to_string(&entries)?);
    encrypt_android_compat_json(plain_json.as_str(), passphrase, file_type)
}

fn import_android_compatible_bundle_internal(
    unlocked: &UnlockedVault,
    bundle_json: &str,
    passphrase: &str,
) -> Result<ImportReport, VaultError> {
    let plain = Zeroizing::new(decrypt_android_compat_json(bundle_json, passphrase)?);
    let incoming: Vec<AndroidCompatEntry> = serde_json::from_str(plain.as_str())?;
    let bundle_id = Uuid::new_v4().to_string();
    let existing_tombstones = tombstones(&unlocked.root, &unlocked.key)?;
    let mut duplicate_keys: HashSet<_> = list_entries_internal(unlocked)?
        .iter()
        .map(public_duplicate_key)
        .collect();
    let mut imported_entries = 0;
    let mut conflicts = 0;
    for item in incoming {
        if !duplicate_keys.insert(android_compat_duplicate_key(&item)) {
            continue;
        }
        if existing_tombstones.contains(&item.id) {
            conflicts += 1;
            continue;
        }
        let now = if item.updated_at.is_empty() {
            now()
        } else {
            item.updated_at.clone()
        };
        let entry = LoginEntry {
            entry_id: item.id.clone(),
            entry_type: "login".into(),
            title: item.title.clone(),
            username: item.username,
            password: item.password,
            url: item.url,
            notes: item.notes,
            tags: vec![],
            favorite: item.favorite,
            created_at: now.clone(),
            updated_at: now,
            updated_by_device: "android-compat-import".into(),
            revision: 1,
        };
        let env = encrypt_with_key(
            "entry",
            &unlocked.vault_id,
            &entry.entry_id,
            &entry,
            &unlocked.key,
        )?;
        if let Some(existing_path) =
            find_entry_path_by_id(&unlocked.root, &unlocked.key, &entry.entry_id)?
        {
            let current: Envelope = serde_json::from_slice(&fs::read(&existing_path)?)?;
            let current_entry: LoginEntry = decrypt_with_key(&current, &unlocked.key)?;
            if current_entry.updated_at != entry.updated_at
                || current_entry.title != entry.title
                || current_entry.username != entry.username
                || current_entry.password != entry.password
                || current_entry.url != entry.url
                || current_entry.notes != entry.notes
                || current_entry.favorite != entry.favorite
            {
                conflicts += 1;
                atomic_write_secure(
                    unlocked.root.join("conflicts").join(format!(
                        "{}.{}.android-compat.conflict.fpass",
                        safe(&bundle_id),
                        safe(&entry.entry_id)
                    )),
                    &serde_json::to_vec_pretty(&env)?,
                )?;
            }
        } else {
            atomic_write_secure(
                entry_path(&unlocked.root, &entry.entry_id),
                &serde_json::to_vec_pretty(&env)?,
            )?;
            imported_entries += 1;
        }
    }
    Ok(ImportReport {
        bundle_id,
        imported_entries,
        imported_tombstones: 0,
        conflicts,
    })
}

fn delete_entry_internal(unlocked: &UnlockedVault, entry_id: &str) -> Result<(), VaultError> {
    let t = Tombstone {
        entry_id: entry_id.into(),
        deleted_at: now(),
        deleted_by_device: "local-linux-qubes-device".into(),
        reason: "user_deleted".into(),
        last_known_revision: 1,
    };
    let env = encrypt_with_key("tombstone", &unlocked.vault_id, entry_id, &t, &unlocked.key)?;
    atomic_write_secure(
        unlocked
            .root
            .join("tombstones")
            .join(format!("{}.deleted.fpass", entry_id)),
        &serde_json::to_vec_pretty(&env)?,
    )?;
    Ok(())
}

fn entry_path(root: &Path, id: &str) -> PathBuf {
    root.join("entries").join(format!("{id}.fpass"))
}

fn migrate_legacy_entry_filenames(
    root: &Path,
    vault_id: &str,
    key: &[u8; 32],
) -> Result<(), VaultError> {
    let entries_dir = root.join("entries");
    if !entries_dir.exists() {
        return Ok(());
    }
    for item in WalkDir::new(&entries_dir).min_depth(1).max_depth(1) {
        let item = item.map_err(|e| VaultError::Io(e.to_string()))?;
        if !item.file_type().is_file()
            || item.path().extension().and_then(|value| value.to_str()) != Some("fpass")
        {
            continue;
        }
        let original_bytes = fs::read(item.path())?;
        let envelope: Envelope = serde_json::from_slice(&original_bytes)?;
        let entry: LoginEntry = decrypt_with_key(&envelope, key)?;
        if envelope.file_type != "entry"
            || envelope.vault_id != vault_id
            || envelope.object_id != entry.entry_id
        {
            return Err(VaultError::InvalidVaultFile);
        }
        let protected_path = entry_path(root, &entry.entry_id);
        if item.path() != protected_path {
            if protected_path.exists() {
                return Err(VaultError::InvalidVaultFile);
            }
            fs::rename(item.path(), &protected_path)?;
        }
        let protected_bytes = serde_json::to_vec_pretty(&envelope)?;
        if original_bytes != protected_bytes {
            atomic_write_secure(protected_path.clone(), &protected_bytes)?;
        }
        #[cfg(unix)]
        fs::set_permissions(&protected_path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn safe(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|x| !x.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}
fn now() -> String {
    Utc::now().to_rfc3339()
}
fn expand(path: &str) -> PathBuf {
    if let Some(s) = path.strip_prefix("~/") {
        if let Some(h) = std::env::var_os("HOME") {
            return PathBuf::from(h).join(s);
        }
    }
    PathBuf::from(path)
}

fn encrypt_android_compat_json(
    plain_json: &str,
    passphrase: &str,
    file_type: &str,
) -> Result<String, VaultError> {
    let mut salt = [0u8; 16];
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut iv);

    let params = argon2::Params::new(
        VAULT_KDF_MEMORY_KIB,
        VAULT_KDF_ITERATIONS,
        VAULT_KDF_PARALLELISM,
        Some(32),
    )
    .map_err(|_| VaultError::Crypto)?;
    let mut key = Zeroizing::new([0u8; 32]);
    let a = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    a.hash_password_into(passphrase.as_bytes(), &salt, key.as_mut())
        .map_err(|_| VaultError::Crypto)?;

    let plain = Zeroizing::new(plain_json.as_bytes().to_vec());
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(plain.as_ref())
        .map_err(|_| VaultError::InvalidSyncBundle)?;
    let compressed = Zeroizing::new(
        encoder
            .finish()
            .map_err(|_| VaultError::InvalidSyncBundle)?,
    );
    let aad = format!("fosspass-sync-envelope-v3\0{file_type}\0zlib");
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| VaultError::Crypto)?;
    let ciphertext = cipher
        .encrypt(
            AesNonce::from_slice(&iv),
            aes_gcm::aead::Payload {
                msg: compressed.as_ref(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| VaultError::Crypto)?;
    let out = AndroidCompatBundle {
        r#type: file_type.to_string(),
        version: Some(3),
        compression: Some("zlib".into()),
        salt: B64.encode(salt),
        iv: B64.encode(iv),
        ciphertext: B64.encode(ciphertext),
    };
    Ok(serde_json::to_string(&out)?)
}

fn decrypt_android_compat_json(bundle_json: &str, passphrase: &str) -> Result<String, VaultError> {
    const MAX_DECOMPRESSED_BYTES: u64 = 20 * 1024 * 1024;

    let bundle: AndroidCompatBundle = serde_json::from_str(bundle_json.trim())?;
    if bundle.r#type != "fosspass-qr-sync-v1" && bundle.r#type != "fosspass-vault-file-v1" {
        return Err(VaultError::InvalidSyncBundle);
    }
    let salt = B64
        .decode(&bundle.salt)
        .map_err(|_| VaultError::InvalidSyncBundle)?;
    let iv = B64
        .decode(&bundle.iv)
        .map_err(|_| VaultError::InvalidSyncBundle)?;
    let ciphertext = B64
        .decode(&bundle.ciphertext)
        .map_err(|_| VaultError::InvalidSyncBundle)?;
    if salt.len() != 16 || iv.len() != 12 {
        return Err(VaultError::InvalidSyncBundle);
    }

    let params = argon2::Params::new(
        VAULT_KDF_MEMORY_KIB,
        VAULT_KDF_ITERATIONS,
        VAULT_KDF_PARALLELISM,
        Some(32),
    )
    .map_err(|_| VaultError::Crypto)?;
    let mut key = Zeroizing::new([0u8; 32]);
    let a = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    a.hash_password_into(passphrase.as_bytes(), &salt, key.as_mut())
        .map_err(|_| VaultError::Crypto)?;

    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| VaultError::Crypto)?;
    let plain = Zeroizing::new(
        match bundle.version {
            Some(3) => {
                if bundle.compression.as_deref() != Some("zlib") {
                    return Err(VaultError::InvalidSyncBundle);
                }
                let aad = format!("fosspass-sync-envelope-v3\0{}\0zlib", bundle.r#type);
                cipher.decrypt(
                    AesNonce::from_slice(&iv),
                    aes_gcm::aead::Payload {
                        msg: ciphertext.as_ref(),
                        aad: aad.as_bytes(),
                    },
                )
            }
            Some(2) => {
                if bundle.compression.is_some() {
                    return Err(VaultError::InvalidSyncBundle);
                }
                cipher.decrypt(
                    AesNonce::from_slice(&iv),
                    aes_gcm::aead::Payload {
                        msg: ciphertext.as_ref(),
                        aad: bundle.r#type.as_bytes(),
                    },
                )
            }
            None => {
                if bundle.compression.is_some() {
                    return Err(VaultError::InvalidSyncBundle);
                }
                cipher.decrypt(AesNonce::from_slice(&iv), ciphertext.as_ref())
            }
            _ => return Err(VaultError::InvalidSyncBundle),
        }
        .map_err(|_| VaultError::Crypto)?,
    );

    let decoded = if bundle.version == Some(3) {
        let decoder = ZlibDecoder::new(plain.as_slice());
        let mut limited = decoder.take(MAX_DECOMPRESSED_BYTES + 1);
        let mut output = Zeroizing::new(Vec::new());
        limited
            .read_to_end(output.as_mut())
            .map_err(|_| VaultError::InvalidSyncBundle)?;
        if output.len() as u64 > MAX_DECOMPRESSED_BYTES {
            return Err(VaultError::InvalidSyncBundle);
        }
        output
    } else {
        plain
    };
    String::from_utf8(decoded.to_vec()).map_err(|_| VaultError::InvalidSyncBundle)
}

fn find_entry_path_by_id(
    root: &Path,
    key: &[u8; 32],
    entry_id: &str,
) -> Result<Option<PathBuf>, VaultError> {
    let path = entry_path(root, entry_id);
    if !path.exists() {
        return Ok(None);
    }
    let env: Envelope = serde_json::from_slice(&fs::read(&path)?)?;
    if env.file_type != "entry" || env.object_id != entry_id {
        return Err(VaultError::InvalidVaultFile);
    }
    let entry: LoginEntry = decrypt_with_key(&env, key)?;
    if entry.entry_id != entry_id {
        return Err(VaultError::InvalidVaultFile);
    }
    Ok(Some(path))
}

fn encrypt_with_password<T: Serialize>(
    file_type: &str,
    vault_id: &str,
    object_id: &str,
    payload: &T,
    master_password: &str,
) -> Result<Envelope, VaultError> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let kdf = KdfParams {
        name: "argon2id".into(),
        salt: B64.encode(salt),
        memory_kib: VAULT_KDF_MEMORY_KIB,
        iterations: VAULT_KDF_ITERATIONS,
        parallelism: VAULT_KDF_PARALLELISM,
    };
    let key = derive(master_password, &kdf)?;
    encrypt_with_key_and_kdf(file_type, vault_id, object_id, payload, &key, kdf)
}

fn encrypt_with_key<T: Serialize>(
    file_type: &str,
    vault_id: &str,
    object_id: &str,
    payload: &T,
    key: &[u8; 32],
) -> Result<Envelope, VaultError> {
    let kdf = KdfParams {
        name: VAULT_KEY_KDF_NAME.into(),
        salt: String::new(),
        memory_kib: 0,
        iterations: 0,
        parallelism: 0,
    };
    encrypt_with_key_and_kdf(file_type, vault_id, object_id, payload, key, kdf)
}

fn encrypt_with_key_and_kdf<T: Serialize>(
    file_type: &str,
    vault_id: &str,
    object_id: &str,
    payload: &T,
    key: &[u8; 32],
    kdf: KdfParams,
) -> Result<Envelope, VaultError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| VaultError::Crypto)?;
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let aad = Aad {
        file_type: file_type.into(),
        vault_id: vault_id.into(),
        object_id: object_id.into(),
    };
    let aad_bytes = serde_json::to_vec(&aad)?;
    let plain = serde_json::to_vec(payload)?;
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: &plain,
                aad: &aad_bytes,
            },
        )
        .map_err(|_| VaultError::Crypto)?;
    Ok(Envelope {
        magic: "FOSSPASS".into(),
        format_version: 1,
        file_type: file_type.into(),
        vault_id: vault_id.into(),
        object_id: object_id.into(),
        kdf,
        cipher: CipherParams {
            name: "xchacha20-poly1305".into(),
            nonce: B64.encode(nonce),
        },
        aad,
        ciphertext: B64.encode(ct),
    })
}

fn decrypt_with_key<T: for<'de> Deserialize<'de>>(
    env: &Envelope,
    key: &[u8; 32],
) -> Result<T, VaultError> {
    if env.magic != "FOSSPASS"
        || env.cipher.name != "xchacha20-poly1305"
        || env.format_version != 1
        || env.aad.file_type != env.file_type
        || env.aad.vault_id != env.vault_id
        || env.aad.object_id != env.object_id
    {
        return Err(VaultError::InvalidVaultFile);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| VaultError::Crypto)?;
    let nonce = B64
        .decode(&env.cipher.nonce)
        .map_err(|_| VaultError::Crypto)?;
    if nonce.len() != 24 {
        return Err(VaultError::InvalidVaultFile);
    }
    let ct = B64
        .decode(&env.ciphertext)
        .map_err(|_| VaultError::Crypto)?;
    let aad = serde_json::to_vec(&env.aad)?;
    let plain = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: &ct,
                aad: &aad,
            },
        )
        .map_err(|_| VaultError::Crypto)?;
    Ok(serde_json::from_slice(&plain)?)
}

fn validate_kdf_params(kdf: &KdfParams) -> Result<Vec<u8>, VaultError> {
    const MIN_MEMORY_KIB: u32 = 19 * 1024;
    const MAX_MEMORY_KIB: u32 = 256 * 1024;
    if kdf.name != "argon2id"
        || !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&kdf.memory_kib)
        || !(1..=10).contains(&kdf.iterations)
        || !(1..=8).contains(&kdf.parallelism)
    {
        return Err(VaultError::InvalidVaultFile);
    }
    let salt = B64
        .decode(&kdf.salt)
        .map_err(|_| VaultError::InvalidVaultFile)?;
    if !(16..=64).contains(&salt.len()) {
        return Err(VaultError::InvalidVaultFile);
    }
    Ok(salt)
}

fn derive(master_password: &str, kdf: &KdfParams) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let salt_bytes = validate_kdf_params(kdf)?;
    let mut key = Zeroizing::new([0u8; 32]);
    let params = argon2::Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32))
        .map_err(|_| VaultError::Crypto)?;
    let a = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    a.hash_password_into(master_password.as_bytes(), &salt_bytes, key.as_mut())
        .map_err(|_| VaultError::Crypto)?;
    Ok(key)
}

fn load_meta_and_key(
    root: &Path,
    master_password: &str,
) -> Result<(VaultMeta, Zeroizing<[u8; 32]>), VaultError> {
    let p = root.join("vault.meta.fpass");
    if !p.exists() {
        return Err(VaultError::VaultNotFound);
    }
    let env: Envelope = serde_json::from_slice(&fs::read(p)?)?;
    let key = derive(master_password, &env.kdf)?;
    let meta = decrypt_with_key(&env, &key)?;
    Ok((meta, key))
}

fn tombstones(root: &Path, vault_key: &[u8; 32]) -> Result<HashSet<String>, VaultError> {
    let mut ids = HashSet::new();
    let dir = root.join("tombstones");
    if !dir.exists() {
        return Ok(ids);
    }
    for item in WalkDir::new(dir).min_depth(1).max_depth(1) {
        let item = item.map_err(|error| VaultError::Io(error.to_string()))?;
        if !item.file_type().is_file()
            || item.path().extension().and_then(|value| value.to_str()) != Some("fpass")
        {
            continue;
        }
        let env: Envelope = serde_json::from_slice(&fs::read(item.path())?)?;
        if env.file_type != "tombstone" {
            return Err(VaultError::InvalidVaultFile);
        }
        let tombstone: Tombstone = decrypt_with_key(&env, vault_key)?;
        if env.object_id != tombstone.entry_id {
            return Err(VaultError::InvalidVaultFile);
        }
        ids.insert(tombstone.entry_id);
    }
    Ok(ids)
}

fn secure_create_dir_all(path: &Path) -> Result<(), VaultError> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn atomic_write_secure(path: PathBuf, bytes: &[u8]) -> Result<(), VaultError> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    #[cfg(unix)]
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    fs::rename(&tmp, &path)?;
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_vault(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("fosspass-{name}-{}", Uuid::new_v4()))
    }

    #[test]
    fn master_password_change_rekeys_vault_and_preserves_entries() {
        let root = temp_vault("master-password-change");
        let path = root.to_string_lossy().to_string();
        let old_password = "old-master-password";
        let new_password = "New-Master-Password-2026!";

        init_vault(&path, old_password).unwrap();
        let unlocked = unlock_vault(&path, old_password).unwrap();
        unlocked
            .add_entry(AddEntryRequest {
                title: "Rekeyed Login".into(),
                username: "alice".into(),
                password: "entry-secret".into(),
                url: "https://example.com".into(),
                notes: "must survive rekey".into(),
            })
            .unwrap();

        let changed = change_master_password(&path, old_password, new_password).unwrap();
        assert_eq!(changed.list_entries().unwrap().len(), 1);
        assert!(unlock_vault(&path, old_password).is_err());
        let reopened = unlock_vault(&path, new_password).unwrap();
        let entries = reopened.list_entries().unwrap();
        assert_eq!(entries[0].title, "Rekeyed Login");
        assert_eq!(entries[0].password, "entry-secret");
        assert_eq!(entries[0].notes, "must survive rekey");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn entry_files_do_not_leak_plaintext_fields_or_titles_in_filenames() {
        let root = temp_vault("plaintext-leak-check");
        let path = root.to_string_lossy().to_string();
        init_vault(&path, "correct horse battery staple").unwrap();
        let unlocked = unlock_vault(&path, "correct horse battery staple").unwrap();
        let forbidden_title_slug = "confidential-bank-title-8472";
        let secrets = [
            "confidential bank title 8472",
            "private-user@example.test",
            "UltraSecretPassword-987!",
            "https://private-bank.example.test/login",
            "private recovery note",
        ];
        unlocked
            .add_entry(AddEntryRequest {
                title: secrets[0].into(),
                username: secrets[1].into(),
                password: secrets[2].into(),
                url: secrets[3].into(),
                notes: secrets[4].into(),
            })
            .unwrap();

        for item in WalkDir::new(&root).min_depth(1) {
            let item = item.unwrap();
            let path_text = item.path().to_string_lossy();
            assert!(
                !path_text.contains(forbidden_title_slug),
                "title leaked in path: {path_text}"
            );
            for secret in &secrets {
                assert!(
                    !path_text.contains(secret),
                    "plaintext leaked in path: {path_text}"
                );
            }
            if item.file_type().is_file() {
                let bytes = fs::read(item.path()).unwrap();
                let serialized = String::from_utf8_lossy(&bytes);
                assert!(!serialized.contains("\"created_at\""));
                assert!(!serialized.contains("\"updated_at\""));
                for secret in &secrets {
                    assert!(
                        !bytes
                            .windows(secret.len())
                            .any(|window| window == secret.as_bytes()),
                        "plaintext leaked in file {}",
                        item.path().display()
                    );
                }
            }
        }

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn unlock_migrates_legacy_title_bearing_entry_filenames() {
        let root = temp_vault("legacy-filename-migration");
        let path = root.to_string_lossy().to_string();
        init_vault(&path, "migration master password").unwrap();
        let unlocked = unlock_vault(&path, "migration master password").unwrap();
        unlocked
            .add_entry(AddEntryRequest {
                title: "legacy private title".into(),
                username: "alice".into(),
                password: "secret".into(),
                url: "".into(),
                notes: "".into(),
            })
            .unwrap();
        let id = unlocked.list_entries().unwrap()[0].entry_id.clone();
        let protected_path = entry_path(&root, &id);
        let legacy_path = root
            .join("entries")
            .join(format!("{id}.legacy-private-title.fpass"));
        fs::rename(&protected_path, &legacy_path).unwrap();

        let reopened = unlock_vault(&path, "migration master password").unwrap();
        assert_eq!(reopened.list_entries().unwrap().len(), 1);
        assert!(protected_path.exists());
        assert!(!legacy_path.exists());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn core_rejects_exact_duplicate_entries() {
        let root = temp_vault("duplicate-defense");
        let path = root.to_string_lossy().to_string();
        init_vault(&path, "duplicate master password").unwrap();
        let unlocked = unlock_vault(&path, "duplicate master password").unwrap();
        let request = || AddEntryRequest {
            title: "GitHub".into(),
            username: "alice".into(),
            password: "same-secret".into(),
            url: "https://github.com".into(),
            notes: "primary".into(),
        };
        unlocked.add_entry(request()).unwrap();
        let error = unlocked.add_entry(request()).unwrap_err();
        assert!(matches!(error, VaultError::DuplicateEntry));
        assert_eq!(unlocked.list_entries().unwrap().len(), 1);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn android_bundle_import_skips_exact_duplicate_with_a_different_id() {
        let source_root = temp_vault("duplicate-import-source");
        let dest_root = temp_vault("duplicate-import-dest");
        let source_path = source_root.to_string_lossy().to_string();
        let dest_path = dest_root.to_string_lossy().to_string();
        init_vault(&source_path, "vault password").unwrap();
        init_vault(&dest_path, "vault password").unwrap();
        let source = unlock_vault(&source_path, "vault password").unwrap();
        let dest = unlock_vault(&dest_path, "vault password").unwrap();
        source
            .add_entry(AddEntryRequest {
                title: "GitHub".into(),
                username: "alice".into(),
                password: "same-secret".into(),
                url: "https://github.com".into(),
                notes: "primary".into(),
            })
            .unwrap();
        dest.add_entry(AddEntryRequest {
            title: " github ".into(),
            username: "ALICE".into(),
            password: "same-secret".into(),
            url: "HTTPS://GITHUB.COM/".into(),
            notes: " PRIMARY ".into(),
        })
        .unwrap();

        let bundle = source
            .export_android_compatible_bundle("offline-sync-passphrase", "fosspass-vault-file-v1")
            .unwrap();
        let report = dest
            .import_android_compatible_bundle(&bundle, "offline-sync-passphrase")
            .unwrap();
        assert_eq!(report.imported_entries, 0);
        assert_eq!(dest.list_entries().unwrap().len(), 1);

        let _ = fs::remove_dir_all(source_root);
        let _ = fs::remove_dir_all(dest_root);
    }

    #[test]
    fn tampered_entry_fails_closed_instead_of_disappearing() {
        let root = temp_vault("tamper-fail-closed");
        let path = root.to_string_lossy().to_string();
        init_vault(&path, "tamper master password").unwrap();
        let unlocked = unlock_vault(&path, "tamper master password").unwrap();
        unlocked
            .add_entry(AddEntryRequest {
                title: "Bank".into(),
                username: "alice".into(),
                password: "secret".into(),
                url: "".into(),
                notes: "".into(),
            })
            .unwrap();
        let id = unlocked.list_entries().unwrap()[0].entry_id.clone();
        let path = entry_path(&root, &id);
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        envelope["ciphertext"] = serde_json::Value::String("AAAA".into());
        fs::write(&path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();

        assert!(unlocked.list_entries().is_err());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn android_v3_bundle_round_trips_and_declares_compression() {
        let plain = r#"[{"id":"1","title":"Example","username":"alice","password":"secret","url":"https://example.com","notes":"hello","updatedAt":"2026-08-16T00:00:00Z","favorite":false}]"#;
        let bundle =
            encrypt_android_compat_json(plain, "bundle passphrase", "fosspass-qr-sync-v1").unwrap();
        let envelope: AndroidCompatBundle = serde_json::from_str(&bundle).unwrap();
        assert_eq!(envelope.version, Some(3));
        assert_eq!(envelope.compression.as_deref(), Some("zlib"));
        assert_eq!(
            decrypt_android_compat_json(&bundle, "bundle passphrase").unwrap(),
            plain
        );
    }

    fn old_android_bundle(plain: &str, version: Option<u32>) -> String {
        let salt = [7u8; 16];
        let iv = [9u8; 12];
        let params = argon2::Params::new(
            VAULT_KDF_MEMORY_KIB,
            VAULT_KDF_ITERATIONS,
            VAULT_KDF_PARALLELISM,
            Some(32),
        )
        .unwrap();
        let mut key = Zeroizing::new([0u8; 32]);
        Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
            .hash_password_into(b"old bundle passphrase", &salt, key.as_mut())
            .unwrap();
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).unwrap();
        let ciphertext = match version {
            Some(2) => cipher
                .encrypt(
                    AesNonce::from_slice(&iv),
                    aes_gcm::aead::Payload {
                        msg: plain.as_bytes(),
                        aad: b"fosspass-qr-sync-v1",
                    },
                )
                .unwrap(),
            None => cipher
                .encrypt(AesNonce::from_slice(&iv), plain.as_bytes())
                .unwrap(),
            _ => unreachable!(),
        };
        serde_json::to_string(&AndroidCompatBundle {
            r#type: "fosspass-qr-sync-v1".into(),
            version,
            compression: None,
            salt: B64.encode(salt),
            iv: B64.encode(iv),
            ciphertext: B64.encode(ciphertext),
        })
        .unwrap()
    }

    #[test]
    fn android_import_still_accepts_v2_and_legacy_bundles() {
        let plain = r#"[{"title":"old"}]"#;
        for version in [Some(2), None] {
            let bundle = old_android_bundle(plain, version);
            assert_eq!(
                decrypt_android_compat_json(&bundle, "old bundle passphrase").unwrap(),
                plain
            );
        }
    }

    #[test]
    fn android_v3_type_and_compression_are_authenticated() {
        let bundle =
            encrypt_android_compat_json("[]", "bundle passphrase", "fosspass-qr-sync-v1").unwrap();
        let relabeled = bundle.replace("fosspass-qr-sync-v1", "fosspass-vault-file-v1");
        assert!(decrypt_android_compat_json(&relabeled, "bundle passphrase").is_err());
        let recompressed = bundle.replace("\"zlib\"", "\"gzip\"");
        assert!(decrypt_android_compat_json(&recompressed, "bundle passphrase").is_err());
    }

    fn encrypted_v3_payload(payload: &[u8]) -> String {
        let salt = [3u8; 16];
        let iv = [4u8; 12];
        let params = argon2::Params::new(
            VAULT_KDF_MEMORY_KIB,
            VAULT_KDF_ITERATIONS,
            VAULT_KDF_PARALLELISM,
            Some(32),
        )
        .unwrap();
        let mut key = Zeroizing::new([0u8; 32]);
        Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
            .hash_password_into(b"bomb passphrase", &salt, key.as_mut())
            .unwrap();
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).unwrap();
        let ciphertext = cipher
            .encrypt(
                AesNonce::from_slice(&iv),
                aes_gcm::aead::Payload {
                    msg: payload,
                    aad: b"fosspass-sync-envelope-v3\0fosspass-qr-sync-v1\0zlib",
                },
            )
            .unwrap();
        serde_json::to_string(&AndroidCompatBundle {
            r#type: "fosspass-qr-sync-v1".into(),
            version: Some(3),
            compression: Some("zlib".into()),
            salt: B64.encode(salt),
            iv: B64.encode(iv),
            ciphertext: B64.encode(ciphertext),
        })
        .unwrap()
    }

    #[test]
    fn android_v3_rejects_decompression_bomb_over_20_mib() {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder
            .write_all(&vec![b'x'; 20 * 1024 * 1024 + 1])
            .unwrap();
        let compressed = encoder.finish().unwrap();
        let bundle = encrypted_v3_payload(&compressed);
        assert!(decrypt_android_compat_json(&bundle, "bomb passphrase").is_err());
    }

    #[test]
    fn android_v3_substantially_reduces_realistic_400_entry_bundle() {
        let entries: Vec<_> = (0..400)
            .map(|index| AndroidCompatEntry {
                id: format!("00000000-0000-4000-8000-{index:012}"),
                title: format!("Example Service {index}"),
                username: format!("person{index}@example.com"),
                password: format!("correct-horse-battery-staple-{index}"),
                url: format!("https://accounts.example.com/service/{index}/login"),
                notes: "Recovery contact: security@example.com; managed personal account".into(),
                updated_at: "2026-08-16T12:34:56Z".into(),
                favorite: index % 7 == 0,
            })
            .collect();
        let plain = serde_json::to_string(&entries).unwrap();
        let bundle =
            encrypt_android_compat_json(&plain, "bundle passphrase", "fosspass-qr-sync-v1")
                .unwrap();
        let envelope: AndroidCompatBundle = serde_json::from_str(&bundle).unwrap();
        let encrypted_len = B64.decode(envelope.ciphertext).unwrap().len();
        assert!(
            encrypted_len < plain.len() / 2,
            "{encrypted_len} vs {}",
            plain.len()
        );
    }

    #[test]
    fn batch_import_rolls_back_when_any_entry_fails() {
        let root = temp_vault("batch-import-rollback");
        let path = root.to_string_lossy().to_string();
        init_vault(&path, "batch master password").unwrap();
        let unlocked = unlock_vault(&path, "batch master password").unwrap();
        let duplicate = AddEntryRequest {
            title: "Example".into(),
            username: "alice".into(),
            password: "secret".into(),
            url: "https://example.com".into(),
            notes: "".into(),
        };

        assert!(unlocked
            .add_entries(vec![duplicate.clone(), duplicate])
            .is_err());
        assert!(unlocked.list_entries().unwrap().is_empty());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_untrusted_kdf_parameters_that_can_exhaust_resources() {
        let hostile = KdfParams {
            name: "argon2id".into(),
            salt: B64.encode([0u8; 16]),
            memory_kib: 512 * 1024,
            iterations: 2,
            parallelism: 1,
        };
        assert!(validate_kdf_params(&hostile).is_err());
    }

    #[test]
    fn parses_password_protected_keepass_database_for_android() {
        use keepass::{
            db::{fields, GroupMut},
            Database, DatabaseKey,
        };

        let mut database = Database::new();
        database
            .root_mut()
            .add_group()
            .edit(|group: &mut GroupMut<'_>| {
                group.name = "Imported".into();
                group.add_entry().edit(|entry| {
                    entry.set_unprotected(fields::TITLE, "Android KeePass");
                    entry.set_unprotected(fields::USERNAME, "alice");
                    entry.set_protected(fields::PASSWORD, "secret");
                    entry.set_unprotected(fields::URL, "https://keepass.example");
                    entry.set_unprotected(fields::NOTES, "from kdbx");
                });
            });
        let mut bytes = Vec::new();
        database
            .save(
                &mut bytes,
                DatabaseKey::new().with_password("database-password"),
            )
            .unwrap();

        let entries = parse_keepass_database(bytes.clone(), "database-password").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "Android KeePass");
        assert_eq!(entries[0].password, "secret");
        assert!(parse_keepass_database(bytes, "wrong-password").is_err());
    }
}
