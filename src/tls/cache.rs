//! ACME state is restricted to the dedicated, non-swappable guest tmpfs.
use async_trait::async_trait;
use rustls_acme::{AccountCache, CertCache};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub(super) const CACHE_DIR: &str = "/run/hiro/tls";
const MAX_ENTRY: u64 = 128 * 1024;

pub(super) struct RamCache;

impl RamCache {
    pub(super) fn new() -> anyhow::Result<Self> {
        let path = Path::new(CACHE_DIR);
        let metadata = fs::symlink_metadata(path)?;
        anyhow::ensure!(
            metadata.is_dir() && metadata.uid() == 65532 && metadata.mode() & 0o777 == 0o700,
            "TLS cache must be a private directory owned by UID 65532"
        );
        let mounts = fs::read_to_string("/proc/self/mountinfo")?;
        anyhow::ensure!(
            mounts.lines().any(|line| {
                let Some((mount, filesystem)) = line.split_once(" - ") else {
                    return false;
                };
                let fields: Vec<_> = filesystem.split_whitespace().collect();
                mount.split_whitespace().nth(4) == Some(CACHE_DIR)
                    && fields.first() == Some(&"tmpfs")
                    && fields
                        .get(2)
                        .is_some_and(|opts| opts.split(',').any(|opt| opt == "noswap"))
            }),
            "TLS cache must be a dedicated tmpfs mounted with noswap"
        );
        anyhow::ensure!(
            fs::read_to_string("/proc/swaps")?
                .lines()
                .skip(1)
                .all(|line| line.trim().is_empty()),
            "swap must be disabled before generating TLS keys"
        );
        Ok(Self)
    }

    fn path(kind: &str, names: &[String], directory: &str) -> PathBuf {
        let mut hash = Sha256::new();
        for name in names {
            hash.update(name.as_bytes());
            hash.update([0]);
        }
        hash.update(directory.as_bytes());
        Path::new(CACHE_DIR).join(format!("{kind}-{}", hex::encode(hash.finalize())))
    }

    fn load(path: &Path) -> io::Result<Option<Vec<u8>>> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 65532
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() > MAX_ENTRY
        {
            return Err(io::Error::other(
                "invalid TLS cache file permissions or size",
            ));
        }
        let mut bytes = Vec::new();
        file.take(MAX_ENTRY + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_ENTRY {
            return Err(io::Error::other("TLS cache entry too large"));
        }
        Ok(Some(bytes))
    }

    fn store(path: &Path, contents: &[u8]) -> io::Result<()> {
        if contents.len() as u64 > MAX_ENTRY {
            return Err(io::Error::other("TLS cache entry too large"));
        }
        let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&temporary)?;
            file.write_all(contents)?;
            file.sync_all()?;
            fs::rename(&temporary, path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

#[async_trait]
impl CertCache for RamCache {
    type EC = io::Error;

    async fn load_cert(&self, domains: &[String], directory: &str) -> io::Result<Option<Vec<u8>>> {
        Self::load(&Self::path("certificate", domains, directory))
    }

    async fn store_cert(&self, domains: &[String], directory: &str, cert: &[u8]) -> io::Result<()> {
        Self::store(&Self::path("certificate", domains, directory), cert)
    }
}

#[async_trait]
impl AccountCache for RamCache {
    type EA = io::Error;

    async fn load_account(
        &self,
        contacts: &[String],
        directory: &str,
    ) -> io::Result<Option<Vec<u8>>> {
        Self::load(&Self::path("account", contacts, directory))
    }

    async fn store_account(
        &self,
        contacts: &[String],
        directory: &str,
        account: &[u8],
    ) -> io::Result<()> {
        Self::store(&Self::path("account", contacts, directory), account)
    }
}
