//! Root CA + per-domain leaf certificate generation.
//!
//! On first start the bridge generates a self-signed Root CA (RSA-2048, 10y
//! validity) into `data_dir/cert/`. Each TLS handshake then triggers lazy
//! generation of a 1-year leaf certificate signed by that root, cached by SNI
//! hostname for the lifetime of the process.
//!
//! Files written:
//! - `cert/rootCA.key` private key (PKCS#8 PEM, mode 0600)
//! - `cert/rootCA.crt` public cert (PEM)

use anyhow::{Context, Result};
use parking_lot::RwLock;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    NameConstraints, GeneralSubtree, SanType,
};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{info, warn};

/// Reasonable defaults for cert validity.
pub const ROOT_VALIDITY_DAYS: i64 = 365 * 10;
pub const LEAF_VALIDITY_DAYS: i64 = 365;
pub const ROOT_RENEW_THRESHOLD_DAYS: i64 = 30;

/// Hostnames the Root CA is permitted to sign for. Anything else is excluded
/// via X.509 Name Constraints, so a leaked CA cannot impersonate the wider
/// internet.
pub const ALLOWED_HOSTS: &[&str] = &[
    "cloudcode-pa.googleapis.com",
    "daily-cloudcode-pa.googleapis.com",
    "api.individual.githubcopilot.com",
    "q.us-east-1.amazonaws.com",
    "codewhisperer.us-east-1.amazonaws.com",
    "api2.cursor.sh",
];

/// In-memory leaf cert cache keyed by SNI hostname.
#[derive(Clone, Debug)]
pub struct CertManager {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    cert_dir: PathBuf,
    root_key_pem: String,
    root_cert_pem: String,
    leaf_cache: RwLock<HashMap<String, Arc<LeafPair>>>,
}

#[derive(Clone, Debug)]
pub struct LeafPair {
    pub cert_pem: String,
    pub key_pem: String,
}

impl CertManager {
    /// Initialize the manager. Generates a Root CA on first run; reuses the
    /// existing one if it is still valid (≥ 30 days remaining).
    pub fn init(data_dir: &Path) -> Result<Self> {
        let cert_dir = data_dir.join("cert");
        fs::create_dir_all(&cert_dir).context("create cert dir")?;

        let key_path = cert_dir.join("rootCA.key");
        let cert_path = cert_dir.join("rootCA.crt");

        let (key_pem, cert_pem) = if key_path.exists() && cert_path.exists() {
            let cert_pem = fs::read_to_string(&cert_path)?;
            if root_needs_renewal(&cert_pem)? {
                warn!("Root CA expiring or unreadable, regenerating");
                generate_root_ca(&key_path, &cert_path)?
            } else {
                info!("Loaded existing Root CA");
                (fs::read_to_string(&key_path)?, cert_pem)
            }
        } else {
            info!("Generating new Root CA");
            generate_root_ca(&key_path, &cert_path)?
        };

        Ok(Self {
            inner: Arc::new(Inner {
                cert_dir,
                root_key_pem: key_pem,
                root_cert_pem: cert_pem,
                leaf_cache: RwLock::new(HashMap::new()),
            }),
        })
    }

    /// Path to the public Root CA cert (used by the trust installer).
    pub fn root_cert_path(&self) -> PathBuf {
        self.inner.cert_dir.join("rootCA.crt")
    }

    pub fn root_cert_pem(&self) -> &str {
        &self.inner.root_cert_pem
    }

    /// Get or lazily generate a leaf cert for the given SNI hostname.
    pub fn leaf_for(&self, sni: &str) -> Result<Arc<LeafPair>> {
        if let Some(p) = self.inner.leaf_cache.read().get(sni).cloned() {
            return Ok(p);
        }
        let leaf = sign_leaf(&self.inner.root_key_pem, &self.inner.root_cert_pem, sni)?;
        let arc = Arc::new(leaf);
        self.inner.leaf_cache.write().insert(sni.to_owned(), arc.clone());
        Ok(arc)
    }
}

/// Generate Root CA, persist to disk, return PEMs.
fn generate_root_ca(key_path: &Path, cert_path: &Path) -> Result<(String, String)> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    // Critical defense: this CA can only sign certs for the listed hostnames.
    // Modern OS validators (Windows >= 10, macOS, Linux NSS) honor this.
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: ALLOWED_HOSTS
            .iter()
            .map(|h| GeneralSubtree::DnsName((*h).into()))
            .collect(),
        excluded_subtrees: vec![],
    });
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "agbridge Root CA");
    dn.push(DnType::OrganizationName, "agbridge");
    dn.push(DnType::CountryName, "US");
    params.distinguished_name = dn;

    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(ROOT_VALIDITY_DAYS);

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    fs::write(cert_path, &cert_pem).context("write rootCA.crt")?;
    fs::write(key_path, &key_pem).context("write rootCA.key")?;
    set_mode_0600(key_path)?;
    lock_acl_to_current_user(key_path);

    Ok((key_pem, cert_pem))
}

/// Issue a leaf cert for `sni` signed by the given root.
fn sign_leaf(root_key_pem: &str, root_cert_pem: &str, sni: &str) -> Result<LeafPair> {
    let root_key = KeyPair::from_pem(root_key_pem)?;
    let root_params = CertificateParams::from_ca_cert_pem(root_cert_pem)?;
    let root_cert = root_params.self_signed(&root_key)?;

    let mut leaf_params = CertificateParams::new(vec![sni.to_string()])?;
    leaf_params.subject_alt_names = vec![SanType::DnsName(sni.try_into()?)];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, sni);
    leaf_params.distinguished_name = dn;
    let now = OffsetDateTime::now_utc();
    leaf_params.not_before = now;
    leaf_params.not_after = now + Duration::days(LEAF_VALIDITY_DAYS);

    let leaf_key = KeyPair::generate()?;
    let leaf_cert = leaf_params.signed_by(&leaf_key, &root_cert, &root_key)?;

    Ok(LeafPair {
        cert_pem: leaf_cert.pem(),
        key_pem: leaf_key.serialize_pem(),
    })
}

/// Returns true if the existing root cert is unreadable or expires within
/// `ROOT_RENEW_THRESHOLD_DAYS`.
fn root_needs_renewal(cert_pem: &str) -> Result<bool> {
    use x509_parser::pem::parse_x509_pem;
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("parse pem: {e}"))?;
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents)
        .map_err(|e| anyhow::anyhow!("parse x509: {e}"))?;
    let not_after = cert.validity().not_after.timestamp();
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs() as i64;
    let threshold_secs = ROOT_RENEW_THRESHOLD_DAYS * 24 * 60 * 60;
    Ok(not_after - now < threshold_secs)
}

#[cfg(unix)]
fn set_mode_0600(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perm = fs::metadata(path)?.permissions();
    perm.set_mode(0o600);
    fs::set_permissions(path, perm)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode_0600(_path: &Path) -> Result<()> {
    // Windows ACL hardening handled by `lock_acl_to_current_user` below.
    Ok(())
}

#[cfg(windows)]
fn lock_acl_to_current_user(path: &Path) {
    use std::process::Command;
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "Administrators".to_string());
    // Strip inherited ACEs and grant exclusive Full Control to the current
    // user. Best-effort: we log and continue if `icacls` is missing.
    let path_str = path.to_string_lossy().to_string();
    let _ = Command::new("icacls").args([&path_str, "/inheritance:r"]).status();
    let _ = Command::new("icacls")
        .args([&path_str, "/grant:r", &format!("{user}:F")])
        .status();
    tracing::info!(?path, %user, "locked ACL via icacls");
}

#[cfg(not(windows))]
fn lock_acl_to_current_user(_path: &Path) {}

// `time` is a public dep through rcgen; declared explicitly in Cargo.toml.
use ::time::{Duration, OffsetDateTime};

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn init_creates_root_ca() {
        let dir = tempdir().unwrap();
        let mgr = CertManager::init(dir.path()).unwrap();
        let root = mgr.root_cert_path();
        assert!(root.exists());
        assert!(mgr.root_cert_pem().contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn leaf_is_cached() {
        let dir = tempdir().unwrap();
        let mgr = CertManager::init(dir.path()).unwrap();
        let a = mgr.leaf_for("example.com").unwrap();
        let b = mgr.leaf_for("example.com").unwrap();
        assert!(Arc::ptr_eq(&a, &b));
    }
}
