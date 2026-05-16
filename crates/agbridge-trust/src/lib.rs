//! Install / uninstall the agbridge Root CA in the OS trust store.
//!
//! All of these calls require admin/root.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;
use tracing::{info, warn};

/// Install the Root CA into the platform trust store.
pub fn install(cert_path: &Path) -> Result<()> {
    if !cert_path.exists() {
        anyhow::bail!("cert not found: {}", cert_path.display());
    }
    #[cfg(target_os = "windows")] {
        run("certutil", &["-addstore", "-f", "Root", cert_path.to_str().unwrap()])?;
    }
    #[cfg(target_os = "macos")] {
        run("security", &[
            "add-trusted-cert",
            "-d",
            "-r", "trustRoot",
            "-k", "/Library/Keychains/System.keychain",
            cert_path.to_str().unwrap(),
        ])?;
    }
    #[cfg(all(unix, not(target_os = "macos")))] {
        let dest = "/usr/local/share/ca-certificates/agbridge-root.crt";
        run("cp", &[cert_path.to_str().unwrap(), dest])?;
        run("update-ca-certificates", &[])?;
    }
    info!("Root CA installed into system trust store");
    Ok(())
}

/// Remove the Root CA from the trust store.
pub fn uninstall() -> Result<()> {
    #[cfg(target_os = "windows")] {
        // CN match — `agbridge Root CA`
        let _ = run("certutil", &["-delstore", "Root", "agbridge Root CA"]);
    }
    #[cfg(target_os = "macos")] {
        let _ = run("security", &[
            "delete-certificate", "-c", "agbridge Root CA",
            "/Library/Keychains/System.keychain",
        ]);
    }
    #[cfg(all(unix, not(target_os = "macos")))] {
        let dest = "/usr/local/share/ca-certificates/agbridge-root.crt";
        let _ = std::fs::remove_file(dest);
        let _ = run("update-ca-certificates", &["--fresh"]);
    }
    Ok(())
}

/// Best-effort check that the Root CA is currently trusted.
pub fn is_installed() -> bool {
    #[cfg(target_os = "windows")] {
        match Command::new("certutil").args(["-store", "Root", "agbridge Root CA"]).output() {
            Ok(o) => o.status.success(),
            _ => false,
        }
    }
    #[cfg(target_os = "macos")] {
        match Command::new("security")
            .args(["find-certificate", "-c", "agbridge Root CA", "/Library/Keychains/System.keychain"])
            .output() {
            Ok(o) => o.status.success(),
            _ => false,
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))] {
        std::path::Path::new("/usr/local/share/ca-certificates/agbridge-root.crt").exists()
    }
}

fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let out = Command::new(cmd).args(args).output()
        .with_context(|| format!("spawn {cmd}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("{cmd} failed: {stderr}");
    }
    if !out.stdout.is_empty() {
        warn!("{cmd}: {}", String::from_utf8_lossy(&out.stdout).trim());
    }
    Ok(())
}
