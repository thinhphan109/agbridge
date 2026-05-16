//! TOML config loader.
//!
//! Default location: `${config_dir}/agbridge/config.toml`.
//! On Unix the file is created with mode 0600. Secrets (`api_key`) never
//! appear in `Debug`/`Display` output.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Upstream 9router base URL (e.g. `https://your-vps.example.com`).
    pub router_url: String,
    /// Bearer token for the upstream router.
    #[serde(default)]
    pub api_key: SecretString,
    /// Listen address. Default `0.0.0.0:443`.
    #[serde(default = "default_listen")]
    pub listen_addr: String,
    /// Per-tool settings.
    #[serde(default)]
    pub tools: ToolsConfig,
    /// Optional override for the data directory.
    #[serde(default)]
    pub data_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolsConfig {
    #[serde(default)]
    pub antigravity: ToolConfig,
    #[serde(default)]
    pub copilot: ToolConfig,
    #[serde(default)]
    pub kiro: ToolConfig,
    #[serde(default)]
    pub cursor: ToolConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Mapping from the model alias the IDE sends to the upstream model name.
    #[serde(default)]
    pub model_map: HashMap<String, String>,
}

impl Default for ToolConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            model_map: HashMap::new(),
        }
    }
}

fn default_true() -> bool { true }
fn default_listen() -> String { "0.0.0.0:443".to_string() }

/// Wrapper around a string that never gets printed in Debug/Display.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(s: impl Into<String>) -> Self { Self(s.into()) }
    pub fn expose(&self) -> &str { &self.0 }
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl std::fmt::Display for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl Config {
    /// Resolve the default config path: `~/.config/agbridge/config.toml` on
    /// Unix, `%APPDATA%\agbridge\config.toml` on Windows.
    pub fn default_path() -> Result<PathBuf> {
        let base = dirs::config_dir()
            .ok_or_else(|| anyhow::anyhow!("config_dir not available"))?;
        Ok(base.join("agbridge").join("config.toml"))
    }

    /// Default DATA_DIR for runtime files (cert, logs).
    pub fn default_data_dir() -> Result<PathBuf> {
        let base = dirs::data_dir()
            .ok_or_else(|| anyhow::anyhow!("data_dir not available"))?;
        Ok(base.join("agbridge"))
    }

    pub fn resolved_data_dir(&self) -> Result<PathBuf> {
        if let Some(p) = &self.data_dir {
            return Ok(p.clone());
        }
        Self::default_data_dir()
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        let cfg: Self = toml::from_str(&raw).context("parse config TOML")?;
        Ok(cfg)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let toml = toml::to_string_pretty(self)?;
        fs::write(path, toml).with_context(|| format!("write {}", path.display()))?;
        set_mode_0600(path)?;
        Ok(())
    }
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
fn set_mode_0600(_path: &Path) -> Result<()> { Ok(()) }

impl Default for Config {
    fn default() -> Self {
        Self {
            router_url: "https://example.com".into(),
            api_key: SecretString::default(),
            listen_addr: default_listen(),
            tools: ToolsConfig::default(),
            data_dir: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn round_trip_save_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut cfg = Config::default();
        cfg.api_key = SecretString::new("sk-test");
        cfg.tools.antigravity.model_map.insert("a".into(), "b".into());
        cfg.save(&path).unwrap();
        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.api_key.expose(), "sk-test");
        assert_eq!(loaded.tools.antigravity.model_map.get("a").unwrap(), "b");
    }

    #[test]
    fn secret_does_not_leak_in_debug() {
        let s = SecretString::new("sk-leak");
        assert_eq!(format!("{s:?}"), "[REDACTED]");
        assert_eq!(format!("{s}"), "[REDACTED]");
    }
}
