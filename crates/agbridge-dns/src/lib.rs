//! Hosts-file based DNS hijack.
//!
//! Adds `127.0.0.1 <host>` and `::1 <host>` lines for every host in the per-tool
//! list, marked with a sentinel comment so we can find and remove them again
//! atomically. Mutations require admin/root.

use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use tracing::info;

/// Sentinel suffix appended to every line we manage.
const SENTINEL: &str = "# agbridge";

/// All hostnames per tool. Keep in sync with the corresponding handler list.
pub fn tool_hosts(tool: Tool) -> &'static [&'static str] {
    match tool {
        Tool::Antigravity => &[
            "cloudcode-pa.googleapis.com",
            "daily-cloudcode-pa.googleapis.com",
        ],
        Tool::Copilot => &["api.individual.githubcopilot.com"],
        Tool::Kiro => &[
            "q.us-east-1.amazonaws.com",
            "codewhisperer.us-east-1.amazonaws.com",
        ],
        Tool::Cursor => &["api2.cursor.sh"],
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tool {
    Antigravity,
    Copilot,
    Kiro,
    Cursor,
}

pub struct HostsEditor {
    path: PathBuf,
}

impl HostsEditor {
    /// Default OS hosts file path.
    pub fn system() -> Self {
        let path = if cfg!(target_os = "windows") {
            let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
            PathBuf::from(format!(r"{root}\System32\drivers\etc\hosts"))
        } else {
            PathBuf::from("/etc/hosts")
        };
        Self { path }
    }

    pub fn at(path: PathBuf) -> Self {
        Self { path }
    }

    /// True if at least one of the tool's hosts has the agbridge sentinel.
    pub fn is_active(&self, tool: Tool) -> Result<bool> {
        let content = self.read()?;
        Ok(tool_hosts(tool)
            .iter()
            .any(|h| content.lines().any(|l| line_matches(l, h))))
    }

    /// Add 127.0.0.1 and ::1 entries for `tool`. Idempotent.
    pub fn enable(&self, tool: Tool) -> Result<()> {
        let mut content = self.read()?;
        let mut existing: BTreeSet<String> = content.lines().map(|l| l.to_string()).collect();
        for host in tool_hosts(tool) {
            existing.insert(format!("127.0.0.1 {host} {SENTINEL}"));
            existing.insert(format!("::1 {host} {SENTINEL}"));
        }
        content = existing.into_iter().collect::<Vec<_>>().join(line_sep());
        content.push_str(line_sep());
        self.atomic_write(&content)?;
        info!(?tool, "hosts: enabled");
        Ok(())
    }

    /// Remove every line we tagged for `tool`.
    pub fn disable(&self, tool: Tool) -> Result<()> {
        let content = self.read()?;
        let hosts: BTreeSet<&str> = tool_hosts(tool).iter().copied().collect();
        let kept: Vec<&str> = content
            .lines()
            .filter(|l| {
                if !l.contains(SENTINEL) {
                    return true;
                }
                !hosts.iter().any(|h| line_matches(l, h))
            })
            .collect();
        let mut joined = kept.join(line_sep());
        joined.push_str(line_sep());
        self.atomic_write(&joined)?;
        info!(?tool, "hosts: disabled");
        Ok(())
    }

    /// Remove every agbridge-managed line regardless of tool.
    pub fn cleanup_all(&self) -> Result<()> {
        let content = self.read()?;
        let kept: Vec<&str> = content
            .lines()
            .filter(|l| !l.contains(SENTINEL))
            .collect();
        let mut joined = kept.join(line_sep());
        joined.push_str(line_sep());
        self.atomic_write(&joined)?;
        info!("hosts: cleaned up all agbridge entries");
        Ok(())
    }

    fn read(&self) -> Result<String> {
        if !self.path.exists() {
            return Ok(String::new());
        }
        fs::read_to_string(&self.path).with_context(|| format!("read {}", self.path.display()))
    }

    fn atomic_write(&self, content: &str) -> Result<()> {
        let dir = self
            .path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("hosts file has no parent dir"))?;
        let new = dir.join("hosts.agbridge.new");
        fs::write(&new, content).with_context(|| format!("write {}", new.display()))?;
        // On Windows we cannot atomically rename if the target exists, so we
        // back the original up first; on Unix `rename` is atomic.
        if cfg!(target_os = "windows") {
            let bak = dir.join("hosts.agbridge.bak");
            let _ = fs::remove_file(&bak);
            if self.path.exists() {
                fs::rename(&self.path, &bak).with_context(|| "backup current hosts")?;
            }
            if let Err(e) = fs::rename(&new, &self.path) {
                // rollback
                if bak.exists() {
                    let _ = fs::rename(&bak, &self.path);
                }
                return Err(e).context("install new hosts");
            }
            let _ = fs::remove_file(&bak);
        } else {
            fs::rename(&new, &self.path).context("rename new hosts file")?;
        }
        Ok(())
    }
}

fn line_matches(line: &str, host: &str) -> bool {
    line.split_whitespace().any(|tok| tok == host)
}

fn line_sep() -> &'static str {
    if cfg!(target_os = "windows") { "\r\n" } else { "\n" }
}

/// Best-effort DNS cache flush. Errors logged, never fatal.
pub fn flush_dns_cache() {
    use std::process::Command;
    let res = if cfg!(target_os = "windows") {
        Command::new("ipconfig").arg("/flushdns").output()
    } else if cfg!(target_os = "macos") {
        Command::new("sh")
            .arg("-c")
            .arg("dscacheutil -flushcache && killall -HUP mDNSResponder")
            .output()
    } else {
        Command::new("sh")
            .arg("-c")
            .arg("resolvectl flush-caches 2>/dev/null || true")
            .output()
    };
    if let Err(e) = res {
        tracing::debug!("flush_dns_cache failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn editor() -> (NamedTempFile, HostsEditor) {
        let f = NamedTempFile::new().unwrap();
        std::fs::write(f.path(), "127.0.0.1 localhost\n").unwrap();
        let e = HostsEditor::at(f.path().to_path_buf());
        (f, e)
    }

    #[test]
    fn enable_disable_round_trip() {
        let (_f, e) = editor();
        assert!(!e.is_active(Tool::Antigravity).unwrap());
        e.enable(Tool::Antigravity).unwrap();
        assert!(e.is_active(Tool::Antigravity).unwrap());
        e.disable(Tool::Antigravity).unwrap();
        assert!(!e.is_active(Tool::Antigravity).unwrap());
    }

    #[test]
    fn cleanup_removes_only_agbridge_lines() {
        let (f, e) = editor();
        std::fs::write(
            f.path(),
            "127.0.0.1 localhost\n10.0.0.1 not-ours\n",
        )
        .unwrap();
        e.enable(Tool::Copilot).unwrap();
        e.cleanup_all().unwrap();
        let content = std::fs::read_to_string(f.path()).unwrap();
        assert!(content.contains("localhost"));
        assert!(content.contains("not-ours"));
        assert!(!content.contains("agbridge"));
    }
}
