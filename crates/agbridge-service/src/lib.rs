//! Process lifecycle helpers.
//!
//! - `pidfile` provides atomic create/read/delete of a PID file used by
//!   `agbridge stop` to find a running instance.
//! - `windows::service` wraps `windows-service` for install/uninstall/start/
//!   stop of the agbridge background service via SCM.
//!
//! All non-Windows targets fall back to plain process kill via `kill(2)`.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

pub const SERVICE_NAME: &str = "agbridge";
pub const SERVICE_DISPLAY: &str = "agbridge — local AI MITM bridge";

/// Default PID file location: `${data_dir}/agbridge.pid`.
pub fn default_pid_path(data_dir: &Path) -> PathBuf {
    data_dir.join("agbridge.pid")
}

/// Write `pid` (current process by default) to `path`. Creates parent dirs as
/// needed. The file contains a single ASCII line: `<pid>`.
pub fn write_pid(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
    let pid = std::process::id();
    fs::write(path, pid.to_string()).with_context(|| format!("write pid {}", path.display()))?;
    info!(?path, %pid, "wrote pid file");
    Ok(())
}

pub fn read_pid(path: &Path) -> Result<u32> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read pid {}", path.display()))?;
    raw.trim().parse::<u32>()
        .with_context(|| format!("invalid pid contents in {}", path.display()))
}

pub fn remove_pid(path: &Path) {
    if path.exists() {
        if let Err(e) = fs::remove_file(path) {
            warn!(?path, "remove pid: {e}");
        }
    }
}

/// Send a kill signal (Windows: `taskkill /F /PID`, Unix: SIGTERM then SIGKILL).
/// Returns Ok if the process was terminated or was already gone.
pub fn kill_pid(pid: u32) -> Result<()> {
    if pid == 0 || pid == std::process::id() {
        bail!("refusing to kill pid {pid}");
    }
    #[cfg(windows)]
    {
        let status = std::process::Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .status()
            .context("invoke taskkill")?;
        if !status.success() {
            warn!(%pid, ?status, "taskkill returned non-zero");
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        unsafe {
            // SIGTERM then short wait then SIGKILL
            libc::kill(pid as libc::pid_t, libc::SIGTERM);
            std::thread::sleep(std::time::Duration::from_millis(500));
            libc::kill(pid as libc::pid_t, libc::SIGKILL);
        }
        Ok(())
    }
}

#[cfg(windows)]
pub mod service {
    use super::*;
    use std::ffi::OsString;
    use std::path::Path;
    use windows_service::service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    /// Install agbridge as a Windows Service that auto-starts on boot.
    pub fn install(exe_path: &Path, args: &[&str]) -> Result<()> {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .context("connect SCM (run as Administrator)")?;
        let info = ServiceInfo {
            name: OsString::from(super::SERVICE_NAME),
            display_name: OsString::from(super::SERVICE_DISPLAY),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe_path.to_path_buf(),
            launch_arguments: args.iter().map(OsString::from).collect(),
            dependencies: vec![],
            account_name: None,
            account_password: None,
        };
        let svc = manager
            .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
            .context("create_service")?;
        svc.set_description("Local TLS MITM bridge that routes Antigravity / Copilot / Kiro / Cursor requests to a 9router VPS.")
            .ok();
        info!(name = super::SERVICE_NAME, "service installed");
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT,
        )?;
        let svc = manager
            .open_service(super::SERVICE_NAME, ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)
            .context("open_service")?;
        let status = svc.query_status()?;
        if status.current_state != ServiceState::Stopped {
            let _ = svc.stop();
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        svc.delete()?;
        info!(name = super::SERVICE_NAME, "service deleted");
        Ok(())
    }

    pub fn start() -> Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let svc = manager.open_service(super::SERVICE_NAME, ServiceAccess::START)?;
        svc.start::<&str>(&[])?;
        Ok(())
    }

    pub fn stop() -> Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let svc = manager.open_service(super::SERVICE_NAME, ServiceAccess::STOP)?;
        svc.stop()?;
        Ok(())
    }

    pub fn status() -> Result<&'static str> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let svc = match manager.open_service(super::SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
            Ok(s) => s,
            Err(_) => return Ok("not installed"),
        };
        let s = svc.query_status()?;
        Ok(match s.current_state {
            ServiceState::Stopped => "stopped",
            ServiceState::StartPending => "start_pending",
            ServiceState::StopPending => "stop_pending",
            ServiceState::Running => "running",
            ServiceState::ContinuePending => "continue_pending",
            ServiceState::PausePending => "pause_pending",
            ServiceState::Paused => "paused",
        })
    }
}

#[cfg(not(windows))]
pub mod service {
    use anyhow::Result;
    pub fn install(_: &std::path::Path, _: &[&str]) -> Result<()> { anyhow::bail!("service mode is Windows-only in this build") }
    pub fn uninstall() -> Result<()> { anyhow::bail!("service mode is Windows-only in this build") }
    pub fn start() -> Result<()> { anyhow::bail!("service mode is Windows-only in this build") }
    pub fn stop() -> Result<()> { anyhow::bail!("service mode is Windows-only in this build") }
    pub fn status() -> Result<&'static str> { Ok("unsupported") }
}
