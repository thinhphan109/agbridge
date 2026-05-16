use agbridge_cert::CertManager;
use agbridge_config::{ensure_loopback, Config};
use agbridge_core::Server;
use agbridge_dns::{flush_dns_cache, HostsEditor, Tool};
use agbridge_service::{default_pid_path, kill_pid, read_pid, remove_pid, service, write_pid};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{info, warn};

#[derive(Parser)]
#[command(name = "agbridge", version, about = "Local MITM bridge for 9router")]
struct Cli {
    /// Override config file path.
    #[arg(long, env = "AGBRIDGE_CONFIG", global = true)]
    config: Option<PathBuf>,

    /// Override log level (e.g. `info`, `debug`, `agbridge=trace`).
    #[arg(long, default_value = "info", global = true)]
    log: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run cert+hosts setup, then start the proxy.
    Start {
        #[arg(long)] skip_setup: bool,
        /// Allow binding to a non-loopback address. **Dangerous** — exposes
        /// the proxy on your LAN with full upstream credentials.
        #[arg(long)] allow_remote: bool,
    },
    /// Stop a previously started agbridge instance (PID file based).
    Stop,
    /// Generate Root CA, install into trust store, write hosts entries.
    Setup,
    /// Remove agbridge hosts entries (default) or do a full uninstall.
    Cleanup {
        /// Hard-kill switch: remove hosts, uninstall Root CA, securely delete
        /// the CA private key, and flush DNS.
        #[arg(long)] hard: bool,
    },
    /// Print runtime status as JSON.
    Status,
    /// Run diagnostics.
    Doctor,
    /// Print resolved config (secrets redacted).
    ConfigShow,
    /// Set a single config key, e.g. `config-set router_url=https://...`.
    ConfigSet { kv: Vec<String> },
    /// Remove the Root CA from the OS trust store.
    UninstallCert,
    /// Manage the agbridge Windows Service (Windows only).
    Service {
        #[command(subcommand)]
        action: ServiceCmd,
    },
    /// Internal: launched by SCM. Do not call this directly.
    #[command(hide = true)]
    ScmRun,
}

#[derive(Subcommand)]
enum ServiceCmd {
    /// Install agbridge as an auto-start Windows Service.
    Install,
    /// Remove the Windows Service entry.
    Uninstall,
    /// Start the installed service.
    Start,
    /// Stop the installed service.
    Stop,
    /// Print current service state.
    Status,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    agbridge_logging::init(&cli.log);

    let config_path = cli.config.unwrap_or_else(|| Config::default_path().expect("config path"));

    // SCM dispatcher path runs **synchronously** because
    // `service_dispatcher::start` blocks the calling thread until SCM exits.
    #[cfg(windows)]
    if matches!(cli.cmd, Cmd::ScmRun) {
        let config_path_owned = config_path.clone();
        return agbridge_service::service::run_dispatcher(move |notify| {
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
            rt.block_on(async move {
                start_with_notify(&config_path_owned, true, false, Some(notify)).await
            })
        });
    }

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async move {
        match cli.cmd {
            Cmd::Start { skip_setup, allow_remote } => start(&config_path, skip_setup, allow_remote).await,
            Cmd::Stop => stop(&config_path),
            Cmd::Setup => setup(&config_path),
            Cmd::Cleanup { hard } => cleanup(&config_path, hard),
            Cmd::Status => status(&config_path).await,
            Cmd::Doctor => doctor(&config_path).await,
            Cmd::ConfigShow => show_config(&config_path),
            Cmd::ConfigSet { kv } => set_config(&config_path, kv),
            Cmd::UninstallCert => { agbridge_trust::uninstall()?; Ok(()) }
            Cmd::Service { action } => run_service(action),
            Cmd::ScmRun => Err(anyhow::anyhow!("scm-run is internal; use `agbridge service install` then `service start`")),
        }
    })
}

async fn start(config_path: &std::path::Path, skip_setup: bool, allow_remote: bool) -> Result<()> {
    start_with_notify(config_path, skip_setup, allow_remote, None).await
}

async fn start_with_notify(
    config_path: &std::path::Path,
    skip_setup: bool,
    allow_remote: bool,
    scm_notify: Option<std::sync::Arc<tokio::sync::Notify>>,
) -> Result<()> {
    let config = load_or_init(config_path)?;
    if !allow_remote {
        ensure_loopback(&config.listen_addr).context(
            "listener bound to a non-loopback address; pass --allow-remote to acknowledge",
        )?;
    } else {
        warn!(addr = %config.listen_addr, "non-loopback bind enabled by --allow-remote");
    }
    if !skip_setup { setup(config_path)?; }

    let data_dir = config.resolved_data_dir()?;
    let pid_path = default_pid_path(&data_dir);
    if let Ok(prev) = read_pid(&pid_path) {
        warn!(prev_pid = prev, "stale pid file detected; replacing");
    }
    write_pid(&pid_path)?;

    let cert = CertManager::init(&data_dir)?;
    let server = Server::new(config, cert)?;

    let server_fut = tokio::spawn(async move { server.run().await });
    let result = tokio::select! {
        r = server_fut => r.unwrap_or_else(|e| Err(anyhow::anyhow!("join error: {e}"))),
        _ = wait_for_shutdown() => {
            info!("shutdown signal received");
            Ok(())
        }
        _ = wait_scm(scm_notify) => {
            info!("SCM stop received");
            Ok(())
        }
    };

    info!("removing hosts entries before exit");
    let _ = HostsEditor::system().cleanup_all();
    flush_dns_cache();
    remove_pid(&pid_path);
    result
}

async fn wait_scm(notify: Option<std::sync::Arc<tokio::sync::Notify>>) {
    if let Some(n) = notify {
        n.notified().await;
    } else {
        std::future::pending::<()>().await;
    }
}

#[cfg(windows)]
async fn wait_for_shutdown() {
    use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close};
    let mut c = ctrl_c().expect("ctrl_c");
    let mut b = ctrl_break().expect("ctrl_break");
    let mut x = ctrl_close().expect("ctrl_close");
    tokio::select! {
        _ = c.recv() => {},
        _ = b.recv() => {},
        _ = x.recv() => {},
    }
}

#[cfg(not(windows))]
async fn wait_for_shutdown() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("sigterm");
    let mut int_ = signal(SignalKind::interrupt()).expect("sigint");
    tokio::select! {
        _ = term.recv() => {},
        _ = int_.recv() => {},
    }
}

fn stop(config_path: &std::path::Path) -> Result<()> {
    let cfg = load_or_init(config_path)?;
    let pid_path = default_pid_path(&cfg.resolved_data_dir()?);
    if !pid_path.exists() {
        warn!("no PID file at {} — nothing to stop", pid_path.display());
        return Ok(());
    }
    let pid = read_pid(&pid_path)?;
    info!(%pid, "sending kill");
    kill_pid(pid)?;
    remove_pid(&pid_path);
    let _ = HostsEditor::system().cleanup_all();
    flush_dns_cache();
    Ok(())
}

fn run_service(action: ServiceCmd) -> Result<()> {
    match action {
        ServiceCmd::Install => {
            let exe = std::env::current_exe().context("current_exe")?;
            service::install(&exe, &["scm-run"])
        }
        ServiceCmd::Uninstall => service::uninstall(),
        ServiceCmd::Start => service::start(),
        ServiceCmd::Stop => service::stop(),
        ServiceCmd::Status => {
            let s = service::status()?;
            println!("{s}");
            Ok(())
        }
    }
}

fn setup(config_path: &std::path::Path) -> Result<()> {
    let config = load_or_init(config_path)?;
    let cert = CertManager::init(&config.resolved_data_dir()?)?;
    info!("Installing Root CA into OS trust store…");
    agbridge_trust::install(&cert.root_cert_path())
        .context("install Root CA — re-run as Administrator/sudo")?;
    info!("Patching hosts file…");
    let hosts = HostsEditor::system();
    for tool in active_tools(&config) {
        hosts.enable(tool)?;
    }
    flush_dns_cache();
    Ok(())
}

fn cleanup(config_path: &std::path::Path, hard: bool) -> Result<()> {
    HostsEditor::system().cleanup_all()?;
    flush_dns_cache();
    if !hard {
        return Ok(());
    }
    warn!("--hard: tearing down Root CA, private key, and trust store entries");
    let _ = agbridge_trust::uninstall();
    if let Ok(cfg) = load_or_init(config_path) {
        if let Ok(data_dir) = cfg.resolved_data_dir() {
            let key = data_dir.join("cert").join("rootCA.key");
            let crt = data_dir.join("cert").join("rootCA.crt");
            secure_remove(&key);
            secure_remove(&crt);
        }
    }
    Ok(())
}

/// Best-effort secure file removal: overwrite with zeros (1 pass) then unlink.
fn secure_remove(path: &std::path::Path) {
    use std::fs::{remove_file, OpenOptions};
    use std::io::{Seek, Write};
    if !path.exists() { return; }
    let res = (|| -> Result<()> {
        let mut f = OpenOptions::new().write(true).open(path)?;
        let len = f.metadata()?.len() as usize;
        f.seek(std::io::SeekFrom::Start(0))?;
        let buf = vec![0u8; 4096.min(len.max(1))];
        let mut written = 0usize;
        while written < len {
            let n = (len - written).min(buf.len());
            f.write_all(&buf[..n])?;
            written += n;
        }
        f.flush()?;
        f.sync_all()?;
        drop(f);
        remove_file(path)?;
        Ok(())
    })();
    if let Err(e) = res {
        warn!(?path, "secure_remove failed: {e}");
    } else {
        info!(?path, "shredded");
    }
}

async fn status(config_path: &std::path::Path) -> Result<()> {
    let config = load_or_init(config_path)?;
    let cert_installed = agbridge_trust::is_installed();
    let hosts = HostsEditor::system();
    let dns_status = serde_json::json!({
        "antigravity": hosts.is_active(Tool::Antigravity).unwrap_or(false),
        "copilot":     hosts.is_active(Tool::Copilot).unwrap_or(false),
        "kiro":        hosts.is_active(Tool::Kiro).unwrap_or(false),
        "cursor":      hosts.is_active(Tool::Cursor).unwrap_or(false),
    });
    let payload = serde_json::json!({
        "router_url": config.router_url,
        "listen_addr": config.listen_addr,
        "cert_installed": cert_installed,
        "dns": dns_status,
    });
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}

async fn doctor(config_path: &std::path::Path) -> Result<()> {
    let config = load_or_init(config_path)?;
    println!("• config_path: {}", config_path.display());
    println!("• router_url: {}", config.router_url);
    println!("• listen_addr: {}", config.listen_addr);
    println!("• cert_installed: {}", agbridge_trust::is_installed());
    println!("• loopback bind: {}", ensure_loopback(&config.listen_addr).is_ok());
    println!("• cursor_enabled: {}", config.tools.cursor.enabled);

    let resp = reqwest::Client::new()
        .get(format!("{}/api/health", config.router_url.trim_end_matches('/')))
        .send()
        .await;
    match resp {
        Ok(r) => println!("• upstream reachable: {} ({})", r.status(), r.url()),
        Err(e) => println!("• upstream reachable: FAIL ({e})"),
    }

    println!("• per-host TLS handshake (real upstream, via Cloudflare DNS):");
    for host in [
        "cloudcode-pa.googleapis.com",
        "api.individual.githubcopilot.com",
        "q.us-east-1.amazonaws.com",
        "api2.cursor.sh",
    ] {
        match probe_real_upstream(host).await {
            Ok(status) => println!("    {host:50} OK ({status})"),
            Err(e) => println!("    {host:50} FAIL: {e}"),
        }
    }
    Ok(())
}

/// Performs a HEAD request to the **real** upstream (DNS resolved via the
/// hosts file *bypass*). Detects: (1) network unreachable, (2) cert pinning
/// rejection, (3) hosts hijack reaching ourselves and self-signed cert
/// failing default trust.
async fn probe_real_upstream(host: &str) -> Result<u16> {
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use hickory_resolver::TokioAsyncResolver;
    use std::net::SocketAddr;

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());
    let lookup = resolver.lookup_ip(host).await
        .with_context(|| format!("public DNS for {host}"))?;
    let ip = lookup.iter().next().ok_or_else(|| anyhow::anyhow!("no IP"))?;

    let client = reqwest::Client::builder()
        .resolve(host, SocketAddr::new(ip, 443))
        .connect_timeout(std::time::Duration::from_secs(6))
        .build()?;
    let resp = client
        .head(format!("https://{host}/"))
        .send()
        .await?;
    Ok(resp.status().as_u16())
}


fn show_config(config_path: &std::path::Path) -> Result<()> {
    let config = load_or_init(config_path)?;
    println!("{}", toml::to_string_pretty(&config)?);
    Ok(())
}

fn set_config(config_path: &std::path::Path, kv: Vec<String>) -> Result<()> {
    let mut config = load_or_init(config_path)?;
    for pair in kv {
        let (k, v) = pair.split_once('=').ok_or_else(|| anyhow::anyhow!("expected key=value, got {pair}"))?;
        match k {
            "router_url" => config.router_url = v.into(),
            "api_key" => config.api_key = agbridge_config::SecretString::new(v),
            "listen_addr" => config.listen_addr = v.into(),
            other => anyhow::bail!("unsupported key: {other}"),
        }
    }
    config.save(config_path)?;
    Ok(())
}

fn active_tools(cfg: &Config) -> Vec<Tool> {
    let mut out = Vec::new();
    if cfg.tools.antigravity.enabled { out.push(Tool::Antigravity); }
    if cfg.tools.copilot.enabled     { out.push(Tool::Copilot); }
    if cfg.tools.kiro.enabled        { out.push(Tool::Kiro); }
    if cfg.tools.cursor.enabled      { out.push(Tool::Cursor); }
    out
}

fn load_or_init(path: &std::path::Path) -> Result<Config> {
    if path.exists() { Config::load(path) }
    else {
        info!(path = %path.display(), "config not found, writing default");
        let cfg = Config::default();
        cfg.save(path)?;
        Ok(cfg)
    }
}
