use agbridge_cert::CertManager;
use agbridge_config::Config;
use agbridge_core::Server;
use agbridge_dns::{flush_dns_cache, HostsEditor, Tool};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

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
    },
    /// Stop a previously started agbridge instance.
    Stop,
    /// Generate Root CA, install into trust store, write hosts entries.
    Setup,
    /// Remove all agbridge hosts entries.
    Cleanup,
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let filter = EnvFilter::try_new(&cli.log).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let config_path = cli.config.unwrap_or_else(|| Config::default_path().expect("config path"));

    match cli.cmd {
        Cmd::Start { skip_setup } => start(&config_path, skip_setup).await,
        Cmd::Stop => stop(),
        Cmd::Setup => setup(&config_path),
        Cmd::Cleanup => cleanup(),
        Cmd::Status => status(&config_path).await,
        Cmd::Doctor => doctor(&config_path).await,
        Cmd::ConfigShow => show_config(&config_path),
        Cmd::ConfigSet { kv } => set_config(&config_path, kv),
        Cmd::UninstallCert => { agbridge_trust::uninstall()?; Ok(()) }
    }
}

async fn start(config_path: &std::path::Path, skip_setup: bool) -> Result<()> {
    let config = load_or_init(config_path)?;
    if !skip_setup { setup(config_path)?; }
    let cert = CertManager::init(&config.resolved_data_dir()?)?;
    let server = Server::new(config, cert)?;
    server.run().await
}

fn stop() -> Result<()> {
    warn!("`stop` not implemented yet — kill the process or use Ctrl+C");
    Ok(())
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

fn cleanup() -> Result<()> {
    HostsEditor::system().cleanup_all()?;
    flush_dns_cache();
    Ok(())
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
    let resp = reqwest::Client::new()
        .get(format!("{}/api/health", config.router_url.trim_end_matches('/')))
        .send()
        .await;
    match resp {
        Ok(r) => println!("• upstream reachable: {} ({})", r.status(), r.url()),
        Err(e) => println!("• upstream reachable: FAIL ({e})"),
    }
    Ok(())
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
