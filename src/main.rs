//! Arbor — console web d'administration d'annuaires et de services d'infrastructure,
//! inspirée des outils RSAT (ADUC, ADSI Edit, DNS, DHCP, GPMC, Sites et services...).
//! Un binaire unique, multiplateforme (Windows / Linux), sans dépendance OpenSSL.

mod audit;
mod config;
mod directory;
mod error;
mod ldap;
mod services;
mod state;
mod web;
#[cfg(all(windows, feature = "windows-service"))]
mod winsvc;

use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Parser)]
#[command(name = "arbor", version, about = "Console web d'administration LDAP / Active Directory et services connexes")]
struct Cli {
    /// Fichier de configuration
    #[arg(short, long, default_value = "arbor.toml", global = true)]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Démarre le serveur web (commande par défaut)
    Run,
    /// Écrit un fichier de configuration d'exemple
    InitConfig {
        #[arg(default_value = "arbor.toml")]
        path: PathBuf,
    },
    /// Vérifie la configuration et la connectivité vers chaque annuaire
    Check,
    /// Exécution en tant que service Windows (lancé par le gestionnaire de services)
    #[cfg(all(windows, feature = "windows-service"))]
    Service,
}

fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    #[cfg(all(windows, feature = "windows-service"))]
    if matches!(cli.cmd, Some(Cmd::Service)) {
        let path = std::fs::canonicalize(&cli.config).unwrap_or(cli.config.clone());
        return winsvc::run(path);
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,arbor=info".into()),
        )
        .init();
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        match cli.cmd.unwrap_or(Cmd::Run) {
            Cmd::InitConfig { path } => {
                if path.exists() {
                    anyhow::bail!("{} existe déjà", path.display());
                }
                std::fs::write(&path, config::EXAMPLE_CONFIG)?;
                println!("Configuration d'exemple écrite dans {}", path.display());
                Ok(())
            }
            Cmd::Check => check(&cli.config).await,
            Cmd::Run => {
                let cfg = config::Config::load(&cli.config)?;
                run_with_shutdown(cfg, shutdown_signal()).await
            }
            #[cfg(all(windows, feature = "windows-service"))]
            Cmd::Service => unreachable!(),
        }
    })
}

async fn check(path: &Path) -> anyhow::Result<()> {
    let cfg = config::Config::load(path)?;
    println!("Configuration valide : {} annuaire(s)", cfg.directories.len());
    for p in &cfg.directories {
        let tls = ldap::conn::profile_tls(p)?;
        match ldap::conn::connect(p, &tls).await {
            Ok((mut l, url)) => {
                let root = ldap::flavor::read_root_dse(&mut l, Duration::from_secs(p.timeout_secs)).await;
                match root {
                    Ok(r) => {
                        let info = ldap::flavor::initial_info(&r, p, &url);
                        println!(
                            "  [{}] {url} : OK — {} ({}), base {}",
                            p.id,
                            info.flavor.label(),
                            info.vendor,
                            info.base_dn
                        );
                    }
                    Err(e) => println!("  [{}] {url} : connecté mais RootDSE illisible : {e}", p.id),
                }
                let _ = l.unbind().await;
            }
            Err(e) => println!("  [{}] ÉCHEC : {e}", p.id),
        }
    }
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
    tracing::info!("arrêt demandé");
}

/// Certificat auto-signé persistant dans data_dir.
fn ensure_self_signed(dir: &Path) -> anyhow::Result<(PathBuf, PathBuf)> {
    let cert = dir.join("arbor-cert.pem");
    let key = dir.join("arbor-key.pem");
    if cert.exists() && key.exists() {
        return Ok((cert, key));
    }
    let mut names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    if let Ok(h) = hostname() {
        names.push(h);
    }
    let ck = rcgen::generate_simple_self_signed(names)?;
    std::fs::write(&cert, ck.cert.pem())?;
    std::fs::write(&key, ck.signing_key.serialize_pem())?;
    restrict_permissions(&key);
    tracing::warn!("certificat auto-signé généré : {} (remplacez-le en production)", cert.display());
    Ok((cert, key))
}

fn hostname() -> anyhow::Result<String> {
    if let Ok(h) = std::env::var("COMPUTERNAME") {
        return Ok(h.to_lowercase());
    }
    if let Ok(h) = std::env::var("HOSTNAME") {
        return Ok(h);
    }
    Ok(std::fs::read_to_string("/etc/hostname")?.trim().to_string())
}

#[cfg(unix)]
fn restrict_permissions(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict_permissions(_p: &Path) {}

/// Démarre le serveur web jusqu'à ce que `stop` se termine.
pub async fn run_with_shutdown(
    cfg: config::Config,
    stop: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(&cfg.server.data_dir)?;
    let st = state::AppState::new(cfg.clone())?;
    st.sessions.spawn_reaper();
    let app = web::router(st.clone());
    let addr: SocketAddr = cfg.server.listen.parse().map_err(|e| anyhow::anyhow!("listen invalide : {e}"))?;
    let svc = app.into_make_service_with_connect_info::<SocketAddr>();
    for p in &cfg.directories {
        tracing::info!("annuaire « {} » : {}", p.name, p.urls.join(", "));
    }
    match cfg.server.tls {
        config::TlsMode::Off => {
            tracing::warn!("HTTPS désactivé : à n'utiliser que derrière un reverse-proxy TLS");
            tracing::info!("écoute sur http://{addr}");
            let l = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(l, svc).with_graceful_shutdown(stop).await?;
        }
        mode => {
            let (cert, key) = if mode == config::TlsMode::SelfSigned {
                ensure_self_signed(&cfg.server.data_dir)?
            } else {
                (cfg.server.tls_cert.clone().unwrap(), cfg.server.tls_key.clone().unwrap())
            };
            let rcfg = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key)
                .await
                .map_err(|e| anyhow::anyhow!("certificat TLS ({}) : {e}", cert.display()))?;
            let handle = axum_server::Handle::new();
            let h2 = handle.clone();
            tokio::spawn(async move {
                stop.await;
                h2.graceful_shutdown(Some(Duration::from_secs(10)));
            });
            tracing::info!("écoute sur https://{addr}");
            // TCP_NODELAY : évite ~40 ms de latence par réponse (Nagle + acquittement retardé).
            let acceptor = axum_server::tls_rustls::RustlsAcceptor::new(rcfg).acceptor(
                axum_server::accept::TcpConfigAcceptor::new(axum_server::accept::TcpSocketConfig::new().nodelay(true)),
            );
            axum_server::bind(addr).acceptor(acceptor).handle(handle).serve(svc).await?;
        }
    }
    Ok(())
}
