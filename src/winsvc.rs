//! Exécution en tant que service Windows natif (fonctionnalité `windows-service`).
//!
//! Installation (PowerShell administrateur) :
//!   sc.exe create Arbor binPath= "\"C:\Program Files\Arbor\arbor.exe\" -c \"C:\ProgramData\Arbor\arbor.toml\" service" start= auto
//!   sc.exe start Arbor

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

pub const SERVICE_NAME: &str = "Arbor";
static CONFIG: OnceLock<PathBuf> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

/// Point d'entrée appelé par `arbor service` (lancé par le gestionnaire de services).
pub fn run(config: PathBuf) -> anyhow::Result<()> {
    let _ = CONFIG.set(config);
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!("service Windows : {e:#}");
    }
}

fn run_service() -> anyhow::Result<()> {
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let handler = move |control: ServiceControl| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status = service_control_handler::register(SERVICE_NAME, handler)?;
    let set = |state: ServiceState, accept: ServiceControlAccept| {
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        })
    };
    set(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN)?;

    let cfg_path = CONFIG.get().cloned().unwrap_or_else(|| PathBuf::from("arbor.toml"));
    // Le répertoire courant d'un service est System32 : on se place à côté de la configuration.
    if let Some(dir) = cfg_path.parent().filter(|d| !d.as_os_str().is_empty()) {
        let _ = std::env::set_current_dir(dir);
    }
    let result = (|| -> anyhow::Result<()> {
        let cfg = crate::config::Config::load(&cfg_path)?;
        std::fs::create_dir_all(&cfg.server.data_dir)?;
        let log = std::fs::OpenOptions::new().create(true).append(true).open(cfg.server.data_dir.join("arbor.log"))?;
        let _ = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(Mutex::new(log))
            .with_env_filter(tracing_subscriber::EnvFilter::new("info,arbor=info"))
            .try_init();
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async move {
            let stop = async move {
                let _ = tokio::task::spawn_blocking(move || rx.recv()).await;
                tracing::info!("arrêt demandé par le gestionnaire de services");
            };
            crate::run_with_shutdown(cfg, stop).await
        })
    })();
    set(ServiceState::Stopped, ServiceControlAccept::empty())?;
    result
}
