//! État partagé de l'application.

use crate::audit::Audit;
use crate::config::{Config, DirectoryProfile};
use crate::error::{AppError, AppResult};
use crate::ldap::Dir;
use crate::ldap::schema::Schema;
use crate::web::session::SessionStore;
use rustls::ClientConfig;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub profiles: Arc<Vec<Arc<DirectoryProfile>>>,
    pub tls: Arc<HashMap<String, Arc<ClientConfig>>>,
    pub sessions: Arc<SessionStore>,
    pub schemas: Arc<RwLock<HashMap<String, Arc<Schema>>>>,
    pub audit: Arc<Audit>,
    pub login_failures: Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>>,
    pub secure_cookies: bool,
}

impl AppState {
    pub fn new(cfg: Config) -> anyhow::Result<AppState> {
        let mut tls = HashMap::new();
        for p in &cfg.directories {
            tls.insert(p.id.clone(), crate::ldap::conn::profile_tls(p)?);
            if p.tls_insecure {
                tracing::warn!("annuaire {} : vérification TLS désactivée (tls_insecure = true)", p.id);
            }
        }
        let audit = Audit::new(if cfg.audit.enabled { Some(cfg.audit_path()) } else { None })?;
        let secure = cfg.server.tls != crate::config::TlsMode::Off;
        Ok(AppState {
            profiles: Arc::new(cfg.directories.iter().cloned().map(Arc::new).collect()),
            sessions: Arc::new(SessionStore::new(&cfg.security)),
            cfg: Arc::new(cfg),
            tls: Arc::new(tls),
            schemas: Arc::new(RwLock::new(HashMap::new())),
            audit: Arc::new(audit),
            login_failures: Arc::new(Mutex::new(HashMap::new())),
            secure_cookies: secure,
        })
    }

    pub fn profile(&self, id: &str) -> Option<Arc<DirectoryProfile>> {
        self.profiles.iter().find(|p| p.id == id).cloned()
    }

    pub fn tls_for(&self, id: &str) -> AppResult<Arc<ClientConfig>> {
        self.tls.get(id).cloned().ok_or_else(|| AppError::internal("profil TLS introuvable"))
    }

    /// Schéma du serveur (chargé une fois par profil puis mis en cache).
    pub async fn schema(&self, dir: &mut Dir) -> AppResult<Arc<Schema>> {
        if let Some(s) = self.schemas.read().ok().and_then(|m| m.get(&dir.profile.id).cloned()) {
            return Ok(s);
        }
        let s = Arc::new(Schema::load(dir).await?);
        if !s.attrs.is_empty() {
            if let Ok(mut m) = self.schemas.write() {
                m.insert(dir.profile.id.clone(), s.clone());
            }
        }
        Ok(s)
    }

    /// Limitation des tentatives de connexion par adresse IP (fenêtre de 15 min).
    pub fn login_blocked(&self, ip: IpAddr) -> bool {
        let max = self.cfg.security.max_login_failures as usize;
        if max == 0 {
            return false;
        }
        let mut g = self.login_failures.lock().unwrap();
        let v = g.entry(ip).or_default();
        v.retain(|t| t.elapsed().as_secs() < 900);
        v.len() >= max
    }

    pub fn login_failed(&self, ip: IpAddr) {
        let mut g = self.login_failures.lock().unwrap();
        g.entry(ip).or_default().push(Instant::now());
    }

    pub fn login_succeeded(&self, ip: IpAddr) {
        self.login_failures.lock().unwrap().remove(&ip);
    }
}
