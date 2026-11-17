//! Sessions côté serveur. Le navigateur ne reçoit qu'un identifiant aléatoire
//! (cookie HttpOnly, SameSite=Strict). Les identifiants de l'utilisateur restent
//! en mémoire (effacés à la destruction) et servent à ré-ouvrir la connexion LDAP :
//! toutes les opérations s'exécutent avec les droits de l'utilisateur, comme RSAT.

use crate::config::{DirectoryProfile, SecurityConfig};
use crate::error::{AppError, AppResult};
use crate::ldap::{Dir, ServerInfo, conn};
use crate::state::AppState;
use base64::Engine;
use ldap3::Ldap;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const COOKIE: &str = "arbor_sid";

pub struct Download {
    pub filename: String,
    pub mime: String,
    pub data: Zeroizing<Vec<u8>>,
    pub created: Instant,
}

pub struct Session {
    pub id: String,
    pub csrf: String,
    pub profile: Arc<DirectoryProfile>,
    pub info: Arc<ServerInfo>,
    pub login: String,
    pub bind_dn: String,
    pub user_dn: String,
    pub display: String,
    password: Zeroizing<String>,
    ldap: tokio::sync::Mutex<Option<(Ldap, Instant)>>,
    pub created: Instant,
    pub last_seen: Mutex<Instant>,
    pub advanced: AtomicBool,
    pub downloads: Mutex<HashMap<String, Download>>,
}

pub fn random_token(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

pub struct NewSession {
    pub profile: Arc<DirectoryProfile>,
    pub info: Arc<ServerInfo>,
    pub login: String,
    pub bind_dn: String,
    pub user_dn: String,
    pub display: String,
    pub password: Zeroizing<String>,
    pub ldap: Ldap,
}

impl Session {
    /// Poignée LDAP de la session ; reconnexion transparente si la connexion a été
    /// fermée ou est restée inactive (les DC AD ferment les connexions inactives).
    pub async fn dir(&self, st: &AppState) -> AppResult<Dir> {
        let mut g = self.ldap.lock().await;
        if let Some((l, used)) = g.as_mut() {
            if !l.is_closed() && used.elapsed() < Duration::from_secs(300) {
                *used = Instant::now();
                return Ok(Dir { ldap: l.clone(), info: self.info.clone(), profile: self.profile.clone() });
            }
        }
        if let Some((mut old, _)) = g.take() {
            tokio::spawn(async move {
                let _ = old.unbind().await;
            });
        }
        let tls = st.tls_for(&self.profile.id)?;
        let (mut l, _url) = conn::connect(&self.profile, &tls).await?;
        let timeout = Duration::from_secs(self.profile.timeout_secs.max(2));
        conn::simple_bind(&mut l, &self.bind_dn, &self.password, timeout).await.map_err(|e| {
            if e.is_ldap(49) {
                AppError::new(
                    axum::http::StatusCode::UNAUTHORIZED,
                    "vos identifiants ne sont plus acceptés par l'annuaire (mot de passe changé ?) — reconnectez-vous",
                )
            } else {
                e
            }
        })?;
        *g = Some((l.clone(), Instant::now()));
        Ok(Dir { ldap: l, info: self.info.clone(), profile: self.profile.clone() })
    }

    pub fn touch(&self) {
        *self.last_seen.lock().unwrap() = Instant::now();
    }

    pub fn is_advanced(&self) -> bool {
        self.advanced.load(Ordering::Relaxed)
    }

    pub fn set_advanced(&self, v: bool) {
        self.advanced.store(v, Ordering::Relaxed)
    }

    pub fn add_download(&self, filename: String, mime: &str, data: Vec<u8>) -> String {
        let token = random_token(24);
        let mut g = self.downloads.lock().unwrap();
        g.retain(|_, d| d.created.elapsed() < Duration::from_secs(600));
        g.insert(
            token.clone(),
            Download { filename, mime: mime.into(), data: Zeroizing::new(data), created: Instant::now() },
        );
        token
    }

    /// Téléchargement à usage unique.
    pub fn take_download(&self, token: &str) -> Option<Download> {
        let mut g = self.downloads.lock().unwrap();
        g.remove(token).filter(|d| d.created.elapsed() < Duration::from_secs(600))
    }

    pub async fn close(&self) {
        if let Some((mut l, _)) = self.ldap.lock().await.take() {
            let _ = l.unbind().await;
        }
    }
}

pub struct SessionStore {
    map: RwLock<HashMap<String, Arc<Session>>>,
    idle: Duration,
    max: Duration,
}

impl SessionStore {
    pub fn new(sec: &SecurityConfig) -> Self {
        SessionStore {
            map: RwLock::new(HashMap::new()),
            idle: Duration::from_secs(sec.session_idle_minutes.max(1) * 60),
            max: Duration::from_secs(sec.session_max_hours.max(1) * 3600),
        }
    }

    pub fn create(&self, n: NewSession) -> Arc<Session> {
        let s = Arc::new(Session {
            id: random_token(32),
            csrf: random_token(32),
            profile: n.profile,
            info: n.info,
            login: n.login,
            bind_dn: n.bind_dn,
            user_dn: n.user_dn,
            display: n.display,
            password: n.password,
            ldap: tokio::sync::Mutex::new(Some((n.ldap, Instant::now()))),
            created: Instant::now(),
            last_seen: Mutex::new(Instant::now()),
            advanced: AtomicBool::new(false),
            downloads: Mutex::new(HashMap::new()),
        });
        self.map.write().unwrap().insert(s.id.clone(), s.clone());
        s
    }

    pub fn get(&self, id: &str) -> Option<Arc<Session>> {
        let s = self.map.read().unwrap().get(id).cloned()?;
        let idle = s.last_seen.lock().unwrap().elapsed();
        if idle > self.idle || s.created.elapsed() > self.max {
            self.remove(id);
            return None;
        }
        Some(s)
    }

    pub fn remove(&self, id: &str) -> Option<Arc<Session>> {
        let s = self.map.write().unwrap().remove(id);
        if let Some(sess) = &s {
            let sess = sess.clone();
            tokio::spawn(async move { sess.close().await });
        }
        s
    }

    pub fn count(&self) -> usize {
        self.map.read().unwrap().len()
    }

    /// Purge périodique des sessions expirées.
    pub fn spawn_reaper(self: &Arc<Self>) {
        let me = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                let expired: Vec<String> = {
                    let g = me.map.read().unwrap();
                    g.iter()
                        .filter(|(_, s)| {
                            s.last_seen.lock().unwrap().elapsed() > me.idle || s.created.elapsed() > me.max
                        })
                        .map(|(k, _)| k.clone())
                        .collect()
                };
                for id in expired {
                    me.remove(&id);
                }
            }
        });
    }
}
