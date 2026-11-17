//! Journal d'audit : chaque action d'administration effectuée via l'interface
//! est consignée (JSON Lines) avec l'auteur, l'adresse IP, la cible et le résultat.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub ts: String,
    pub user: String,
    pub directory: String,
    pub ip: String,
    pub action: String,
    pub target: String,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

pub struct Audit {
    path: Option<PathBuf>,
    file: Mutex<Option<std::fs::File>>,
}

impl Audit {
    pub fn new(path: Option<PathBuf>) -> anyhow::Result<Audit> {
        let file = match &path {
            Some(p) => {
                if let Some(parent) = p.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                Some(std::fs::OpenOptions::new().create(true).append(true).open(p)?)
            }
            None => None,
        };
        Ok(Audit { path, file: Mutex::new(file) })
    }

    pub fn enabled(&self) -> bool {
        self.path.is_some()
    }

    pub fn record(&self, ev: AuditEvent) {
        tracing::info!(
            target: "audit",
            user = %ev.user, ip = %ev.ip, action = %ev.action, target_dn = %ev.target, ok = ev.ok, "{}", ev.detail
        );
        if let Ok(mut g) = self.file.lock() {
            if let Some(f) = g.as_mut() {
                if let Ok(line) = serde_json::to_string(&ev) {
                    let _ = writeln!(f, "{line}");
                    let _ = f.flush();
                }
            }
        }
    }

    pub fn event(
        user: &str,
        directory: &str,
        ip: &str,
        action: &str,
        target: &str,
        ok: bool,
        detail: &str,
    ) -> AuditEvent {
        AuditEvent {
            ts: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            user: user.into(),
            directory: directory.into(),
            ip: ip.into(),
            action: action.into(),
            target: target.into(),
            ok,
            detail: detail.into(),
        }
    }

    /// Dernières entrées (lecture de la fin du fichier, 4 Mo max).
    pub fn tail(&self, max: usize) -> Vec<AuditEvent> {
        let Some(p) = &self.path else { return vec![] };
        let Ok(mut f) = std::fs::File::open(p) else { return vec![] };
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        let start = len.saturating_sub(4 * 1024 * 1024);
        if f.seek(SeekFrom::Start(start)).is_err() {
            return vec![];
        }
        let mut buf = String::new();
        let _ = f.read_to_string(&mut buf);
        let mut lines: Vec<&str> = buf.lines().collect();
        if start > 0 && !lines.is_empty() {
            lines.remove(0); // ligne probablement tronquée
        }
        lines.iter().rev().filter_map(|l| serde_json::from_str::<AuditEvent>(l).ok()).take(max).collect()
    }
}
