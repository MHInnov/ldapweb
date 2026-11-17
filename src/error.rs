//! Gestion des erreurs : conversion des erreurs LDAP en messages lisibles (en français),
//! rendu HTML pour la navigation classique et en-tête dédié pour les requêtes htmx.

use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use ldap3::LdapError;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug)]
pub struct AppError {
    pub status: StatusCode,
    pub message: String,
    /// Code de retour LDAP éventuel.
    pub ldap_rc: Option<u32>,
}

impl AppError {
    pub fn new(status: StatusCode, msg: impl Into<String>) -> Self {
        Self { status, message: msg.into(), ldap_rc: None }
    }
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, msg)
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, msg)
    }
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, msg)
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, msg)
    }
    pub fn unavailable(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, msg)
    }
    pub fn is_ldap(&self, rc: u32) -> bool {
        self.ldap_rc == Some(rc)
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AppError {}

/// Libellé français des codes de résultat LDAP (RFC 4511).
pub fn ldap_rc_label(rc: u32) -> &'static str {
    match rc {
        0 => "succès",
        1 => "erreur d'opération",
        2 => "erreur de protocole",
        3 => "délai dépassé",
        4 => "limite de taille dépassée",
        7 => "méthode d'authentification non supportée",
        8 => "authentification plus forte requise (utilisez LDAPS ou StartTLS)",
        10 => "référence vers un autre serveur",
        11 => "limite administrative dépassée",
        12 => "extension critique non disponible",
        13 => "confidentialité requise (connexion chiffrée nécessaire)",
        16 => "attribut inexistant",
        17 => "type d'attribut inconnu du schéma",
        18 => "règle de correspondance inappropriée",
        19 => "violation de contrainte",
        20 => "l'attribut ou la valeur existe déjà",
        21 => "syntaxe de valeur invalide",
        32 => "objet introuvable",
        33 => "problème d'alias",
        34 => "syntaxe de DN invalide",
        48 => "authentification inappropriée",
        49 => "identifiants invalides",
        50 => "droits d'accès insuffisants",
        51 => "serveur occupé",
        52 => "serveur indisponible",
        53 => "le serveur refuse d'effectuer l'opération",
        54 => "boucle détectée",
        64 => "violation de nommage",
        65 => "violation de classe d'objet (attribut obligatoire manquant ou non autorisé)",
        66 => "opération interdite sur un objet non terminal (il contient des objets)",
        67 => "opération interdite sur le RDN",
        68 => "l'objet existe déjà",
        69 => "modification de classe d'objet interdite",
        71 => "affecte plusieurs agents DSA",
        80 => "erreur inconnue",
        _ => "erreur LDAP",
    }
}

/// Décode les sous-codes Active Directory (« data 52e », « 0000052D »...).
pub fn ad_diagnostic(text: &str) -> Option<&'static str> {
    let lower = text.to_ascii_lowercase();
    let data = lower.split("data ").nth(1).map(|s| s.split([',', ' ']).next().unwrap_or(""));
    if let Some(code) = data {
        let msg = match code {
            "525" => Some("utilisateur introuvable"),
            "52e" => Some("nom d'utilisateur ou mot de passe incorrect"),
            "530" => Some("connexion non autorisée à cette heure"),
            "531" => Some("connexion non autorisée depuis ce poste"),
            "532" => Some("le mot de passe a expiré"),
            "533" => Some("le compte est désactivé"),
            "568" => Some("trop de SID dans le jeton (appartenance à trop de groupes)"),
            "701" => Some("le compte a expiré"),
            "773" => Some("l'utilisateur doit changer son mot de passe"),
            "775" => Some("le compte est verrouillé"),
            _ => None,
        };
        if msg.is_some() {
            return msg;
        }
    }
    if lower.starts_with("0000052d")
        || lower.contains("check_password_restrictions")
        || lower.contains("password_restrictions")
    {
        return Some("le mot de passe ne respecte pas la stratégie (longueur, complexité, historique ou âge minimal)");
    }
    if lower.starts_with("00002098") || lower.contains("insufficient access") {
        return Some("droits insuffisants sur cet objet");
    }
    if lower.starts_with("00000005") {
        return Some("accès refusé");
    }
    if lower.starts_with("00002071") {
        return Some("un objet portant ce nom existe déjà");
    }
    if lower.starts_with("00000523") || lower.contains("samaccountname") && lower.contains("already") {
        return Some("le nom de connexion (sAMAccountName) est déjà utilisé");
    }
    if lower.contains("can only be modified as system") {
        return Some(
            "attribut réservé au système sur ce serveur (fonctionnalité non prise en charge par cette version de l'annuaire)",
        );
    }
    if lower.starts_with("00002024") || lower.contains("not allowed on non-leaf") {
        return Some("l'objet contient des objets enfants");
    }
    None
}

pub fn ldap_result_message(rc: u32, text: &str) -> String {
    let base = ldap_rc_label(rc);
    let detail = text.trim().trim_end_matches('\0').trim();
    match ad_diagnostic(detail) {
        Some(hint) => format!("{base} : {hint} [code {rc}] — {detail}"),
        None if detail.is_empty() => format!("{base} [code {rc}]"),
        None => format!("{base} [code {rc}] — {detail}"),
    }
}

impl From<LdapError> for AppError {
    fn from(e: LdapError) -> Self {
        match e {
            LdapError::LdapResult { result } => {
                let status = match result.rc {
                    32 => StatusCode::NOT_FOUND,
                    49 | 48 => StatusCode::UNAUTHORIZED,
                    50 => StatusCode::FORBIDDEN,
                    51 | 52 => StatusCode::SERVICE_UNAVAILABLE,
                    _ => StatusCode::UNPROCESSABLE_ENTITY,
                };
                AppError { status, message: ldap_result_message(result.rc, &result.text), ldap_rc: Some(result.rc) }
            }
            LdapError::Timeout { .. } => AppError::unavailable("délai de réponse du serveur LDAP dépassé"),
            LdapError::Io { source } => {
                AppError::unavailable(format!("connexion au serveur LDAP impossible : {source}"))
            }
            other => AppError::unavailable(format!("erreur de communication LDAP : {other}")),
        }
    }
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        AppError::internal(format!("{e:#}"))
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::internal(format!("erreur d'entrée/sortie : {e}"))
    }
}

impl From<askama::Error> for AppError {
    fn from(e: askama::Error) -> Self {
        AppError::internal(format!("erreur de rendu : {e}"))
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if self.status.is_server_error() {
            tracing::error!(status = %self.status, "{}", self.message);
        } else {
            tracing::debug!(status = %self.status, "{}", self.message);
        }
        let body = format!(
            "<!doctype html><html lang=\"fr\"><head><meta charset=\"utf-8\"><title>Erreur</title>\
             <link rel=\"stylesheet\" href=\"/static/app.css\"></head><body class=\"error-page\">\
             <main class=\"error-box\"><h1>Erreur {}</h1><p>{}</p><p><a href=\"javascript:history.back()\">← Retour</a> · \
             <a href=\"/\">Accueil</a></p></main></body></html>",
            self.status.as_u16(),
            crate::web::html::esc(&self.message)
        );
        let mut resp = (self.status, axum::response::Html(body)).into_response();
        // Lu par app.js pour afficher une notification lors des requêtes htmx.
        let enc = percent_encoding::utf8_percent_encode(&self.message, percent_encoding::NON_ALPHANUMERIC).to_string();
        if let Ok(v) = HeaderValue::from_str(&enc) {
            resp.headers_mut().insert("X-Error-Message", v);
        }
        resp
    }
}
