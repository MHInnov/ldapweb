//! Données de formulaire avec clés répétées (cases à cocher multiples, listes).

use axum::Form;
use axum::extract::{FromRequest, Request};

#[derive(Debug, Default, Clone)]
pub struct FormData(pub Vec<(String, String)>);

impl FormData {
    pub fn get(&self, k: &str) -> Option<&str> {
        self.0.iter().find(|(a, _)| a == k).map(|(_, v)| v.as_str())
    }
    /// Valeur nettoyée (espaces retirés) ou chaîne vide.
    pub fn s(&self, k: &str) -> String {
        self.get(k).map(|v| v.trim().to_string()).unwrap_or_default()
    }
    /// Valeur brute (mots de passe : ne pas modifier les espaces).
    pub fn raw(&self, k: &str) -> String {
        self.get(k).map(|v| v.to_string()).unwrap_or_default()
    }
    pub fn opt(&self, k: &str) -> Option<String> {
        self.get(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
    }
    pub fn all(&self, k: &str) -> Vec<String> {
        self.0.iter().filter(|(a, _)| a == k).map(|(_, v)| v.trim().to_string()).filter(|v| !v.is_empty()).collect()
    }
    pub fn checked(&self, k: &str) -> bool {
        matches!(self.get(k), Some("on") | Some("1") | Some("true") | Some("yes"))
    }
    pub fn int(&self, k: &str) -> Option<i64> {
        self.get(k).and_then(|v| v.trim().parse().ok())
    }
    /// Valeurs d'un champ multi-lignes (une valeur par ligne).
    pub fn lines(&self, k: &str) -> Vec<String> {
        self.get(k)
            .map(|v| v.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect())
            .unwrap_or_default()
    }
}

impl<S: Send + Sync> FromRequest<S> for FormData {
    type Rejection = crate::error::AppError;
    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let is_form = req
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.starts_with("application/x-www-form-urlencoded"))
            .unwrap_or(false);
        if !is_form {
            // Requête sans corps (bouton htmx sans champ) : formulaire vide.
            let bytes = axum::body::Bytes::from_request(req, state)
                .await
                .map_err(|e| crate::error::AppError::bad_request(format!("requête invalide : {e}")))?;
            if bytes.iter().all(|b| b.is_ascii_whitespace()) {
                return Ok(FormData::default());
            }
            let v: Vec<(String, String)> = serde_urlencoded_parse(&bytes);
            return Ok(FormData(v));
        }
        let Form(v) = Form::<Vec<(String, String)>>::from_request(req, state)
            .await
            .map_err(|e| crate::error::AppError::bad_request(format!("formulaire invalide : {e}")))?;
        Ok(FormData(v))
    }
}

fn serde_urlencoded_parse(b: &[u8]) -> Vec<(String, String)> {
    String::from_utf8_lossy(b)
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            let dec =
                |s: &str| percent_encoding::percent_decode_str(&s.replace('+', " ")).decode_utf8_lossy().into_owned();
            (dec(k), dec(v))
        })
        .collect()
}
