//! Aides au rendu : échappement HTML, réponses htmx (notifications, rafraîchissements),
//! rendu des templates askama.

use crate::error::AppResult;
use askama::Template;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use serde_json::{Map, Value, json};

pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            _ => o.push(c),
        }
    }
    o
}

/// Encodage pour paramètre d'URL.
pub fn url(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

/// JSON limité à l'ASCII (les en-têtes HTTP sont décodés en Latin-1 par les navigateurs).
pub fn ascii_json(v: &Value) -> String {
    let s = v.to_string();
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            let mut buf = [0u16; 2];
            for u in c.encode_utf16(&mut buf) {
                out.push_str(&format!("\\u{:04x}", u));
            }
        }
    }
    out
}

pub fn render<T: Template>(t: &T) -> AppResult<Response> {
    Ok(Html(t.render()?).into_response())
}

/// Réponse htmx avec déclencheurs d'événements côté client.
#[derive(Default)]
pub struct Hx {
    triggers: Map<String, Value>,
    redirect: Option<String>,
    refresh: bool,
    retarget: Option<String>,
    reswap: Option<String>,
    status: Option<StatusCode>,
}

impl Hx {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn ok(msg: impl Into<String>) -> Self {
        Self::new().toast("ok", msg)
    }
    pub fn warn(msg: impl Into<String>) -> Self {
        Self::new().toast("warn", msg)
    }
    pub fn toast(mut self, level: &str, msg: impl Into<String>) -> Self {
        self.triggers.insert("toast".into(), json!({"level": level, "msg": msg.into()}));
        self
    }
    pub fn trigger(mut self, ev: &str) -> Self {
        self.triggers.insert(ev.into(), Value::Bool(true));
        self
    }
    /// Ferme la boîte de dialogue modale.
    pub fn close_modal(self) -> Self {
        self.trigger("close-modal")
    }
    /// Rafraîchit la liste d'objets et l'arborescence.
    pub fn refresh_list(self) -> Self {
        self.trigger("refresh-list")
    }
    pub fn redirect(mut self, url: impl Into<String>) -> Self {
        self.redirect = Some(url.into());
        self
    }
    pub fn refresh_page(mut self) -> Self {
        self.refresh = true;
        self
    }

    pub fn body(self, html: impl Into<String>) -> Response {
        let mut r = Html(html.into()).into_response();
        if let Some(s) = self.status {
            *r.status_mut() = s;
        }
        let h = r.headers_mut();
        if !self.triggers.is_empty() {
            if let Ok(v) = HeaderValue::from_str(&ascii_json(&Value::Object(self.triggers))) {
                h.insert(HeaderName::from_static("hx-trigger"), v);
            }
        }
        if let Some(u) = self.redirect {
            if let Ok(v) = HeaderValue::from_str(&u) {
                h.insert(HeaderName::from_static("hx-redirect"), v);
            }
        }
        if self.refresh {
            h.insert(HeaderName::from_static("hx-refresh"), HeaderValue::from_static("true"));
        }
        if let Some(t) = self.retarget {
            if let Ok(v) = HeaderValue::from_str(&t) {
                h.insert(HeaderName::from_static("hx-retarget"), v);
            }
        }
        if let Some(t) = self.reswap {
            if let Ok(v) = HeaderValue::from_str(&t) {
                h.insert(HeaderName::from_static("hx-reswap"), v);
            }
        }
        r
    }

    pub fn empty(self) -> Response {
        self.body(String::new())
    }
}

// ------------------------------------------------------------------ petits constructeurs HTML
// (les cellules passées à `table` doivent déjà être échappées)

pub fn icon(name: &str) -> String {
    format!("<svg class=\"i\" aria-hidden=\"true\"><use href=\"/static/icons.svg#{name}\"></use></svg>")
}

pub fn kicon(name: &str) -> String {
    format!(
        "<svg class=\"i kind-icon {name}\" aria-hidden=\"true\"><use href=\"/static/icons.svg#{name}\"></use></svg>"
    )
}

pub fn badge(level: &str, text: &str) -> String {
    format!("<span class=\"badge {level}\">{}</span>", esc(text))
}

pub fn table(headers: &[&str], rows: &[Vec<String>], empty: &str) -> String {
    let mut s = String::from("<div class=\"table-wrap\"><table class=\"grid compact\"><thead><tr>");
    for h in headers {
        s.push_str(&format!("<th>{}</th>", esc(h)));
    }
    s.push_str("</tr></thead><tbody>");
    for r in rows {
        s.push_str("<tr>");
        for c in r {
            s.push_str(&format!("<td>{c}</td>"));
        }
        s.push_str("</tr>");
    }
    s.push_str("</tbody></table>");
    if rows.is_empty() && !empty.is_empty() {
        s.push_str(&format!("<div class=\"empty\">{}</div>", esc(empty)));
    }
    s.push_str("</div>");
    s
}

pub fn kv(rows: &[(String, String)]) -> String {
    let mut s = String::from("<dl class=\"kv\">");
    for (k, v) in rows {
        s.push_str(&format!("<dt>{}</dt><dd>{}</dd>", esc(k), esc(v)));
    }
    s.push_str("</dl>");
    s
}

/// Bouton ouvrant un dialogue (GET → #modal).
pub fn btn_dialog(label: &str, icon_name: &str, href: &str, class: &str) -> String {
    format!(
        "<button class=\"btn-sm {class}\" hx-get=\"{}\" hx-target=\"#modal\">{} {}</button>",
        esc(href),
        icon(icon_name),
        esc(label)
    )
}

/// Bouton d'action (POST, confirmation optionnelle).
pub fn btn_post(label: &str, icon_name: &str, href: &str, confirm: &str, class: &str) -> String {
    let c = if confirm.is_empty() { String::new() } else { format!(" hx-confirm=\"{}\"", esc(confirm)) };
    let ic = if icon_name.is_empty() { String::new() } else { icon(icon_name) };
    let title = if label.is_empty() { String::new() } else { format!(" title=\"{}\"", esc(label)) };
    format!(
        "<button class=\"btn-sm {class}\" hx-post=\"{}\" hx-swap=\"none\"{c}{title}>{ic} {}</button>",
        esc(href),
        esc(label)
    )
}
