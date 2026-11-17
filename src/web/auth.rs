//! Authentification : connexion par bind LDAP avec les identifiants de l'utilisateur,
//! extracteur `Auth` (session + jeton anti-CSRF), contexte commun des pages.

use super::form::FormData;
use super::html::Hx;
use super::session::{COOKIE, NewSession, Session};
use crate::audit::Audit;
use crate::error::{AppError, AppResult};
use crate::ldap::{Dir, conn, flavor};
use crate::state::AppState;
use askama::Template;
use axum::extract::{ConnectInfo, FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use ldap3::Scope;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get_all(header::COOKIE).iter().filter_map(|v| v.to_str().ok()).find_map(|c| {
        c.split(';').find_map(|kv| {
            let (k, v) = kv.trim().split_once('=')?;
            (k == name).then(|| v.to_string())
        })
    })
}

pub fn client_ip(parts: &Parts, st: &AppState) -> IpAddr {
    if st.cfg.server.trust_proxy_headers {
        if let Some(ip) = parts
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|v| v.trim().parse().ok())
        {
            return ip;
        }
    }
    parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip()).unwrap_or(IpAddr::from([127, 0, 0, 1]))
}

fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Contexte commun à toutes les pages (barre supérieure, navigation).
pub struct Ctx {
    pub app_title: String,
    pub user: String,
    pub profile_name: String,
    pub flavor: &'static str,
    pub flavor_short: &'static str,
    pub server: String,
    pub csrf: String,
    pub nav: &'static str,
    pub is_ad: bool,
    pub has_dns: bool,
    pub has_dhcp: bool,
    pub advanced: bool,
    pub version: &'static str,
}

pub struct Auth {
    pub s: Arc<Session>,
    pub st: AppState,
    pub ip: String,
}

impl Auth {
    pub async fn dir(&self) -> AppResult<Dir> {
        self.s.dir(&self.st).await
    }

    pub fn is_ad(&self) -> bool {
        self.s.info.flavor.is_ad()
    }

    pub fn ctx(&self, nav: &'static str) -> Ctx {
        let info = &self.s.info;
        Ctx {
            app_title: self.st.cfg.server.title.clone(),
            user: self.s.display.clone(),
            profile_name: self.s.profile.name.clone(),
            flavor: info.flavor.label(),
            flavor_short: info.flavor.short(),
            server: info.host(),
            csrf: self.s.csrf.clone(),
            nav,
            is_ad: info.flavor.is_ad(),
            has_dns: crate::services::dns::provider_kind(&self.s.profile, info).is_some(),
            has_dhcp: !self.s.profile.dhcp.is_empty(),
            advanced: self.s.is_advanced(),
            version: env!("CARGO_PKG_VERSION"),
        }
    }

    /// Consigne une action dans le journal d'audit.
    pub fn audit(&self, action: &str, target: &str, ok: bool, detail: &str) {
        self.st.audit.record(Audit::event(&self.s.login, &self.s.profile.id, &self.ip, action, target, ok, detail));
    }

    /// Consigne le résultat d'une opération et le renvoie.
    pub fn audited<T>(&self, action: &str, target: &str, detail: &str, r: AppResult<T>) -> AppResult<T> {
        match &r {
            Ok(_) => self.audit(action, target, true, detail),
            Err(e) => self.audit(action, target, false, &format!("{detail} — {}", e.message)),
        }
        r
    }
}

fn login_redirect(parts: &Parts) -> Response {
    if parts.headers.contains_key("hx-request") {
        Hx::new().redirect("/login").empty()
    } else {
        Redirect::to("/login").into_response()
    }
}

impl FromRequestParts<AppState> for Auth {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, Self::Rejection> {
        let Some(sid) = cookie_value(&parts.headers, COOKIE) else { return Err(login_redirect(parts)) };
        let Some(s) = st.sessions.get(&sid) else { return Err(login_redirect(parts)) };
        if parts.method != Method::GET && parts.method != Method::HEAD {
            let tok = parts.headers.get("x-csrf-token").and_then(|v| v.to_str().ok()).unwrap_or("");
            if !ct_eq(tok, &s.csrf) {
                return Err(
                    AppError::forbidden("jeton anti-CSRF invalide ou absent — rechargez la page").into_response()
                );
            }
        }
        s.touch();
        let ip = client_ip(parts, st).to_string();
        Ok(Auth { s, st: st.clone(), ip })
    }
}

// ------------------------------------------------------------------ pages

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTpl {
    title: String,
    profiles: Vec<(String, String)>,
    selected: String,
    username: String,
    error: String,
    version: &'static str,
}

fn login_page(st: &AppState, selected: &str, username: &str, error: &str, status: StatusCode) -> Response {
    let t = LoginTpl {
        title: st.cfg.server.title.clone(),
        profiles: st.profiles.iter().map(|p| (p.id.clone(), p.name.clone())).collect(),
        selected: selected.to_string(),
        username: username.to_string(),
        error: error.to_string(),
        version: env!("CARGO_PKG_VERSION"),
    };
    match t.render() {
        Ok(h) => (status, Html(h)).into_response(),
        Err(e) => AppError::from(e).into_response(),
    }
}

pub async fn login_form(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(sid) = cookie_value(&headers, COOKIE) {
        if st.sessions.get(&sid).is_some() {
            return Redirect::to("/dashboard").into_response();
        }
    }
    let first = st.profiles.first().map(|p| p.id.clone()).unwrap_or_default();
    login_page(&st, &first, "", "", StatusCode::OK)
}

fn set_cookie(st: &AppState, value: &str, clear: bool) -> HeaderValue {
    let secure = if st.secure_cookies { "; Secure" } else { "" };
    let s = if clear {
        format!("{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure}")
    } else {
        format!("{COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict{secure}")
    };
    HeaderValue::from_str(&s).unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// Nom de bind AD : UPN, DOMAINE\utilisateur ou DN acceptés tels quels.
fn ad_bind_name(user: &str, profile_suffix: Option<&str>, domain: &str) -> String {
    if user.contains('@') || user.contains('\\') || user.contains('=') {
        return user.to_string();
    }
    let suffix = profile_suffix.unwrap_or(domain);
    format!("{user}@{suffix}")
}

pub async fn login_submit(
    State(st): State<AppState>,
    ci: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    f: FormData,
) -> Response {
    let ip = if st.cfg.server.trust_proxy_headers {
        headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(ci.0.ip())
    } else {
        ci.0.ip()
    };
    let profile_id = f.s("profile");
    let username = f.s("username");
    let password = Zeroizing::new(f.raw("password"));
    if st.login_blocked(ip) {
        return login_page(
            &st,
            &profile_id,
            &username,
            "Trop de tentatives échouées depuis votre adresse. Réessayez dans quelques minutes.",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    match do_login(&st, &profile_id, &username, &password).await {
        Ok(n) => {
            st.login_succeeded(ip);
            let s = st.sessions.create(n);
            st.audit.record(Audit::event(&s.login, &s.profile.id, &ip.to_string(), "connexion", &s.user_dn, true, ""));
            let mut r = Redirect::to("/dashboard").into_response();
            r.headers_mut().insert(header::SET_COOKIE, set_cookie(&st, &s.id, false));
            r
        }
        Err(e) => {
            st.login_failed(ip);
            st.audit.record(Audit::event(&username, &profile_id, &ip.to_string(), "connexion", "", false, &e.message));
            tracing::warn!("échec de connexion de {username} depuis {ip} : {}", e.message);
            login_page(&st, &profile_id, &username, &e.message, StatusCode::UNAUTHORIZED)
        }
    }
}

async fn do_login(st: &AppState, profile_id: &str, username: &str, password: &str) -> AppResult<NewSession> {
    if username.is_empty() || password.is_empty() {
        return Err(AppError::bad_request("identifiant et mot de passe requis"));
    }
    let profile = st.profile(profile_id).ok_or_else(|| AppError::bad_request("annuaire inconnu"))?;
    let tls = st.tls_for(&profile.id)?;
    let timeout = Duration::from_secs(profile.timeout_secs.max(2));
    let (mut ldap, url) = conn::connect(&profile, &tls).await?;
    let root = flavor::read_root_dse(&mut ldap, timeout).await.unwrap_or_default();
    let mut info = flavor::initial_info(&root, &profile, &url);
    let forced = profile.flavor != crate::config::FlavorSetting::Auto;

    // Détermination du nom de bind
    let bind_dn = if info.flavor.is_ad() {
        ad_bind_name(username, profile.login.default_upn_suffix.as_deref(), &info.domain_dns)
    } else if username.contains('=') {
        username.to_string()
    } else {
        if let (Some(dn), Some(pw)) = (&profile.login.lookup_bind_dn, &profile.login.lookup_bind_password) {
            conn::simple_bind(&mut ldap, dn, pw, timeout)
                .await
                .map_err(|e| AppError::internal(format!("compte de recherche ({dn}) refusé : {}", e.message)))?;
        }
        let filter_tpl =
            profile.login.user_filter.clone().unwrap_or_else(|| "(|(uid={user})(cn={user})(mail={user}))".into());
        let filter = filter_tpl.replace("{user}", &crate::ldap::codec::filter_escape(username));
        let base = profile.login.user_search_base.clone().unwrap_or_else(|| info.base_dn.clone());
        let res = ldap.with_timeout(timeout).search(&base, Scope::Subtree, &filter, vec!["1.1"]).await?;
        let (entries, _) = res.non_error()?;
        let dns: Vec<String> = entries.into_iter().filter_map(crate::ldap::Entry::from_result).map(|e| e.dn).collect();
        match dns.len() {
            0 => return Err(AppError::new(StatusCode::UNAUTHORIZED, "identifiants invalides")),
            1 => dns[0].clone(),
            _ => {
                return Err(AppError::new(
                    StatusCode::UNAUTHORIZED,
                    "identifiant ambigu (plusieurs comptes correspondent)",
                ));
            }
        }
    };

    conn::simple_bind(&mut ldap, &bind_dn, password, timeout).await.map_err(|e| {
        if e.is_ldap(49) {
            let hint = crate::error::ad_diagnostic(&e.message).unwrap_or("identifiants invalides");
            AppError::new(StatusCode::UNAUTHORIZED, format!("Connexion refusée : {hint}"))
        } else if e.is_ldap(8) || e.is_ldap(13) {
            AppError::new(
                StatusCode::UNAUTHORIZED,
                "le serveur exige une connexion chiffrée : utilisez une URL ldaps:// ou activez starttls",
            )
        } else {
            e
        }
    })?;

    let mut dir = Dir { ldap: ldap.clone(), info: Arc::new(info.clone()), profile: profile.clone() };
    flavor::enrich(&mut dir, &mut info, forced).await;
    let info = Arc::new(info);
    dir.info = info.clone();

    // Identité de l'utilisateur connecté
    let (user_dn, display) = if info.flavor.is_ad() {
        let (sam, upn) = if let Some((_, s)) = bind_dn.split_once('\\') {
            (s.to_string(), String::new())
        } else if let Some((s, _)) = bind_dn.split_once('@') {
            (s.to_string(), bind_dn.clone())
        } else {
            (String::new(), String::new())
        };
        let filter = if bind_dn.contains('=') {
            String::new()
        } else {
            format!(
                "(&(objectClass=user)(|(sAMAccountName={})(userPrincipalName={})))",
                crate::ldap::codec::filter_escape(&sam),
                crate::ldap::codec::filter_escape(if upn.is_empty() { "\u{1}" } else { &upn })
            )
        };
        let found = if filter.is_empty() {
            dir.read(&bind_dn, &["displayName", "cn"]).await.ok().flatten()
        } else {
            dir.search(&info.base_dn, Scope::Subtree, &filter, &["displayName", "cn"])
                .await
                .ok()
                .and_then(|v| v.into_iter().next())
        };
        match found {
            Some(e) => {
                let d = e.str("displayName").unwrap_or_else(|| e.s("cn"));
                (e.dn.clone(), d)
            }
            None => (bind_dn.clone(), username.to_string()),
        }
    } else {
        let d = dir
            .read(&bind_dn, &["displayName", "cn", "uid"])
            .await
            .ok()
            .flatten()
            .map(|e| e.str("displayName").or_else(|| e.str("cn")).unwrap_or_else(|| e.s("uid")))
            .unwrap_or_else(|| username.to_string());
        (bind_dn.clone(), d)
    };

    // Restriction à un groupe d'administration
    if let Some(group) = &profile.login.required_group {
        let ok = if info.flavor.is_ad() {
            let f = format!("(memberOf:1.2.840.113556.1.4.1941:={})", crate::ldap::codec::filter_escape(group));
            !dir.search(&user_dn, Scope::Base, &f, &["1.1"]).await.unwrap_or_default().is_empty()
        } else {
            let uid = crate::ldap::dn::rdn_value(&user_dn);
            let f = format!(
                "(|(member={0})(uniqueMember={0})(memberUid={1}))",
                crate::ldap::codec::filter_escape(&user_dn),
                crate::ldap::codec::filter_escape(&uid)
            );
            !dir.search(group, Scope::Base, &f, &["1.1"]).await.unwrap_or_default().is_empty()
        };
        if !ok {
            return Err(AppError::forbidden("votre compte n'est pas autorisé à utiliser cette console"));
        }
    }

    Ok(NewSession {
        profile,
        info,
        login: username.to_string(),
        bind_dn,
        user_dn,
        display: if display.is_empty() { username.to_string() } else { display },
        password: Zeroizing::new(password.to_string()),
        ldap,
    })
}

pub async fn logout(State(st): State<AppState>, a: Auth) -> Response {
    a.audit("déconnexion", &a.s.user_dn, true, "");
    st.sessions.remove(&a.s.id);
    let mut r = Hx::new().redirect("/login").empty();
    r.headers_mut().insert(header::SET_COOKIE, set_cookie(&st, "", true));
    r
}

/// Bascule de l'affichage avancé (objets système, conteneurs masqués).
pub async fn toggle_advanced(a: Auth) -> Response {
    let v = !a.s.is_advanced();
    a.s.set_advanced(v);
    Hx::ok(if v { "Fonctionnalités avancées activées" } else { "Fonctionnalités avancées désactivées" })
        .refresh_page()
        .empty()
}
