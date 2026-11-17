//! Couche web : routes, intergiciels de sécurité, ressources statiques embarquées.

pub mod auth;
pub mod form;
pub mod html;
pub mod pages;
pub mod session;

use crate::state::AppState;
use axum::Router;
use axum::extract::{Path, Request};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use rust_embed::RustEmbed;
use tower_http::compression::CompressionLayer;
use tower_http::limit::RequestBodyLimitLayer;

#[derive(RustEmbed)]
#[folder = "static/"]
struct Assets;

async fn static_file(Path(path): Path<String>) -> Response {
    match Assets::get(&path) {
        Some(f) => {
            let mime = mime_guess::from_path(&path).first_or_octet_stream();
            let etag = format!("\"{}\"", hex::encode(&f.metadata.sha256_hash()[..12]));
            (
                [
                    (header::CONTENT_TYPE, mime.as_ref().to_string()),
                    (header::CACHE_CONTROL, "public, max-age=3600".to_string()),
                    (header::ETAG, etag),
                ],
                f.data,
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// En-têtes de sécurité et vérification d'origine pour les requêtes modifiantes.
async fn security(req: Request, next: Next) -> Response {
    let mutating = !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if mutating {
        if let Some(origin) = req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
            // HTTP/1.1 : en-tête Host ; HTTP/2 : pseudo-en-tête :authority (porté par l'URI).
            let host = req
                .headers()
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(String::from)
                .or_else(|| req.uri().authority().map(|a| a.to_string()))
                .unwrap_or_default();
            let host = host.as_str();
            let o_host = origin.split("://").nth(1).unwrap_or("");
            if origin != "null" && !o_host.eq_ignore_ascii_case(host) {
                tracing::warn!("requête refusée : origine {origin} ≠ hôte {host}");
                return (StatusCode::FORBIDDEN, "origine non autorisée").into_response();
            }
        }
    }
    let is_static = req.uri().path().starts_with("/static/");
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; \
             frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none'",
        ),
    );
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert("cross-origin-opener-policy", HeaderValue::from_static("same-origin"));
    if !is_static && !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    resp
}

async fn hsts(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    resp.headers_mut().insert(header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=31536000"));
    resp
}

pub fn router(st: AppState) -> Router {
    use pages::*;
    let tls = st.secure_cookies;
    let r = Router::new()
        .route("/", get(|| async { Redirect::to("/dashboard") }))
        .route("/login", get(auth::login_form).post(auth::login_submit))
        .route("/logout", post(auth::logout))
        .route("/prefs/advanced", post(auth::toggle_advanced))
        .route("/static/{*path}", get(static_file))
        // Tableau de bord
        .route("/dashboard", get(dashboard::page))
        .route("/dashboard/stats", get(dashboard::stats))
        .route("/dashboard/health", get(dashboard::health))
        // Utilisateurs et ordinateurs
        .route("/dir", get(directory::page))
        .route("/dir/tree", get(directory::tree))
        .route("/dir/list", get(directory::list))
        .route("/browse", get(directory::browse))
        .route("/browse/tree", get(directory::browse_tree))
        .route("/obj", get(objects::page))
        .route("/obj/props", get(objects::props_modal))
        .route("/obj/tab", get(objects::tab).post(objects::tab_save))
        .route("/obj/new", get(objects::new_form).post(objects::new_submit))
        .route("/obj/password", get(objects::password_form).post(objects::password_submit))
        .route("/obj/state", post(objects::set_state))
        .route("/obj/move", get(objects::move_form).post(objects::move_submit))
        .route("/obj/rename", get(objects::rename_form).post(objects::rename_submit))
        .route("/obj/delete", get(objects::delete_form).post(objects::delete_submit))
        .route("/obj/members", post(objects::members_change))
        .route("/obj/memberof", post(objects::memberof_change))
        .route("/obj/account", post(objects::account_save))
        .route("/obj/laps/expire", post(objects::laps_expire))
        .route("/pick", get(objects::pick_dialog))
        .route("/pick/search", get(objects::pick_search))
        .route("/pick/containers", get(objects::pick_containers))
        // Éditeur d'attributs
        .route("/attrs/edit", get(attrs::edit_form).post(attrs::edit_submit))
        .route("/attrs/delete", post(attrs::delete_attr))
        .route("/attrs/download", get(attrs::download_value))
        // Recherche
        .route("/search", get(search::page))
        .route("/search/results", get(search::results))
        .route("/search/export.csv", get(search::export_csv))
        // DNS
        .route("/dns", get(dns::page))
        .route("/dns/zone", get(dns::zone))
        .route("/dns/record/new", get(dns::record_form).post(dns::record_add))
        .route("/dns/record/edit", get(dns::record_edit_form).post(dns::record_edit))
        .route("/dns/record/delete", post(dns::record_delete))
        .route("/dns/zone/new", get(dns::zone_form).post(dns::zone_add))
        .route("/dns/zone/delete", post(dns::zone_delete))
        .route("/dns/stale", get(dns::stale))
        // DHCP
        .route("/dhcp", get(dhcp::page))
        .route("/dhcp/server", get(dhcp::server))
        .route("/dhcp/subnet", get(dhcp::subnet))
        .route("/dhcp/reservation/new", get(dhcp::reservation_form).post(dhcp::reservation_add))
        .route("/dhcp/reservation/delete", post(dhcp::reservation_delete))
        .route("/dhcp/lease/delete", post(dhcp::lease_delete))
        // GPO
        .route("/gpo", get(gpo::page))
        .route("/gpo/view", get(gpo::view))
        .route("/gpo/new", get(gpo::new_form).post(gpo::new_submit))
        .route("/gpo/delete", post(gpo::delete))
        .route("/gpo/update", post(gpo::update))
        .route("/gpo/link", get(gpo::link_form).post(gpo::link_add))
        .route("/gpo/link/update", post(gpo::link_update))
        .route("/gpo/inheritance", post(gpo::block_inheritance))
        .route("/gpo/container", get(gpo::container))
        // Kerberos
        .route("/kerberos", get(kerberos::page))
        .route("/kerberos/spn", get(kerberos::spn_search))
        .route("/kerberos/spn/change", post(kerberos::spn_change))
        .route("/kerberos/settings", post(kerberos::settings_save))
        .route("/kerberos/keytab", get(kerberos::keytab_form).post(kerberos::keytab_submit))
        .route("/download/{token}", get(kerberos::download))
        // PKI
        .route("/pki", get(pki::page))
        .route("/pki/probe", get(pki::probe))
        .route("/pki/expiring", get(pki::expiring))
        .route("/pki/cert", get(pki::cert_view))
        .route("/obj/cert/add", post(pki::cert_add))
        .route("/obj/cert/remove", post(pki::cert_remove))
        // Domaine
        .route("/sites", get(domain::sites))
        .route("/sites/subnet", get(domain::subnet_form).post(domain::subnet_add))
        .route("/sites/subnet/delete", post(domain::subnet_delete))
        .route("/trusts", get(domain::trusts))
        .route("/policies", get(domain::policies))
        .route("/policies/domain", post(domain::domain_policy_save))
        .route("/policies/pso", get(domain::pso_form).post(domain::pso_save))
        .route("/policies/pso/delete", post(domain::pso_delete))
        .route("/policies/ppolicy", get(domain::ppolicy_form).post(domain::ppolicy_save))
        .route("/recycle", get(domain::recycle))
        .route("/recycle/restore", post(domain::recycle_restore))
        .route("/schema", get(domain::schema_page))
        .route("/audit", get(domain::audit_page))
        .layer(middleware::from_fn(security))
        .layer(RequestBodyLimitLayer::new(8 * 1024 * 1024))
        .layer(CompressionLayer::new())
        .with_state(st);
    if tls { r.layer(middleware::from_fn(hsts)) } else { r }
}
