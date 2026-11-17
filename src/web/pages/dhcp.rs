//! Console DHCP (ISC Kea) : serveurs, étendues, utilisation, réservations, baux.

use super::{DlgForm, Generic};
use crate::error::{AppError, AppResult};
use crate::services::dhcp::{Kea, norm_mac, valid_mac};
use crate::web::auth::Auth;
use crate::web::form::FormData;
use crate::web::html::{Hx, badge, btn_dialog, btn_post, esc, kv, render, table, url};
use axum::extract::Query;
use axum::response::{Html, IntoResponse, Response};
use chrono::{TimeZone, Utc};
use serde::Deserialize;
use serde_json::json;

fn kea(a: &Auth, id: &str) -> AppResult<Kea> {
    let s = a.s.profile.dhcp.iter().find(|k| k.id == id).ok_or_else(|| AppError::not_found("serveur DHCP inconnu"))?;
    Kea::new(s)
}

pub async fn page(a: Auth) -> AppResult<Response> {
    let mut body = String::new();
    if a.s.profile.dhcp.is_empty() {
        body.push_str(
            "<div class=\"notice\">Aucun serveur DHCP configuré (section <code>[[directory.dhcp]]</code>).</div>",
        );
    }
    for s in &a.s.profile.dhcp {
        body.push_str(&format!(
            "<section class=\"card\" style=\"margin-bottom:16px\"><h2>{} {} <span class=\"badge\">{}</span></h2><div class=\"small muted mono\" style=\"margin-bottom:10px\">{}</div>\
             <div hx-get=\"/dhcp/server?s={}\" hx-trigger=\"load\"><span class=\"muted\">Interrogation du serveur…</span></div></section>",
            crate::web::html::icon("dhcp"),
            esc(&s.name),
            esc(&s.service.to_uppercase()),
            esc(&s.url),
            url(&s.id)
        ));
    }
    render(&Generic {
        ctx: a.ctx("dhcp"),
        title: "DHCP".into(),
        subtitle: "Serveurs ISC Kea".into(),
        actions: String::new(),
        body,
    })
}

#[derive(Deserialize)]
pub struct SQ {
    pub s: String,
    #[serde(default)]
    pub id: Option<i64>,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub hw: String,
}

pub async fn server(a: Auth, Query(q): Query<SQ>) -> AppResult<Response> {
    let k = kea(&a, &q.s)?;
    let mut h = String::new();
    match k.call("version-get", None).await {
        Ok((_, text, _)) => {
            let status = k.ok("status-get", None).await.ok();
            let uptime = status
                .as_ref()
                .and_then(|s| s["uptime"].as_i64())
                .map(crate::ldap::codec::fmt_duration)
                .unwrap_or_else(|| "—".into());
            h.push_str(&format!(
                "<p>{} <span class=\"small muted\">{}</span> · en service depuis {}</p>",
                badge("ok", "joignable"),
                esc(&text),
                esc(&uptime)
            ));
        }
        Err(e) => {
            return Ok(Html(format!("<p>{}</p>", badge("danger", &e.message))).into_response());
        }
    }
    let cfg = k.config().await?;
    let usage = k.usage().await;
    let subnets = k.subnets(&cfg);
    let rows: Vec<Vec<String>> = subnets
        .iter()
        .map(|s| {
            let (used, total) = usage.get(&s.id).copied().unwrap_or((0, 0));
            let pct = if total > 0 { used * 100 / total } else { 0 };
            let lvl = if pct >= 90 {
                "danger"
            } else if pct >= 75 {
                "warn"
            } else {
                "ok"
            };
            vec![
                s.id.to_string(),
                format!(
                    "<a href=\"/dhcp/subnet?s={}&id={}\"><strong class=\"mono\">{}</strong></a>",
                    url(&q.s),
                    s.id,
                    esc(&s.subnet)
                ),
                format!("<span class=\"mono small\">{}</span>", esc(&s.pools.join(", "))),
                if total > 0 {
                    format!("{} <span class=\"small muted\">{used} / {total}</span>", badge(lvl, &format!("{pct} %")))
                } else {
                    "—".into()
                },
                s.reservations.len().to_string(),
                esc(&s.shared_network),
            ]
        })
        .collect();
    h.push_str(&table(
        &["ID", "Étendue", "Plages", "Utilisation", "Réservations", "Réseau partagé"],
        &rows,
        "Aucune étendue configurée.",
    ));
    Ok(Html(h).into_response())
}

pub async fn subnet(a: Auth, Query(q): Query<SQ>) -> AppResult<Response> {
    let k = kea(&a, &q.s)?;
    let id = q.id.ok_or_else(|| AppError::bad_request("identifiant d'étendue requis"))?;
    let cfg = k.config().await?;
    let s =
        k.subnets(&cfg).into_iter().find(|x| x.id == id).ok_or_else(|| AppError::not_found("étendue introuvable"))?;
    let su = url(&q.s);
    let mut body = String::from("<div class=\"cards\"><section class=\"card\"><h2>Étendue</h2>");
    let mut facts = vec![("Sous-réseau".to_string(), s.subnet.clone()), ("Plages".into(), s.pools.join(", "))];
    if let Some(l) = s.valid_lifetime {
        facts.push(("Durée du bail".into(), crate::ldap::codec::fmt_duration(l)));
    }
    if !s.shared_network.is_empty() {
        facts.push(("Réseau partagé".into(), s.shared_network.clone()));
    }
    body.push_str(&kv(&facts));
    body.push_str("</section><section class=\"card\"><h2>Options</h2>");
    body.push_str(&kv(&s.options));
    if s.options.is_empty() {
        body.push_str("<p class=\"muted\">Options héritées de la configuration globale.</p>");
    }
    body.push_str("</section></div>");
    // réservations
    body.push_str(&format!(
        "<h2 style=\"margin-top:24px\">Réservations</h2><div style=\"margin-bottom:8px\">{}</div>",
        btn_dialog("Nouvelle réservation", "plus", &format!("/dhcp/reservation/new?s={su}&id={id}"), "btn-primary")
    ));
    let rows: Vec<Vec<String>> = s
        .reservations
        .iter()
        .map(|r| {
            vec![
                format!("<span class=\"mono\">{}</span>", esc(&r.ip)),
                format!(
                    "<span class=\"mono small\">{}</span>",
                    esc(if r.hw.is_empty() { &r.client_id } else { &r.hw })
                ),
                esc(&r.hostname),
                format!(
                    "<div class=\"right\">{}</div>",
                    btn_post(
                        "",
                        "trash",
                        &format!("/dhcp/reservation/delete?s={su}&id={id}&ip={}&hw={}", url(&r.ip), url(&r.hw)),
                        "Supprimer cette réservation ?",
                        "btn-ghost"
                    )
                ),
            ]
        })
        .collect();
    body.push_str(&table(&["Adresse", "Adresse MAC / DUID", "Nom d'hôte", ""], &rows, "Aucune réservation."));
    // baux
    body.push_str("<h2 style=\"margin-top:24px\">Baux d'adresses</h2>");
    match k.leases(id).await? {
        Ok(leases) => {
            let now = Utc::now().timestamp();
            let rows: Vec<Vec<String>> = leases
                .iter()
                .map(|l| {
                    let exp =
                        Utc.timestamp_opt(l.expire, 0).single().map(crate::ldap::codec::fmt_dt).unwrap_or_default();
                    let st = match l.state {
                        1 => badge("muted", "refusé"),
                        2 => badge("muted", "expiré (récupéré)"),
                        _ if l.expire < now => badge("warn", "expiré"),
                        _ => badge("ok", "actif"),
                    };
                    vec![
                        format!("<span class=\"mono\">{}</span>", esc(&l.ip)),
                        format!("<span class=\"mono small\">{}</span>", esc(&l.hw)),
                        esc(&l.hostname),
                        esc(&exp),
                        st,
                        format!(
                            "<div class=\"right\">{}</div>",
                            btn_post(
                                "",
                                "trash",
                                &format!("/dhcp/lease/delete?s={su}&id={id}&ip={}", url(&l.ip)),
                                "Supprimer ce bail ?",
                                "btn-ghost"
                            )
                        ),
                    ]
                })
                .collect();
            body.push_str(&table(
                &["Adresse", "MAC / DUID", "Nom d'hôte", "Expiration", "État", ""],
                &rows,
                "Aucun bail.",
            ));
        }
        Err(msg) => body.push_str(&format!("<div class=\"notice warn\">{}</div>", esc(&msg))),
    }
    let srv = a.s.profile.dhcp.iter().find(|x| x.id == q.s).map(|x| x.name.clone()).unwrap_or_default();
    render(&Generic {
        ctx: a.ctx("dhcp"),
        title: format!("Étendue {}", s.subnet),
        subtitle: format!("{srv} · ID {id}"),
        actions: "<a class=\"btn btn-sm\" href=\"/dhcp\">← Serveurs</a>".into(),
        body: format!(
            "<div hx-get=\"/dhcp/subnet?s={su}&id={id}\" hx-trigger=\"refresh-list from:body\" hx-select=\"#main > *\" hx-target=\"#main\">{body}</div>"
        ),
    })
}

pub async fn reservation_form(a: Auth, Query(q): Query<SQ>) -> AppResult<Response> {
    let k = kea(&a, &q.s)?;
    let id = q.id.unwrap_or(0);
    let v6 = k.server.service == "dhcp6";
    let body = format!(
        "<div class=\"form-grid\"><label>Adresse IP réservée</label><input type=\"text\" name=\"ip\" required autofocus class=\"mono\">\
         <label>{}</label><input type=\"text\" name=\"hw\" required class=\"mono\" placeholder=\"{}\">\
         <label>Nom d'hôte</label><input type=\"text\" name=\"hostname\"></div>",
        if v6 { "DUID" } else { "Adresse MAC" },
        if v6 { "00:01:00:01:..." } else { "aa:bb:cc:dd:ee:ff" }
    );
    render(&DlgForm::new(
        "Nouvelle réservation",
        "dhcp",
        format!("/dhcp/reservation/new?s={}&id={id}", url(&q.s)),
        body,
        "Réserver",
    ))
}

pub async fn reservation_add(a: Auth, Query(q): Query<SQ>, f: FormData) -> AppResult<Response> {
    let k = kea(&a, &q.s)?;
    let id = q.id.ok_or_else(|| AppError::bad_request("étendue requise"))?;
    let ip = f.s("ip");
    let hw = f.s("hw");
    let v6 = k.server.service == "dhcp6";
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Err(AppError::bad_request("adresse IP invalide"));
    }
    if !v6 && !valid_mac(&hw) {
        return Err(AppError::bad_request("adresse MAC invalide (format aa:bb:cc:dd:ee:ff)"));
    }
    let mut cfg = k.config().await?;
    let sn = k.subnet_mut(&mut cfg, id).ok_or_else(|| AppError::not_found("étendue introuvable"))?;
    let resv = sn
        .as_object_mut()
        .ok_or_else(|| AppError::internal("configuration inattendue"))?
        .entry("reservations")
        .or_insert(json!([]));
    let list = resv.as_array_mut().ok_or_else(|| AppError::internal("configuration inattendue"))?;
    let exists = list.iter().any(|r| {
        r["ip-address"].as_str() == Some(ip.as_str()) || r["hw-address"].as_str().map(norm_mac) == Some(norm_mac(&hw))
    });
    if exists {
        return Err(AppError::bad_request("une réservation existe déjà pour cette adresse IP ou MAC"));
    }
    let mut r = if v6 {
        json!({ "duid": hw, "ip-addresses": [ip] })
    } else {
        json!({ "hw-address": norm_mac(&hw), "ip-address": ip })
    };
    if let Some(h) = f.opt("hostname") {
        r["hostname"] = json!(h);
    }
    list.push(r);
    let res = k.set_config(cfg).await;
    a.audited("DHCP : réservation", &format!("{}/{}", k.server.id, id), &format!("{ip} ↔ {hw}"), res)?;
    Ok(Hx::ok("Réservation ajoutée").close_modal().refresh_list().empty())
}

pub async fn reservation_delete(a: Auth, Query(q): Query<SQ>) -> AppResult<Response> {
    let k = kea(&a, &q.s)?;
    let id = q.id.ok_or_else(|| AppError::bad_request("étendue requise"))?;
    let mut cfg = k.config().await?;
    let sn = k.subnet_mut(&mut cfg, id).ok_or_else(|| AppError::not_found("étendue introuvable"))?;
    if let Some(list) = sn["reservations"].as_array_mut() {
        let before = list.len();
        list.retain(|r| {
            let ip_match = r["ip-address"].as_str() == Some(q.ip.as_str())
                || r["ip-addresses"]
                    .as_array()
                    .map(|a| a.iter().any(|x| x.as_str() == Some(q.ip.as_str())))
                    .unwrap_or(false);
            !ip_match
        });
        if list.len() == before {
            return Err(AppError::not_found("réservation introuvable"));
        }
    }
    let res = k.set_config(cfg).await;
    a.audited(
        "DHCP : suppression de réservation",
        &format!("{}/{}", k.server.id, id),
        &format!("{} ↔ {}", q.ip, q.hw),
        res,
    )?;
    Ok(Hx::ok("Réservation supprimée").refresh_list().empty())
}

pub async fn lease_delete(a: Auth, Query(q): Query<SQ>) -> AppResult<Response> {
    let k = kea(&a, &q.s)?;
    let res = k.delete_lease(&q.ip).await;
    a.audited("DHCP : suppression de bail", &k.server.id, &q.ip, res)?;
    Ok(Hx::ok("Bail supprimé").refresh_list().empty())
}
