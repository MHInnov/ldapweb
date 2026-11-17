//! Certificats : inventaire AD CS (équivalent pkiview / certtmpl), certificats
//! publiés sur les objets, expirations, sonde LDAPS.

use super::Generic;
use crate::error::{AppError, AppResult};
use crate::ldap::dir::{m_add, m_delete};
use crate::ldap::{Dir, Entry, dn};
use crate::services::pki::{self, CERT_ATTRS, CertInfo};
use crate::web::auth::Auth;
use crate::web::html::{Hx, badge, esc, kicon, kv, render, table, url};
use axum::extract::{Multipart, Query};
use axum::response::{Html, IntoResponse, Response};
use ldap3::Scope;
use serde::Deserialize;

fn cert_cells(c: &CertInfo) -> Vec<String> {
    let (lvl, st) = c.status();
    vec![
        format!("<strong>{}</strong><div class=\"small muted\">{}</div>", esc(&c.short_subject()), esc(&c.subject)),
        format!("<span class=\"small\">{}</span>", esc(&c.short_issuer())),
        format!("<span class=\"small nowrap\">{}</span>", esc(&c.validity())),
        badge(lvl, &st),
    ]
}

// ---------------------------------------------------------------- onglet Certificats

pub fn certs_tab_html(dir: &Dir, e: &Entry) -> AppResult<String> {
    let du = url(&e.dn);
    let mut rows = Vec::new();
    for attr in CERT_ATTRS {
        for (i, raw) in e.bins(attr).iter().enumerate() {
            let mut cells = match CertInfo::parse(raw) {
                Some(c) => {
                    let mut v = cert_cells(&c);
                    v.insert(0, format!("<span class=\"mono small\">{attr}</span>"));
                    v[1].push_str(&format!(
                        "<div class=\"small muted\">{}</div>",
                        esc(&c.eku.iter().map(|x| pki::eku_name(x)).collect::<Vec<_>>().join(", "))
                    ));
                    v
                }
                None => vec![
                    format!("<span class=\"mono small\">{attr}</span>"),
                    "certificat illisible".into(),
                    String::new(),
                    String::new(),
                    String::new(),
                ],
            };
            cells.push(format!(
                "<div class=\"right nowrap\"><button class=\"btn-sm btn-ghost\" hx-get=\"/pki/cert?dn={du}&attr={attr}&i={i}\" hx-target=\"#modal2\">Détails</button>\
                 <a class=\"btn btn-sm btn-ghost\" href=\"/attrs/download?dn={du}&attr={attr}&i={i}\" hx-boost=\"false\">.cer</a>\
                 <button class=\"btn-sm btn-ghost\" hx-post=\"/obj/cert/remove?dn={du}&attr={attr}&i={i}\" hx-swap=\"none\" hx-confirm=\"Retirer ce certificat de l'objet ?\">Retirer</button></div>"
            ));
            rows.push(cells);
        }
    }
    let attr = if dir.is_ad() { "userCertificate" } else { "userCertificate;binary" };
    let html = format!(
        "{}<form style=\"margin-top:14px\" hx-post=\"/obj/cert/add?dn={du}\" hx-encoding=\"multipart/form-data\" hx-swap=\"none\" class=\"row wrap\">\
         <input type=\"file\" name=\"file\" accept=\".cer,.crt,.pem,.der\" required style=\"max-width:340px\">\
         <span class=\"small muted\">→ attribut <code>{attr}</code></span><button type=\"submit\" class=\"btn-sm\">Publier le certificat</button></form>",
        table(
            &["Attribut", "Sujet", "Émetteur", "Validité", "État", ""],
            &rows,
            "Aucun certificat publié sur cet objet."
        )
    );
    Ok(format!(
        "<div hx-get=\"/obj/tab?dn={du}&tab=certs\" hx-trigger=\"refresh-tab from:body\" hx-swap=\"outerHTML\">{html}</div>"
    ))
}

#[derive(Deserialize)]
pub struct CertQ {
    pub dn: String,
    #[serde(default)]
    pub attr: String,
    #[serde(default)]
    pub i: usize,
}

fn cert_detail_html(c: &CertInfo, der: &[u8]) -> String {
    let (lvl, st) = c.status();
    let mut h = format!("<p>{}</p>", badge(lvl, &st));
    h.push_str(&kv(&[
        ("Sujet".into(), c.subject.clone()),
        ("Émetteur".into(), c.issuer.clone()),
        ("Numéro de série".into(), c.serial.clone()),
        ("Validité".into(), c.validity()),
        ("Noms alternatifs".into(), c.san.join(", ")),
        ("Utilisations avancées".into(), c.eku.iter().map(|x| pki::eku_name(x)).collect::<Vec<_>>().join(", ")),
        ("Clé publique".into(), c.key.clone()),
        ("Signature".into(), c.sig_alg.clone()),
        ("Autorité de certification".into(), if c.is_ca { "oui".into() } else { "non".into() }),
        ("Auto-signé".into(), if c.self_signed { "oui".into() } else { "non".into() }),
        ("Empreinte SHA-1".into(), c.sha1.clone()),
        ("Empreinte SHA-256".into(), c.sha256.clone()),
    ]));
    h.push_str(&format!(
        "<h3>PEM</h3><textarea class=\"mono\" rows=\"8\" readonly>{}</textarea>",
        esc(&pki::to_pem(der))
    ));
    h
}

pub async fn cert_view(a: Auth, Query(q): Query<CertQ>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let e = dir.read_req(&q.dn, &[q.attr.as_str()]).await?;
    let vals = e.bins(&q.attr);
    let der = vals.get(q.i).ok_or_else(|| AppError::not_found("certificat introuvable"))?;
    let c = CertInfo::parse(der).ok_or_else(|| AppError::bad_request("certificat illisible"))?;
    let mut d =
        super::DlgForm::new(format!("Certificat — {}", c.short_subject()), "cert", "#", cert_detail_html(&c, der), "");
    d.cancel = "Fermer";
    render(&d)
}

#[derive(Deserialize)]
pub struct DnQ {
    pub dn: String,
}

pub async fn cert_add(a: Auth, Query(q): Query<DnQ>, mut mp: Multipart) -> AppResult<Response> {
    let mut data = Vec::new();
    while let Some(field) = mp.next_field().await.map_err(|e| AppError::bad_request(e.to_string()))? {
        if field.name() == Some("file") {
            data = field.bytes().await.map_err(|e| AppError::bad_request(e.to_string()))?.to_vec();
        }
    }
    let certs = pki::parse_upload(&data);
    if certs.is_empty() {
        return Err(AppError::bad_request("aucun certificat X.509 valide (PEM ou DER) dans le fichier"));
    }
    let mut dir = a.dir().await?;
    let attr = if dir.is_ad() { "userCertificate" } else { "userCertificate;binary" };
    let subjects: Vec<String> = certs.iter().filter_map(|c| CertInfo::parse(c)).map(|c| c.short_subject()).collect();
    let res = dir.modify_permissive(&q.dn, vec![m_add(attr, certs.iter())]).await;
    a.audited("publication de certificat", &q.dn, &subjects.join(", "), res)?;
    Ok(Hx::ok(format!("{} certificat(s) publié(s)", certs.len())).trigger("refresh-tab").empty())
}

pub async fn cert_remove(a: Auth, Query(q): Query<CertQ>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let e = dir.read_req(&q.dn, &[q.attr.as_str()]).await?;
    // retrouver le nom exact de l'attribut (éventuelle option ;binary)
    let (name, vals) = e
        .attrs
        .iter()
        .find(|(n, _)| crate::ldap::entry::base_attr(n).eq_ignore_ascii_case(crate::ldap::entry::base_attr(&q.attr)))
        .ok_or_else(|| AppError::not_found("attribut absent"))?;
    let v = vals.get(q.i).ok_or_else(|| AppError::not_found("certificat introuvable"))?.clone();
    let subj = CertInfo::parse(&v).map(|c| c.short_subject()).unwrap_or_default();
    let res = dir.modify(&q.dn, vec![m_delete(name, [v])]).await;
    a.audited("retrait de certificat", &q.dn, &subj, res)?;
    Ok(Hx::ok("Certificat retiré").trigger("refresh-tab").empty())
}

// ---------------------------------------------------------------- page PKI

pub async fn page(a: Auth) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let mut body = String::from(
        "<div class=\"cards\"><section class=\"card\"><h2>Certificat du serveur LDAP</h2><div hx-get=\"/pki/probe\" hx-trigger=\"load\"><span class=\"muted\">Analyse…</span></div></section>\
         <section class=\"card\"><h2>Certificats publiés expirant bientôt</h2><div hx-get=\"/pki/expiring?days=60\" hx-trigger=\"load\"><span class=\"muted\">Recherche…</span></div></section></div>",
    );
    if dir.is_ad() {
        match pki::load_ad_pki(&mut dir).await? {
            None => body.push_str("<div class=\"notice\" style=\"margin-top:16px\">Aucun conteneur « Public Key Services » : services de certificats AD non déployés.</div>"),
            Some(p) => {
                body.push_str("<h2 style=\"margin-top:24px\">Autorités de certification d'entreprise</h2>");
                let rows: Vec<Vec<String>> = p
                    .services
                    .iter()
                    .map(|s| {
                        let mut v = vec![
                            format!("<strong>{}</strong>", esc(&s.name)),
                            format!("<span class=\"mono small\">{}</span>", esc(&s.host)),
                            s.templates.len().to_string(),
                        ];
                        match &s.cert {
                            Some(c) => {
                                let (l, st) = c.status();
                                v.push(format!("<span class=\"small\">{}</span>", esc(&c.validity())));
                                v.push(badge(l, &st));
                            }
                            None => {
                                v.push(String::new());
                                v.push(String::new());
                            }
                        }
                        v
                    })
                    .collect();
                body.push_str(&table(&["Autorité", "Serveur", "Modèles publiés", "Validité", "État"], &rows, "Aucun service d'inscription."));
                let ca_rows: Vec<Vec<String>> = p
                    .cas
                    .iter()
                    .map(|(n, c)| match c {
                        Some(c) => {
                            let mut v = cert_cells(c);
                            v.insert(0, esc(n));
                            v
                        }
                        None => vec![esc(n), String::new(), String::new(), String::new(), String::new()],
                    })
                    .collect();
                body.push_str("<h3>Autorités racines approuvées (annuaire)</h3>");
                body.push_str(&table(&["Nom", "Sujet", "Émetteur", "Validité", "État"], &ca_rows, "Aucune."));
                let nt_rows: Vec<Vec<String>> = p.ntauth.iter().map(cert_cells).collect();
                body.push_str("<h3>Magasin NTAuth (authentification par carte à puce / PKINIT)</h3>");
                body.push_str(&table(&["Sujet", "Émetteur", "Validité", "État"], &nt_rows, "Vide."));
                body.push_str("<h2 style=\"margin-top:24px\">Modèles de certificats</h2>");
                let risky = p.templates.iter().filter(|t| t.risks.iter().any(|r| r.0 == "danger")).count();
                if risky > 0 {
                    body.push_str(&format!("<div class=\"notice danger\">{risky} modèle(s) présentent un risque d'élévation de privilèges (ESC1 à ESC4).</div>"));
                }
                let rows: Vec<Vec<String>> = p
                    .templates
                    .iter()
                    .map(|t| {
                        vec![
                            format!("<a class=\"obj-name\" hx-get=\"/obj/props?dn={}&tab=attrs\" hx-target=\"#modal\">{}</a><div class=\"small muted mono\">{}</div>", url(&t.dn), esc(&t.display), esc(&t.name)),
                            format!("v{}", t.schema_version),
                            esc(&t.validity),
                            format!("<span class=\"small\">{}</span>", esc(&t.ekus.iter().map(|x| pki::eku_name(x)).collect::<Vec<_>>().join(", "))),
                            if t.published_on.is_empty() { "<span class=\"faint\">non publié</span>".into() } else { esc(&t.published_on.join(", ")) },
                            t.risks.iter().map(|(l, m)| badge(l, m)).collect::<Vec<_>>().join(" "),
                        ]
                    })
                    .collect();
                body.push_str(&table(&["Modèle", "Version", "Validité", "Utilisations", "Publié sur", "Analyse"], &rows, "Aucun modèle."));
            }
        }
    } else {
        let base = dir.base().to_string();
        let v = dir
            .search(
                &base,
                Scope::Subtree,
                "(|(objectClass=pkiCA)(cACertificate=*)(cACertificate;binary=*))",
                &["cACertificate"],
            )
            .await
            .unwrap_or_default();
        let mut rows = Vec::new();
        for e in &v {
            for raw in e.bins("cACertificate") {
                if let Some(c) = CertInfo::parse(raw) {
                    let mut r = cert_cells(&c);
                    r.insert(
                        0,
                        format!(
                            "<a class=\"obj-name\" hx-get=\"/obj/props?dn={}\" hx-target=\"#modal\">{}</a>",
                            url(&e.dn),
                            esc(&dn::rdn_value(&e.dn))
                        ),
                    );
                    rows.push(r);
                }
            }
        }
        body.push_str("<h2 style=\"margin-top:24px\">Autorités publiées dans l'annuaire (pkiCA)</h2>");
        body.push_str(&table(&["Entrée", "Sujet", "Émetteur", "Validité", "État"], &rows, "Aucune autorité publiée."));
    }
    render(&Generic {
        ctx: a.ctx("pki"),
        title: "Certificats (PKI)".into(),
        subtitle: "Autorités, modèles, certificats publiés et expirations".into(),
        actions: String::new(),
        body,
    })
}

pub async fn probe(a: Auth) -> AppResult<Response> {
    let info = a.s.info.clone();
    let tls = a.st.tls_for(&a.s.profile.id)?;
    let mut html = String::new();
    let mut hosts: Vec<(String, u16)> = Vec::new();
    for u in &a.s.profile.urls {
        let (h, p) = crate::ldap::flavor::url_host(u);
        let port = if u.starts_with("ldaps://") { p } else { 636 };
        if !hosts.contains(&(h.clone(), port)) {
            hosts.push((h, port));
        }
    }
    for (h, port) in hosts {
        match crate::ldap::conn::probe_tls_chain(&h, port, &tls).await {
            Ok((chain, verdict)) => {
                html.push_str(&format!("<h3 style=\"margin-top:0\">{}:{}</h3>", esc(&h), port));
                html.push_str(&match &verdict {
                    Ok(()) => badge("ok", "chaîne approuvée"),
                    Err(e) => badge("danger", &format!("non approuvée : {e}")),
                });
                let rows: Vec<Vec<String>> =
                    chain.iter().filter_map(|d| CertInfo::parse(d)).map(|c| cert_cells(&c)).collect();
                html.push_str(&table(&["Sujet", "Émetteur", "Validité", "État"], &rows, "Aucun certificat présenté."));
            }
            Err(e) => html.push_str(&format!(
                "<p>{} {}</p>",
                esc(&format!("{h}:{port}")),
                badge("warn", &format!("LDAPS injoignable : {e}"))
            )),
        }
    }
    if !info.tls {
        html.push_str(
            "<div class=\"notice warn\" style=\"margin-top:10px\">La session actuelle n'utilise pas TLS.</div>",
        );
    }
    Ok(Html(html).into_response())
}

#[derive(Deserialize)]
pub struct ExpQ {
    #[serde(default)]
    pub days: Option<i64>,
}

pub async fn expiring(a: Auth, Query(q): Query<ExpQ>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let days = q.days.unwrap_or(60);
    let base = dir.base().to_string();
    let (v, truncated) = dir
        .search_paged(
            &base,
            Scope::Subtree,
            "(|(userCertificate=*)(userCertificate;binary=*))",
            &["userCertificate", "objectClass", "cn", "displayName", "name"],
            20_000,
        )
        .await?;
    let mut items: Vec<(String, &'static str, CertInfo, String)> = Vec::new();
    for e in &v {
        for raw in e.bins("userCertificate") {
            if let Some(c) = CertInfo::parse(raw) {
                if c.days_left() <= days {
                    items.push((e.display_name(), crate::directory::Kind::of(e).icon(), c, e.dn.clone()));
                }
            }
        }
    }
    items.sort_by_key(|x| x.2.not_after);
    let rows: Vec<Vec<String>> = items
        .iter()
        .take(200)
        .map(|(n, icon, c, d)| {
            let (l, st) = c.status();
            vec![
                format!("<span class=\"name\">{}<a class=\"obj-name\" hx-get=\"/obj/props?dn={}&tab=certs\" hx-target=\"#modal\">{}</a></span>", kicon(icon), url(d), esc(n)),
                format!("<span class=\"small\">{}</span>", esc(&c.short_subject())),
                badge(l, &st),
            ]
        })
        .collect();
    let mut html = format!(
        "<p class=\"small muted\">{} certificat(s) expiré(s) ou expirant sous {days} jours, parmi {} objet(s) porteurs{}.</p>",
        items.len(),
        v.len(),
        if truncated { " (analyse tronquée)" } else { "" }
    );
    html.push_str(&table(&["Objet", "Certificat", "État"], &rows, "Rien à signaler."));
    Ok(Html(html).into_response())
}
