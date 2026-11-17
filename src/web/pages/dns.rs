//! Gestionnaire DNS : zones, enregistrements, création de PTR, nettoyage des
//! enregistrements dynamiques obsolètes.

use super::{DlgForm, Generic};
use crate::error::{AppError, AppResult};
use crate::ldap::codec::fmt_dt;
use crate::services::dns::{self, EDITABLE_TYPES, Provider, RData, Record};
use crate::web::auth::Auth;
use crate::web::form::FormData;
use crate::web::html::{Hx, badge, btn_dialog, btn_post, esc, render, table, url};
use axum::extract::Query;
use axum::response::Response;
use chrono::Utc;
use serde::Deserialize;

fn provider(a: &Auth) -> AppResult<Provider> {
    dns::provider_kind(&a.s.profile, &a.s.info)
        .ok_or_else(|| AppError::bad_request("aucun fournisseur DNS configuré pour cet annuaire"))
}

pub async fn page(a: Auth) -> AppResult<Response> {
    let p = provider(&a)?;
    let mut dir = a.dir().await?;
    let zones = dns::zones(&mut dir, p).await?;
    let rows: Vec<Vec<String>> = zones
        .iter()
        .map(|z| {
            vec![
                format!("<a href=\"/dns/zone?z={}\"><strong>{}</strong></a>", url(&z.id), esc(&z.name)),
                if z.system {
                    badge("muted", "système")
                } else if z.reverse {
                    badge("accent", "recherche inversée")
                } else {
                    badge("ok", "recherche directe")
                },
                format!("<span class=\"small muted\">{}</span>", esc(&z.location)),
                esc(&z.dynamic_update),
            ]
        })
        .collect();
    let mut actions = btn_dialog("Nouvelle zone", "plus", "/dns/zone/new", "btn-primary");
    if p == Provider::Ad {
        actions.push_str(&format!(
            " <a class=\"btn btn-sm\" href=\"/dns/stale\">{} Enregistrements obsolètes</a>",
            crate::web::html::icon("recycle")
        ));
    }
    let src = match p {
        Provider::Ad => "zones intégrées à l'annuaire (MicrosoftDNS)",
        Provider::Dnszone => "schéma LDAP dnszone (BIND / PowerDNS)",
    };
    render(&Generic {
        ctx: a.ctx("dns"),
        title: "DNS".into(),
        subtitle: format!("{} zone(s) — {src}", zones.len()),
        actions,
        body: table(&["Zone", "Type", "Stockage", "Mises à jour dynamiques"], &rows, "Aucune zone."),
    })
}

#[derive(Deserialize, Default)]
pub struct ZoneQ {
    #[serde(default)]
    pub z: String,
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub t: String,
    #[serde(default)]
    pub id: String,
}

fn rec_name(r: &Record, zone: &str) -> String {
    if r.name == "@" {
        "<span class=\"muted\">(identique au dossier parent)</span>".to_string()
    } else {
        format!("<span title=\"{}.{}\">{}</span>", esc(&r.name), esc(zone), esc(&r.name))
    }
}

pub async fn zone(a: Auth, Query(q): Query<ZoneQ>) -> AppResult<Response> {
    let p = provider(&a)?;
    let mut dir = a.dir().await?;
    let (z, recs) = dns::records(&mut dir, p, &q.z).await?;
    let zq = url(&q.z);
    let ql = q.q.to_lowercase();
    let filtered: Vec<&Record> = recs
        .iter()
        .filter(|r| q.t.is_empty() || r.rdata.type_name() == q.t)
        .filter(|r| {
            ql.is_empty() || r.name.to_lowercase().contains(&ql) || r.rdata.display().to_lowercase().contains(&ql)
        })
        .collect();
    let rows: Vec<Vec<String>> = filtered
        .iter()
        .map(|r| {
            let editable = EDITABLE_TYPES.contains(&r.rdata.type_name().as_str()) || matches!(r.rdata, RData::Soa { .. });
            let mut acts = String::from("<div class=\"right nowrap\">");
            if editable {
                acts.push_str(&format!(
                    "<button class=\"btn-sm btn-ghost\" hx-get=\"/dns/record/edit?z={zq}&id={}\" hx-target=\"#modal\">Modifier</button>",
                    url(&r.id)
                ));
            }
            if !matches!(r.rdata, RData::Soa { .. }) {
                acts.push_str(&btn_post("", "trash", &format!("/dns/record/delete?z={zq}&id={}", url(&r.id)), "Supprimer cet enregistrement ?", "btn-ghost"));
            }
            acts.push_str("</div>");
            vec![
                rec_name(r, &z.name),
                format!("<span class=\"badge\">{}</span>", esc(&r.rdata.type_name())),
                format!("<span class=\"mono small\">{}</span>", esc(&r.rdata.display())),
                format!("<span class=\"small\">{}</span>", r.ttl),
                match r.timestamp {
                    Some(t) => format!("<span class=\"small\">{}</span>", esc(&fmt_dt(t))),
                    None => "<span class=\"small faint\">statique</span>".into(),
                },
                acts,
            ]
        })
        .collect();
    let mut types: Vec<String> = recs.iter().map(|r| r.rdata.type_name()).collect();
    types.sort();
    types.dedup();
    let type_opts: String = std::iter::once("<option value=\"\">Tous les types</option>".to_string())
        .chain(types.iter().map(|t| format!("<option {}>{}</option>", if *t == q.t { "selected" } else { "" }, esc(t))))
        .collect();
    let body = format!(
        "<form class=\"row\" style=\"margin-bottom:12px\" method=\"get\" action=\"/dns/zone\"><input type=\"hidden\" name=\"z\" value=\"{}\">\
         <input type=\"search\" name=\"q\" value=\"{}\" placeholder=\"Filtrer par nom ou valeur…\" style=\"max-width:320px\"><select name=\"t\" style=\"max-width:180px\">{type_opts}</select>\
         <button type=\"submit\" class=\"btn-sm\">Filtrer</button><span class=\"spacer\"></span><span class=\"small muted\">{} / {} enregistrement(s)</span></form>{}",
        esc(&q.z),
        esc(&q.q),
        filtered.len(),
        recs.len(),
        table(&["Nom", "Type", "Données", "TTL", "Horodatage", ""], &rows, "Aucun enregistrement.")
    );
    let actions = format!(
        "{} {}",
        btn_dialog("Nouvel enregistrement", "plus", &format!("/dns/record/new?z={zq}"), "btn-primary"),
        btn_post(
            "Supprimer la zone",
            "trash",
            &format!("/dns/zone/delete?z={zq}"),
            "Supprimer définitivement cette zone et tous ses enregistrements ?",
            "btn-danger"
        )
    );
    render(&Generic {
        ctx: a.ctx("dns"),
        title: z.name.clone(),
        subtitle: format!("{} · mises à jour dynamiques : {}", z.location, z.dynamic_update),
        actions,
        body: format!(
            "<div hx-get=\"/dns/zone?z={zq}&q={}&t={}\" hx-trigger=\"refresh-list from:body\" hx-select=\"#main > *\" hx-target=\"#main\">{body}</div>",
            url(&q.q),
            url(&q.t)
        ),
    })
}

fn record_form_body(zone: &str, r: Option<&Record>) -> String {
    let rtype = r.map(|x| x.rdata.type_name()).unwrap_or_else(|| "A".into());
    let (mut ip, mut ip6, mut target, mut prio, mut weight, mut port, mut text) = (
        String::new(),
        String::new(),
        String::new(),
        "10".to_string(),
        "100".to_string(),
        String::new(),
        String::new(),
    );
    let mut soa = vec![String::new(); 7];
    if let Some(rec) = r {
        match &rec.rdata {
            RData::A(x) => ip = x.to_string(),
            RData::Aaaa(x) => ip6 = x.to_string(),
            RData::Cname(t) | RData::Ns(t) | RData::Ptr(t) => target = t.clone(),
            RData::Mx(p, t) => {
                prio = p.to_string();
                target = t.clone();
            }
            RData::Srv { priority, weight: w, port: po, target: t } => {
                prio = priority.to_string();
                weight = w.to_string();
                port = po.to_string();
                target = t.clone();
            }
            RData::Txt(v) => text = v.join("\n"),
            RData::Soa { mname, rname, serial, refresh, retry, expire, minimum } => {
                soa = vec![
                    mname.clone(),
                    rname.clone(),
                    (serial + 1).to_string(),
                    refresh.to_string(),
                    retry.to_string(),
                    expire.to_string(),
                    minimum.to_string(),
                ]
            }
            _ => {}
        }
    }
    let editing = r.is_some();
    let types: String = if editing {
        format!("<option selected>{}</option>", esc(&rtype))
    } else {
        EDITABLE_TYPES
            .iter()
            .map(|t| format!("<option {}>{t}</option>", if *t == rtype { "selected" } else { "" }))
            .collect()
    };
    let name = r.map(|x| x.name.clone()).unwrap_or_default();
    let mut h = format!(
        "<div class=\"form-grid\">\
         <label>Type</label><select name=\"rtype\" data-show-when {}>{types}</select>\
         <label>Nom</label><div><input type=\"text\" name=\"name\" value=\"{}\" placeholder=\"vide ou @ = {}\" {}><div class=\"small faint\">relatif à la zone {}</div></div>\
         <div class=\"full form-grid\" data-when=\"rtype=A\"><label>Adresse IPv4</label><input type=\"text\" name=\"ip\" value=\"{}\" placeholder=\"192.0.2.10\"></div>\
         <div class=\"full form-grid\" data-when=\"rtype=AAAA\"><label>Adresse IPv6</label><input type=\"text\" name=\"ip6\" value=\"{}\" placeholder=\"2001:db8::10\"></div>\
         <div class=\"full form-grid\" data-when=\"rtype=MX|SRV\"><label>Priorité</label><input type=\"number\" name=\"priority\" value=\"{}\" min=\"0\" max=\"65535\"></div>\
         <div class=\"full form-grid\" data-when=\"rtype=SRV\"><label>Poids</label><input type=\"number\" name=\"weight\" value=\"{}\" min=\"0\" max=\"65535\"><label>Port</label><input type=\"number\" name=\"port\" value=\"{}\" min=\"0\" max=\"65535\"></div>\
         <div class=\"full form-grid\" data-when=\"rtype=CNAME|NS|PTR|MX|SRV\"><label>Nom cible (FQDN)</label><input type=\"text\" name=\"target\" value=\"{}\" class=\"mono\" placeholder=\"hote.{}.\"></div>\
         <div class=\"full form-grid\" data-when=\"rtype=TXT\"><label>Texte</label><textarea name=\"text\" rows=\"3\" class=\"mono\" placeholder=\"une chaîne par ligne\">{}</textarea></div>",
        if editing { "disabled" } else { "" },
        esc(&name),
        esc(zone),
        if editing { "readonly" } else { "autofocus" },
        esc(zone),
        esc(&ip),
        esc(&ip6),
        esc(&prio),
        esc(&weight),
        esc(&port),
        esc(&target),
        esc(zone),
        esc(&text),
    );
    if editing {
        h.push_str(&format!("<input type=\"hidden\" name=\"rtype\" value=\"{}\">", esc(&rtype)));
    }
    if rtype == "SOA" {
        let labels = [
            "Serveur principal",
            "Responsable",
            "Numéro de série",
            "Actualisation (s)",
            "Nouvelle tentative (s)",
            "Expiration (s)",
            "TTL minimal (s)",
        ];
        let names = ["mname", "rname", "serial", "refresh", "retry", "expire", "minimum"];
        h.push_str("<div class=\"full form-grid\" data-when=\"rtype=SOA\">");
        for i in 0..7 {
            h.push_str(&format!(
                "<label>{}</label><input type=\"text\" name=\"{}\" value=\"{}\" class=\"mono\">",
                labels[i],
                names[i],
                esc(&soa[i])
            ));
        }
        h.push_str("</div>");
    }
    h.push_str(&format!(
        "<label>TTL (secondes)</label><input type=\"number\" name=\"ttl\" value=\"{}\" min=\"0\" style=\"max-width:160px\">",
        r.map(|x| x.ttl).unwrap_or(3600)
    ));
    if !editing {
        h.push_str("<div class=\"full form-grid\" data-when=\"rtype=A|AAAA\"><label></label><label class=\"row\"><input type=\"checkbox\" name=\"ptr\"> Créer l'enregistrement de pointeur (PTR) associé</label></div>");
    }
    h.push_str("</div>");
    h
}

pub async fn record_form(a: Auth, Query(q): Query<ZoneQ>) -> AppResult<Response> {
    let p = provider(&a)?;
    let mut dir = a.dir().await?;
    let (z, _) = dns::records(&mut dir, p, &q.z).await?;
    let body = record_form_body(&z.name, None);
    render(&DlgForm::new(
        format!("Nouvel enregistrement — {}", z.name),
        "dns",
        format!("/dns/record/new?z={}", url(&q.z)),
        body,
        "Ajouter",
    ))
}

pub async fn record_add(a: Auth, Query(q): Query<ZoneQ>, f: FormData) -> AppResult<Response> {
    let p = provider(&a)?;
    let mut dir = a.dir().await?;
    let (z, _) = dns::records(&mut dir, p, &q.z).await?;
    let rd = RData::from_form(&f, &z.name)?;
    let ttl = f.int("ttl").unwrap_or(3600).clamp(0, 2_147_483_647) as u32;
    let name = f.s("name");
    let res = dns::add(&mut dir, p, &q.z, &name, &rd, ttl).await;
    let label = format!("{} {} {}", dns::relative(&name, &z.name), rd.type_name(), rd.display());
    a.audited("DNS : ajout", &z.name, &label, res)?;
    let mut msg = format!("Enregistrement ajouté : {label}");
    if f.checked("ptr") {
        let ip: Option<std::net::IpAddr> = match &rd {
            RData::A(x) => Some((*x).into()),
            RData::Aaaa(x) => Some((*x).into()),
            _ => None,
        };
        if let Some(ip) = ip {
            let rev = dns::reverse_name(&ip);
            let zones = dns::zones(&mut dir, p).await?;
            let best = zones
                .iter()
                .filter(|zz| zz.reverse && (rev == zz.name || rev.ends_with(&format!(".{}", zz.name))))
                .max_by_key(|zz| zz.name.len());
            match best {
                Some(rz) => {
                    let fqdn = dns::qualify(&name, &z.name);
                    let res = dns::add(&mut dir, p, &rz.id, &rev, &RData::Ptr(fqdn.clone()), ttl).await;
                    match a.audited("DNS : ajout", &rz.name, &format!("PTR {rev} → {fqdn}"), res) {
                        Ok(_) => msg.push_str(" (+ PTR)"),
                        Err(e) => msg.push_str(&format!(" — PTR non créé : {}", e.message)),
                    }
                }
                None => msg.push_str(" — aucune zone inverse correspondante pour le PTR"),
            }
        }
    }
    Ok(Hx::ok(msg).close_modal().refresh_list().empty())
}

pub async fn record_edit_form(a: Auth, Query(q): Query<ZoneQ>) -> AppResult<Response> {
    let p = provider(&a)?;
    let mut dir = a.dir().await?;
    let (z, recs) = dns::records(&mut dir, p, &q.z).await?;
    let r = recs
        .iter()
        .find(|r| r.id == q.id)
        .ok_or_else(|| AppError::not_found("enregistrement introuvable (modifié entre-temps ?)"))?;
    let body = record_form_body(&z.name, Some(r));
    render(&DlgForm::new(
        format!(
            "Modifier {} — {}",
            r.rdata.type_name(),
            if r.name == "@" { z.name.clone() } else { format!("{}.{}", r.name, z.name) }
        ),
        "dns",
        format!("/dns/record/edit?z={}&id={}", url(&q.z), url(&q.id)),
        body,
        "Enregistrer",
    ))
}

pub async fn record_edit(a: Auth, Query(q): Query<ZoneQ>, f: FormData) -> AppResult<Response> {
    let p = provider(&a)?;
    let mut dir = a.dir().await?;
    let (z, _) = dns::records(&mut dir, p, &q.z).await?;
    let rd = RData::from_form(&f, &z.name)?;
    let ttl = f.int("ttl").unwrap_or(3600).clamp(0, 2_147_483_647) as u32;
    let res = dns::replace(&mut dir, p, &q.z, &q.id, &rd, ttl).await;
    a.audited("DNS : modification", &z.name, &format!("{} {}", rd.type_name(), rd.display()), res)?;
    Ok(Hx::ok("Enregistrement modifié").close_modal().refresh_list().empty())
}

pub async fn record_delete(a: Auth, Query(q): Query<ZoneQ>, f: FormData) -> AppResult<Response> {
    let p = provider(&a)?;
    let mut dir = a.dir().await?;
    let mut items: Vec<(String, String)> = Vec::new();
    if !q.id.is_empty() {
        items.push((q.z.clone(), q.id.clone()));
    }
    for zid in f.all("zid") {
        let parts = dns::decode_id(&zid)?;
        if parts.len() == 2 {
            items.push((String::from_utf8_lossy(&parts[0]).into(), String::from_utf8_lossy(&parts[1]).into()));
        }
    }
    if items.is_empty() {
        return Ok(Hx::warn("Aucun enregistrement sélectionné").empty());
    }
    let mut ok = 0;
    let mut errors = Vec::new();
    for (z, id) in &items {
        let res = dns::delete(&mut dir, p, z, id).await;
        match a.audited("DNS : suppression", z, "", res) {
            Ok(_) => ok += 1,
            Err(e) => errors.push(e.message),
        }
    }
    let hx = if errors.is_empty() {
        Hx::ok(format!("{ok} enregistrement(s) supprimé(s)"))
    } else {
        Hx::new().toast("error", errors.join(" — "))
    };
    Ok(hx.refresh_list().empty())
}

pub async fn zone_form(a: Auth) -> AppResult<Response> {
    let p = provider(&a)?;
    let mut body = String::from(
        "<div class=\"form-grid\"><label>Nom de la zone</label><input type=\"text\" name=\"name\" required autofocus placeholder=\"exemple.lan ou 2.0.192.in-addr.arpa\">",
    );
    if p == Provider::Ad {
        body.push_str(
            "<label>Réplication</label><select name=\"location\"><option value=\"Domaine\">Tous les serveurs DNS du domaine (DomainDnsZones)</option>\
             <option value=\"Forêt\">Tous les serveurs DNS de la forêt (ForestDnsZones)</option></select>\
             <label>Mises à jour dynamiques</label><select name=\"dyn\"><option value=\"2\">Sécurisées uniquement</option><option value=\"1\">Non sécurisées et sécurisées</option><option value=\"0\">Aucune</option></select>",
        );
    }
    body.push_str("</div><p class=\"small muted\">La zone est créée avec un enregistrement SOA et un NS pointant vers le serveur connecté.</p>");
    render(&DlgForm::new("Nouvelle zone principale", "dns", "/dns/zone/new", body, "Créer"))
}

pub async fn zone_add(a: Auth, f: FormData) -> AppResult<Response> {
    let p = provider(&a)?;
    let mut dir = a.dir().await?;
    let name = f.s("name");
    let res = dns::create_zone(
        &mut dir,
        p,
        &name,
        &f.opt("location").unwrap_or_else(|| "Domaine".into()),
        f.int("dyn").unwrap_or(2) as u8,
    )
    .await;
    let id = a.audited("DNS : création de zone", &name, "", res)?;
    Ok(Hx::ok(format!("Zone {name} créée")).close_modal().redirect(format!("/dns/zone?z={}", url(&id))).empty())
}

pub async fn zone_delete(a: Auth, Query(q): Query<ZoneQ>) -> AppResult<Response> {
    let p = provider(&a)?;
    let mut dir = a.dir().await?;
    let res = dns::delete_zone(&mut dir, p, &q.z).await;
    a.audited("DNS : suppression de zone", &q.z, "", res)?;
    Ok(Hx::ok("Zone supprimée").redirect("/dns").empty())
}

#[derive(Deserialize)]
pub struct StaleQ {
    #[serde(default)]
    pub days: Option<i64>,
}

pub async fn stale(a: Auth, Query(q): Query<StaleQ>) -> AppResult<Response> {
    let p = provider(&a)?;
    if p != Provider::Ad {
        return Err(AppError::bad_request("le vieillissement ne concerne que les zones intégrées à AD"));
    }
    let days = q.days.unwrap_or(14).max(1);
    let mut dir = a.dir().await?;
    let limit = Utc::now() - chrono::Duration::days(days);
    let mut rows = Vec::new();
    for z in dns::zones(&mut dir, p).await? {
        if z.system {
            continue;
        }
        let (_, recs) = dns::records(&mut dir, p, &z.id).await?;
        for r in recs.iter().filter(|r| r.timestamp.map(|t| t < limit).unwrap_or(false)) {
            rows.push(vec![
                format!(
                    "<input type=\"checkbox\" name=\"zid\" value=\"{}\">",
                    esc(&dns::encode_id(&[z.id.as_bytes(), r.id.as_bytes()]))
                ),
                format!("{}.{}", esc(&r.name), esc(&z.name)),
                format!("<span class=\"badge\">{}</span>", esc(&r.rdata.type_name())),
                format!("<span class=\"mono small\">{}</span>", esc(&r.rdata.display())),
                esc(&r.timestamp.map(fmt_dt).unwrap_or_default()),
            ]);
        }
    }
    let n = rows.len();
    let body = format!(
        "<form class=\"row\" method=\"get\" action=\"/dns/stale\" style=\"margin-bottom:12px\"><label>Non actualisés depuis</label><input type=\"number\" name=\"days\" value=\"{days}\" min=\"1\" style=\"max-width:100px\"><span>jours</span><button type=\"submit\" class=\"btn-sm\">Analyser</button></form>\
         <form hx-post=\"/dns/record/delete\" hx-swap=\"none\" hx-confirm=\"Supprimer les enregistrements sélectionnés ?\">\
         <p class=\"small muted\">{n} enregistrement(s) dynamique(s) obsolète(s). Les enregistrements statiques ne sont jamais proposés.</p>{}\
         <div class=\"form-actions\"><button type=\"submit\" class=\"btn-danger\" {}>Supprimer la sélection</button></div></form>",
        table(&["", "Nom", "Type", "Données", "Dernière actualisation"], &rows, "Aucun enregistrement obsolète."),
        if n == 0 { "disabled" } else { "" }
    );
    render(&Generic {
        ctx: a.ctx("dns"),
        title: "Enregistrements DNS obsolètes".into(),
        subtitle: "Nettoyage manuel (équivalent du nettoyage / vieillissement)".into(),
        actions: String::new(),
        body: format!(
            "<div hx-get=\"/dns/stale?days={days}\" hx-trigger=\"refresh-list from:body\" hx-select=\"#main > *\" hx-target=\"#main\">{body}</div>"
        ),
    })
}
