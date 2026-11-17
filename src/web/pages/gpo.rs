//! Gestion des stratégies de groupe (équivalent GPMC).

use super::{DlgForm, Generic};
use crate::error::{AppError, AppResult};
use crate::ldap::codec::fmt_dt_opt;
use crate::ldap::dir::{ctrl, m_clear, m_replace};
use crate::ldap::{Dir, Entry, dn, security};
use crate::services::gpo::{self, Link};
use crate::web::auth::Auth;
use crate::web::form::FormData;
use crate::web::html::{Hx, badge, btn_dialog, btn_post, esc, kicon, kv, render, table, url};
use axum::extract::Query;
use axum::response::{Html, IntoResponse, Response};
use ldap3::Scope;
use serde::Deserialize;
use std::collections::HashMap;

fn require_ad(a: &Auth) -> AppResult<()> {
    if !a.is_ad() {
        return Err(AppError::bad_request("les stratégies de groupe n'existent que dans Active Directory / Samba AD"));
    }
    Ok(())
}

fn sysvol(a: &Auth) -> Option<std::path::PathBuf> {
    a.s.profile.gpo.sysvol_path.clone()
}

fn status_badge(flags: i64) -> String {
    let lvl = match flags & 3 {
        0 => "ok",
        3 => "muted",
        _ => "warn",
    };
    badge(lvl, gpo::status_label(flags))
}

fn gpo_link(g: &gpo::Gpo) -> String {
    format!(
        "<span class=\"name\">{}<a class=\"obj-name\" hx-get=\"/gpo/view?guid={}\" hx-target=\"#modal\">{}</a></span>",
        kicon("gpo"),
        url(&g.guid),
        esc(&g.name)
    )
}

fn container_label(dn_: &str, base: &str) -> String {
    if dn::eq(dn_, base) {
        dn::dc_to_domain(dn_)
    } else if dn_.to_ascii_lowercase().contains(",cn=sites,") {
        format!("Site : {}", dn::rdn_value(dn_))
    } else {
        dn::canonical(dn_)
    }
}

// ---------------------------------------------------------------- page principale

pub async fn page(a: Auth) -> AppResult<Response> {
    require_ad(&a)?;
    let mut dir = a.dir().await?;
    let base = dir.base().to_string();
    let gpos = gpo::list(&mut dir).await?;
    let by_dn: HashMap<String, &gpo::Gpo> = gpos.iter().map(|g| (dn::normalize(&g.dn), g)).collect();
    // conteneurs avec liens ou blocage
    let mut containers = dir
        .search(
            &base,
            Scope::Subtree,
            "(|(gPLink=*)(gPOptions=1)(objectClass=domainDNS))",
            &["gPLink", "gPOptions", "objectClass"],
        )
        .await?;
    if let Some(c) = dir.info.config_nc.clone() {
        containers.extend(
            dir.search(&format!("CN=Sites,{c}"), Scope::OneLevel, "(gPLink=*)", &["gPLink", "gPOptions"])
                .await
                .unwrap_or_default(),
        );
    }
    containers.sort_by_key(|e| {
        if dn::eq(&e.dn, &base) { String::new() } else { container_label(&e.dn, &base).to_lowercase() }
    });
    let mut link_count: HashMap<String, usize> = HashMap::new();
    let mut tree = String::new();
    for c in &containers {
        let links = gpo::parse_gplink(&c.s("gPLink"));
        let block = c.int("gPOptions").unwrap_or(0) & 1 != 0;
        tree.push_str(&format!(
            "<div class=\"card\" style=\"padding:10px 14px;margin-bottom:8px\"><div class=\"row\">{}<a class=\"obj-name\" hx-get=\"/gpo/container?dn={}\" hx-target=\"#modal\"><strong>{}</strong></a>{}<span class=\"spacer\"></span><span class=\"small muted\">{} lien(s)</span></div>",
            kicon(if dn::eq(&c.dn, &base) { "domain" } else if c.dn.to_ascii_lowercase().contains(",cn=sites,") { "site" } else { "ou" }),
            url(&c.dn),
            esc(&container_label(&c.dn, &base)),
            if block { format!(" {}", badge("warn", "héritage bloqué")) } else { String::new() },
            links.len()
        ));
        if !links.is_empty() {
            tree.push_str("<ol class=\"small\" style=\"margin:6px 0 0;padding-left:22px\">");
            for l in &links {
                *link_count.entry(dn::normalize(&l.gpo_dn)).or_default() += 1;
                let name = by_dn.get(&dn::normalize(&l.gpo_dn)).map(|g| g.name.clone()).unwrap_or_else(|| l.guid());
                tree.push_str(&format!(
                    "<li>{}{}{}</li>",
                    esc(&name),
                    if l.enforced() { format!(" {}", badge("accent", "appliqué")) } else { String::new() },
                    if !l.enabled() { format!(" {}", badge("muted", "lien désactivé")) } else { String::new() }
                ));
            }
            tree.push_str("</ol>");
        }
        tree.push_str("</div>");
    }
    let rows: Vec<Vec<String>> = gpos
        .iter()
        .map(|g| {
            let n = link_count.get(&dn::normalize(&g.dn)).copied().unwrap_or(0);
            vec![
                gpo_link(g),
                status_badge(g.flags),
                format!("<span class=\"mono small\">U:{} / O:{}</span>", g.user_version(), g.computer_version()),
                if n == 0 { badge("warn", "non lié") } else { n.to_string() },
                format!("<span class=\"small\">{}</span>", esc(&fmt_dt_opt(g.changed))),
                if g.wmi.is_empty() { String::new() } else { badge("accent", "filtre WMI") },
            ]
        })
        .collect();
    let mut body = String::new();
    if sysvol(&a).is_none() {
        body.push_str("<div class=\"notice warn\">Chemin SYSVOL non configuré (<code>gpo.sysvol_path</code>) : la création de GPO et la vérification des versions SYSVOL sont limitées.</div>");
    }
    body.push_str("<div style=\"display:grid;grid-template-columns:minmax(0,3fr) minmax(280px,2fr);gap:16px;align-items:start\"><div>");
    body.push_str(&table(
        &["Objet de stratégie de groupe", "État", "Version", "Liens", "Modifié", ""],
        &rows,
        "Aucun GPO.",
    ));
    body.push_str("</div><div><h2>Liens par conteneur</h2>");
    body.push_str(&tree);
    body.push_str("</div></div>");
    render(&Generic {
        ctx: a.ctx("gpo"),
        title: "Gestion des stratégies de groupe".into(),
        subtitle: format!("{} objet(s) de stratégie de groupe — domaine {}", gpos.len(), dir.info.domain_dns),
        actions: btn_dialog("Nouveau GPO", "plus", "/gpo/new", "btn-primary"),
        body,
    })
}

// ---------------------------------------------------------------- détail d'un GPO

#[derive(Deserialize)]
pub struct GuidQ {
    pub guid: String,
}

pub async fn view(a: Auth, Query(q): Query<GuidQ>) -> AppResult<Response> {
    require_ad(&a)?;
    let mut dir = a.dir().await?;
    let base = dir.base().to_string();
    let g = gpo::get(&mut dir, &q.guid).await?;
    let gu = url(&g.guid);
    let mut h = String::new();
    // Général
    let sys_ver = sysvol(&a).and_then(|p| gpo::sysvol_version(&p, &g.guid));
    let ver = match sys_ver {
        Some(v) if v == g.version => {
            format!("AD et SYSVOL : {v} (U:{} / O:{}) — cohérentes", g.user_version(), g.computer_version())
        }
        Some(v) => format!("AD : {} ≠ SYSVOL : {v} — réplication SYSVOL incomplète ?", g.version),
        None => format!("AD : {} (U:{} / O:{})", g.version, g.user_version(), g.computer_version()),
    };
    h.push_str(&format!(
        "<form class=\"row wrap\" hx-post=\"/gpo/update?guid={gu}&op=status\" hx-swap=\"none\" style=\"margin-bottom:12px\"><label>État du GPO</label>\
         <select name=\"value\" style=\"max-width:320px\">{}</select><button type=\"submit\" class=\"btn-sm\">Appliquer</button></form>",
        (0..4).map(|i| format!("<option value=\"{i}\" {}>{}</option>", if g.flags & 3 == i { "selected" } else { "" }, gpo::status_label(i))).collect::<String>()
    ));
    h.push_str(&kv(&[
        ("Nom".into(), g.name.clone()),
        ("GUID".into(), g.guid.clone()),
        ("Version".into(), ver),
        ("Créé".into(), fmt_dt_opt(g.created)),
        ("Modifié".into(), fmt_dt_opt(g.changed)),
        ("Chemin SYSVOL".into(), g.path.clone()),
        ("Filtre WMI".into(), if g.wmi.is_empty() { "aucun".into() } else { g.wmi.clone() }),
    ]));
    // Liens
    let links = gpo::links_of(&mut dir, &g.guid).await?;
    h.push_str("<h3>Liens</h3>");
    let rows: Vec<Vec<String>> = links.iter().map(|(c, l)| link_row(c, l, &base, false)).collect();
    h.push_str(&table(&["Emplacement", "Lien activé", "Appliqué", ""], &rows, "Ce GPO n'est lié à aucun conteneur."));
    h.push_str(&format!(
        "<div style=\"margin-top:8px\">{}</div>",
        btn_dialog("Lier à un conteneur…", "link", &format!("/gpo/link?guid={gu}"), "")
    ));
    // Extensions
    h.push_str("<h3>Extensions configurées</h3>");
    let me = gpo::extensions(&g.machine_ext);
    let ue = gpo::extensions(&g.user_ext);
    h.push_str(&kv(&[
        ("Configuration ordinateur".into(), if me.is_empty() { "aucune".into() } else { me.join(", ") }),
        ("Configuration utilisateur".into(), if ue.is_empty() { "aucune".into() } else { ue.join(", ") }),
    ]));
    // Filtrage de sécurité
    h.push_str("<h3>Filtrage de sécurité</h3>");
    if let Some(e) = dir.read_ctrl(&g.dn, &["nTSecurityDescriptor"], vec![ctrl::sd_flags()]).await? {
        if let Some(sd) = e.bin("nTSecurityDescriptor").and_then(security::parse_sd) {
            let apply: Vec<String> = sd
                .dacl
                .iter()
                .filter(|x| {
                    x.is_allow()
                        && x.mask & 0x100 != 0
                        && x.object_type.as_deref() == Some("edacfd8f-ffb3-11d1-b41d-00a0c968f939")
                })
                .map(|x| x.sid.clone())
                .collect();
            let editors: Vec<String> = sd
                .dacl
                .iter()
                .filter(|x| x.is_allow() && x.mask & 0x20 != 0 && x.object_type.is_none() && !x.is_inherited())
                .map(|x| x.sid.clone())
                .collect();
            let mut all = apply.clone();
            all.extend(editors.iter().cloned());
            let names = security::resolve_sids(&mut dir, &all).await;
            let nm = |s: &String| names.get(s).map(|x| x.0.clone()).unwrap_or_else(|| s.clone());
            h.push_str(&kv(&[
                ("S'applique à".into(), apply.iter().map(nm).collect::<Vec<_>>().join(", ")),
                ("Peuvent modifier".into(), editors.iter().map(nm).collect::<Vec<_>>().join(", ")),
            ]));
        }
    }
    // Actions
    h.push_str(&format!(
        "<h3>Renommer</h3><form class=\"row\" hx-post=\"/gpo/update?guid={gu}&op=rename\" hx-swap=\"none\"><input type=\"text\" name=\"value\" value=\"{}\" required><button type=\"submit\" class=\"btn-sm\">Renommer</button></form>",
        esc(&g.name)
    ));
    if !g.is_default() {
        h.push_str(&format!(
            "<div class=\"form-actions\">{}</div>",
            btn_post(
                "Supprimer le GPO",
                "trash",
                &format!("/gpo/delete?guid={gu}"),
                "Supprimer ce GPO, ses liens et son dossier SYSVOL ?",
                "btn-danger"
            )
        ));
    }
    let mut d = DlgForm::new(
        format!("GPO — {}", g.name),
        "gpo",
        "#",
        format!(
            "<div hx-get=\"/gpo/view?guid={gu}\" hx-trigger=\"refresh-gpo from:body\" hx-select=\".dlg-body > div\" hx-swap=\"outerHTML\">{h}</div>"
        ),
        "",
    );
    d.cancel = "Fermer";
    d.size = "wide";
    render(&d)
}

fn link_row(container: &str, l: &Link, base: &str, with_order: bool) -> Vec<String> {
    let q = format!("dn={}&gpo={}", url(container), url(&l.gpo_dn));
    let mut v = Vec::new();
    v.push(format!(
        "<span class=\"name\">{}{}</span>",
        kicon(if dn::eq(container, base) { "domain" } else { "ou" }),
        esc(&container_label(container, base))
    ));
    v.push(if l.enabled() { badge("ok", "oui") } else { badge("muted", "non") });
    v.push(if l.enforced() { badge("accent", "oui") } else { "non".into() });
    let mut acts = String::from("<div class=\"right nowrap\">");
    acts.push_str(&btn_post(
        if l.enabled() { "Désactiver" } else { "Activer" },
        "power",
        &format!("/gpo/link/update?{q}&op=toggle"),
        "",
        "btn-ghost",
    ));
    acts.push_str(&btn_post(
        if l.enforced() { "Ne plus appliquer" } else { "Appliquer" },
        "shield",
        &format!("/gpo/link/update?{q}&op=enforce"),
        "",
        "btn-ghost",
    ));
    if with_order {
        acts.push_str(&btn_post("▲", "", &format!("/gpo/link/update?{q}&op=up"), "", "btn-ghost"));
        acts.push_str(&btn_post("▼", "", &format!("/gpo/link/update?{q}&op=down"), "", "btn-ghost"));
    }
    acts.push_str(&btn_post(
        "Supprimer le lien",
        "trash",
        &format!("/gpo/link/update?{q}&op=remove"),
        "Supprimer ce lien ?",
        "btn-ghost",
    ));
    acts.push_str("</div>");
    v.push(acts);
    v
}

// ---------------------------------------------------------------- conteneur (OU / domaine)

/// Contenu de l'onglet « Stratégie de groupe » d'une OU ou du domaine.
pub async fn links_tab_html(a: &Auth, dir: &mut Dir, e: &Entry) -> AppResult<String> {
    if !a.is_ad() {
        return Ok(String::new());
    }
    container_html(dir, &e.dn).await
}

async fn container_html(dir: &mut Dir, container: &str) -> AppResult<String> {
    let base = dir.base().to_string();
    let (links, block) = gpo::read_links(dir, container).await?;
    let gpos = gpo::list(dir).await?;
    let by_dn: HashMap<String, &gpo::Gpo> = gpos.iter().map(|g| (dn::normalize(&g.dn), g)).collect();
    let name_of = |d: &str| by_dn.get(&dn::normalize(d)).map(|g| g.name.clone()).unwrap_or_else(|| dn::rdn_value(d));
    let du = url(container);
    let mut h = String::new();
    let is_site = container.to_ascii_lowercase().contains(",cn=sites,");
    if !is_site {
        h.push_str(&format!(
            "<form class=\"row\" hx-post=\"/gpo/inheritance?dn={du}\" hx-swap=\"none\" style=\"margin-bottom:12px\"><label class=\"row\"><input type=\"checkbox\" name=\"block\" {}> Bloquer l'héritage</label><button type=\"submit\" class=\"btn-sm\">Appliquer</button></form>",
            if block { "checked" } else { "" }
        ));
    }
    h.push_str("<h3 style=\"margin-top:0\">GPO liés (ordre de liaison)</h3>");
    let rows: Vec<Vec<String>> = links
        .iter()
        .enumerate()
        .map(|(i, l)| {
            let mut r = link_row(container, l, &base, true);
            r[0] = format!("{}. {}", i + 1, esc(&name_of(&l.gpo_dn)));
            r
        })
        .collect();
    h.push_str(&table(&["GPO", "Lien activé", "Appliqué", ""], &rows, "Aucun GPO lié."));
    let options: String = gpos
        .iter()
        .filter(|g| !links.iter().any(|l| dn::eq(&l.gpo_dn, &g.dn)))
        .map(|g| format!("<option value=\"{}\">{}</option>", esc(&g.guid), esc(&g.name)))
        .collect();
    h.push_str(&format!(
        "<form class=\"row\" style=\"margin-top:8px\" hx-post=\"/gpo/link?target={du}\" hx-swap=\"none\"><select name=\"guid\" style=\"max-width:360px\">{options}</select><button type=\"submit\" class=\"btn-sm\">Lier ce GPO</button></form>"
    ));
    if !is_site {
        h.push_str("<h3>Héritage de stratégie de groupe (priorité)</h3>");
        let inh = gpo::inheritance(dir, container).await?;
        let rows: Vec<Vec<String>> = inh
            .iter()
            .map(|x| {
                let st = by_dn.get(&dn::normalize(&x.gpo_dn)).map(|g| g.flags).unwrap_or(0);
                vec![
                    x.precedence.to_string(),
                    format!(
                        "{}{}",
                        esc(&name_of(&x.gpo_dn)),
                        if x.enforced { format!(" {}", badge("accent", "appliqué")) } else { String::new() }
                    ),
                    esc(&container_label(&x.from, &base)),
                    status_badge(st),
                ]
            })
            .collect();
        h.push_str(&table(&["Priorité", "GPO", "Emplacement", "État du GPO"], &rows, "Aucun GPO ne s'applique."));
        h.push_str("<p class=\"small muted\">Les liens de site ne sont pas inclus ; la priorité 1 l'emporte.</p>");
    }
    Ok(format!(
        "<div hx-get=\"/gpo/container?dn={du}&frag=1\" hx-trigger=\"refresh-gpo from:body\" hx-swap=\"outerHTML\">{h}</div>"
    ))
}

#[derive(Deserialize)]
pub struct ContainerQ {
    pub dn: String,
    #[serde(default)]
    pub frag: Option<String>,
}

pub async fn container(a: Auth, Query(q): Query<ContainerQ>) -> AppResult<Response> {
    require_ad(&a)?;
    let mut dir = a.dir().await?;
    let base = dir.base().to_string();
    let h = container_html(&mut dir, &q.dn).await?;
    if q.frag.is_some() {
        return Ok(Html(h).into_response());
    }
    let mut d = DlgForm::new(format!("Stratégie de groupe — {}", container_label(&q.dn, &base)), "gpo", "#", h, "");
    d.cancel = "Fermer";
    d.size = "wide";
    render(&d)
}

// ---------------------------------------------------------------- actions

pub async fn new_form(a: Auth) -> AppResult<Response> {
    require_ad(&a)?;
    let warn = if sysvol(&a).is_none() {
        "<div class=\"notice warn\">SYSVOL non configuré : seul l'objet annuaire sera créé.</div>"
    } else {
        ""
    };
    let body = format!(
        "{warn}<div class=\"form-grid\"><label>Nom</label><input type=\"text\" name=\"name\" required autofocus></div>"
    );
    render(&DlgForm::new("Nouvel objet de stratégie de groupe", "gpo", "/gpo/new", body, "Créer"))
}

pub async fn new_submit(a: Auth, f: FormData) -> AppResult<Response> {
    require_ad(&a)?;
    let mut dir = a.dir().await?;
    let name = f.s("name");
    let sv = sysvol(&a);
    let res = gpo::create(&mut dir, &name, sv.as_deref()).await;
    let (g, warnings) = a.audited("création de GPO", &name, "", res)?;
    let hx = if warnings.is_empty() {
        Hx::ok(format!("GPO « {} » créé", g.name))
    } else {
        Hx::warn(format!("GPO « {} » créé — {}", g.name, warnings.join(" ; ")))
    };
    Ok(hx.close_modal().refresh_page().empty())
}

pub async fn delete(a: Auth, Query(q): Query<GuidQ>) -> AppResult<Response> {
    require_ad(&a)?;
    let mut dir = a.dir().await?;
    let sv = sysvol(&a);
    let res = gpo::delete(&mut dir, &q.guid, sv.as_deref()).await;
    let warnings = a.audited("suppression de GPO", &q.guid, "", res)?;
    let hx = if warnings.is_empty() {
        Hx::ok("GPO supprimé")
    } else {
        Hx::warn(format!("GPO supprimé — {}", warnings.join(" ; ")))
    };
    Ok(hx.trigger("close-all-modals").refresh_page().empty())
}

#[derive(Deserialize)]
pub struct UpdateQ {
    pub guid: String,
    pub op: String,
}

pub async fn update(a: Auth, Query(q): Query<UpdateQ>, f: FormData) -> AppResult<Response> {
    require_ad(&a)?;
    let mut dir = a.dir().await?;
    let g = gpo::get(&mut dir, &q.guid).await?;
    let (m, label) = match q.op.as_str() {
        "status" => {
            let v = f.int("value").unwrap_or(0).clamp(0, 3);
            (m_replace("flags", [((g.flags & !3) | v).to_string()]), format!("état : {}", gpo::status_label(v)))
        }
        "rename" => {
            let v = f.s("value");
            if v.is_empty() {
                return Err(AppError::bad_request("nom requis"));
            }
            (m_replace("displayName", [v.as_str()]), format!("renommé en {v}"))
        }
        _ => return Err(AppError::bad_request("opération inconnue")),
    };
    let res = dir.modify(&g.dn, vec![m]).await;
    a.audited("modification de GPO", &g.dn, &label, res)?;
    Ok(Hx::ok("GPO mis à jour").trigger("refresh-gpo").empty())
}

pub async fn link_form(a: Auth, Query(q): Query<GuidQ>) -> AppResult<Response> {
    require_ad(&a)?;
    let mut dir = a.dir().await?;
    let base = dir.base().to_string();
    let (mut v, _) = dir
        .search_paged(
            &base,
            Scope::Subtree,
            "(|(objectClass=organizationalUnit)(objectClass=domainDNS))",
            &["1.1"],
            10_000,
        )
        .await?;
    if let Some(c) = dir.info.config_nc.clone() {
        v.extend(
            dir.search(&format!("CN=Sites,{c}"), Scope::OneLevel, "(objectClass=site)", &["1.1"])
                .await
                .unwrap_or_default(),
        );
    }
    v.sort_by_key(|e| if dn::eq(&e.dn, &base) { String::new() } else { container_label(&e.dn, &base).to_lowercase() });
    let u = super::objects::uid();
    let mut body = format!(
        "<input type=\"hidden\" name=\"guid\" value=\"{}\"><input type=\"search\" placeholder=\"Filtrer…\" data-filter-table=\"#lk-{u}\" autofocus><ul class=\"val-list table-wrap\" id=\"lk-{u}\" style=\"max-height:380px;margin-top:8px;padding:6px\">",
        esc(&q.guid)
    );
    for e in v {
        let l = container_label(&e.dn, &base);
        body.push_str(&format!(
            "<li data-name=\"{}\"><label class=\"row\"><input type=\"radio\" name=\"target\" value=\"{}\" required> {}</label></li>",
            esc(&l.to_lowercase()),
            esc(&e.dn),
            esc(&l)
        ));
    }
    body.push_str("</ul>");
    let mut d = DlgForm::new("Lier le GPO", "link", "/gpo/link", body, "Lier");
    d.size = "";
    render(&d)
}

#[derive(Deserialize, Default)]
pub struct LinkAddQ {
    #[serde(default)]
    pub target: String,
}

pub async fn link_add(a: Auth, Query(q): Query<LinkAddQ>, f: FormData) -> AppResult<Response> {
    require_ad(&a)?;
    let mut dir = a.dir().await?;
    let target = if q.target.is_empty() { f.s("target") } else { q.target.clone() };
    let guid = gpo::guid_norm(&f.s("guid"))?;
    let g = gpo::get(&mut dir, &guid).await?;
    let (mut links, _) = gpo::read_links(&mut dir, &target).await?;
    if links.iter().any(|l| dn::eq(&l.gpo_dn, &g.dn)) {
        return Err(AppError::bad_request("ce GPO est déjà lié à ce conteneur"));
    }
    // un nouveau lien prend le dernier rang (priorité la plus faible)
    links.push(Link { gpo_dn: g.dn.clone(), options: 0 });
    let res = gpo::write_links(&mut dir, &target, &links).await;
    a.audited("liaison de GPO", &target, &g.name, res)?;
    Ok(Hx::ok(format!("GPO « {} » lié", g.name)).close_modal_if(q.target.is_empty()).trigger("refresh-gpo").empty())
}

#[derive(Deserialize)]
pub struct LinkUpdQ {
    pub dn: String,
    pub gpo: String,
    pub op: String,
}

pub async fn link_update(a: Auth, Query(q): Query<LinkUpdQ>) -> AppResult<Response> {
    require_ad(&a)?;
    let mut dir = a.dir().await?;
    let (mut links, _) = gpo::read_links(&mut dir, &q.dn).await?;
    let i =
        links.iter().position(|l| dn::eq(&l.gpo_dn, &q.gpo)).ok_or_else(|| AppError::not_found("lien introuvable"))?;
    match q.op.as_str() {
        "toggle" => links[i].options ^= 1,
        "enforce" => links[i].options ^= 2,
        "remove" => {
            links.remove(i);
        }
        "up" if i > 0 => links.swap(i, i - 1),
        "down" if i + 1 < links.len() => links.swap(i, i + 1),
        "up" | "down" => return Ok(Hx::new().empty()),
        _ => return Err(AppError::bad_request("opération inconnue")),
    }
    let res = gpo::write_links(&mut dir, &q.dn, &links).await;
    a.audited("lien de GPO", &q.dn, &format!("{} : {}", q.op, dn::rdn_value(&q.gpo)), res)?;
    Ok(Hx::ok("Lien mis à jour").trigger("refresh-gpo").empty())
}

#[derive(Deserialize)]
pub struct DnQ {
    pub dn: String,
}

pub async fn block_inheritance(a: Auth, Query(q): Query<DnQ>, f: FormData) -> AppResult<Response> {
    require_ad(&a)?;
    let mut dir = a.dir().await?;
    let block = f.checked("block");
    let m = if block { m_replace("gPOptions", ["1"]) } else { m_clear("gPOptions") };
    let res = match dir.modify(&q.dn, vec![m]).await {
        Err(e) if e.is_ldap(16) && !block => Ok(()),
        r => r,
    };
    a.audited("héritage de GPO", &q.dn, if block { "bloqué" } else { "rétabli" }, res)?;
    Ok(Hx::ok(if block { "Héritage bloqué" } else { "Héritage rétabli" }).trigger("refresh-gpo").empty())
}
