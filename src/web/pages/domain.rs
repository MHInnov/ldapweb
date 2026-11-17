//! Domaine : sites et sous-réseaux, approbations, stratégies de mot de passe
//! (domaine, PSO, ppolicy), corbeille AD, schéma, journal d'audit.

use super::{DlgForm, Generic};
use crate::error::{AppError, AppResult};
use crate::ldap::codec::{
    ad_interval_secs, fmt_dt, fmt_duration, parse_generalized, secs_to_ad_interval, sid_to_string,
};
use crate::ldap::dir::{AttrsBuilder, Mods, ctrl, m_clear, m_replace};
use crate::ldap::{Entry, dn};
use crate::web::auth::Auth;
use crate::web::form::FormData;
use crate::web::html::{Hx, badge, btn_dialog, btn_post, esc, kicon, kv, render, table, url};
use axum::extract::Query;
use axum::response::Response;
use ldap3::Scope;
use serde::Deserialize;

fn cfg_nc(a: &Auth) -> AppResult<String> {
    a.s.info
        .config_nc
        .clone()
        .ok_or_else(|| AppError::bad_request("partition de configuration indisponible (Active Directory requis)"))
}

// ---------------------------------------------------------------- sites

pub async fn sites(a: Auth) -> AppResult<Response> {
    let cfg = cfg_nc(&a)?;
    let mut dir = a.dir().await?;
    let sites_dn = format!("CN=Sites,{cfg}");
    let sites = dir
        .search(&sites_dn, Scope::OneLevel, "(objectClass=site)", &["cn", "description", "location", "gPLink"])
        .await?;
    let subnets = dir
        .search(
            &format!("CN=Subnets,{sites_dn}"),
            Scope::OneLevel,
            "(objectClass=subnet)",
            &["cn", "siteObject", "description", "location"],
        )
        .await
        .unwrap_or_default();
    let servers =
        dir.search(&sites_dn, Scope::Subtree, "(objectClass=server)", &["cn", "dNSHostName"]).await.unwrap_or_default();
    let links = dir
        .search(
            &format!("CN=Inter-Site Transports,{sites_dn}"),
            Scope::Subtree,
            "(objectClass=siteLink)",
            &["cn", "cost", "replInterval", "siteList"],
        )
        .await
        .unwrap_or_default();
    let mut body = String::new();
    for s in &sites {
        let srv: Vec<String> = servers
            .iter()
            .filter(|x| dn::is_under(&x.dn, &s.dn))
            .map(|x| x.str("dNSHostName").unwrap_or_else(|| x.s("cn")))
            .collect();
        let sub: Vec<&Entry> = subnets.iter().filter(|x| dn::eq(&x.s("siteObject"), &s.dn)).collect();
        body.push_str(&format!(
            "<section class=\"card\" style=\"margin-bottom:14px\"><h2>{} {}</h2><p class=\"small muted\">{}</p>",
            kicon("site"),
            esc(&s.s("cn")),
            esc(&[s.s("description"), s.s("location")]
                .iter()
                .filter(|x| !x.is_empty())
                .cloned()
                .collect::<Vec<_>>()
                .join(" · "))
        ));
        body.push_str(&kv(&[
            ("Serveurs".into(), if srv.is_empty() { "aucun".into() } else { srv.join(", ") }),
            ("GPO liés".into(), crate::services::gpo::parse_gplink(&s.s("gPLink")).len().to_string()),
        ]));
        let rows: Vec<Vec<String>> = sub
            .iter()
            .map(|x| {
                vec![
                    format!("<span class=\"mono\">{}</span>", esc(&x.s("cn"))),
                    esc(&x.s("description")),
                    esc(&x.s("location")),
                    format!(
                        "<div class=\"right\">{}</div>",
                        btn_post(
                            "",
                            "trash",
                            &format!("/sites/subnet/delete?dn={}", url(&x.dn)),
                            "Supprimer ce sous-réseau ?",
                            "btn-ghost"
                        )
                    ),
                ]
            })
            .collect();
        body.push_str("<h3>Sous-réseaux</h3>");
        body.push_str(&table(&["Préfixe", "Description", "Emplacement", ""], &rows, "Aucun sous-réseau associé."));
        body.push_str("</section>");
    }
    let orphan: Vec<Vec<String>> = subnets
        .iter()
        .filter(|x| x.str("siteObject").is_none())
        .map(|x| vec![format!("<span class=\"mono\">{}</span>", esc(&x.s("cn"))), esc(&x.s("description"))])
        .collect();
    if !orphan.is_empty() {
        body.push_str("<div class=\"notice warn\">Sous-réseaux sans site : les clients de ces réseaux ne trouveront pas de DC proche.</div>");
        body.push_str(&table(&["Préfixe", "Description"], &orphan, ""));
    }
    body.push_str("<h2 style=\"margin-top:20px\">Liens de sites</h2>");
    let rows: Vec<Vec<String>> = links
        .iter()
        .map(|l| {
            vec![
                esc(&l.s("cn")),
                esc(&l.strs("siteList").iter().map(|x| dn::rdn_value(x)).collect::<Vec<_>>().join(", ")),
                esc(&l.s("cost")),
                format!("{} min", esc(&l.s("replInterval"))),
            ]
        })
        .collect();
    body.push_str(&table(&["Lien", "Sites", "Coût", "Intervalle de réplication"], &rows, "Aucun lien de sites."));
    render(&Generic {
        ctx: a.ctx("sites"),
        title: "Sites et services".into(),
        subtitle: format!("{} site(s), {} sous-réseau(x)", sites.len(), subnets.len()),
        actions: btn_dialog("Nouveau sous-réseau", "plus", "/sites/subnet", "btn-primary"),
        body,
    })
}

pub async fn subnet_form(a: Auth) -> AppResult<Response> {
    let cfg = cfg_nc(&a)?;
    let mut dir = a.dir().await?;
    let sites = dir.search(&format!("CN=Sites,{cfg}"), Scope::OneLevel, "(objectClass=site)", &["cn"]).await?;
    let opts: String =
        sites.iter().map(|s| format!("<option value=\"{}\">{}</option>", esc(&s.dn), esc(&s.s("cn")))).collect();
    let body = format!(
        "<div class=\"form-grid\"><label>Préfixe</label><input type=\"text\" name=\"prefix\" required autofocus class=\"mono\" placeholder=\"10.1.0.0/16 ou 2001:db8::/48\">\
         <label>Site</label><select name=\"site\">{opts}</select><label>Description</label><input type=\"text\" name=\"description\"><label>Emplacement</label><input type=\"text\" name=\"location\"></div>"
    );
    render(&DlgForm::new("Nouveau sous-réseau", "site", "/sites/subnet", body, "Créer"))
}

fn valid_prefix(p: &str) -> bool {
    let Some((ip, len)) = p.split_once('/') else { return false };
    let Ok(len) = len.parse::<u8>() else { return false };
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => len <= 32,
        Ok(std::net::IpAddr::V6(_)) => len <= 128,
        Err(_) => false,
    }
}

pub async fn subnet_add(a: Auth, f: FormData) -> AppResult<Response> {
    let cfg = cfg_nc(&a)?;
    let mut dir = a.dir().await?;
    let prefix = f.s("prefix");
    if !valid_prefix(&prefix) {
        return Err(AppError::bad_request("préfixe invalide (notation CIDR attendue)"));
    }
    let target = dn::child("CN", &prefix, &format!("CN=Subnets,CN=Sites,{cfg}"));
    let mut b = AttrsBuilder::new();
    b.set("objectClass", ["top", "subnet"]);
    b.one("cn", &prefix);
    b.one("siteObject", &f.s("site"));
    b.one("description", &f.s("description"));
    b.one("location", &f.s("location"));
    let res = dir.add(&target, b.build()).await;
    a.audited("création de sous-réseau", &target, "", res)?;
    Ok(Hx::ok(format!("Sous-réseau {prefix} créé")).close_modal().refresh_page().empty())
}

#[derive(Deserialize)]
pub struct DnQ {
    #[serde(default)]
    pub dn: String,
}

pub async fn subnet_delete(a: Auth, Query(q): Query<DnQ>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    if !q.dn.to_ascii_lowercase().contains(",cn=subnets,cn=sites,") {
        return Err(AppError::bad_request("objet invalide"));
    }
    let res = dir.delete(&q.dn).await;
    a.audited("suppression de sous-réseau", &q.dn, "", res)?;
    Ok(Hx::ok("Sous-réseau supprimé").refresh_page().empty())
}

// ---------------------------------------------------------------- approbations

pub async fn trusts(a: Auth) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let base = dir.base().to_string();
    let v = dir
        .search(
            &format!("CN=System,{base}"),
            Scope::OneLevel,
            "(objectClass=trustedDomain)",
            &[
                "trustPartner",
                "flatName",
                "trustDirection",
                "trustType",
                "trustAttributes",
                "whenCreated",
                "securityIdentifier",
            ],
        )
        .await?;
    let rows: Vec<Vec<String>> = v
        .iter()
        .map(|t| {
            let dirn = match t.int("trustDirection").unwrap_or(0) {
                1 => "entrante",
                2 => "sortante",
                3 => "bidirectionnelle",
                _ => "désactivée",
            };
            let ty = match t.int("trustType").unwrap_or(0) {
                1 => "Windows (NT4)",
                2 => "Active Directory",
                3 => "Royaume Kerberos (MIT)",
                _ => "autre",
            };
            let at = t.int("trustAttributes").unwrap_or(0);
            let mut attrs = Vec::new();
            if at & 0x1 != 0 {
                attrs.push("non transitive");
            }
            if at & 0x4 != 0 {
                attrs.push("filtrage SID (quarantaine)");
            }
            if at & 0x8 != 0 {
                attrs.push("approbation de forêt");
            }
            if at & 0x10 != 0 {
                attrs.push("inter-organisations (authentification sélective)");
            }
            if at & 0x20 != 0 {
                attrs.push("intra-forêt");
            }
            if at & 0x40 != 0 {
                attrs.push("traitée comme externe");
            }
            vec![
                format!(
                    "<strong>{}</strong><div class=\"small muted\">{}</div>",
                    esc(&t.s("trustPartner")),
                    esc(&t.s("flatName"))
                ),
                esc(dirn),
                esc(ty),
                esc(&attrs.join(", ")),
                esc(&t.bin("securityIdentifier").and_then(sid_to_string).unwrap_or_default()),
                esc(&t.str("whenCreated").and_then(|x| parse_generalized(&x)).map(fmt_dt).unwrap_or_default()),
            ]
        })
        .collect();
    render(&Generic {
        ctx: a.ctx("trusts"),
        title: "Domaines et approbations".into(),
        subtitle: format!(
            "Domaine {} — niveau fonctionnel : {}",
            dir.info.domain_dns,
            dir.info.domain_level.map(crate::ldap::flavor::functional_level_label).unwrap_or("?")
        ),
        actions: String::new(),
        body: table(
            &["Domaine approuvé", "Direction", "Type", "Attributs", "SID", "Créée"],
            &rows,
            "Aucune relation d'approbation.",
        ),
    })
}

// ---------------------------------------------------------------- stratégies de mot de passe

fn days_field(e: &Entry, attr: &str) -> String {
    e.int(attr).and_then(ad_interval_secs).map(|s| (s / 86400).to_string()).unwrap_or_else(|| "0".into())
}
fn mins_field(e: &Entry, attr: &str) -> String {
    e.int(attr).and_then(ad_interval_secs).map(|s| (s / 60).to_string()).unwrap_or_else(|| "0".into())
}

const PSO_ATTRS: &[&str] = &[
    "cn",
    "msDS-PasswordSettingsPrecedence",
    "msDS-MinimumPasswordLength",
    "msDS-PasswordHistoryLength",
    "msDS-PasswordComplexityEnabled",
    "msDS-PasswordReversibleEncryptionEnabled",
    "msDS-MinimumPasswordAge",
    "msDS-MaximumPasswordAge",
    "msDS-LockoutThreshold",
    "msDS-LockoutDuration",
    "msDS-LockoutObservationWindow",
    "msDS-PSOAppliesTo",
];

pub async fn policies(a: Auth) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let base = dir.base().to_string();
    let mut body = String::new();
    if dir.is_ad() {
        let d = dir
            .read_req(
                &base,
                &[
                    "minPwdLength",
                    "pwdHistoryLength",
                    "maxPwdAge",
                    "minPwdAge",
                    "pwdProperties",
                    "lockoutThreshold",
                    "lockoutDuration",
                    "lockOutObservationWindow",
                ],
            )
            .await?;
        let props = d.int("pwdProperties").unwrap_or(0);
        if a.s.info.flavor == crate::ldap::Flavor::ActiveDirectory {
            body.push_str("<div class=\"notice warn\">Sur Windows, ces valeurs sont imposées par la GPO « Default Domain Policy » : une modification directe peut être écrasée lors du prochain rafraîchissement.</div>");
        }
        body.push_str(&format!(
            "<section class=\"card\"><h2>Stratégie du domaine</h2><form hx-post=\"/policies/domain\" hx-swap=\"none\"><div class=\"form-grid\">\
             <label>Longueur minimale</label><input type=\"number\" name=\"minPwdLength\" value=\"{}\" min=\"0\" max=\"255\">\
             <label>Historique (mots de passe mémorisés)</label><input type=\"number\" name=\"pwdHistoryLength\" value=\"{}\" min=\"0\" max=\"1024\">\
             <label>Durée de vie maximale (jours, 0 = jamais)</label><input type=\"number\" name=\"maxPwdAge\" value=\"{}\" min=\"0\">\
             <label>Durée de vie minimale (jours)</label><input type=\"number\" name=\"minPwdAge\" value=\"{}\" min=\"0\">\
             <label>Complexité exigée</label><input type=\"checkbox\" name=\"complex\" {}>\
             <label>Chiffrement réversible</label><input type=\"checkbox\" name=\"reversible\" {}>\
             <label>Seuil de verrouillage (0 = jamais)</label><input type=\"number\" name=\"lockoutThreshold\" value=\"{}\" min=\"0\">\
             <label>Durée de verrouillage (min)</label><input type=\"number\" name=\"lockoutDuration\" value=\"{}\" min=\"0\">\
             <label>Réinitialisation du compteur (min)</label><input type=\"number\" name=\"lockOutObservationWindow\" value=\"{}\" min=\"0\">\
             </div><div class=\"form-actions\"><button type=\"submit\" class=\"btn-primary\">Enregistrer</button></div></form></section>",
            d.s("minPwdLength"),
            d.s("pwdHistoryLength"),
            days_field(&d, "maxPwdAge"),
            days_field(&d, "minPwdAge"),
            if props & 1 != 0 { "checked" } else { "" },
            if props & 0x10 != 0 { "checked" } else { "" },
            d.s("lockoutThreshold"),
            mins_field(&d, "lockoutDuration"),
            mins_field(&d, "lockOutObservationWindow"),
        ));
        let psos = dir
            .search(
                &format!("CN=Password Settings Container,CN=System,{base}"),
                Scope::OneLevel,
                "(objectClass=msDS-PasswordSettings)",
                PSO_ATTRS,
            )
            .await
            .unwrap_or_default();
        let rows: Vec<Vec<String>> = psos
            .iter()
            .map(|p| {
                vec![
                    format!(
                        "<a class=\"obj-name\" hx-get=\"/policies/pso?dn={}\" hx-target=\"#modal\">{}</a>",
                        url(&p.dn),
                        esc(&p.s("cn"))
                    ),
                    esc(&p.s("msDS-PasswordSettingsPrecedence")),
                    esc(&p.s("msDS-MinimumPasswordLength")),
                    esc(&p
                        .int("msDS-MaximumPasswordAge")
                        .and_then(ad_interval_secs)
                        .map(fmt_duration)
                        .unwrap_or_else(|| "jamais".into())),
                    esc(&p.s("msDS-LockoutThreshold")),
                    esc(&p.strs("msDS-PSOAppliesTo").iter().map(|x| dn::rdn_value(x)).collect::<Vec<_>>().join(", ")),
                ]
            })
            .collect();
        body.push_str(&format!(
            "<h2 style=\"margin-top:24px\">Stratégies de mot de passe affinées (PSO)</h2><div style=\"margin-bottom:8px\">{}</div>{}",
            btn_dialog("Nouvelle PSO", "plus", "/policies/pso", "btn-primary"),
            table(&["Nom", "Priorité", "Longueur min.", "Durée max.", "Seuil de verrouillage", "S'applique à"], &rows, "Aucune PSO.")
        ));
    } else {
        let v = dir
            .search(
                &base,
                Scope::Subtree,
                "(objectClass=pwdPolicy)",
                &[
                    "cn",
                    "pwdMinLength",
                    "pwdMaxAge",
                    "pwdInHistory",
                    "pwdMaxFailure",
                    "pwdLockout",
                    "pwdLockoutDuration",
                    "pwdMustChange",
                ],
            )
            .await
            .unwrap_or_default();
        let rows: Vec<Vec<String>> = v
            .iter()
            .map(|p| {
                vec![
                    format!("<a class=\"obj-name\" hx-get=\"/policies/ppolicy?dn={}\" hx-target=\"#modal\">{}</a><div class=\"small muted mono\">{}</div>", url(&p.dn), esc(&p.rdn_name()), esc(&p.dn)),
                    esc(&p.s("pwdMinLength")),
                    esc(&p.int("pwdMaxAge").filter(|x| *x > 0).map(fmt_duration).unwrap_or_else(|| "jamais".into())),
                    esc(&p.s("pwdInHistory")),
                    format!("{}{}", esc(&p.s("pwdMaxFailure")), if p.bool("pwdLockout").unwrap_or(false) { " (verrouillage actif)" } else { "" }),
                    esc(&p.s("pwdMustChange")),
                ]
            })
            .collect();
        body.push_str(&format!(
            "<p class=\"muted\">Stratégies de l'overlay ppolicy (objets pwdPolicy). La stratégie par défaut est définie par <code>olcPPolicyDefault</code>.</p><div style=\"margin-bottom:8px\">{}</div>{}",
            btn_dialog("Nouvelle stratégie", "plus", "/policies/ppolicy", "btn-primary"),
            table(&["Stratégie", "Longueur min.", "Durée max.", "Historique", "Échecs max.", "Changement à la 1re connexion"], &rows, "Aucune stratégie pwdPolicy trouvée.")
        ));
    }
    render(&Generic {
        ctx: a.ctx("policies"),
        title: "Stratégies de mot de passe".into(),
        subtitle: String::new(),
        actions: String::new(),
        body,
    })
}

pub async fn domain_policy_save(a: Auth, f: FormData) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    if !dir.is_ad() {
        return Err(AppError::bad_request("Active Directory requis"));
    }
    let base = dir.base().to_string();
    let d = dir.read_req(&base, &["pwdProperties"]).await?;
    let mut props = d.int("pwdProperties").unwrap_or(0) & !(0x1 | 0x10);
    if f.checked("complex") {
        props |= 0x1;
    }
    if f.checked("reversible") {
        props |= 0x10;
    }
    let n = |k: &str| f.int(k).unwrap_or(0).max(0);
    let max_age = n("maxPwdAge");
    let mods: Mods = vec![
        m_replace("minPwdLength", [n("minPwdLength").to_string()]),
        m_replace("pwdHistoryLength", [n("pwdHistoryLength").to_string()]),
        m_replace(
            "maxPwdAge",
            [if max_age == 0 { i64::MIN.to_string() } else { secs_to_ad_interval(max_age * 86400).to_string() }],
        ),
        m_replace("minPwdAge", [(-(n("minPwdAge") * 86400 * 10_000_000)).to_string()]),
        m_replace("pwdProperties", [props.to_string()]),
        m_replace("lockoutThreshold", [n("lockoutThreshold").to_string()]),
        m_replace("lockoutDuration", [(-(n("lockoutDuration") * 60 * 10_000_000)).to_string()]),
        m_replace("lockOutObservationWindow", [(-(n("lockOutObservationWindow") * 60 * 10_000_000)).to_string()]),
    ];
    let res = dir.modify(&base, mods).await;
    a.audited("stratégie de mot de passe du domaine", &base, "", res)?;
    Ok(Hx::ok("Stratégie du domaine enregistrée").empty())
}

pub async fn pso_form(a: Auth, Query(q): Query<DnQ>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let e = if q.dn.is_empty() { None } else { Some(dir.read_req(&q.dn, PSO_ATTRS).await?) };
    let g = |attr: &str, def: &str| e.as_ref().and_then(|x| x.str(attr)).unwrap_or_else(|| def.to_string());
    let days = |attr: &str, def: i64| {
        e.as_ref().and_then(|x| x.int(attr)).and_then(ad_interval_secs).map(|s| s / 86400).unwrap_or(def)
    };
    let mins = |attr: &str, def: i64| {
        e.as_ref().and_then(|x| x.int(attr)).and_then(ad_interval_secs).map(|s| s / 60).unwrap_or(def)
    };
    let applies = e.as_ref().map(|x| x.strs("msDS-PSOAppliesTo").join("\n")).unwrap_or_default();
    let body = format!(
        "<input type=\"hidden\" name=\"dn\" value=\"{}\"><div class=\"form-grid\">\
         <label>Nom</label><input type=\"text\" name=\"cn\" value=\"{}\" {} required>\
         <label>Priorité (plus petit = prioritaire)</label><input type=\"number\" name=\"prec\" value=\"{}\" min=\"1\">\
         <label>Longueur minimale</label><input type=\"number\" name=\"minlen\" value=\"{}\" min=\"0\">\
         <label>Historique</label><input type=\"number\" name=\"hist\" value=\"{}\" min=\"0\">\
         <label>Complexité</label><input type=\"checkbox\" name=\"complex\" {}>\
         <label>Chiffrement réversible</label><input type=\"checkbox\" name=\"rev\" {}>\
         <label>Durée de vie minimale (jours)</label><input type=\"number\" name=\"minage\" value=\"{}\" min=\"0\">\
         <label>Durée de vie maximale (jours, 0 = jamais)</label><input type=\"number\" name=\"maxage\" value=\"{}\" min=\"0\">\
         <label>Seuil de verrouillage</label><input type=\"number\" name=\"lockth\" value=\"{}\" min=\"0\">\
         <label>Durée de verrouillage (min)</label><input type=\"number\" name=\"lockdur\" value=\"{}\" min=\"0\">\
         <label>Réinitialisation du compteur (min)</label><input type=\"number\" name=\"lockwin\" value=\"{}\" min=\"0\">\
         <label>S'applique à (DN de groupes ou d'utilisateurs, un par ligne)</label><textarea name=\"applies\" class=\"mono\" rows=\"3\">{}</textarea></div>",
        esc(&q.dn),
        esc(&g("cn", "")),
        if e.is_some() { "readonly" } else { "autofocus" },
        esc(&g("msDS-PasswordSettingsPrecedence", "10")),
        esc(&g("msDS-MinimumPasswordLength", "12")),
        esc(&g("msDS-PasswordHistoryLength", "24")),
        if g("msDS-PasswordComplexityEnabled", "TRUE") == "TRUE" { "checked" } else { "" },
        if g("msDS-PasswordReversibleEncryptionEnabled", "FALSE") == "TRUE" { "checked" } else { "" },
        days("msDS-MinimumPasswordAge", 1),
        days("msDS-MaximumPasswordAge", 0),
        esc(&g("msDS-LockoutThreshold", "10")),
        mins("msDS-LockoutDuration", 30),
        mins("msDS-LockoutObservationWindow", 30),
        esc(&applies)
    );
    let mut d = DlgForm::new(
        if e.is_some() { "Modifier la PSO" } else { "Nouvelle PSO" },
        "policy",
        "/policies/pso",
        body,
        "Enregistrer",
    );
    if e.is_some() {
        d.body.push_str(&format!(
            "<div class=\"form-actions\">{}</div>",
            btn_post(
                "Supprimer cette PSO",
                "trash",
                &format!("/policies/pso/delete?dn={}", url(&q.dn)),
                "Supprimer cette PSO ?",
                "btn-danger"
            )
        ));
    }
    render(&d)
}

pub async fn pso_save(a: Auth, f: FormData) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let base = dir.base().to_string();
    let n = |k: &str| f.int(k).unwrap_or(0).max(0);
    let iv = |secs: i64| (-(secs * 10_000_000)).to_string();
    let maxage = n("maxage");
    let vals: Vec<(&str, String)> = vec![
        ("msDS-PasswordSettingsPrecedence", n("prec").max(1).to_string()),
        ("msDS-MinimumPasswordLength", n("minlen").to_string()),
        ("msDS-PasswordHistoryLength", n("hist").to_string()),
        ("msDS-PasswordComplexityEnabled", if f.checked("complex") { "TRUE".into() } else { "FALSE".into() }),
        ("msDS-PasswordReversibleEncryptionEnabled", if f.checked("rev") { "TRUE".into() } else { "FALSE".into() }),
        ("msDS-MinimumPasswordAge", iv(n("minage") * 86400)),
        ("msDS-MaximumPasswordAge", if maxage == 0 { i64::MIN.to_string() } else { iv(maxage * 86400) }),
        ("msDS-LockoutThreshold", n("lockth").to_string()),
        ("msDS-LockoutDuration", iv(n("lockdur") * 60)),
        ("msDS-LockoutObservationWindow", iv(n("lockwin") * 60)),
    ];
    let applies = f.lines("applies");
    let existing = f.s("dn");
    let res = if existing.is_empty() {
        let cn = f.s("cn");
        if cn.is_empty() {
            return Err(AppError::bad_request("nom requis"));
        }
        let target = dn::child("CN", &cn, &format!("CN=Password Settings Container,CN=System,{base}"));
        let mut b = AttrsBuilder::new();
        b.set("objectClass", ["top", "msDS-PasswordSettings"]);
        b.one("cn", &cn);
        for (k, v) in &vals {
            b.one(k, v);
        }
        b.set("msDS-PSOAppliesTo", applies.iter());
        dir.add(&target, b.build()).await.map(|_| target)
    } else {
        let mut mods: Mods = vals.iter().map(|(k, v)| m_replace(k, [v.as_str()])).collect();
        mods.push(if applies.is_empty() {
            m_clear("msDS-PSOAppliesTo")
        } else {
            m_replace("msDS-PSOAppliesTo", applies.iter())
        });
        let r = match dir.modify(&existing, mods).await {
            Err(e) if e.is_ldap(16) => Ok(()),
            r => r,
        };
        r.map(|_| existing.clone())
    };
    let target = a.audited("PSO", &f.s("cn"), "", res)?;
    Ok(Hx::ok(format!("PSO enregistrée : {}", dn::rdn_value(&target))).close_modal().refresh_page().empty())
}

pub async fn pso_delete(a: Auth, Query(q): Query<DnQ>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let res = dir.delete(&q.dn).await;
    a.audited("suppression de PSO", &q.dn, "", res)?;
    Ok(Hx::ok("PSO supprimée").trigger("close-all-modals").refresh_page().empty())
}

const PPOLICY_FIELDS: &[(&str, &str, &str)] = &[
    ("pwdMinLength", "Longueur minimale", "8"),
    ("pwdInHistory", "Historique", "5"),
    ("pwdMaxAge", "Durée de vie maximale (s, 0 = jamais)", "0"),
    ("pwdMinAge", "Durée de vie minimale (s)", "0"),
    ("pwdExpireWarning", "Avertissement avant expiration (s)", "0"),
    ("pwdGraceAuthNLimit", "Connexions de grâce", "0"),
    ("pwdMaxFailure", "Échecs avant verrouillage", "5"),
    ("pwdLockoutDuration", "Durée de verrouillage (s, 0 = manuel)", "900"),
    ("pwdFailureCountInterval", "Fenêtre de comptage des échecs (s)", "900"),
    ("pwdCheckQuality", "Contrôle de qualité (0, 1, 2)", "1"),
];
const PPOLICY_BOOLS: &[(&str, &str)] = &[
    ("pwdLockout", "Verrouiller après échecs"),
    ("pwdMustChange", "Changement obligatoire après réinitialisation"),
    ("pwdAllowUserChange", "L'utilisateur peut changer son mot de passe"),
    ("pwdSafeModify", "Ancien mot de passe exigé pour le changement"),
];

pub async fn ppolicy_form(a: Auth, Query(q): Query<DnQ>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let e = if q.dn.is_empty() { None } else { Some(dir.read_req(&q.dn, &["*"]).await?) };
    let mut body = format!("<input type=\"hidden\" name=\"dn\" value=\"{}\"><div class=\"form-grid\">", esc(&q.dn));
    if e.is_none() {
        body.push_str(&format!(
            "<label>Nom (cn)</label><input type=\"text\" name=\"cn\" required autofocus><label>Conteneur</label><input type=\"text\" name=\"parent\" class=\"mono\" value=\"ou=policies,{}\">",
            esc(dir.base())
        ));
    }
    for (attr, label, def) in PPOLICY_FIELDS {
        let v = e.as_ref().and_then(|x| x.str(attr)).unwrap_or_else(|| def.to_string());
        body.push_str(&format!(
            "<label>{label}</label><input type=\"number\" name=\"{attr}\" value=\"{}\" min=\"0\">",
            esc(&v)
        ));
    }
    for (attr, label) in PPOLICY_BOOLS {
        let v = e.as_ref().and_then(|x| x.bool(attr)).unwrap_or(*attr == "pwdAllowUserChange" || *attr == "pwdLockout");
        body.push_str(&format!(
            "<label>{label}</label><input type=\"checkbox\" name=\"{attr}\" {}>",
            if v { "checked" } else { "" }
        ));
    }
    body.push_str("</div>");
    render(&DlgForm::new(
        if e.is_some() { "Modifier la stratégie" } else { "Nouvelle stratégie ppolicy" },
        "policy",
        "/policies/ppolicy",
        body,
        "Enregistrer",
    ))
}

pub async fn ppolicy_save(a: Auth, f: FormData) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let existing = f.s("dn");
    let mut values: Vec<(&str, String)> =
        PPOLICY_FIELDS.iter().map(|(k, _, _)| (*k, f.int(k).unwrap_or(0).max(0).to_string())).collect();
    for (k, _) in PPOLICY_BOOLS {
        values.push((k, if f.checked(k) { "TRUE".into() } else { "FALSE".into() }));
    }
    let res = if existing.is_empty() {
        let cn = f.s("cn");
        let parent = f.s("parent");
        if cn.is_empty() || parent.is_empty() {
            return Err(AppError::bad_request("nom et conteneur requis"));
        }
        let target = dn::child("cn", &cn, &parent);
        let mut b = AttrsBuilder::new();
        b.set("objectClass", ["top", "device", "pwdPolicy"]);
        b.one("cn", &cn);
        b.one("pwdAttribute", "userPassword");
        for (k, v) in &values {
            b.one(k, v);
        }
        dir.add(&target, b.build()).await.map(|_| target)
    } else {
        let mods: Mods = values.iter().map(|(k, v)| m_replace(k, [v.as_str()])).collect();
        dir.modify(&existing, mods).await.map(|_| existing.clone())
    };
    let target = a.audited("stratégie ppolicy", &existing, "", res)?;
    Ok(Hx::ok(format!("Stratégie enregistrée : {}", dn::rdn_value(&target))).close_modal().refresh_page().empty())
}

// ---------------------------------------------------------------- corbeille AD

pub async fn recycle(a: Auth) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    if !dir.is_ad() {
        return Err(AppError::bad_request("Active Directory requis"));
    }
    let base = dir.base().to_string();
    let (v, truncated) = dir
        .search_paged_ctrl(
            &format!("CN=Deleted Objects,{base}"),
            Scope::OneLevel,
            "(isDeleted=TRUE)",
            &[
                "cn",
                "name",
                "objectClass",
                "lastKnownParent",
                "msDS-LastKnownRDN",
                "whenChanged",
                "isRecycled",
                "sAMAccountName",
            ],
            2000,
            vec![ctrl::show_deleted(), ctrl::show_recycled()],
        )
        .await?;
    let mut items: Vec<&Entry> = v.iter().collect();
    items.sort_by_key(|e| std::cmp::Reverse(e.s("whenChanged")));
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|e| {
            let k = crate::directory::Kind::of(e);
            let rdn =
                e.str("msDS-LastKnownRDN").unwrap_or_else(|| e.s("cn").split('\n').next().unwrap_or("").to_string());
            // Sans corbeille, les objets supprimés sont des « tombstones » (isRecycled)
            // mais restent réanimables ; avec la corbeille, un objet recyclé ne l'est plus.
            let recycled = dir.info.recycle_bin && e.bool("isRecycled").unwrap_or(false);
            vec![
                format!("<span class=\"name\">{}{}</span>", kicon(k.icon()), esc(&rdn)),
                esc(k.label()),
                format!("<span class=\"small mono\">{}</span>", esc(&dn::canonical(&e.s("lastKnownParent")))),
                esc(&e.str("whenChanged").and_then(|x| parse_generalized(&x)).map(fmt_dt).unwrap_or_default()),
                if recycled {
                    badge("muted", "recyclé (non restaurable)")
                } else {
                    format!(
                        "<div class=\"right\">{}</div>",
                        btn_post(
                            "Restaurer",
                            "recycle",
                            &format!("/recycle/restore?dn={}", url(&e.dn)),
                            "Restaurer cet objet dans son emplacement d'origine ?",
                            ""
                        )
                    )
                },
            ]
        })
        .collect();
    let mut body = String::new();
    if !dir.info.recycle_bin {
        body.push_str("<div class=\"notice warn\">La corbeille AD n'est pas activée : les objets restaurés (« réanimation de tombstone ») perdent la plupart de leurs attributs, dont l'appartenance aux groupes.</div>");
    }
    if truncated {
        body.push_str("<div class=\"notice\">Affichage limité aux 2000 premiers objets.</div>");
    }
    body.push_str(&table(&["Objet", "Type", "Dernier emplacement", "Supprimé le", ""], &rows, "Aucun objet supprimé."));
    render(&Generic {
        ctx: a.ctx("recycle"),
        title: "Objets supprimés".into(),
        subtitle: "Corbeille Active Directory".into(),
        actions: String::new(),
        body,
    })
}

pub async fn recycle_restore(a: Auth, Query(q): Query<DnQ>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let e = dir
        .read_ctrl(
            &q.dn,
            &["cn", "lastKnownParent", "msDS-LastKnownRDN", "objectClass"],
            vec![ctrl::show_deleted(), ctrl::show_recycled()],
        )
        .await?
        .ok_or_else(|| AppError::not_found("objet supprimé introuvable"))?;
    let rdn_val = e.str("msDS-LastKnownRDN").unwrap_or_else(|| e.s("cn").split('\n').next().unwrap_or("").to_string());
    let parent = e.s("lastKnownParent");
    if rdn_val.is_empty() || parent.is_empty() {
        return Err(AppError::bad_request("informations de restauration manquantes (lastKnownParent)"));
    }
    let attr = if e.has_class("organizationalUnit") { "OU" } else { "CN" };
    let new_dn = dn::child(attr, &rdn_val, &parent);
    let res = dir
        .modify_ctrl(
            &q.dn,
            vec![m_clear("isDeleted"), m_replace("distinguishedName", [new_dn.as_str()])],
            vec![ctrl::show_deleted()],
        )
        .await;
    a.audited("restauration", &new_dn, "", res)?;
    Ok(Hx::ok(format!("Objet restauré : {}", dn::canonical(&new_dn))).refresh_page().empty())
}

// ---------------------------------------------------------------- schéma

#[derive(Deserialize, Default)]
pub struct SchemaQ {
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub class: String,
    #[serde(default)]
    pub attr: String,
}

pub async fn schema_page(a: Auth, Query(q): Query<SchemaQ>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let schema = a.st.schema(&mut dir).await?;
    let mut body = format!(
        "<form class=\"row\" method=\"get\" action=\"/schema\" style=\"margin-bottom:14px\"><input type=\"search\" name=\"q\" value=\"{}\" placeholder=\"Rechercher une classe ou un attribut…\" style=\"max-width:360px\"><button type=\"submit\" class=\"btn-sm\">Rechercher</button></form>",
        esc(&q.q)
    );
    if !q.class.is_empty() {
        if let Some(c) = schema.classes.get(&q.class.to_ascii_lowercase()) {
            let (must, may) = schema.allowed(std::slice::from_ref(&q.class));
            let link = |n: &String| format!("<a href=\"/schema?attr={}\">{}</a>", url(n), esc(n));
            body.push_str(&format!(
                "<section class=\"card\"><h2>Classe {}</h2>{}<h3>Obligatoires ({})</h3><p class=\"mono small\">{}</p><h3>Facultatifs ({})</h3><p class=\"mono small\">{}</p></section>",
                esc(&q.class),
                kv(&[
                    ("OID".into(), c.oid.clone()),
                    ("Type".into(), format!("{:?}", c.kind)),
                    ("Hérite de".into(), c.sups.join(", ")),
                    ("Auxiliaires".into(), c.aux.join(", ")),
                ]),
                must.len(),
                must.iter().map(link).collect::<Vec<_>>().join(", "),
                may.len(),
                may.iter().map(link).collect::<Vec<_>>().join(", ")
            ));
        }
    } else if !q.attr.is_empty() {
        if let Some(at) = schema.attr(&q.attr) {
            body.push_str(&format!(
                "<section class=\"card\"><h2>Attribut {}</h2>{}</section>",
                esc(&q.attr),
                kv(&[
                    ("OID".into(), at.oid.clone()),
                    ("Noms".into(), at.names.join(", ")),
                    ("Description".into(), at.desc.clone()),
                    ("Syntaxe".into(), format!("{} ({})", schema.syntax_label(&q.attr), at.syntax)),
                    ("Valeur unique".into(), if at.single { "oui".into() } else { "non".into() }),
                    ("Lecture seule".into(), if at.no_user_mod { "oui".into() } else { "non".into() }),
                    ("Opérationnel".into(), if at.operational { "oui".into() } else { "non".into() }),
                ])
            ));
        }
    } else if !q.q.is_empty() {
        let ql = q.q.to_lowercase();
        let mut classes: Vec<&String> = schema.classes.keys().filter(|k| k.contains(&ql)).collect();
        classes.sort();
        classes.dedup();
        let mut attrs: Vec<&String> = schema.attrs.keys().filter(|k| k.contains(&ql)).collect();
        attrs.sort();
        let crow: Vec<Vec<String>> = classes
            .iter()
            .take(200)
            .map(|c| {
                let name = schema.classes[*c].names.first().cloned().unwrap_or_else(|| (*c).clone());
                vec![
                    format!("<a href=\"/schema?class={}\">{}</a>", url(&name), esc(&name)),
                    esc(&schema.classes[*c].oid),
                ]
            })
            .collect();
        let arow: Vec<Vec<String>> = attrs
            .iter()
            .take(200)
            .map(|k| {
                let a = &schema.attrs[*k];
                let name = a.names.iter().find(|n| n.to_lowercase() == **k).cloned().unwrap_or_else(|| (*k).clone());
                vec![
                    format!("<a href=\"/schema?attr={}\">{}</a>", url(&name), esc(&name)),
                    esc(schema.syntax_label(&name)),
                    if a.single { "unique".into() } else { "multiple".into() },
                ]
            })
            .collect();
        body.push_str(&format!(
            "<div class=\"cards\"><section><h2>Classes</h2>{}</section><section><h2>Attributs</h2>{}</section></div>",
            table(&["Classe", "OID"], &crow, "Aucune."),
            table(&["Attribut", "Syntaxe", "Valeurs"], &arow, "Aucun.")
        ));
    }
    let n_cls = schema.classes.values().map(|c| &c.oid).collect::<std::collections::HashSet<_>>().len();
    let n_att = schema.attrs.values().map(|c| &c.oid).collect::<std::collections::HashSet<_>>().len();
    render(&Generic {
        ctx: a.ctx("schema"),
        title: "Schéma".into(),
        subtitle: format!("{n_cls} classes, {n_att} attributs — {}", dir.info.subschema.clone().unwrap_or_default()),
        actions: String::new(),
        body,
    })
}

// ---------------------------------------------------------------- audit

#[derive(Deserialize, Default)]
pub struct AuditQ {
    #[serde(default)]
    pub q: String,
}

pub async fn audit_page(a: Auth, Query(q): Query<AuditQ>) -> AppResult<Response> {
    let events = a.st.audit.tail(2000);
    let ql = q.q.to_lowercase();
    let rows: Vec<Vec<String>> = events
        .iter()
        .filter(|e| {
            ql.is_empty()
                || format!("{} {} {} {} {}", e.user, e.action, e.target, e.detail, e.ip).to_lowercase().contains(&ql)
        })
        .take(500)
        .map(|e| {
            let ts = chrono::DateTime::parse_from_rfc3339(&e.ts)
                .map(|d| fmt_dt(d.with_timezone(&chrono::Utc)))
                .unwrap_or_else(|_| e.ts.clone());
            vec![
                format!("<span class=\"nowrap small\">{}</span>", esc(&ts)),
                esc(&e.user),
                format!("<span class=\"small mono\">{}</span>", esc(&e.ip)),
                esc(&e.action),
                format!("<span class=\"small mono\">{}</span>", esc(&e.target)),
                if e.ok { badge("ok", "succès") } else { badge("danger", "échec") },
                format!("<span class=\"small\">{}</span>", esc(&e.detail)),
            ]
        })
        .collect();
    let body = format!(
        "{}<form class=\"row\" method=\"get\" action=\"/audit\" style=\"margin-bottom:12px\"><input type=\"search\" name=\"q\" value=\"{}\" placeholder=\"Filtrer (utilisateur, action, objet…)\" style=\"max-width:360px\"><button type=\"submit\" class=\"btn-sm\">Filtrer</button></form>{}",
        if a.st.audit.enabled() {
            String::new()
        } else {
            "<div class=\"notice warn\">Journal d'audit désactivé dans la configuration.</div>".into()
        },
        esc(&q.q),
        table(&["Date", "Utilisateur", "IP", "Action", "Cible", "Résultat", "Détail"], &rows, "Aucun événement.")
    );
    render(&Generic {
        ctx: a.ctx("audit"),
        title: "Journal d'audit".into(),
        subtitle: format!("Actions effectuées via {} (500 dernières)", a.st.cfg.server.title),
        actions: String::new(),
        body,
    })
}
