//! Kerberos : vue d'ensemble du royaume, SPN (recherche, doublons, ajout/retrait),
//! délégation (non contrainte, contrainte, RBCD), types de chiffrement, keytabs.

use super::{DlgForm, Generic};
use crate::directory::kinds::Kind;
use crate::directory::ops;
use crate::error::{AppError, AppResult};
use crate::ldap::codec::{enctypes, filetime_to_dt, fmt_dt_opt, sid_to_string, uac};
use crate::ldap::dir::{Mods, m_clear, m_delete, m_replace};
use crate::ldap::{Dir, Entry, security};
use crate::services::kerberos::{self as krb, crypto};
use crate::web::auth::Auth;
use crate::web::form::FormData;
use crate::web::html::{Hx, badge, btn_dialog, btn_post, esc, kicon, kv, render, table, url};
use axum::extract::{Path, Query};
use axum::http::header;
use axum::response::{Html, IntoResponse, Response};
use ldap3::Scope;
use serde::Deserialize;
use std::collections::HashMap;

// ---------------------------------------------------------------- onglet Kerberos d'un compte

pub async fn tab_html(_a: &Auth, dir: &mut Dir, e: &Entry) -> AppResult<String> {
    if !dir.is_ad() {
        return Ok(
            "<div class=\"notice\">Paramètres Kerberos disponibles pour Active Directory / Samba AD.</div>".into()
        );
    }
    let du = url(&e.dn);
    let mut h = String::new();
    // SPN
    let spns = e.strs("servicePrincipalName");
    h.push_str("<h3 style=\"margin-top:0\">Noms principaux de service (SPN)</h3>");
    let rows: Vec<Vec<String>> = spns
        .iter()
        .map(|s| {
            vec![
                format!("<span class=\"mono\">{}</span>", esc(s)),
                format!(
                    "<div class=\"right\">{}</div>",
                    btn_post(
                        "Retirer",
                        "trash",
                        &format!("/kerberos/spn/change?op=remove&dn={du}&spn={}", url(s)),
                        "Retirer ce SPN ?",
                        "btn-ghost"
                    )
                ),
            ]
        })
        .collect();
    h.push_str(&table(&["SPN", ""], &rows, "Aucun SPN."));
    h.push_str(&format!(
        "<form class=\"row\" style=\"margin-top:8px\" hx-post=\"/kerberos/spn/change?op=add&dn={du}\" hx-swap=\"none\">\
         <input type=\"text\" name=\"spn\" placeholder=\"ex. HTTP/web.{}\" class=\"mono\" required><button type=\"submit\" class=\"btn-sm\">Ajouter</button></form>",
        esc(&dir.info.domain_dns)
    ));

    // Types de chiffrement
    let enc = e.int("msDS-SupportedEncryptionTypes").unwrap_or(0);
    h.push_str(&format!("<h3>Types de chiffrement pris en charge</h3><form hx-post=\"/kerberos/settings?section=enctypes&dn={du}\" hx-swap=\"none\"><div class=\"checks\">"));
    for (v, l) in enctypes::LABELS {
        h.push_str(&format!(
            "<label><input type=\"checkbox\" name=\"et\" value=\"{v}\" {}> {}</label>",
            if enc & v != 0 { "checked" } else { "" },
            esc(l)
        ));
    }
    h.push_str(&format!(
        "</div><p class=\"small muted\">Valeur actuelle : {} {}. Recommandé : AES uniquement (0x18).</p><button type=\"submit\" class=\"btn-sm\">Enregistrer</button></form>",
        enc,
        if enc == 0 { "(non défini : valeurs par défaut du domaine)" } else { "" }
    ));

    // Délégation
    let u = e.int("userAccountControl").unwrap_or(0);
    let a2d = e.strs("msDS-AllowedToDelegateTo");
    let mode = if u & uac::TRUSTED_FOR_DELEGATION != 0 {
        "unconstrained"
    } else if !a2d.is_empty() && u & uac::TRUSTED_TO_AUTH_FOR_DELEGATION != 0 {
        "constrained_any"
    } else if !a2d.is_empty() {
        "constrained_k"
    } else {
        "none"
    };
    let radio = |v: &str, l: &str| {
        format!(
            "<label><input type=\"radio\" name=\"mode\" value=\"{v}\" {}> {}</label>",
            if v == mode { "checked" } else { "" },
            esc(l)
        )
    };
    h.push_str(&format!("<h3>Délégation</h3><form hx-post=\"/kerberos/settings?section=delegation&dn={du}\" hx-swap=\"none\"><div class=\"checks\">"));
    h.push_str(&radio("none", "Ne pas approuver ce compte pour la délégation"));
    h.push_str(&radio(
        "unconstrained",
        "Approuver pour la délégation à n'importe quel service (Kerberos uniquement) — déconseillé",
    ));
    h.push_str(&radio(
        "constrained_k",
        "Approuver pour la délégation aux services spécifiés uniquement — Kerberos uniquement",
    ));
    h.push_str(&radio(
        "constrained_any",
        "Approuver pour la délégation aux services spécifiés uniquement — tout protocole d'authentification",
    ));
    h.push_str(&format!(
        "</div><label class=\"small muted\" style=\"display:block;margin-top:8px\">Services autorisés (msDS-AllowedToDelegateTo, un SPN par ligne)</label>\
         <textarea name=\"services\" class=\"mono\" rows=\"3\">{}</textarea><div style=\"margin-top:8px\"><button type=\"submit\" class=\"btn-sm\">Enregistrer</button></div></form>",
        esc(&a2d.join("\n"))
    ));

    // RBCD
    h.push_str("<h3>Délégation basée sur les ressources (RBCD)</h3><p class=\"small muted\">Comptes autorisés à agir au nom d'autres utilisateurs auprès de ce compte (msDS-AllowedToActOnBehalfOfOtherIdentity).</p>");
    let mut rbcd_rows = Vec::new();
    if let Some(raw) = e.bin("msDS-AllowedToActOnBehalfOfOtherIdentity") {
        if let Some(sd) = security::parse_sd(raw) {
            let sids: Vec<String> = sd.dacl.iter().map(|x| x.sid.clone()).collect();
            let names = security::resolve_sids(dir, &sids).await;
            for s in sids {
                let n = names.get(&s).map(|x| x.0.clone()).unwrap_or_else(|| s.clone());
                rbcd_rows.push(vec![
                    format!(
                        "<label class=\"row\"><input type=\"checkbox\" name=\"dn\" value=\"{}\"> {}</label>",
                        esc(&s),
                        esc(&n)
                    ),
                    format!("<span class=\"mono small\">{}</span>", esc(&s)),
                ]);
            }
        }
    }
    h.push_str(&format!(
        "<form data-selection-scope hx-post=\"/kerberos/settings?section=rbcd_remove&dn={du}\" hx-swap=\"none\">{}<div class=\"row\" style=\"margin-top:8px\">\
         <button type=\"button\" class=\"btn-sm\" hx-get=\"/pick?mode=multi&kinds=computer,user,service&action={}&title=Autoriser%20la%20d%C3%A9l%C3%A9gation\" hx-target=\"#modal2\">Ajouter…</button>\
         <button type=\"submit\" class=\"btn-sm btn-danger\" {}>Retirer la sélection</button></div></form>",
        table(&["Principal", "SID"], &rbcd_rows, "Aucun compte autorisé."),
        url(&format!("/kerberos/settings?section=rbcd_add&dn={}", e.dn)),
        if rbcd_rows.is_empty() { "disabled" } else { "" }
    ));

    // Informations
    h.push_str("<h3>Informations</h3>");
    let mut facts = vec![
        (
            "Numéro de version de clé (kvno)".to_string(),
            e.int("msDS-KeyVersionNumber").map(|v| v.to_string()).unwrap_or("—".into()),
        ),
        ("Mot de passe modifié".to_string(), fmt_dt_opt(e.int("pwdLastSet").and_then(filetime_to_dt))),
    ];
    if let Some(p) = e.str("msDS-PrincipalName") {
        facts.push(("Nom de principal".into(), p));
    }
    h.push_str(&kv(&facts));
    h.push_str(&format!(
        "<div class=\"form-actions\">{}</div>",
        btn_dialog("Générer un keytab…", "key", &format!("/kerberos/keytab?dn={du}"), "")
    ));
    Ok(format!(
        "<div hx-get=\"/obj/tab?dn={du}&tab=kerberos\" hx-trigger=\"refresh-tab from:body\" hx-swap=\"outerHTML\">{h}</div>"
    ))
}

#[derive(Deserialize)]
pub struct SpnQ {
    pub op: String,
    pub dn: String,
    #[serde(default)]
    pub spn: String,
}

pub async fn spn_change(a: Auth, Query(q): Query<SpnQ>, f: FormData) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let spn = if q.spn.is_empty() { f.s("spn") } else { q.spn.clone() };
    if spn.is_empty() {
        return Err(AppError::bad_request("SPN requis"));
    }
    let res = match q.op.as_str() {
        "add" => krb::add_spn(&mut dir, &q.dn, &spn).await,
        "remove" => dir.modify(&q.dn, vec![m_delete("servicePrincipalName", [spn.as_str()])]).await,
        _ => return Err(AppError::bad_request("opération inconnue")),
    };
    a.audited(if q.op == "add" { "ajout de SPN" } else { "retrait de SPN" }, &q.dn, &spn, res)?;
    Ok(Hx::ok(format!("SPN {} {}", spn, if q.op == "add" { "ajouté" } else { "retiré" }))
        .trigger("refresh-tab")
        .empty())
}

#[derive(Deserialize)]
pub struct SettingsQ {
    pub section: String,
    pub dn: String,
}

pub async fn settings_save(a: Auth, Query(q): Query<SettingsQ>, f: FormData) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let e = dir
        .read_req(
            &q.dn,
            &["userAccountControl", "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity"],
        )
        .await?;
    let mut mods: Mods = Vec::new();
    let label;
    match q.section.as_str() {
        "enctypes" => {
            let v: i64 = f.all("et").iter().filter_map(|x| x.parse::<i64>().ok()).sum();
            mods.push(if v == 0 {
                m_clear("msDS-SupportedEncryptionTypes")
            } else {
                m_replace("msDS-SupportedEncryptionTypes", [v.to_string()])
            });
            label = "types de chiffrement";
        }
        "delegation" => {
            let u = e.int("userAccountControl").unwrap_or(0);
            let mut nu = u & !(uac::TRUSTED_FOR_DELEGATION | uac::TRUSTED_TO_AUTH_FOR_DELEGATION);
            let services = f.lines("services");
            let mode = f.s("mode");
            match mode.as_str() {
                "unconstrained" => nu |= uac::TRUSTED_FOR_DELEGATION,
                "constrained_any" => nu |= uac::TRUSTED_TO_AUTH_FOR_DELEGATION,
                _ => {}
            }
            if mode.starts_with("constrained") && services.is_empty() {
                return Err(AppError::bad_request("indiquez au moins un service pour la délégation contrainte"));
            }
            if nu != u {
                mods.push(m_replace("userAccountControl", [nu.to_string()]));
            }
            let keep = if mode.starts_with("constrained") { services } else { vec![] };
            if keep != e.strs("msDS-AllowedToDelegateTo") {
                mods.push(if keep.is_empty() {
                    m_clear("msDS-AllowedToDelegateTo")
                } else {
                    m_replace("msDS-AllowedToDelegateTo", keep.iter())
                });
            }
            label = "délégation";
        }
        "rbcd_add" | "rbcd_remove" => {
            let mut sids: Vec<String> = e
                .bin("msDS-AllowedToActOnBehalfOfOtherIdentity")
                .and_then(security::parse_sd)
                .map(|sd| sd.dacl.into_iter().map(|x| x.sid).collect())
                .unwrap_or_default();
            if q.section == "rbcd_add" {
                for p in f.all("pick") {
                    let x = dir.read_req(&p, &["objectSid"]).await?;
                    if let Some(s) = x.bin("objectSid").and_then(sid_to_string) {
                        if !sids.contains(&s) {
                            sids.push(s);
                        }
                    }
                }
            } else {
                let rm = f.all("dn");
                sids.retain(|s| !rm.contains(s));
            }
            if sids.is_empty() {
                mods.push(m_clear("msDS-AllowedToActOnBehalfOfOtherIdentity"));
            } else {
                let sd = security::build_rbcd_sd(&sids).ok_or_else(|| AppError::internal("SID invalide"))?;
                mods.push(m_replace("msDS-AllowedToActOnBehalfOfOtherIdentity", [sd]));
            }
            label = "délégation RBCD";
        }
        _ => return Err(AppError::bad_request("section inconnue")),
    }
    if mods.is_empty() {
        return Ok(Hx::new().toast("info", "Aucune modification").empty());
    }
    let res = dir.modify(&q.dn, mods).await;
    a.audited("Kerberos", &q.dn, label, res)?;
    Ok(Hx::ok(format!("Paramètres Kerberos enregistrés ({label})"))
        .close_modal_if(q.section == "rbcd_add")
        .trigger("refresh-tab")
        .empty())
}

// ---------------------------------------------------------------- page Kerberos

pub async fn page(a: Auth) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let info = dir.info.clone();
    let mut body = String::new();
    let mut facts = vec![("Royaume".to_string(), info.realm.clone())];
    if info.flavor.is_ad() {
        let base = info.base_dn.clone();
        if let Ok(Some(k)) =
            dir.read(&format!("CN=krbtgt,CN=Users,{base}"), &["pwdLastSet", "msDS-KeyVersionNumber"]).await
        {
            facts.push((
                "krbtgt : mot de passe modifié".into(),
                fmt_dt_opt(k.int("pwdLastSet").and_then(filetime_to_dt)),
            ));
            facts.push((
                "krbtgt : kvno".into(),
                k.int("msDS-KeyVersionNumber").map(|v| v.to_string()).unwrap_or("—".into()),
            ));
        }
        let f = "(&(objectCategory=computer)(|(userAccountControl:1.2.840.113556.1.4.803:=8192)(userAccountControl:1.2.840.113556.1.4.803:=67108864)))";
        let kdcs: Vec<String> = dir
            .search(&base, Scope::Subtree, f, &["dNSHostName"])
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|e| e.s("dNSHostName"))
            .collect();
        facts.push(("KDC (contrôleurs de domaine)".into(), kdcs.join(", ")));
    }
    body.push_str("<div class=\"cards\"><section class=\"card\"><h2>Royaume</h2>");
    body.push_str(&kv(&facts));
    body.push_str("</section>");
    body.push_str(&format!(
        "<section class=\"card\"><h2>Keytab</h2><p class=\"muted\">Générez un fichier keytab pour un compte de service (ktpass) ou à partir d'un mot de passe connu (ktutil).</p>{}</section></div>",
        btn_dialog("Générer un keytab…", "key", "/kerberos/keytab", "btn-primary")
    ));
    if info.flavor.is_ad() {
        body.push_str(
            "<h2 style=\"margin-top:24px\">Noms principaux de service</h2>\
             <form class=\"row\" hx-get=\"/kerberos/spn\" hx-target=\"#spn-res\"><input type=\"search\" name=\"q\" placeholder=\"Motif, ex. HTTP/* ou */sql01*\" class=\"mono\" style=\"max-width:380px\">\
             <button type=\"submit\" class=\"btn-sm btn-primary\">Rechercher</button>\
             <button type=\"button\" class=\"btn-sm\" hx-get=\"/kerberos/spn?dup=1\" hx-target=\"#spn-res\">Détecter les SPN en double</button></form>\
             <div id=\"spn-res\" style=\"margin-top:12px\"></div>",
        );
    } else {
        body.push_str("<div class=\"notice\" style=\"margin-top:16px\">Pour un KDC MIT ou Heimdal adossé à LDAP, la gestion des principaux s'effectue avec kadmin ; Arbor permet de générer des keytabs à partir d'un mot de passe connu.</div>");
    }
    render(&Generic {
        ctx: a.ctx("kerberos"),
        title: "Kerberos".into(),
        subtitle: "SPN, délégation, types de chiffrement et keytabs".into(),
        actions: String::new(),
        body,
    })
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    let (mut pi, mut ti, mut star, mut mark) = (0usize, 0usize, None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == t[ti] || p[pi] == '?') {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[derive(Deserialize)]
pub struct SpnSearchQ {
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub dup: Option<String>,
}

pub async fn spn_search(a: Auth, Query(q): Query<SpnSearchQ>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let base = dir.base().to_string();
    let pat = if q.q.trim().is_empty() { "*".to_string() } else { q.q.trim().to_string() };
    let ldap_pat: String = pat.chars().filter(|c| !matches!(c, '(' | ')' | '\\' | '\0')).collect();
    let filter = if q.dup.is_some() {
        "(servicePrincipalName=*)".to_string()
    } else {
        format!("(servicePrincipalName={ldap_pat})")
    };
    let (v, truncated) = dir
        .search_paged(
            &base,
            Scope::Subtree,
            &filter,
            &["servicePrincipalName", "sAMAccountName", "objectClass"],
            50_000,
        )
        .await?;
    let mut rows = Vec::new();
    if q.dup.is_some() {
        let mut map: HashMap<String, Vec<&Entry>> = HashMap::new();
        for e in &v {
            for s in e.strs("servicePrincipalName") {
                map.entry(s.to_lowercase()).or_default().push(e);
            }
        }
        let mut dups: Vec<_> = map.into_iter().filter(|(_, l)| l.len() > 1).collect();
        dups.sort_by(|a, b| a.0.cmp(&b.0));
        for (spn, owners) in dups {
            rows.push(vec![
                format!("<span class=\"mono\">{}</span>", esc(&spn)),
                owners
                    .iter()
                    .map(|e| {
                        format!(
                            "<a class=\"obj-name\" hx-get=\"/obj/props?dn={}\" hx-target=\"#modal\">{}</a>",
                            url(&e.dn),
                            esc(&e.s("sAMAccountName"))
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
            ]);
        }
        let html = format!(
            "{}{}",
            if rows.is_empty() {
                "<div class=\"notice ok\">Aucun SPN en double.</div>".to_string()
            } else {
                format!(
                    "<div class=\"notice danger\">{} SPN en double : l'authentification Kerberos échouera pour ces services.</div>",
                    rows.len()
                )
            },
            table(&["SPN", "Comptes"], &rows, "")
        );
        return Ok(Html(html).into_response());
    }
    for e in &v {
        for s in e.strs("servicePrincipalName") {
            if glob_match(&pat, &s) {
                rows.push(vec![
                    format!("<span class=\"mono\">{}</span>", esc(&s)),
                    format!(
                        "<span class=\"name\">{}<a class=\"obj-name\" hx-get=\"/obj/props?dn={}&tab=kerberos\" hx-target=\"#modal\">{}</a></span>",
                        kicon(Kind::of(e).icon()),
                        url(&e.dn),
                        esc(&e.s("sAMAccountName"))
                    ),
                ]);
            }
        }
    }
    let note = if truncated { "<div class=\"notice warn\">Résultats tronqués.</div>" } else { "" };
    Ok(Html(format!(
        "{note}<p class=\"small muted\">{} SPN</p>{}",
        rows.len(),
        table(&["SPN", "Compte"], &rows, "Aucun SPN trouvé.")
    ))
    .into_response())
}

// ---------------------------------------------------------------- keytab

#[derive(Deserialize, Default)]
pub struct KtQ {
    #[serde(default)]
    pub dn: String,
}

pub async fn keytab_form(a: Auth, Query(q): Query<KtQ>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let ad = dir.is_ad();
    let realm = dir.info.realm.clone();
    let mut principals = Vec::new();
    let mut account = String::new();
    let mut kvno = String::new();
    if !q.dn.is_empty() {
        let e = dir
            .read_req(
                &q.dn,
                &[
                    "sAMAccountName",
                    "userPrincipalName",
                    "servicePrincipalName",
                    "msDS-KeyVersionNumber",
                    "uid",
                    "krbPrincipalName",
                ],
            )
            .await?;
        account = e.display_name();
        if ad {
            principals.push(e.s("sAMAccountName"));
            principals.extend(e.strs("servicePrincipalName"));
            kvno = e.int("msDS-KeyVersionNumber").map(|v| v.to_string()).unwrap_or_default();
        } else {
            principals
                .extend(e.strs("krbPrincipalName").into_iter().map(|p| p.split('@').next().unwrap_or(&p).to_string()));
            if principals.is_empty() {
                principals.push(e.s("uid"));
            }
        }
    }
    let u = super::objects::uid();
    let mut body = format!(
        "<div class=\"form-grid\">\
         <label>Compte</label><div class=\"inline\"><input type=\"text\" name=\"dn\" id=\"kt-dn-{u}\" value=\"{dn}\" class=\"mono\" placeholder=\"(facultatif : mot de passe connu)\" hx-get=\"/kerberos/keytab\" hx-trigger=\"change\" hx-target=\"#modal\" hx-include=\"this\">\
         <button type=\"button\" class=\"btn-sm\" hx-get=\"/pick?mode=single&target=kt-dn-{u}&kinds=user,computer,service\" hx-target=\"#modal2\">…</button></div>",
        dn = esc(&q.dn)
    );
    if !account.is_empty() {
        body.push_str(&format!("<label></label><div class=\"muted\">{}</div>", esc(&account)));
    }
    body.push_str("<label>Mode</label><div class=\"checks\">");
    if ad && !q.dn.is_empty() {
        body.push_str("<label><input type=\"radio\" name=\"mode\" value=\"reset\" checked> Réinitialiser le mot de passe du compte puis générer le keytab (équivalent ktpass)</label>");
        body.push_str("<label><input type=\"radio\" name=\"mode\" value=\"known\"> Utiliser le mot de passe actuel (connu)</label>");
    } else {
        body.push_str("<label><input type=\"radio\" name=\"mode\" value=\"known\" checked> Mot de passe connu</label>");
    }
    body.push_str(&format!(
        "</div><label>Mot de passe</label><div class=\"inline\"><input type=\"password\" name=\"password\" id=\"kt-pw-{u}\" autocomplete=\"new-password\" placeholder=\"vide = aléatoire (mode réinitialisation)\">\
         <button type=\"button\" class=\"btn-sm\" data-action=\"genpw\" data-targets=\"kt-pw-{u}\">Générer</button></div>\
         <label>Principaux (un par ligne)</label><textarea name=\"principals\" class=\"mono\" rows=\"4\" required>{}</textarea>\
         <label>Royaume</label><input type=\"text\" name=\"realm\" value=\"{}\" class=\"mono\">\
         <label>Sel (facultatif)</label><input type=\"text\" name=\"salt\" class=\"mono\" placeholder=\"automatique\">\
         <label>kvno</label><input type=\"number\" name=\"kvno\" value=\"{}\" placeholder=\"automatique\" style=\"max-width:140px\">\
         <label>Chiffrement</label><div class=\"checks\">\
         <label><input type=\"checkbox\" name=\"et\" value=\"18\" checked> AES256-CTS-HMAC-SHA1-96</label>\
         <label><input type=\"checkbox\" name=\"et\" value=\"17\" checked> AES128-CTS-HMAC-SHA1-96</label>\
         <label><input type=\"checkbox\" name=\"et\" value=\"23\"> RC4-HMAC (compatibilité)</label></div></div>\
         <div id=\"kt-res-{u}\" style=\"margin-top:14px\"></div>",
        esc(&principals.join("\n")),
        esc(&realm),
        esc(&kvno)
    ));
    let mut d = DlgForm::new("Générer un keytab", "key", "/kerberos/keytab", body, "Générer");
    d.swap = "innerHTML";
    d.target = format!("#kt-res-{u}");
    d.cancel = "Fermer";
    render(&d)
}

pub async fn keytab_submit(a: Auth, f: FormData) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let realm = f.opt("realm").unwrap_or_else(|| dir.info.realm.clone()).to_uppercase();
    let target = f.s("dn");
    let mode = f.s("mode");
    let mut password = f.raw("password");
    let principals: Vec<String> =
        f.lines("principals").into_iter().map(|p| p.split('@').next().unwrap_or(&p).to_string()).collect();
    if principals.is_empty() {
        return Err(AppError::bad_request("au moins un principal est requis"));
    }
    let etypes: Vec<i32> = f.all("et").iter().filter_map(|x| x.parse().ok()).collect();
    if etypes.is_empty() {
        return Err(AppError::bad_request("sélectionnez au moins un type de chiffrement"));
    }
    let mut generated = false;
    let mut account: Option<Entry> = None;
    if !target.is_empty() {
        account = Some(
            dir.read_req(&target, &["sAMAccountName", "objectClass", "msDS-KeyVersionNumber", "userAccountControl"])
                .await?,
        );
    }
    if mode == "reset" {
        if !dir.is_ad() || target.is_empty() {
            return Err(AppError::bad_request("la réinitialisation n'est possible que pour un compte AD"));
        }
        if password.is_empty() {
            password = ops::generate_password(32);
            generated = true;
        }
        let res = ops::set_password(&mut dir, &target, &password, false, false).await.map(|_| ());
        a.audited("keytab (réinitialisation du mot de passe)", &target, &principals.join(", "), res)?;
        account = Some(
            dir.read_req(&target, &["sAMAccountName", "objectClass", "msDS-KeyVersionNumber", "userAccountControl"])
                .await?,
        );
    } else if password.is_empty() {
        return Err(AppError::bad_request("mot de passe requis"));
    }
    let kvno: u32 = f
        .int("kvno")
        .map(|v| v as u32)
        .or_else(|| account.as_ref().and_then(|e| e.int("msDS-KeyVersionNumber")).map(|v| v as u32))
        .unwrap_or(1);
    let salt = match f.opt("salt") {
        Some(s) => s,
        None => match (&account, dir.is_ad()) {
            (Some(e), true) => {
                let is_computer = e.has_class("computer")
                    || e.int("userAccountControl").unwrap_or(0) & uac::WORKSTATION_TRUST_ACCOUNT != 0;
                crypto::ad_salt(&realm, &e.s("sAMAccountName"), is_computer)
            }
            _ => crypto::mit_salt(&realm, &principals[0]),
        },
    };
    let spec = krb::KeytabSpec {
        principals: principals.clone(),
        realm: realm.clone(),
        password: password.clone(),
        salt: salt.clone(),
        kvno,
        etypes: etypes.clone(),
    };
    let data = krb::build_keytab(&spec);
    let fname = format!("{}.keytab", principals[0].replace(['/', '$', '\\', ':'], "_"));
    let token = a.s.add_download(fname.clone(), "application/octet-stream", data);
    if mode != "reset" {
        a.audit("keytab (mot de passe connu)", &target, true, &principals.join(", "));
    }
    let u = super::objects::uid();
    let mut html = format!(
        "<div class=\"notice ok\">Keytab généré : {} entrée(s). Le lien de téléchargement est à usage unique (10 min).</div>\
         <p><a class=\"btn btn-primary\" href=\"/download/{token}\" hx-boost=\"false\" download>Télécharger {}</a></p>",
        principals.len() * etypes.len(),
        esc(&fname)
    );
    html.push_str(&kv(&[
        ("Principaux".into(), principals.iter().map(|p| format!("{p}@{realm}")).collect::<Vec<_>>().join(", ")),
        ("kvno".into(), kvno.to_string()),
        ("Sel".into(), salt),
        ("Chiffrement".into(), etypes.iter().map(|e| crypto::etype_name(*e)).collect::<Vec<_>>().join(", ")),
    ]));
    if generated {
        html.push_str(&format!(
            "<p style=\"margin-top:10px\"><button type=\"button\" class=\"btn-sm\" data-action=\"reveal\" data-target=\"ktpw-{u}\">Afficher le mot de passe généré</button></p><div id=\"ktpw-{u}\" class=\"secret hidden\">{}</div>",
            esc(&password)
        ));
    }
    if mode == "reset" {
        html.push_str(&format!(
            "<p class=\"small muted\">{}</p>",
            badge("warn", "Le mot de passe du compte a été changé : mettez à jour les services qui l'utilisent.")
        ));
    }
    Ok(Hx::new().trigger("refresh-tab").body(html))
}

pub async fn download(a: Auth, Path(token): Path<String>) -> AppResult<Response> {
    let d = a.s.take_download(&token).ok_or_else(|| AppError::not_found("lien expiré ou déjà utilisé"))?;
    let data: Vec<u8> = d.data.to_vec();
    Ok((
        [
            (header::CONTENT_TYPE, d.mime.clone()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", d.filename.replace('"', ""))),
        ],
        data,
    )
        .into_response())
}
