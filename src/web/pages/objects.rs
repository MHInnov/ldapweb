//! Fiches de propriétés et actions sur les objets (création, mot de passe,
//! activation, déplacement, renommage, suppression, appartenance aux groupes).

use crate::directory::kinds::{Kind, account_state};
use crate::directory::ops;
use crate::directory::sheets::{FK, Tab, read_attrs, tabs_for};
use crate::error::{AppError, AppResult};
use crate::ldap::codec::{
    dt_to_filetime, filetime_to_dt, filter_escape, fmt_dt, fmt_dt_opt, guid_to_string, parse_generalized,
    sid_to_string, uac,
};
use crate::ldap::dir::{Mods, ctrl, m_clear, m_replace};
use crate::ldap::{Dir, Entry, dn, security};
use crate::web::auth::{Auth, Ctx};
use crate::web::form::FormData;
use crate::web::html::{Hx, esc, render, url};
use crate::web::session::random_token;
use askama::Template;
use axum::extract::Query;
use axum::response::{Html, IntoResponse, Response};
use chrono::{Local, NaiveDate, TimeZone, Utc};
use ldap3::Scope;
use serde::Deserialize;

pub fn uid() -> String {
    random_token(6).replace(['-', '_'], "x")
}

#[derive(Deserialize, Default)]
pub struct ObjQ {
    #[serde(default)]
    pub dn: String,
    #[serde(default)]
    pub tab: String,
    #[serde(default)]
    pub nested: Option<String>,
    #[serde(default)]
    pub unset: Option<String>,
}

pub struct Action {
    pub label: String,
    pub icon: &'static str,
    pub method: &'static str,
    pub url: String,
    pub class: &'static str,
    pub confirm: String,
}

fn act(label: &str, icon: &'static str, method: &'static str, url: String) -> Action {
    Action { label: label.into(), icon, method, url, class: "", confirm: String::new() }
}

pub struct Props {
    pub uid: String,
    pub dn: String,
    pub name: String,
    pub icon: &'static str,
    pub kind_label: &'static str,
    pub badges: Vec<(&'static str, &'static str)>,
    pub actions: Vec<Action>,
    pub tabs: Vec<(String, String)>,
    pub active: String,
    pub body: String,
}

#[derive(Template)]
#[template(path = "props_modal.html")]
struct PropsModal {
    p: Props,
}

#[derive(Template)]
#[template(path = "obj_page.html")]
struct ObjPage {
    ctx: Ctx,
    p: Props,
    crumbs: Vec<(String, String)>,
}

async fn read_full(dir: &mut Dir, target: &str) -> AppResult<Entry> {
    let attrs = read_attrs(dir.is_ad());
    dir.read_req(target, &attrs).await
}

fn actions_for(e: &Entry, kind: Kind, a: &Auth) -> Vec<Action> {
    let du = url(&e.dn);
    let mut v = Vec::new();
    let st = account_state(e, a.s.info.flavor);
    if matches!(kind, Kind::User | Kind::Computer | Kind::ServiceAccount) {
        if kind != Kind::ServiceAccount {
            v.push(act("Réinitialiser le mot de passe", "key", "get", format!("/obj/password?dn={du}")));
        }
        if st.disabled {
            v.push(act("Activer", "power", "post", format!("/obj/state?op=enable&dn={du}")));
        } else {
            let mut x = act("Désactiver", "power", "post", format!("/obj/state?op=disable&dn={du}"));
            x.confirm = "Désactiver ce compte ?".into();
            v.push(x);
        }
        if st.locked {
            v.push(act("Déverrouiller", "unlock", "post", format!("/obj/state?op=unlock&dn={du}")));
        }
    }
    if kind.is_container() {
        v.push(act("Afficher le contenu", "folder", "link", format!("/dir?dn={du}")));
    }
    v.push(act("Renommer", "edit", "get", format!("/obj/rename?dn={du}")));
    v.push(act("Déplacer", "move", "get", format!("/obj/move?dn={du}")));
    let mut d = act("Supprimer", "trash", "get", format!("/obj/delete?dn={du}"));
    d.class = "btn-danger";
    v.push(d);
    v
}

async fn build_props(a: &Auth, dir: &mut Dir, target: &str, tab: &str) -> AppResult<Props> {
    let e = read_full(dir, target).await?;
    let kind = Kind::of(&e);
    let tabs = tabs_for(kind, dir.info.flavor);
    let active = if tab.is_empty() || !tabs.iter().any(|t| t.id == tab) {
        tabs[0].id
    } else {
        tabs.iter().find(|t| t.id == tab).unwrap().id
    };
    let body = tab_html(a, dir, &e, active, &ObjQ::default()).await?;
    let name = if kind == Kind::Domain { dn::dc_to_domain(&e.dn) } else { e.display_name() };
    Ok(Props {
        uid: uid(),
        dn: e.dn.clone(),
        name,
        icon: kind.icon(),
        kind_label: kind.label(),
        badges: crate::directory::kinds::state_badges(&e, dir.info.flavor),
        actions: actions_for(&e, kind, a),
        tabs: tabs.iter().map(|t| (t.id.to_string(), t.label.to_string())).collect(),
        active: active.to_string(),
        body,
    })
}

pub async fn props_modal(a: Auth, Query(q): Query<ObjQ>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let p = build_props(&a, &mut dir, &q.dn, &q.tab).await?;
    render(&PropsModal { p })
}

pub async fn page(a: Auth, Query(q): Query<ObjQ>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let p = build_props(&a, &mut dir, &q.dn, &q.tab).await?;
    let base = dir.base().to_string();
    let crumbs = dn::breadcrumb(&dn::parent(&q.dn), &base);
    render(&ObjPage { ctx: a.ctx("dir"), p, crumbs })
}

// ------------------------------------------------------------------ onglets

pub async fn tab(a: Auth, Query(q): Query<ObjQ>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    if q.tab == "browse" {
        return Ok(Html(browse_detail(&a, &mut dir, &q.dn).await?).into_response());
    }
    let e = read_full(&mut dir, &q.dn).await?;
    let html = tab_html(&a, &mut dir, &e, &q.tab, &q).await?;
    Ok(Html(html).into_response())
}

async fn tab_html(a: &Auth, dir: &mut Dir, e: &Entry, tab: &str, q: &ObjQ) -> AppResult<String> {
    let kind = Kind::of(e);
    let tabs = tabs_for(kind, dir.info.flavor);
    let def = tabs.iter().find(|t| t.id == tab);
    if let Some(t) = def {
        if !t.fields.is_empty() {
            return fields_tab(dir, e, t, "");
        }
    }
    match tab {
        "account" => {
            if dir.is_ad() {
                account_ad_tab(dir, e)
            } else {
                account_ldap_tab(dir, e).await
            }
        }
        "members" => members_tab(dir, e).await,
        "memberof" => memberof_tab(dir, e, q.nested.is_some()).await,
        "object" => object_tab(dir, e),
        "security" => security_tab(dir, e).await,
        "attrs" => super::attrs::attrs_tab_html(a, dir, e, q.unset.is_some()).await,
        "kerberos" => super::kerberos::tab_html(a, dir, e).await,
        "certs" => super::pki::certs_tab_html(dir, e),
        "gpo" => super::gpo::links_tab_html(a, dir, e).await,
        "laps" => laps_tab(a, dir, e).await,
        "bitlocker" => bitlocker_tab(a, dir, e).await,
        _ => Err(AppError::not_found("onglet inconnu")),
    }
}

// ---------------------------------------------------- onglet générique (champs)

pub struct FieldView {
    pub id: String,
    pub attr: String,
    pub label: String,
    pub kind: &'static str,
    pub value: String,
    pub options: Vec<(String, String)>,
    pub pick_kinds: &'static str,
}

#[derive(Template)]
#[template(path = "tab_fields.html")]
struct FieldsTpl {
    dn: String,
    tab: String,
    fields: Vec<FieldView>,
    editable: bool,
    note: String,
}

fn fields_tab(dir: &Dir, e: &Entry, t: &Tab, note: &str) -> AppResult<String> {
    let (rdn_attr, _) = dn::rdn_parts(&e.dn);
    let u = uid();
    let mut fields = Vec::new();
    for f in t.fields {
        let vals = e.strs(f.attr);
        let is_rdn = rdn_attr.eq_ignore_ascii_case(f.attr);
        let (kind, options) = match f.kind {
            _ if is_rdn => ("ro", vec![]),
            FK::Ro => ("ro", vec![]),
            FK::Text => ("text", vec![]),
            FK::Area => ("area", vec![]),
            FK::Lines => ("lines", vec![]),
            FK::Dn => ("dn", vec![]),
            FK::Select(opts) => {
                let mut o: Vec<(String, String)> = opts.iter().map(|(v, l)| (v.to_string(), l.to_string())).collect();
                if let Some(cur) = vals.first() {
                    if !o.iter().any(|(v, _)| v == cur) {
                        o.insert(0, (cur.clone(), format!("Autre ({cur})")));
                    }
                }
                ("select", o)
            }
        };
        let value = match kind {
            "lines" => vals.join("\n"),
            _ => vals.first().cloned().unwrap_or_default(),
        };
        fields.push(FieldView {
            id: format!("f-{u}-{}", f.attr.replace(|c: char| !c.is_ascii_alphanumeric(), "")),
            attr: f.attr.to_string(),
            label: f.label.to_string(),
            kind,
            value,
            options,
            pick_kinds: if f.attr == "managedBy" || f.attr == "manager" || f.attr == "owner" {
                "user,group,contact"
            } else {
                "user,group"
            },
        });
    }
    let editable = fields.iter().any(|f| f.kind != "ro");
    let _ = dir;
    Ok(FieldsTpl { dn: e.dn.clone(), tab: t.id.to_string(), fields, editable, note: note.to_string() }.render()?)
}

pub async fn tab_save(a: Auth, Query(q): Query<ObjQ>, f: FormData) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let e = read_full(&mut dir, &q.dn).await?;
    let kind = Kind::of(&e);
    let tabs = tabs_for(kind, dir.info.flavor);
    let t = tabs.iter().find(|t| t.id == q.tab).ok_or_else(|| AppError::bad_request("onglet inconnu"))?;
    let (rdn_attr, _) = dn::rdn_parts(&e.dn);
    let mut mods: Mods = Vec::new();
    let mut changed = Vec::new();
    for fd in t.fields {
        if matches!(fd.kind, FK::Ro) || rdn_attr.eq_ignore_ascii_case(fd.attr) {
            continue;
        }
        let key = format!("a.{}", fd.attr);
        if f.get(&key).is_none() {
            continue;
        }
        let new: Vec<String> = match fd.kind {
            FK::Lines => f.lines(&key),
            _ => f.opt(&key).into_iter().collect(),
        };
        let old = e.strs(fd.attr);
        if new == old {
            continue;
        }
        changed.push(fd.attr);
        if new.is_empty() {
            if !old.is_empty() {
                mods.push(m_clear(fd.attr));
            }
        } else {
            mods.push(m_replace(fd.attr, new.iter()));
        }
    }
    if mods.is_empty() {
        return Hx::new().toast("info", "Aucune modification").render_str(fields_tab(&dir, &e, t, "")?);
    }
    let res = dir.modify(&e.dn, mods).await;
    a.audited("modification", &e.dn, &format!("attributs : {}", changed.join(", ")), res)?;
    let e2 = read_full(&mut dir, &e.dn).await?;
    Hx::ok("Modifications enregistrées").refresh_list().render_str(fields_tab(&dir, &e2, t, "")?)
}

impl Hx {
    pub fn render_str(self, s: String) -> AppResult<Response> {
        Ok(self.body(s))
    }
}

// ---------------------------------------------------------------- onglet Compte

#[derive(Template)]
#[template(path = "tab_account_ad.html")]
struct AccountAdTpl {
    dn: String,
    is_user: bool,
    disabled: bool,
    locked: bool,
    pwd_expired: bool,
    expired: bool,
    upn_prefix: String,
    upn_suffix: String,
    suffixes: Vec<String>,
    netbios: String,
    sam: String,
    workstations: String,
    options: Vec<(&'static str, &'static str, bool)>,
    expires_date: String,
    facts: Vec<(String, String)>,
}

fn ft_fact(e: &Entry, attr: &str) -> String {
    match e.int(attr) {
        Some(v) => match filetime_to_dt(v) {
            Some(dt) => format!("{} ({})", fmt_dt(dt), crate::ldap::codec::ago(dt)),
            None => "jamais".into(),
        },
        None => "—".into(),
    }
}

const AD_USER_OPTIONS: &[(&str, &str, i64)] = &[
    ("never_expires", "Le mot de passe n'expire jamais", uac::DONT_EXPIRE_PASSWORD),
    ("disabled", "Le compte est désactivé", uac::ACCOUNTDISABLE),
    ("smartcard", "Une carte à puce est nécessaire pour l'ouverture de session interactive", uac::SMARTCARD_REQUIRED),
    (
        "reversible",
        "Enregistrer le mot de passe en utilisant un chiffrement réversible",
        uac::ENCRYPTED_TEXT_PWD_ALLOWED,
    ),
    ("not_delegated", "Le compte est sensible et ne peut pas être délégué", uac::NOT_DELEGATED),
    ("des_only", "Utiliser uniquement les types de chiffrement DES Kerberos", uac::USE_DES_KEY_ONLY),
    ("no_preauth", "Ne pas demander la pré-authentification Kerberos", uac::DONT_REQ_PREAUTH),
    ("passwd_notreqd", "Mot de passe non requis (PASSWD_NOTREQD)", uac::PASSWD_NOTREQD),
];
const AD_COMPUTER_OPTIONS: &[(&str, &str, i64)] = &[
    ("disabled", "Le compte est désactivé", uac::ACCOUNTDISABLE),
    ("not_delegated", "Le compte est sensible et ne peut pas être délégué", uac::NOT_DELEGATED),
    ("passwd_notreqd", "Mot de passe non requis (PASSWD_NOTREQD)", uac::PASSWD_NOTREQD),
];

fn account_ad_tab(dir: &Dir, e: &Entry) -> AppResult<String> {
    let kind = Kind::of(e);
    let is_user = kind == Kind::User;
    let st = account_state(e, dir.info.flavor);
    let u = e.int("userAccountControl").unwrap_or(0);
    let upn = e.s("userPrincipalName");
    let (upn_prefix, upn_suffix) = match upn.split_once('@') {
        Some((p, s)) => (p.to_string(), s.to_string()),
        None => (upn.clone(), dir.info.domain_dns.clone()),
    };
    let mut suffixes = vec![dir.info.domain_dns.clone()];
    for s in &dir.info.upn_suffixes {
        if !suffixes.iter().any(|x| x.eq_ignore_ascii_case(s)) {
            suffixes.push(s.clone());
        }
    }
    if !upn_suffix.is_empty() && !suffixes.iter().any(|x| x.eq_ignore_ascii_case(&upn_suffix)) {
        suffixes.push(upn_suffix.clone());
    }
    let mut options: Vec<(&'static str, &'static str, bool)> = Vec::new();
    if is_user {
        options.push((
            "must_change",
            "L'utilisateur doit changer le mot de passe à la prochaine ouverture de session",
            st.must_change,
        ));
    }
    for (k, l, flag) in if is_user { AD_USER_OPTIONS } else { AD_COMPUTER_OPTIONS } {
        options.push((k, l, u & flag != 0));
    }
    let expires_date = match e.int("accountExpires").and_then(filetime_to_dt) {
        Some(dt) => (dt.with_timezone(&Local) - chrono::Duration::days(1)).format("%Y-%m-%d").to_string(),
        None => String::new(),
    };
    let mut facts = vec![
        ("Dernière ouverture de session".to_string(), ft_fact(e, "lastLogonTimestamp")),
        ("Mot de passe modifié".to_string(), ft_fact(e, "pwdLastSet")),
    ];
    if let Some(v) = e.int("msDS-UserPasswordExpiryTimeComputed") {
        facts.push((
            "Expiration du mot de passe".into(),
            match filetime_to_dt(v) {
                Some(dt) => fmt_dt(dt),
                None => "jamais".into(),
            },
        ));
    }
    facts.push((
        "Tentatives erronées (ce DC)".into(),
        e.int("badPwdCount").map(|x| x.to_string()).unwrap_or("—".into()),
    ));
    facts.push(("Dernière tentative erronée".into(), ft_fact(e, "badPasswordTime")));
    if e.int("lockoutTime").unwrap_or(0) > 0 {
        facts.push(("Verrouillé depuis".into(), ft_fact(e, "lockoutTime")));
    }
    facts.push((
        "Ouvertures de session (ce DC)".into(),
        e.int("logonCount").map(|x| x.to_string()).unwrap_or("—".into()),
    ));
    facts.push(("userAccountControl".into(), format!("{u} — {}", uac::labels(u).join(", "))));
    if let Some(sid) = e.bin("objectSid").and_then(sid_to_string) {
        facts.push(("SID".into(), sid));
    }
    Ok(AccountAdTpl {
        dn: e.dn.clone(),
        is_user,
        disabled: st.disabled,
        locked: st.locked,
        pwd_expired: st.pwd_expired,
        expired: st.expired,
        upn_prefix,
        upn_suffix,
        suffixes,
        netbios: dir.info.netbios.clone().unwrap_or_default(),
        sam: e.s("sAMAccountName"),
        workstations: e.s("userWorkstations"),
        options,
        expires_date,
        facts,
    }
    .render()?)
}

#[derive(Template)]
#[template(path = "tab_account_ldap.html")]
struct AccountLdapTpl {
    dn: String,
    disabled: bool,
    locked: bool,
    must_change: bool,
    policy: String,
    policies: Vec<String>,
    facts: Vec<(String, String)>,
}

async fn account_ldap_tab(dir: &mut Dir, e: &Entry) -> AppResult<String> {
    let st = account_state(e, dir.info.flavor);
    let base = dir.base().to_string();
    let policies: Vec<String> = dir
        .search(&base, Scope::Subtree, "(objectClass=pwdPolicy)", &["1.1"])
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|x| x.dn)
        .collect();
    let gt = |attr: &str| e.str(attr).and_then(|v| parse_generalized(&v)).map(fmt_dt).unwrap_or_else(|| "—".into());
    let failures = e.strs("pwdFailureTime");
    let mut facts = vec![
        ("Mot de passe modifié".to_string(), gt("pwdChangedTime")),
        ("Échecs d'authentification récents".to_string(), failures.len().to_string()),
    ];
    if let Some(last) = failures.iter().filter_map(|f| parse_generalized(f)).max() {
        facts.push(("Dernier échec".into(), fmt_dt(last)));
    }
    if let Some(v) = e.str("pwdAccountLockedTime") {
        facts.push(("pwdAccountLockedTime".into(), v));
    }
    if let Some(v) = e.str("passwordExpirationTime") {
        facts.push(("Expiration du mot de passe".into(), parse_generalized(&v).map(fmt_dt).unwrap_or(v)));
    }
    facts.push(("Créé".into(), gt("createTimestamp")));
    facts.push(("Modifié".into(), gt("modifyTimestamp")));
    Ok(AccountLdapTpl {
        dn: e.dn.clone(),
        disabled: st.disabled,
        locked: st.locked,
        must_change: st.must_change,
        policy: e.s("pwdPolicySubentry"),
        policies,
        facts,
    }
    .render()?)
}

#[derive(Deserialize)]
pub struct DnOnly {
    pub dn: String,
}

pub async fn account_save(a: Auth, Query(q): Query<DnOnly>, f: FormData) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let e = read_full(&mut dir, &q.dn).await?;
    let mut mods: Mods = Vec::new();
    if dir.is_ad() {
        let kind = Kind::of(&e);
        let is_user = kind == Kind::User;
        let u = e.int("userAccountControl").unwrap_or(0);
        let mut nu = u;
        for (k, _, flag) in if is_user { AD_USER_OPTIONS } else { AD_COMPUTER_OPTIONS } {
            if f.checked(k) {
                nu |= flag;
            } else {
                nu &= !flag;
            }
        }
        if nu != u {
            mods.push(m_replace("userAccountControl", [nu.to_string()]));
        }
        if is_user {
            let must = f.checked("must_change");
            let cur0 = e.str("pwdLastSet").map(|v| v.trim() == "0").unwrap_or(false);
            if must && !cur0 {
                if nu & uac::DONT_EXPIRE_PASSWORD != 0 {
                    return Err(AppError::bad_request(
                        "« doit changer le mot de passe » est incompatible avec « le mot de passe n'expire jamais »",
                    ));
                }
                mods.push(m_replace("pwdLastSet", ["0"]));
            } else if !must && cur0 {
                mods.push(m_replace("pwdLastSet", ["-1"]));
            }
            let prefix = f.s("upn_prefix");
            let suffix = f.s("upn_suffix");
            let upn = if prefix.is_empty() { String::new() } else { format!("{prefix}@{suffix}") };
            if upn != e.s("userPrincipalName") {
                mods.push(if upn.is_empty() {
                    m_clear("userPrincipalName")
                } else {
                    m_replace("userPrincipalName", [upn])
                });
            }
            let sam = f.s("sam");
            if !sam.is_empty() && sam != e.s("sAMAccountName") {
                mods.push(m_replace("sAMAccountName", [sam]));
            }
            let ws = f.s("workstations");
            if ws != e.s("userWorkstations") {
                mods.push(if ws.is_empty() {
                    m_clear("userWorkstations")
                } else {
                    m_replace("userWorkstations", [ws])
                });
            }
            let new_exp = if f.s("expires") == "date" {
                let d = NaiveDate::parse_from_str(&f.s("expires_date"), "%Y-%m-%d")
                    .map_err(|_| AppError::bad_request("date d'expiration invalide"))?;
                let next = d.succ_opt().unwrap_or(d).and_hms_opt(0, 0, 0).unwrap();
                let local =
                    Local.from_local_datetime(&next).single().ok_or_else(|| AppError::bad_request("date invalide"))?;
                dt_to_filetime(local.with_timezone(&Utc)).to_string()
            } else {
                "9223372036854775807".to_string()
            };
            let cur_exp = e.int("accountExpires").unwrap_or(0);
            let cur_never = cur_exp == 0 || cur_exp == i64::MAX;
            if !(cur_never && new_exp == "9223372036854775807") && new_exp != cur_exp.to_string() {
                mods.push(m_replace("accountExpires", [new_exp]));
            }
        }
    } else {
        let must = f.checked("must_change");
        let cur = e.bool("pwdReset").unwrap_or(false);
        if must != cur {
            mods.push(if must { m_replace("pwdReset", ["TRUE"]) } else { m_clear("pwdReset") });
        }
        let pol = f.s("policy");
        if pol != e.s("pwdPolicySubentry") {
            mods.push(if pol.is_empty() {
                m_clear("pwdPolicySubentry")
            } else {
                m_replace("pwdPolicySubentry", [pol])
            });
        }
    }
    if mods.is_empty() {
        return Hx::new().toast("info", "Aucune modification").render_str(if dir.is_ad() {
            account_ad_tab(&dir, &e)?
        } else {
            account_ldap_tab(&mut dir, &e).await?
        });
    }
    let res = dir.modify(&e.dn, mods).await;
    a.audited("compte", &e.dn, "options du compte", res)?;
    let e2 = read_full(&mut dir, &e.dn).await?;
    let html = if dir.is_ad() { account_ad_tab(&dir, &e2)? } else { account_ldap_tab(&mut dir, &e2).await? };
    Hx::ok("Compte mis à jour").refresh_list().render_str(html)
}

// ---------------------------------------------------------------- membres

pub struct MemberView {
    pub dn: String,
    pub name: String,
    pub icon: &'static str,
    pub kind: &'static str,
    pub detail: String,
    pub primary: bool,
    pub location: String,
}

#[derive(Template)]
#[template(path = "tab_members.html")]
struct MembersTpl {
    uid: String,
    dn: String,
    attr: String,
    add_action: String,
    rows: Vec<MemberView>,
}

async fn members_tab(dir: &mut Dir, e: &Entry) -> AppResult<String> {
    let rows = ops::list_members(dir, e).await?;
    let attr = ops::member_attr(e).name().to_string();
    let base = dir.base().to_string();
    let html = MembersTpl {
        uid: uid(),
        dn: e.dn.clone(),
        attr,
        add_action: format!("/obj/members?op=add&group={}", url(&e.dn)),
        rows: rows
            .into_iter()
            .map(|r| MemberView {
                location: if r.dn.contains('=') {
                    dn::canonical(&dn::parent(&r.dn)).replace(&dn::dc_to_domain(&base), "")
                } else {
                    String::new()
                },
                icon: r.kind.icon(),
                kind: r.kind.label(),
                dn: r.dn,
                name: r.name,
                detail: r.detail,
                primary: r.primary,
            })
            .collect(),
    }
    .render()?;
    Ok(format!(
        "<div hx-get=\"/obj/tab?dn={}&tab=members\" hx-trigger=\"refresh-tab from:body\" hx-swap=\"outerHTML\">{html}</div>",
        url(&e.dn)
    ))
}

#[derive(Template)]
#[template(path = "tab_memberof.html")]
struct MemberOfTpl {
    uid: String,
    dn: String,
    is_ad: bool,
    nested: bool,
    add_action: String,
    rows: Vec<MemberView>,
}

async fn memberof_tab(dir: &mut Dir, e: &Entry, nested: bool) -> AppResult<String> {
    let rows = ops::member_of(dir, e, nested).await?;
    let base = dir.base().to_string();
    let html = MemberOfTpl {
        uid: uid(),
        dn: e.dn.clone(),
        is_ad: dir.is_ad(),
        nested,
        add_action: format!("/obj/memberof?op=add&obj={}", url(&e.dn)),
        rows: rows
            .into_iter()
            .map(|r| MemberView {
                location: dn::canonical(&dn::parent(&r.dn)).replace(&dn::dc_to_domain(&base), ""),
                icon: "group",
                kind: "Groupe",
                dn: r.dn,
                name: r.name,
                detail: r.detail,
                primary: r.primary,
            })
            .collect(),
    }
    .render()?;
    Ok(format!(
        "<div hx-get=\"/obj/tab?dn={}&tab=memberof\" hx-trigger=\"refresh-tab from:body\" hx-swap=\"outerHTML\">{html}</div>",
        url(&e.dn)
    ))
}

#[derive(Deserialize)]
pub struct MembersQ {
    pub op: String,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub obj: String,
}

pub async fn members_change(a: Auth, Query(q): Query<MembersQ>, f: FormData) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let (members, verb) = match q.op.as_str() {
        "add" => (f.all("pick"), "ajout de membres"),
        "remove" => (f.all("dn"), "retrait de membres"),
        _ => return Err(AppError::bad_request("opération inconnue")),
    };
    if members.is_empty() {
        return Ok(Hx::warn("Aucun objet sélectionné").empty());
    }
    let res = if q.op == "add" {
        ops::add_members(&mut dir, &q.group, &members).await
    } else {
        ops::remove_members(&mut dir, &q.group, &members).await
    };
    a.audited(verb, &q.group, &members.join(" ; "), res)?;
    Ok(Hx::ok(format!("{} membre(s) {}", members.len(), if q.op == "add" { "ajouté(s)" } else { "retiré(s)" }))
        .close_modal_if(q.op == "add")
        .trigger("refresh-tab")
        .empty())
}

impl Hx {
    pub fn close_modal_if(self, c: bool) -> Self {
        if c { self.close_modal() } else { self }
    }
}

pub async fn memberof_change(a: Auth, Query(q): Query<MembersQ>, f: FormData) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let mut errors = Vec::new();
    let mut n = 0;
    if q.op == "add" {
        let mut objects = f.all("dn");
        if !q.obj.is_empty() {
            objects.push(q.obj.clone());
        }
        let groups = f.all("pick");
        if objects.is_empty() || groups.is_empty() {
            return Ok(Hx::warn("Sélection vide").empty());
        }
        for g in &groups {
            let res = ops::add_members(&mut dir, g, &objects).await;
            match a.audited("ajout de membres", g, &objects.join(" ; "), res) {
                Ok(_) => n += 1,
                Err(e) => errors.push(format!("{} : {}", dn::rdn_value(g), e.message)),
            }
        }
    } else {
        let groups = f.all("dn");
        for g in &groups {
            let res = ops::remove_members(&mut dir, g, std::slice::from_ref(&q.obj)).await;
            match a.audited("retrait de membres", g, &q.obj, res) {
                Ok(_) => n += 1,
                Err(e) => errors.push(format!("{} : {}", dn::rdn_value(g), e.message)),
            }
        }
    }
    let hx = if errors.is_empty() {
        Hx::ok(format!("Appartenance mise à jour ({n} groupe(s))"))
    } else {
        Hx::new().toast("error", errors.join(" — "))
    };
    Ok(hx.close_modal_if(q.op == "add" && errors.is_empty()).trigger("refresh-tab").refresh_list().empty())
}

// ---------------------------------------------------------------- onglet Objet

pub struct Section {
    pub title: String,
    pub rows: Vec<(String, String, bool)>,
}

#[derive(Template)]
#[template(path = "tab_kv.html")]
pub struct KvTpl {
    pub note: String,
    pub note_level: &'static str,
    pub sections: Vec<Section>,
    pub extra: String,
}

impl KvTpl {
    pub fn new(sections: Vec<Section>) -> Self {
        KvTpl { note: String::new(), note_level: "", sections, extra: String::new() }
    }
}

fn gt_fmt(e: &Entry, attr: &str) -> Option<String> {
    e.str(attr).map(|v| parse_generalized(&v).map(fmt_dt).unwrap_or(v))
}

fn object_tab(dir: &Dir, e: &Entry) -> AppResult<String> {
    let mut rows: Vec<(String, String, bool)> = Vec::new();
    let mut push = |l: &str, v: Option<String>, mono: bool| {
        if let Some(v) = v {
            if !v.is_empty() {
                rows.push((l.into(), v, mono));
            }
        }
    };
    if dir.is_ad() {
        push("Nom canonique", e.str("canonicalName").or_else(|| Some(dn::canonical(&e.dn))), false);
    }
    push("Nom unique (DN)", Some(e.dn.clone()), true);
    push("Classes d'objet", Some(e.classes().join(", ")), false);
    push("Classe structurelle", e.str("structuralObjectClass"), false);
    push("Catégorie", e.str("objectCategory").map(|c| dn::rdn_value(&c)), false);
    push("Créé", gt_fmt(e, "whenCreated").or_else(|| gt_fmt(e, "createTimestamp")), false);
    push("Créé par", e.str("creatorsName"), true);
    push("Modifié", gt_fmt(e, "whenChanged").or_else(|| gt_fmt(e, "modifyTimestamp")), false);
    push("Modifié par", e.str("modifiersName"), true);
    push("USN de création", e.str("uSNCreated"), true);
    push("USN de modification", e.str("uSNChanged"), true);
    push("GUID", e.bin("objectGUID").and_then(guid_to_string), true);
    push("SID", e.bin("objectSid").and_then(sid_to_string), true);
    push("entryUUID", e.str("entryUUID"), true);
    push("entryCSN", e.str("entryCSN"), true);
    push(
        "Sous-entrées",
        e.str("hasSubordinates").map(|v| if v == "TRUE" { "oui".into() } else { "non".into() }),
        false,
    );
    let sids: Vec<String> = e.bins("sIDHistory").into_iter().filter_map(sid_to_string).collect();
    if !sids.is_empty() {
        push("Historique des SID", Some(sids.join(", ")), true);
    }
    Ok(KvTpl::new(vec![Section { title: String::new(), rows }]).render()?)
}

// ---------------------------------------------------------------- onglet Sécurité

const KNOWN_GUIDS: &[(&str, &str)] = &[
    ("00299570-246d-11d0-a768-00aa006e0529", "Réinitialiser le mot de passe"),
    ("ab721a53-1e2f-11d0-9819-00aa0040529b", "Modifier le mot de passe"),
    ("ab721a54-1e2f-11d0-9819-00aa0040529b", "Envoyer en tant que"),
    ("ab721a56-1e2f-11d0-9819-00aa0040529b", "Recevoir en tant que"),
    ("bf9679c0-0de6-11d0-a285-00aa003049e2", "Membres (member)"),
    ("bf967a86-0de6-11d0-a285-00aa003049e2", "objets Ordinateur"),
    ("bf967aba-0de6-11d0-a285-00aa003049e2", "objets Utilisateur"),
    ("bf967a9c-0de6-11d0-a285-00aa003049e2", "objets Groupe"),
    ("bf967aa5-0de6-11d0-a285-00aa003049e2", "objets Unité d'organisation"),
    ("4828cc14-1437-45bc-9b07-ad6f015e5f28", "objets inetOrgPerson"),
    ("4c164200-20c0-11d0-a768-00aa006e0529", "Restrictions de compte"),
    ("5f202010-79a5-11d0-9020-00c04fc2d4cf", "Informations d'ouverture de session"),
    ("bc0ac240-79a9-11d0-9020-00c04fc2d4cf", "Appartenance aux groupes"),
    ("e45795b2-9455-11d1-aebd-0000f80367c1", "Informations de messagerie"),
    ("77b5b886-944a-11d1-aebd-0000f80367c1", "Informations personnelles"),
    ("e48d0154-bcf8-11d1-8702-00c04fb96050", "Informations publiques"),
    ("59ba2f42-79a2-11d0-9020-00c04fc2d3cf", "Informations générales"),
    ("037088f8-0ae1-11d2-b422-00a0c968f939", "Informations RAS"),
    ("91e647de-d96f-4b70-9557-d63ff4f3ccd8", "Informations privées"),
    ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "Réplication : obtenir les modifications"),
    ("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "Réplication : obtenir toutes les modifications"),
    ("89e95b76-444d-4c62-991a-0facbeda640c", "Réplication : modifications filtrées"),
    ("edacfd8f-ffb3-11d1-b41d-00a0c968f939", "Appliquer la stratégie de groupe"),
    ("0e10c968-78fb-11d2-90d4-00c04f79dc55", "Inscription de certificat"),
    ("a05b8cc2-17bc-4802-a710-e7c15ab866a2", "Inscription automatique de certificat"),
    ("72e39547-7b18-11d1-adef-00c04fd8d5cd", "Écriture validée du nom DNS"),
    ("f3a64788-5306-11d1-a9c5-0000f80367c1", "Écriture validée du SPN"),
    ("3f78c3e5-f79a-46bd-a0b8-9d18116ddc79", "msDS-AllowedToActOnBehalfOfOtherIdentity"),
    ("5b47d60f-6090-40b2-9f37-2a4de88f3063", "msDS-KeyCredentialLink"),
];

fn guid_label(g: &str) -> String {
    KNOWN_GUIDS
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(g))
        .map(|(_, l)| l.to_string())
        .unwrap_or_else(|| g.to_string())
}

async fn security_tab(dir: &mut Dir, e: &Entry) -> AppResult<String> {
    let se = dir.read_ctrl(&e.dn, &["nTSecurityDescriptor"], vec![ctrl::sd_flags()]).await?;
    let Some(raw) = se.as_ref().and_then(|x| x.bin("nTSecurityDescriptor")) else {
        let mut t = KvTpl::new(vec![]);
        t.note = "Descripteur de sécurité illisible avec vos droits.".into();
        t.note_level = "warn";
        return Ok(t.render()?);
    };
    let sd = security::parse_sd(raw).ok_or_else(|| AppError::internal("descripteur de sécurité invalide"))?;
    let mut sids: Vec<String> = sd.dacl.iter().map(|a| a.sid.clone()).collect();
    sids.extend(sd.owner.iter().cloned());
    sids.extend(sd.group.iter().cloned());
    let names = security::resolve_sids(dir, &sids).await;
    let name = |s: &str| names.get(s).map(|(n, _)| n.clone()).unwrap_or_else(|| s.to_string());
    let mut table = String::from(
        "<div class=\"table-wrap\" style=\"max-height:420px\"><table class=\"grid compact\"><thead><tr><th>Type</th><th>Principal</th><th>Autorisations</th><th>S'applique à</th><th>Héritée</th></tr></thead><tbody>",
    );
    for ace in &sd.dacl {
        let rights = security::mask_labels(ace.mask).join(", ");
        let mut applies = Vec::new();
        if let Some(o) = &ace.object_type {
            applies.push(guid_label(o));
        }
        if let Some(i) = &ace.inherited_object_type {
            applies.push(format!("descendants : {}", guid_label(i)));
        }
        if ace.flags & 0x02 != 0 && applies.is_empty() {
            applies.push("cet objet et les descendants".into());
        }
        table.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td class=\"small\">{}</td><td class=\"small\">{}</td><td>{}</td></tr>",
            if ace.is_allow() {
                "<span class=\"badge ok\">Autoriser</span>"
            } else {
                "<span class=\"badge danger\">Refuser</span>"
            },
            esc(&name(&ace.sid)),
            esc(&rights),
            esc(&if applies.is_empty() { "cet objet".to_string() } else { applies.join(" ; ") }),
            if ace.is_inherited() { "oui" } else { "" },
        ));
    }
    table.push_str("</tbody></table></div>");
    let mut t = KvTpl::new(vec![Section {
        title: String::new(),
        rows: vec![
            ("Propriétaire".into(), sd.owner.as_deref().map(name).unwrap_or_default(), false),
            ("Groupe principal".into(), sd.group.as_deref().map(name).unwrap_or_default(), false),
            ("Entrées (DACL)".into(), sd.dacl.len().to_string(), false),
            (
                "Héritage".into(),
                if sd.control & 0x1000 != 0 { "désactivé (DACL protégée)".into() } else { "activé".into() },
                false,
            ),
        ],
    }]);
    t.note = "Affichage en lecture seule des autorisations (DACL).".into();
    t.extra = table;
    Ok(t.render()?)
}

// ---------------------------------------------------------------- LAPS / BitLocker

async fn laps_tab(a: &Auth, dir: &mut Dir, e: &Entry) -> AppResult<String> {
    let attrs = [
        "ms-Mcs-AdmPwd",
        "ms-Mcs-AdmPwdExpirationTime",
        "msLAPS-Password",
        "msLAPS-PasswordExpirationTime",
        "msLAPS-EncryptedPassword",
    ];
    let x = dir.read(&e.dn, &attrs).await?.unwrap_or_default();
    let mut rows = Vec::new();
    let u = uid();
    let mut secret = String::new();
    if let Some(p) = x.str("msLAPS-Password") {
        // {"n":"Administrator","t":"1d8...","p":"..."}
        let v: serde_json::Value = serde_json::from_str(&p).unwrap_or_default();
        rows.push(("Compte".to_string(), v["n"].as_str().unwrap_or("").to_string(), false));
        secret = v["p"].as_str().unwrap_or("").to_string();
        rows.push(("Type".into(), "Windows LAPS (non chiffré)".into(), false));
    } else if let Some(p) = x.str("ms-Mcs-AdmPwd") {
        secret = p;
        rows.push(("Type".into(), "LAPS hérité (ms-Mcs-AdmPwd)".into(), false));
    }
    if x.has("msLAPS-EncryptedPassword") {
        rows.push((
            "Mot de passe chiffré".into(),
            "présent (msLAPS-EncryptedPassword, déchiffrable uniquement via DPAPI-NG / RSAT)".into(),
            false,
        ));
    }
    for at in ["msLAPS-PasswordExpirationTime", "ms-Mcs-AdmPwdExpirationTime"] {
        if let Some(v) = x.int(at) {
            rows.push(("Expiration".into(), fmt_dt_opt(filetime_to_dt(v)), false));
        }
    }
    let mut t = KvTpl::new(vec![Section { title: String::new(), rows }]);
    if secret.is_empty() && !x.has("msLAPS-EncryptedPassword") {
        t.note = "Aucun mot de passe LAPS lisible (LAPS non déployé ou droits insuffisants).".into();
        t.note_level = "warn";
    } else if !secret.is_empty() {
        a.audit("lecture LAPS", &e.dn, true, "consultation du mot de passe administrateur local");
        t.extra = format!(
            "<h3>Mot de passe administrateur local</h3><div class=\"row\"><button class=\"btn-sm\" data-action=\"reveal\" data-target=\"laps-{u}\">Afficher / masquer</button>\
             <button class=\"btn-sm\" data-copy=\"#laps-{u}\">Copier</button></div><div id=\"laps-{u}\" class=\"secret hidden\" style=\"margin-top:8px\">{}</div>",
            esc(&secret)
        );
    }
    t.extra.push_str(&format!(
        "<div class=\"form-actions\"><button class=\"btn-sm\" hx-post=\"/obj/laps/expire?dn={}\" hx-swap=\"none\" hx-confirm=\"Forcer l'expiration ? Le mot de passe sera renouvelé au prochain cycle de stratégie.\">Expirer maintenant</button></div>",
        url(&e.dn)
    ));
    Ok(t.render()?)
}

pub async fn laps_expire(a: Auth, Query(q): Query<DnOnly>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let x = dir.read_req(&q.dn, &["msLAPS-PasswordExpirationTime", "ms-Mcs-AdmPwdExpirationTime"]).await?;
    let mut mods: Mods = Vec::new();
    if x.has("msLAPS-PasswordExpirationTime") {
        mods.push(m_replace("msLAPS-PasswordExpirationTime", ["0"]));
    }
    if x.has("ms-Mcs-AdmPwdExpirationTime") {
        mods.push(m_replace("ms-Mcs-AdmPwdExpirationTime", ["0"]));
    }
    if mods.is_empty() {
        return Ok(Hx::warn("Aucun attribut LAPS sur cet ordinateur").empty());
    }
    let res = dir.modify(&q.dn, mods).await;
    a.audited("expiration LAPS", &q.dn, "", res)?;
    Ok(Hx::ok("Expiration LAPS forcée").empty())
}

async fn bitlocker_tab(a: &Auth, dir: &mut Dir, e: &Entry) -> AppResult<String> {
    let v = dir
        .search(
            &e.dn,
            Scope::OneLevel,
            "(objectClass=msFVE-RecoveryInformation)",
            &["cn", "msFVE-RecoveryPassword", "msFVE-RecoveryGuid", "whenCreated"],
        )
        .await
        .unwrap_or_default();
    let mut t = KvTpl::new(vec![]);
    if v.is_empty() {
        t.note = "Aucune clé de récupération BitLocker enregistrée (ou droits insuffisants).".into();
        return Ok(t.render()?);
    }
    a.audit("lecture BitLocker", &e.dn, true, &format!("{} clé(s) de récupération consultée(s)", v.len()));
    let mut html = String::from(
        "<div class=\"table-wrap\"><table class=\"grid compact\"><thead><tr><th>Date</th><th>ID de clé</th><th>Mot de passe de récupération</th></tr></thead><tbody>",
    );
    for x in v {
        html.push_str(&format!(
            "<tr><td class=\"nowrap\">{}</td><td class=\"mono small\">{}</td><td class=\"mono\">{}</td></tr>",
            esc(&gt_fmt(&x, "whenCreated").unwrap_or_default()),
            esc(&x.bin("msFVE-RecoveryGuid").and_then(guid_to_string).unwrap_or_default()),
            esc(&x.s("msFVE-RecoveryPassword")),
        ));
    }
    html.push_str("</tbody></table></div>");
    t.extra = html;
    Ok(t.render()?)
}

// ---------------------------------------------------------------- création

#[derive(Deserialize)]
pub struct NewQ {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub parent: String,
}

#[derive(Template)]
#[template(path = "dlg_new.html")]
struct NewTpl {
    uid: String,
    kind: String,
    icon: &'static str,
    title: &'static str,
    parent: String,
    parent_label: String,
    is_ad: bool,
    suffixes: Vec<String>,
    posix_default: bool,
    next_uid_hint: String,
    default_gid: String,
    home_template: String,
    shell: String,
    group_style: String,
}

pub async fn new_form(a: Auth, Query(q): Query<NewQ>) -> AppResult<Response> {
    let dir = a.dir().await?;
    let kind = Kind::from_param(&q.kind).ok_or_else(|| AppError::bad_request("type d'objet inconnu"))?;
    let parent = if q.parent.is_empty() { dir.base().to_string() } else { q.parent.clone() };
    let mut suffixes = vec![dir.info.domain_dns.clone()];
    suffixes.extend(dir.info.upn_suffixes.iter().cloned());
    let posix = &dir.profile.posix;
    let style = ops::group_style(&dir);
    let posix_default = if dir.is_ad() {
        posix.ad_posix_attributes
    } else if kind == Kind::Group {
        matches!(style, crate::config::GroupStyle::PosixGroup | crate::config::GroupStyle::Rfc2307bis)
    } else {
        true
    };
    render(&NewTpl {
        uid: uid(),
        kind: q.kind.clone(),
        icon: kind.icon(),
        title: kind.label(),
        parent_label: dn::canonical(&parent),
        parent,
        is_ad: dir.is_ad(),
        suffixes,
        posix_default,
        next_uid_hint: format!("à partir de {}", posix.uid_number_start),
        default_gid: posix.default_gid_number.map(|g| g.to_string()).unwrap_or_default(),
        home_template: posix.home_template.clone(),
        shell: posix.default_shell.clone(),
        group_style: match style {
            crate::config::GroupStyle::GroupOfNames => "groupOfNames (member)".into(),
            crate::config::GroupStyle::GroupOfUniqueNames => "groupOfUniqueNames (uniqueMember)".into(),
            crate::config::GroupStyle::PosixGroup => "posixGroup (memberUid)".into(),
            crate::config::GroupStyle::Rfc2307bis => "groupOfNames + posixGroup (RFC 2307bis)".into(),
        },
    })
}

pub async fn new_submit(a: Auth, f: FormData) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let kind = Kind::from_param(&f.s("type")).ok_or_else(|| AppError::bad_request("type d'objet inconnu"))?;
    let parent = f.s("parent");
    let (res, label): (AppResult<(String, Vec<String>)>, &str) = match kind {
        Kind::User => {
            let pw = f.raw("password");
            if pw != f.raw("password2") {
                return Err(AppError::bad_request("les mots de passe ne correspondent pas"));
            }
            let u = ops::NewUser {
                parent: parent.clone(),
                given: f.s("given"),
                initials: f.s("initials"),
                sn: f.s("sn"),
                full_name: f.s("full_name"),
                login: f.s("login"),
                upn_suffix: f.s("upn_suffix"),
                password: pw,
                must_change: f.checked("must_change"),
                never_expires: f.checked("never_expires"),
                disabled: f.checked("disabled"),
                mail: f.s("mail"),
                description: f.s("description"),
                posix: f.checked("posix"),
                uid_number: f.int("uid_number").map(|x| x as u32),
                gid_number: f.int("gid_number").map(|x| x as u32),
                home: f.opt("home").unwrap_or_else(|| dir.profile.posix.home_template.clone()),
                shell: f.opt("shell").unwrap_or_else(|| dir.profile.posix.default_shell.clone()),
            };
            (ops::create_user(&mut dir, &u).await, "création d'utilisateur")
        }
        Kind::Group => {
            let g = ops::NewGroup {
                parent: parent.clone(),
                name: f.s("name"),
                sam: f.s("sam"),
                group_type: f.int("group_type").unwrap_or(-2147483646),
                description: f.s("description"),
                mail: f.s("mail"),
                gid_number: f.int("gid_number").map(|x| x as u32),
                posix: f.checked("posix"),
                creator_dn: a.s.user_dn.clone(),
            };
            (ops::create_group(&mut dir, &g).await.map(|d| (d, vec![])), "création de groupe")
        }
        Kind::Ou => (
            ops::create_ou(&mut dir, &parent, &f.s("name"), &f.s("description")).await.map(|d| (d, vec![])),
            "création d'OU",
        ),
        Kind::Computer => (
            ops::create_computer(&mut dir, &parent, &f.s("name"), &f.s("description")).await.map(|d| (d, vec![])),
            "création d'ordinateur",
        ),
        Kind::Contact => (
            ops::create_contact(&mut dir, &parent, &f.s("given"), &f.s("sn"), &f.s("display"), &f.s("mail"))
                .await
                .map(|d| (d, vec![])),
            "création de contact",
        ),
        _ => return Err(AppError::bad_request("type non pris en charge")),
    };
    let target = res.as_ref().map(|(d, _)| d.clone()).unwrap_or_else(|_| parent.clone());
    let (new_dn, warnings) = a.audited(label, &target, "", res)?;
    let msg = if warnings.is_empty() {
        format!("Objet créé : {}", dn::rdn_value(&new_dn))
    } else {
        format!("Objet créé avec avertissements : {}", warnings.join(" ; "))
    };
    Ok(Hx::new().toast(if warnings.is_empty() { "ok" } else { "warn" }, msg).close_modal().refresh_list().empty())
}

// ---------------------------------------------------------------- mot de passe

#[derive(Template)]
#[template(path = "dlg_password.html")]
struct PasswordTpl {
    uid: String,
    dn: String,
    name: String,
    locked: bool,
}

pub async fn password_form(a: Auth, Query(q): Query<DnOnly>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let e = read_full(&mut dir, &q.dn).await?;
    let st = account_state(&e, dir.info.flavor);
    render(&PasswordTpl { uid: uid(), dn: e.dn.clone(), name: e.display_name(), locked: st.locked })
}

pub async fn password_submit(a: Auth, f: FormData) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let target = f.s("dn");
    let pw = f.raw("password");
    if pw.is_empty() {
        return Err(AppError::bad_request("mot de passe vide"));
    }
    if pw != f.raw("password2") {
        return Err(AppError::bad_request("les mots de passe ne correspondent pas"));
    }
    let res = ops::set_password(&mut dir, &target, &pw, f.checked("must_change"), f.checked("unlock")).await;
    let warnings = a.audited("réinitialisation du mot de passe", &target, "", res)?;
    let hx = if warnings.is_empty() {
        Hx::ok("Mot de passe réinitialisé")
    } else {
        Hx::warn(format!("Mot de passe réinitialisé — {}", warnings.join(" ; ")))
    };
    Ok(hx.close_modal().refresh_list().empty())
}

// ---------------------------------------------------------------- états (activer, désactiver, déverrouiller)

#[derive(Deserialize)]
pub struct StateQ {
    pub op: String,
    #[serde(default)]
    pub dn: Option<String>,
}

pub async fn set_state(a: Auth, Query(q): Query<StateQ>, f: FormData) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let mut targets = f.all("dn");
    if let Some(d) = q.dn.clone() {
        targets.push(d);
    }
    if targets.is_empty() {
        return Ok(Hx::warn("Aucun objet sélectionné").empty());
    }
    let mut ok = 0;
    let mut errors = Vec::new();
    for t in &targets {
        let (res, label) = match q.op.as_str() {
            "enable" => (ops::set_enabled(&mut dir, t, true).await, "activation"),
            "disable" => (ops::set_enabled(&mut dir, t, false).await, "désactivation"),
            "unlock" => (ops::unlock(&mut dir, t).await, "déverrouillage"),
            _ => return Err(AppError::bad_request("opération inconnue")),
        };
        match a.audited(label, t, "", res) {
            Ok(_) => ok += 1,
            Err(e) => errors.push(format!("{} : {}", dn::rdn_value(t), e.message)),
        }
    }
    let verb = match q.op.as_str() {
        "enable" => "activé(s)",
        "disable" => "désactivé(s)",
        _ => "déverrouillé(s)",
    };
    let hx = if errors.is_empty() {
        Hx::ok(format!("{ok} compte(s) {verb}"))
    } else {
        Hx::new().toast("error", format!("{ok} compte(s) {verb} ; échecs : {}", errors.join(" — ")))
    };
    Ok(hx.refresh_list().trigger("close-all-modals").empty())
}

// ---------------------------------------------------------------- déplacer / renommer / supprimer

#[derive(Template)]
#[template(path = "dlg_simple.html")]
pub struct SimpleDlg {
    pub size: &'static str,
    pub action: String,
    pub hidden: Vec<(String, String)>,
    pub icon: &'static str,
    pub title: String,
    pub body: String,
    pub submit: String,
    pub submit_class: &'static str,
}

fn dns_from(q: &Query<Vec<(String, String)>>) -> Vec<String> {
    q.0.iter().filter(|(k, v)| k == "dn" && !v.is_empty()).map(|(_, v)| v.clone()).collect()
}

pub async fn move_form(a: Auth, q: Query<Vec<(String, String)>>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let targets = dns_from(&q);
    if targets.is_empty() {
        return Err(AppError::bad_request("aucun objet sélectionné"));
    }
    let base = dir.base().to_string();
    let f = crate::directory::container_filter(
        dir.info.flavor,
        dir.profile.posix.tree_container_classes.as_ref(),
        a.s.is_advanced(),
    );
    let (mut v, _) = dir.search_paged(&base, Scope::Subtree, &f, &["1.1"], 10_000).await?;
    v.sort_by_key(|e| dn::canonical(&e.dn).to_lowercase());
    let u = uid();
    let mut body = format!(
        "<p>Déplacer <strong>{}</strong> objet(s) vers :</p><input type=\"search\" placeholder=\"Filtrer les conteneurs…\" data-filter-table=\"#mv-{u}\" autofocus>\
         <ul class=\"val-list table-wrap\" id=\"mv-{u}\" style=\"max-height:380px;margin-top:8px;padding:6px\">",
        targets.len()
    );
    for e in v {
        let label = dn::canonical(&e.dn);
        body.push_str(&format!(
            "<li data-name=\"{}\"><label class=\"row\"><input type=\"radio\" name=\"target\" value=\"{}\" required> <span>{}</span></label></li>",
            esc(&label.to_lowercase()),
            esc(&e.dn),
            esc(&label)
        ));
    }
    body.push_str("</ul>");
    render(&SimpleDlg {
        size: "",
        action: "/obj/move".into(),
        hidden: targets.into_iter().map(|t| ("dn".to_string(), t)).collect(),
        icon: "move",
        title: "Déplacer".into(),
        body,
        submit: "Déplacer".into(),
        submit_class: "btn-primary",
    })
}

pub async fn move_submit(a: Auth, f: FormData) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let target = f.s("target");
    if target.is_empty() {
        return Err(AppError::bad_request("choisissez un conteneur de destination"));
    }
    let mut ok = 0;
    let mut errors = Vec::new();
    for d in f.all("dn") {
        if dn::is_under(&target, &d) {
            errors.push(format!("{} : impossible de déplacer un conteneur dans lui-même", dn::rdn_value(&d)));
            continue;
        }
        let rdn = dn::rdn(&d);
        let res = dir.rename(&d, &rdn, Some(&target)).await;
        match a.audited("déplacement", &d, &format!("vers {target}"), res) {
            Ok(_) => ok += 1,
            Err(e) => errors.push(format!("{} : {}", dn::rdn_value(&d), e.message)),
        }
    }
    let hx = if errors.is_empty() {
        Hx::ok(format!("{ok} objet(s) déplacé(s)"))
    } else {
        Hx::new().toast("error", errors.join(" — "))
    };
    Ok(hx.close_modal().refresh_list().empty())
}

pub async fn rename_form(a: Auth, Query(q): Query<DnOnly>) -> AppResult<Response> {
    let _ = a.dir().await?;
    let (attr, val) = dn::rdn_parts(&q.dn);
    let body = format!(
        "<div class=\"form-grid\"><label>Nom actuel</label><div class=\"mono\">{}</div><label>Nouveau nom ({})</label><input type=\"text\" name=\"name\" value=\"{}\" required autofocus></div>\
         <div class=\"checks\" style=\"margin-top:12px\"><label><input type=\"checkbox\" name=\"display\" checked> Mettre aussi à jour le nom affiché (displayName) s'il existe</label></div>",
        esc(&val),
        esc(&attr),
        esc(&val)
    );
    render(&SimpleDlg {
        size: "narrow",
        action: "/obj/rename".into(),
        hidden: vec![("dn".into(), q.dn.clone())],
        icon: "edit",
        title: "Renommer".into(),
        body,
        submit: "Renommer".into(),
        submit_class: "btn-primary",
    })
}

pub async fn rename_submit(a: Auth, f: FormData) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let old = f.s("dn");
    let name = f.s("name");
    if name.is_empty() {
        return Err(AppError::bad_request("nom requis"));
    }
    let (attr, _) = dn::rdn_parts(&old);
    let new_rdn = format!("{attr}={}", dn::escape_value(&name));
    let res = dir.rename(&old, &new_rdn, None).await;
    let new_dn = a.audited("renommage", &old, &format!("nouveau nom : {name}"), res)?;
    if f.checked("display") {
        if let Ok(Some(e)) = dir.read(&new_dn, &["displayName"]).await {
            if e.has("displayName") {
                let _ = dir.modify(&new_dn, vec![m_replace("displayName", [name.as_str()])]).await;
            }
        }
    }
    Ok(Hx::ok("Objet renommé").trigger("close-all-modals").refresh_list().empty())
}

pub async fn delete_form(a: Auth, q: Query<Vec<(String, String)>>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let targets = dns_from(&q);
    if targets.is_empty() {
        return Err(AppError::bad_request("aucun objet sélectionné"));
    }
    let mut body = String::from("<div class=\"notice danger\">Cette opération est irréversible");
    if dir.is_ad() && dir.info.recycle_bin {
        body.push_str(" (sauf restauration depuis la corbeille AD)");
    }
    body.push_str(".</div><ul class=\"val-list\">");
    let mut containers = 0;
    for t in targets.iter().take(50) {
        let e = dir.read(t, &["objectClass", "hasSubordinates"]).await?.unwrap_or_default();
        let k = Kind::of(&e);
        let kids = if k.is_container() || e.str("hasSubordinates").as_deref() == Some("TRUE") {
            let (v, more) =
                dir.search_paged(t, Scope::OneLevel, "(objectClass=*)", &["1.1"], 1).await.unwrap_or((vec![], false));
            !v.is_empty() || more
        } else {
            false
        };
        if kids {
            containers += 1;
        }
        body.push_str(&format!(
            "<li><svg class=\"i kind-icon {0}\"><use href=\"/static/icons.svg#{0}\"></use></svg> {1} <span class=\"faint small mono\">{2}</span>{3}</li>",
            k.icon(),
            esc(&dn::rdn_value(t)),
            esc(t),
            if kids { " <span class=\"badge warn\">contient des objets</span>" } else { "" }
        ));
    }
    if targets.len() > 50 {
        body.push_str(&format!("<li class=\"faint\">… et {} autre(s)</li>", targets.len() - 50));
    }
    body.push_str("</ul>");
    if containers > 0 {
        body.push_str("<div class=\"checks\" style=\"margin-top:12px\"><label><input type=\"checkbox\" name=\"tree\" required> Je confirme la suppression des conteneurs <strong>et de tout leur contenu</strong></label></div>");
    }
    render(&SimpleDlg {
        size: "",
        action: "/obj/delete".into(),
        hidden: targets.into_iter().map(|t| ("dn".to_string(), t)).collect(),
        icon: "trash",
        title: "Supprimer".into(),
        body,
        submit: "Supprimer définitivement".into(),
        submit_class: "btn-danger",
    })
}

pub async fn delete_submit(a: Auth, f: FormData) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let tree = f.checked("tree");
    let mut ok = 0;
    let mut errors = Vec::new();
    for d in f.all("dn") {
        let res = if tree { dir.delete_tree(&d).await } else { dir.delete(&d).await };
        match a.audited("suppression", &d, if tree { "récursive" } else { "" }, res) {
            Ok(_) => ok += 1,
            Err(e) => errors.push(format!("{} : {}", dn::rdn_value(&d), e.message)),
        }
    }
    let hx = if errors.is_empty() {
        Hx::ok(format!("{ok} objet(s) supprimé(s)"))
    } else {
        Hx::new().toast("error", errors.join(" — "))
    };
    // ferme aussi la fiche de propriétés éventuellement ouverte
    Ok(hx.trigger("close-all-modals").refresh_list().empty())
}

// ---------------------------------------------------------------- sélecteur d'objets

#[derive(Template)]
#[template(path = "dlg_pick.html")]
struct PickTpl {
    uid: String,
    mode: String,
    kinds: String,
    target: String,
    action: String,
    title: String,
    carry: Vec<String>,
}

pub async fn pick_dialog(_a: Auth, q: Query<Vec<(String, String)>>) -> AppResult<Response> {
    let get = |k: &str| q.0.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone()).unwrap_or_default();
    let mode = if get("mode") == "multi" { "multi" } else { "single" };
    let action = get("action");
    if mode == "multi" && (!action.starts_with('/') || action.starts_with("//")) {
        return Err(AppError::bad_request("action invalide"));
    }
    render(&PickTpl {
        uid: uid(),
        mode: mode.into(),
        kinds: get("kinds"),
        target: get("target"),
        action,
        title: if get("title").is_empty() { "Sélectionner des objets".into() } else { get("title") },
        carry: dns_from(&q),
    })
}

pub struct PickRow {
    pub dn: String,
    pub name: String,
    pub icon: &'static str,
    pub detail: String,
    pub location: String,
}

#[derive(Template)]
#[template(path = "pick_results.html")]
struct PickResTpl {
    uid: String,
    mode: String,
    target: String,
    q: String,
    rows: Vec<PickRow>,
    truncated: bool,
}

pub fn kinds_filter(kinds: &str, ad: bool) -> String {
    let mut parts = Vec::new();
    for k in kinds.split(',').map(|s| s.trim()) {
        let f = match (k, ad) {
            ("user", true) => "(&(objectCategory=person)(objectClass=user))",
            ("user", false) => "(|(objectClass=inetOrgPerson)(objectClass=posixAccount)(objectClass=account))",
            ("group", true) => "(objectClass=group)",
            ("group", false) => "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))",
            ("computer", true) => "(objectCategory=computer)",
            ("computer", false) => "(|(objectClass=device)(objectClass=ipHost))",
            ("contact", true) => "(objectClass=contact)",
            ("ou", _) => "(objectClass=organizationalUnit)",
            ("service", true) => {
                "(|(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))"
            }
            _ => continue,
        };
        parts.push(f.to_string());
    }
    match parts.len() {
        0 => "(objectClass=*)".into(),
        1 => parts.remove(0),
        _ => format!("(|{})", parts.join("")),
    }
}

#[derive(Deserialize)]
pub struct PickQ {
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub kinds: String,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub target: String,
}

pub async fn pick_search(a: Auth, Query(p): Query<PickQ>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let ad = dir.is_ad();
    let kf = kinds_filter(&p.kinds, ad);
    let qv = filter_escape(p.q.trim());
    let filter = if qv.is_empty() {
        kf
    } else {
        let mut or = format!("(cn={qv}*)(displayName=*{qv}*)(mail={qv}*)(sn={qv}*)(givenName={qv}*)");
        or.push_str(&if ad { format!("(sAMAccountName={qv}*)") } else { format!("(uid={qv}*)") });
        format!("(&{kf}(|{or}))")
    };
    let base = dir.base().to_string();
    let (mut v, truncated) = dir
        .search_paged(
            &base,
            Scope::Subtree,
            &filter,
            &["objectClass", "cn", "displayName", "sAMAccountName", "uid", "mail", "name"],
            100,
        )
        .await?;
    v.sort_by_key(|e| e.display_name().to_lowercase());
    let domain = dn::dc_to_domain(&base);
    let rows = v
        .into_iter()
        .map(|e| {
            let k = Kind::of(&e);
            PickRow {
                name: e.display_name(),
                icon: k.icon(),
                detail: if ad { e.s("sAMAccountName") } else { e.s("uid") },
                location: dn::canonical(&dn::parent(&e.dn)).replacen(&domain, "", 1),
                dn: e.dn,
            }
        })
        .collect();
    render(&PickResTpl { uid: uid(), mode: p.mode, target: p.target, q: p.q, rows, truncated })
}

pub async fn pick_containers(a: Auth) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let base = dir.base().to_string();
    let f = crate::directory::container_filter(dir.info.flavor, None, a.s.is_advanced());
    let (v, _) = dir.search_paged(&base, Scope::Subtree, &f, &["1.1"], 10_000).await?;
    let mut out = String::new();
    for e in v {
        out.push_str(&format!("<option value=\"{}\">{}</option>", esc(&e.dn), esc(&dn::canonical(&e.dn))));
    }
    Ok(Html(out).into_response())
}

// ---------------------------------------------------------------- explorateur LDAP

pub async fn browse_detail(a: &Auth, dir: &mut Dir, target: &str) -> AppResult<String> {
    let e = read_full(dir, target).await?;
    let k = Kind::of(&e);
    let du = url(&e.dn);
    let attrs = super::attrs::attrs_tab_html(a, dir, &e, false).await?;
    Ok(format!(
        "<div class=\"props-head\"><svg class=\"i xl kind-icon {icon}\"><use href=\"/static/icons.svg#{icon}\"></use></svg>\
         <div class=\"title\"><div style=\"font-size:16px;font-weight:600\">{name} <span class=\"badge\">{kind}</span></div><div class=\"dn\">{dn}</div></div></div>\
         <div class=\"props-actions\" style=\"margin-bottom:14px\">\
         <button class=\"btn-sm\" hx-get=\"/obj/props?dn={du}\" hx-target=\"#modal\">Propriétés</button>\
         <button class=\"btn-sm\" hx-get=\"/obj/rename?dn={du}\" hx-target=\"#modal\">Renommer</button>\
         <button class=\"btn-sm\" hx-get=\"/obj/move?dn={du}\" hx-target=\"#modal\">Déplacer</button>\
         <button class=\"btn-sm btn-danger\" hx-get=\"/obj/delete?dn={du}\" hx-target=\"#modal\">Supprimer</button></div>{attrs}",
        icon = k.icon(),
        name = esc(&e.rdn_name()),
        kind = k.label(),
        dn = esc(&e.dn),
    ))
}
