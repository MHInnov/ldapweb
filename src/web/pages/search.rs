//! Recherche : requêtes enregistrées (comptes désactivés, inactifs, à risque...),
//! recherche par nom ou par filtre LDAP brut, export CSV.

use crate::directory::kinds::{Kind, LIST_ATTRS, state_badges};
use crate::error::{AppError, AppResult};
use crate::ldap::codec::{dt_to_filetime, filter_escape};
use crate::ldap::{Flavor, dn};
use crate::web::auth::{Auth, Ctx};
use crate::web::html::render;
use askama::Template;
use axum::extract::{Query, RawQuery};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use ldap3::Scope;
use serde::Deserialize;

#[derive(Deserialize, Default, Clone)]
pub struct SearchQ {
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub preset: String,
    #[serde(default)]
    pub base: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub filter: String,
    #[serde(default)]
    pub attrs: String,
    #[serde(default)]
    pub days: Option<i64>,
}

const KINDS: &[(&str, &str)] = &[
    ("", "Tous les objets"),
    ("user", "Utilisateurs"),
    ("group", "Groupes"),
    ("computer", "Ordinateurs"),
    ("contact", "Contacts"),
    ("ou", "Unités d'organisation"),
    ("service", "Comptes de service gérés"),
];

pub fn presets(flavor: Flavor) -> Vec<(&'static str, &'static str)> {
    if flavor.is_ad() {
        vec![
            ("users", "Tous les utilisateurs"),
            ("groups", "Tous les groupes"),
            ("computers", "Tous les ordinateurs"),
            ("contacts", "Tous les contacts"),
            ("ous", "Toutes les unités d'organisation"),
            ("disabled", "Comptes utilisateurs désactivés"),
            ("locked", "Comptes verrouillés"),
            ("never_expires", "Mots de passe n'expirant jamais"),
            ("must_change", "Doivent changer le mot de passe"),
            ("inactive_users", "Utilisateurs inactifs (N jours)"),
            ("inactive_computers", "Ordinateurs inactifs (N jours)"),
            ("expired_accounts", "Comptes expirés"),
            ("no_preauth", "Sans pré-authentification Kerberos"),
            ("kerberoastable", "Utilisateurs avec SPN"),
            ("unconstrained", "Délégation non contrainte (hors DC)"),
            ("constrained", "Délégation contrainte"),
            ("passwd_notreqd", "Mot de passe non requis"),
            ("admincount", "Comptes protégés (adminCount=1)"),
            ("domain_admins", "Membres effectifs de Domain Admins"),
            ("empty_groups", "Groupes vides"),
            ("dcs", "Contrôleurs de domaine"),
            ("with_cert", "Objets avec certificat"),
            ("gmsa", "Comptes de service gérés (gMSA)"),
        ]
    } else {
        vec![
            ("users", "Tous les utilisateurs"),
            ("groups", "Tous les groupes"),
            ("ous", "Toutes les unités d'organisation"),
            ("disabled", "Comptes désactivés"),
            ("locked", "Comptes verrouillés (ppolicy)"),
            ("must_change", "Doivent changer le mot de passe (pwdReset)"),
            ("no_posix", "Utilisateurs sans attributs POSIX"),
            ("empty_groups", "Groupes sans membre"),
            ("with_cert", "Objets avec certificat"),
        ]
    }
}

fn kind_filter(kind: &str, ad: bool) -> Option<String> {
    if kind.is_empty() { None } else { Some(super::objects::kinds_filter(kind, ad)) }
}

/// Filtre LDAP et colonnes par défaut d'une requête prédéfinie.
fn preset_filter(key: &str, ad: bool, days: i64, base: &str) -> Option<(String, &'static str)> {
    let ft = dt_to_filetime(Utc::now() - chrono::Duration::days(days.max(1)));
    let now_ft = dt_to_filetime(Utc::now());
    let bit = |b: i64| format!("(userAccountControl:1.2.840.113556.1.4.803:={b})");
    let person = "(objectCategory=person)(objectClass=user)";
    let r = if ad {
        match key {
            "users" => (format!("(&{person})"), "sAMAccountName,mail,description"),
            "groups" => ("(objectClass=group)".into(), "sAMAccountName,groupType,description"),
            "computers" => ("(objectCategory=computer)".into(), "dNSHostName,operatingSystem,lastLogonTimestamp"),
            "contacts" => ("(objectClass=contact)".into(), "mail,telephoneNumber"),
            "ous" => ("(objectClass=organizationalUnit)".into(), "description"),
            "disabled" => (format!("(&{person}{})", bit(2)), "sAMAccountName,whenChanged"),
            "locked" => (format!("(&{person}(lockoutTime>=1))"), "sAMAccountName,lockoutTime,badPwdCount"),
            "never_expires" => (format!("(&{person}{})", bit(65536)), "sAMAccountName,pwdLastSet"),
            "must_change" => (format!("(&{person}(pwdLastSet=0))"), "sAMAccountName,whenCreated"),
            "inactive_users" => (
                format!("(&{person}(!{})(|(lastLogonTimestamp<={ft})(!(lastLogonTimestamp=*))))", bit(2)),
                "sAMAccountName,lastLogonTimestamp,whenCreated",
            ),
            "inactive_computers" => (
                format!(
                    "(&(objectCategory=computer)(!{})(|(lastLogonTimestamp<={ft})(!(lastLogonTimestamp=*))))",
                    bit(2)
                ),
                "dNSHostName,operatingSystem,lastLogonTimestamp",
            ),
            "expired_accounts" => {
                (format!("(&{person}(accountExpires>=1)(accountExpires<={now_ft}))"), "sAMAccountName,accountExpires")
            }
            "no_preauth" => (format!("(&{person}{})", bit(4194304)), "sAMAccountName,userAccountControl"),
            "kerberoastable" => (
                format!("(&{person}(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))"),
                "sAMAccountName,servicePrincipalName,pwdLastSet",
            ),
            "unconstrained" => (format!("(&{}(!{}))", bit(524288), bit(8192)), "sAMAccountName,userAccountControl"),
            "constrained" => ("(msDS-AllowedToDelegateTo=*)".into(), "sAMAccountName,msDS-AllowedToDelegateTo"),
            "passwd_notreqd" => (format!("(&{person}{})", bit(32)), "sAMAccountName,userAccountControl"),
            "admincount" => ("(&(adminCount=1)(objectClass=user))".into(), "sAMAccountName,memberOf"),
            "domain_admins" => (
                format!(
                    "(&{person}(memberOf:1.2.840.113556.1.4.1941:={}))",
                    filter_escape(&format!("CN=Domain Admins,CN=Users,{base}"))
                ),
                "sAMAccountName,lastLogonTimestamp",
            ),
            "empty_groups" => ("(&(objectClass=group)(!(member=*)))".into(), "sAMAccountName,groupType,description"),
            "dcs" => (
                format!("(&(objectCategory=computer)(|{}{}))", bit(8192), bit(67108864)),
                "dNSHostName,operatingSystem,operatingSystemVersion",
            ),
            "with_cert" => ("(userCertificate=*)".into(), "mail"),
            "gmsa" => (
                "(objectClass=msDS-GroupManagedServiceAccount)".into(),
                "sAMAccountName,dNSHostName,servicePrincipalName",
            ),
            _ => return None,
        }
    } else {
        match key {
            "users" => ("(|(objectClass=inetOrgPerson)(objectClass=posixAccount)(objectClass=account))".into(), "uid,mail,uidNumber"),
            "groups" => ("(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))".into(), "gidNumber,description"),
            "ous" => ("(objectClass=organizationalUnit)".into(), "description"),
            "disabled" => ("(|(nsAccountLock=TRUE)(pwdAccountLockedTime=000001010000Z))".into(), "uid"),
            "locked" => ("(pwdAccountLockedTime=*)".into(), "uid,pwdAccountLockedTime"),
            "must_change" => ("(pwdReset=TRUE)".into(), "uid"),
            "no_posix" => ("(&(objectClass=inetOrgPerson)(!(objectClass=posixAccount)))".into(), "uid,mail"),
            "empty_groups" => ("(&(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))(!(member=*))(!(uniqueMember=*))(!(memberUid=*)))".into(), "description"),
            "with_cert" => ("(|(userCertificate=*)(userCertificate;binary=*))".into(), "mail"),
            _ => return None,
        }
    };
    Some(r)
}

struct Built {
    base: String,
    scope: Scope,
    filter: String,
    columns: Vec<String>,
}

fn build(p: &SearchQ, flavor: Flavor, default_base: &str) -> AppResult<Built> {
    let ad = flavor.is_ad();
    let base = if p.base.trim().is_empty() { default_base.to_string() } else { p.base.trim().to_string() };
    let scope = match p.scope.as_str() {
        "one" => Scope::OneLevel,
        "base" => Scope::Base,
        _ => Scope::Subtree,
    };
    let mut parts: Vec<String> = Vec::new();
    let mut cols = String::new();
    if !p.filter.trim().is_empty() {
        let f = p.filter.trim();
        if ldap3::parse_filter(f).is_err() {
            return Err(AppError::bad_request("filtre LDAP invalide (vérifiez les parenthèses)"));
        }
        parts.push(f.to_string());
    } else if !p.preset.is_empty() {
        let (f, c) = preset_filter(&p.preset, ad, p.days.unwrap_or(90), default_base)
            .ok_or_else(|| AppError::bad_request("requête prédéfinie inconnue"))?;
        parts.push(f);
        cols = c.to_string();
    }
    if let Some(k) = kind_filter(&p.kind, ad) {
        parts.push(k);
    }
    let q = filter_escape(p.q.trim());
    if !q.is_empty() {
        let mut or = format!("(cn=*{q}*)(displayName=*{q}*)(mail=*{q}*)(description=*{q}*)");
        or.push_str(&if ad {
            format!("(sAMAccountName=*{q}*)(userPrincipalName=*{q}*)")
        } else {
            format!("(uid=*{q}*)")
        });
        parts.push(format!("(|{or})"));
    }
    if parts.is_empty() {
        parts.push("(objectClass=*)".into());
    }
    if ad && p.filter.trim().is_empty() && p.kind.is_empty() && p.preset.is_empty() {
        // éviter de lister les objets système dans une recherche par nom
        parts.push("(!(showInAdvancedViewOnly=TRUE))".into());
    }
    let filter = if parts.len() == 1 { parts.remove(0) } else { format!("(&{})", parts.join("")) };
    let col_src = if p.attrs.trim().is_empty() {
        if cols.is_empty() {
            if ad { "sAMAccountName,description".to_string() } else { "uid,description".to_string() }
        } else {
            cols
        }
    } else {
        p.attrs.clone()
    };
    let columns: Vec<String> = col_src
        .split([',', ';', ' '])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == ';'))
        .take(12)
        .collect();
    Ok(Built { base, scope, filter, columns })
}

#[derive(Template)]
#[template(path = "search.html")]
struct Page {
    ctx: Ctx,
    presets: Vec<(&'static str, &'static str)>,
    kinds: &'static [(&'static str, &'static str)],
    q: String,
    kind: String,
    preset: String,
    filter: String,
    base: String,
    scope: String,
    attrs: String,
    days: i64,
    autorun: bool,
    query: String,
}

pub async fn page(a: Auth, Query(p): Query<SearchQ>, RawQuery(raw): RawQuery) -> AppResult<Response> {
    let info = a.s.info.clone();
    let autorun = !p.q.is_empty() || !p.preset.is_empty() || !p.filter.is_empty() || !p.kind.is_empty();
    render(&Page {
        ctx: a.ctx("search"),
        presets: presets(info.flavor),
        kinds: KINDS,
        q: p.q.clone(),
        kind: p.kind.clone(),
        preset: p.preset.clone(),
        filter: p.filter.clone(),
        base: if p.base.is_empty() { info.base_dn.clone() } else { p.base.clone() },
        scope: if p.scope.is_empty() { "sub".into() } else { p.scope.clone() },
        attrs: p.attrs.clone(),
        days: p.days.unwrap_or(90),
        autorun,
        query: raw.unwrap_or_default(),
    })
}

pub struct ResRow {
    pub dn: String,
    pub parent: String,
    pub name: String,
    pub icon: &'static str,
    pub kind: &'static str,
    pub location: String,
    pub badges: Vec<(&'static str, &'static str)>,
    pub cols: Vec<String>,
}

#[derive(Template)]
#[template(path = "search_results.html")]
struct Results {
    rows: Vec<ResRow>,
    columns: Vec<String>,
    truncated: bool,
    limit: usize,
    filter: String,
    query: String,
}

fn col_value(e: &crate::ldap::Entry, attr: &str) -> String {
    let vals = e.bins(attr);
    vals.iter()
        .take(5)
        .map(|v| {
            let s = super::attrs::value_display(attr, v, crate::ldap::codec::is_binary_attr(attr));
            if attr.eq_ignore_ascii_case("memberOf") { dn::rdn_value(&s) } else { s }
        })
        .collect::<Vec<_>>()
        .join(" ; ")
        + if vals.len() > 5 { " …" } else { "" }
}

pub async fn results(a: Auth, Query(p): Query<SearchQ>, RawQuery(raw): RawQuery) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let b = build(&p, dir.info.flavor, &dir.info.base_dn.clone())?;
    let mut attrs: Vec<&str> = LIST_ATTRS.to_vec();
    attrs.extend(b.columns.iter().map(|s| s.as_str()));
    let limit = 2000;
    let (v, truncated) = dir.search_paged(&b.base, b.scope, &b.filter, &attrs, limit).await?;
    let domain = dn::dc_to_domain(&dir.info.base_dn);
    let flavor = dir.info.flavor;
    let mut rows: Vec<ResRow> = v
        .iter()
        .map(|e| {
            let k = Kind::of(e);
            let parent = dn::parent(&e.dn);
            ResRow {
                name: if k == Kind::Domain { dn::dc_to_domain(&e.dn) } else { e.rdn_name() },
                icon: k.icon(),
                kind: k.label(),
                location: dn::canonical(&parent).replacen(&domain, "", 1),
                badges: state_badges(e, flavor),
                cols: b.columns.iter().map(|c| col_value(e, c)).collect(),
                parent,
                dn: e.dn.clone(),
            }
        })
        .collect();
    rows.sort_by_key(|r| r.name.to_lowercase());
    render(&Results { rows, columns: b.columns, truncated, limit, filter: b.filter, query: raw.unwrap_or_default() })
}

pub async fn export_csv(a: Auth, Query(p): Query<SearchQ>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let b = build(&p, dir.info.flavor, &dir.info.base_dn.clone())?;
    let mut attrs: Vec<&str> = vec!["objectClass"];
    attrs.extend(b.columns.iter().map(|s| s.as_str()));
    let (v, truncated) = dir.search_paged(&b.base, b.scope, &b.filter, &attrs, 200_000).await?;
    let mut w = csv::WriterBuilder::new().delimiter(b';').from_writer(vec![0xEF, 0xBB, 0xBF]);
    let mut head = vec!["dn".to_string(), "type".to_string()];
    head.extend(b.columns.iter().cloned());
    w.write_record(&head).map_err(|e| AppError::internal(e.to_string()))?;
    for e in &v {
        let mut rec = vec![e.dn.clone(), Kind::of(e).label().to_string()];
        for c in &b.columns {
            rec.push(
                e.bins(c)
                    .iter()
                    .map(|x| super::attrs::value_display(c, x, crate::ldap::codec::is_binary_attr(c)))
                    .collect::<Vec<_>>()
                    .join(" | "),
            );
        }
        w.write_record(&rec).map_err(|e| AppError::internal(e.to_string()))?;
    }
    let data = w.into_inner().map_err(|e| AppError::internal(e.to_string()))?;
    a.audit(
        "export CSV",
        &b.base,
        true,
        &format!("{} entrée(s){} — {}", v.len(), if truncated { " (tronqué)" } else { "" }, b.filter),
    );
    let name = format!("arbor-export-{}.csv", Utc::now().format("%Y%m%d-%H%M%S"));
    Ok((
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\"")),
        ],
        data,
    )
        .into_response())
}
