//! Éditeur d'attributs générique (équivalent de l'onglet « Éditeur d'attributs » /
//! ADSI Edit), guidé par le schéma du serveur.

use crate::error::{AppError, AppResult};
use crate::ldap::codec::{decode_known, looks_binary};
use crate::ldap::dir::{m_clear, m_replace};
use crate::ldap::{Dir, Entry, dn};
use crate::web::auth::Auth;
use crate::web::form::FormData;
use crate::web::html::{Hx, render, url};
use askama::Template;
use axum::extract::Query;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use serde::Deserialize;

pub struct AttrRow {
    pub name: String,
    pub syntax: &'static str,
    pub values: Vec<String>,
    pub more: usize,
    pub unset: bool,
    pub must: bool,
    pub readonly: bool,
    pub binary: bool,
}

#[derive(Template)]
#[template(path = "tab_attrs.html")]
struct AttrsTpl {
    uid: String,
    dn: String,
    rows: Vec<AttrRow>,
    show_unset: bool,
}

/// Attributs gérés par le système (non modifiables directement).
fn system_attr(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "objectguid"
            | "objectsid"
            | "whencreated"
            | "whenchanged"
            | "usncreated"
            | "usnchanged"
            | "distinguishedname"
            | "instancetype"
            | "objectcategory"
            | "dscorepropagationdata"
            | "memberof"
            | "canonicalname"
            | "createtimestamp"
            | "modifytimestamp"
            | "creatorsname"
            | "modifiersname"
            | "entryuuid"
            | "entrycsn"
            | "entrydn"
            | "hassubordinates"
            | "structuralobjectclass"
            | "subschemasubentry"
            | "msds-user-account-control-computed"
            | "msds-userpasswordexpirytimecomputed"
            | "allowedattributeseffective"
            | "tokengroups"
            | "msds-keyversionnumber"
            | "msds-principalname"
            | "badpwdcount"
            | "badpasswordtime"
            | "lastlogon"
            | "lastlogoff"
            | "logoncount"
            | "lastlogontimestamp"
            | "samaccounttype"
            | "primarygroupid"
            | "pwdfailuretime"
            | "pwdchangedtime"
            | "pwdhistory"
            | "contextcsn"
            | "replpropertymetadata"
            | "msds-revealedusers"
            | "isdeleted"
            | "objectclasscategory"
    )
}

pub fn value_display(name: &str, raw: &[u8], binary: bool) -> String {
    if let Some(d) = decode_known(name, raw) {
        return d;
    }
    if binary || looks_binary(raw) {
        let shown: String = raw.iter().take(32).map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
        return format!("{shown}{} ({} octets)", if raw.len() > 32 { " …" } else { "" }, raw.len());
    }
    let s = String::from_utf8_lossy(raw);
    if s.chars().count() > 400 {
        format!("{}… ({} caractères)", s.chars().take(400).collect::<String>(), s.chars().count())
    } else {
        s.into_owned()
    }
}

pub async fn attrs_tab_html(a: &Auth, dir: &mut Dir, e: &Entry, show_unset: bool) -> AppResult<String> {
    let schema = a.st.schema(dir).await?;
    let (must, may) = schema.allowed(&e.classes());
    let mut names = e.attr_names();
    names.sort_by_key(|n| n.to_lowercase());
    let mut rows = Vec::new();
    for n in &names {
        let vals = e.bins(n);
        let binary = schema.is_binary(n);
        let at = schema.attr(n);
        let readonly = system_attr(n) || at.map(|x| x.no_user_mod).unwrap_or(false);
        rows.push(AttrRow {
            name: schema.canonical_name(n),
            syntax: schema.syntax_label(n),
            values: vals.iter().take(20).map(|v| value_display(n, v, binary)).collect(),
            more: vals.len().saturating_sub(20),
            unset: false,
            must: must.iter().any(|m| m.eq_ignore_ascii_case(n)),
            readonly,
            binary: binary || vals.iter().any(|v| looks_binary(v)),
        });
    }
    if show_unset {
        for n in must.iter().chain(may.iter()) {
            if names.iter().any(|x| x.eq_ignore_ascii_case(n)) {
                continue;
            }
            let readonly = system_attr(n) || schema.is_readonly(n);
            rows.push(AttrRow {
                name: n.clone(),
                syntax: schema.syntax_label(n),
                values: vec![],
                more: 0,
                unset: true,
                must: must.contains(n),
                readonly,
                binary: schema.is_binary(n),
            });
        }
        rows.sort_by_key(|r| r.name.to_lowercase());
    }
    let u = super::objects::uid();
    let html = AttrsTpl { uid: u, dn: e.dn.clone(), rows, show_unset }.render()?;
    Ok(format!(
        "<div hx-get=\"/obj/tab?dn={}&tab=attrs{}\" hx-trigger=\"refresh-tab from:body\" hx-swap=\"outerHTML\">{html}</div>",
        url(&e.dn),
        if show_unset { "&unset=1" } else { "" }
    ))
}

#[derive(Deserialize)]
pub struct AttrQ {
    pub dn: String,
    #[serde(default)]
    pub attr: String,
}

#[derive(Template)]
#[template(path = "dlg_attr_edit.html")]
struct EditTpl {
    uid: String,
    dn: String,
    attr: String,
    syntax: String,
    single: bool,
    binary: bool,
    values: String,
    candidates: Vec<String>,
}

pub async fn edit_form(a: Auth, Query(q): Query<AttrQ>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let schema = a.st.schema(&mut dir).await?;
    let e = dir.read_req(&q.dn, &["*", "+"]).await?;
    let attr = q.attr.trim().to_string();
    let mut candidates = Vec::new();
    if attr.is_empty() {
        let (must, may) = schema.allowed(&e.classes());
        let present = e.attr_names();
        for n in must.iter().chain(may.iter()) {
            if !present.iter().any(|p| p.eq_ignore_ascii_case(n)) && !system_attr(n) && !schema.is_readonly(n) {
                candidates.push(n.clone());
            }
        }
        candidates.sort_by_key(|c| c.to_lowercase());
    }
    let binary = !attr.is_empty() && (schema.is_binary(&attr) || e.bins(&attr).iter().any(|v| looks_binary(v)));
    let values = e
        .bins(&attr)
        .iter()
        .map(|v| if binary { hex::encode(v) } else { String::from_utf8_lossy(v).into_owned() })
        .collect::<Vec<_>>()
        .join("\n");
    render(&EditTpl {
        uid: super::objects::uid(),
        dn: e.dn.clone(),
        syntax: if attr.is_empty() { String::new() } else { schema.syntax_label(&attr).to_string() },
        single: !attr.is_empty() && schema.is_single(&attr),
        binary,
        values,
        candidates,
        attr,
    })
}

fn parse_values(format: &str, text: &str) -> AppResult<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim_end_matches('\r');
        if l.trim().is_empty() {
            continue;
        }
        let v = match format {
            "hex" => hex::decode(l.chars().filter(|c| !c.is_whitespace()).collect::<String>())
                .map_err(|_| AppError::bad_request("valeur hexadécimale invalide"))?,
            "base64" => base64::engine::general_purpose::STANDARD
                .decode(l.trim())
                .map_err(|_| AppError::bad_request("valeur base64 invalide"))?,
            _ => l.as_bytes().to_vec(),
        };
        out.push(v);
    }
    Ok(out)
}

pub async fn edit_submit(a: Auth, f: FormData) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let target = f.s("dn");
    let attr = f.s("attr");
    if attr.is_empty() || !attr.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == ';' || c == '.') {
        return Err(AppError::bad_request("nom d'attribut invalide"));
    }
    let (rdn_attr, _) = dn::rdn_parts(&target);
    if rdn_attr.eq_ignore_ascii_case(&attr) {
        return Err(AppError::bad_request("l'attribut de nommage (RDN) se modifie via « Renommer »"));
    }
    if attr.eq_ignore_ascii_case("unicodePwd") || attr.eq_ignore_ascii_case("userPassword") {
        return Err(AppError::bad_request("utilisez « Réinitialiser le mot de passe » pour modifier un mot de passe"));
    }
    let vals = parse_values(&f.s("format"), &f.raw("values"))?;
    let schema = a.st.schema(&mut dir).await?;
    if vals.len() > 1 && schema.is_single(&attr) {
        return Err(AppError::bad_request(format!("{attr} n'accepte qu'une seule valeur")));
    }
    let mods = if vals.is_empty() { vec![m_clear(&attr)] } else { vec![m_replace(&attr, vals.iter())] };
    let res = dir.modify(&target, mods).await;
    let detail = format!("{attr} : {} valeur(s)", vals.len());
    a.audited("modification d'attribut", &target, &detail, res)?;
    Ok(Hx::ok(format!("Attribut {attr} mis à jour")).close_modal().trigger("refresh-tab").empty())
}

pub async fn delete_attr(a: Auth, Query(q): Query<AttrQ>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let (rdn_attr, _) = dn::rdn_parts(&q.dn);
    if rdn_attr.eq_ignore_ascii_case(&q.attr) {
        return Err(AppError::bad_request("impossible d'effacer l'attribut de nommage"));
    }
    let res = dir.modify(&q.dn, vec![m_clear(&q.attr)]).await;
    a.audited("suppression d'attribut", &q.dn, &q.attr, res)?;
    Ok(Hx::ok(format!("Attribut {} effacé", q.attr)).close_modal().trigger("refresh-tab").empty())
}

#[derive(Deserialize)]
pub struct DlQ {
    pub dn: String,
    pub attr: String,
    #[serde(default)]
    pub i: usize,
}

pub async fn download_value(a: Auth, Query(q): Query<DlQ>) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let e = dir.read_req(&q.dn, &[q.attr.as_str()]).await?;
    let vals = e.bins(&q.attr);
    let v = vals.get(q.i).ok_or_else(|| AppError::not_found("valeur introuvable"))?;
    let lower = q.attr.to_ascii_lowercase();
    let ext = if lower.contains("certificate") {
        "cer"
    } else if lower.contains("photo") {
        "jpg"
    } else {
        "bin"
    };
    let name = format!("{}-{}.{ext}", dn::rdn_value(&q.dn).replace(|c: char| !c.is_ascii_alphanumeric(), "_"), q.attr);
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\"")),
        ],
        v.to_vec(),
    )
        .into_response())
}
