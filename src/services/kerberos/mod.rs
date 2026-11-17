//! Kerberos : SPN, types de chiffrement, délégation, génération de keytabs.

pub mod crypto;
pub mod keytab;

use crate::error::{AppError, AppResult};
use crate::ldap::Dir;
use crate::ldap::codec::filter_escape;
use ldap3::Scope;

/// Validation d'un SPN : « service/hôte[:port][/nom] ».
pub fn spn_valid(spn: &str) -> bool {
    let parts: Vec<&str> = spn.split('/').collect();
    (2..=3).contains(&parts.len())
        && parts.iter().all(|p| !p.is_empty())
        && spn.chars().all(|c| c.is_ascii_graphic())
        && !spn.contains('@')
}

/// Objets portant déjà ce SPN dans le domaine.
pub async fn spn_owners(dir: &mut Dir, spn: &str) -> AppResult<Vec<String>> {
    let base = dir.base().to_string();
    let f = format!("(servicePrincipalName={})", filter_escape(spn));
    Ok(dir.search(&base, Scope::Subtree, &f, &["1.1"]).await?.into_iter().map(|e| e.dn).collect())
}

pub async fn add_spn(dir: &mut Dir, target: &str, spn: &str) -> AppResult<()> {
    if !spn_valid(spn) {
        return Err(AppError::bad_request("SPN invalide (format attendu : service/hôte[:port])"));
    }
    let owners = spn_owners(dir, spn).await?;
    if let Some(o) = owners.iter().find(|o| !crate::ldap::dn::eq(o, target)) {
        return Err(AppError::bad_request(format!("SPN en double : déjà enregistré sur {o}")));
    }
    if owners.is_empty() {
        dir.modify(target, vec![crate::ldap::dir::m_add("servicePrincipalName", [spn])]).await?;
    }
    Ok(())
}

pub struct KeytabSpec {
    pub principals: Vec<String>,
    pub realm: String,
    pub password: String,
    pub salt: String,
    pub kvno: u32,
    pub etypes: Vec<i32>,
}

pub fn build_keytab(spec: &KeytabSpec) -> Vec<u8> {
    let mut entries = Vec::new();
    for et in &spec.etypes {
        let Some(key) = crypto::string_to_key(*et, &spec.password, &spec.salt) else { continue };
        for p in &spec.principals {
            entries.push(keytab::KeytabEntry {
                principal: p.split('@').next().unwrap_or(p).to_string(),
                realm: spec.realm.clone(),
                kvno: spec.kvno,
                etype: *et,
                key: key.clone(),
            });
        }
    }
    keytab::write(&entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn spn_format() {
        assert!(spn_valid("HTTP/web.corp.example"));
        assert!(spn_valid("MSSQLSvc/sql01.corp.example:1433"));
        assert!(spn_valid("ldap/dc1.corp.example/corp.example"));
        assert!(!spn_valid("HTTP"));
        assert!(!spn_valid("HTTP/web@CORP"));
        assert!(!spn_valid("HTTP/ web"));
    }
}
