//! `Dir` : poignée LDAP liée à la session de l'utilisateur, avec des opérations
//! de haut niveau (recherche paginée, lecture, modification, suppression récursive).

use super::entry::Entry;
use super::flavor::ServerInfo;
use crate::config::DirectoryProfile;
use crate::error::{AppError, AppResult};
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::controls::RawControl;
use ldap3::{Ldap, LdapError, Mod, Scope, SearchResult};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

pub type Mods = Vec<Mod<Vec<u8>>>;

pub mod ctrl {
    use ldap3::controls::RawControl;
    pub fn tree_delete() -> RawControl {
        RawControl { ctype: "1.2.840.113556.1.4.805".into(), crit: true, val: None }
    }
    pub fn show_deleted() -> RawControl {
        RawControl { ctype: "1.2.840.113556.1.4.417".into(), crit: true, val: None }
    }
    pub fn show_recycled() -> RawControl {
        RawControl { ctype: "1.2.840.113556.1.4.2064".into(), crit: false, val: None }
    }
    /// SD_FLAGS : propriétaire, groupe et DACL (lisible sans privilège SACL).
    pub fn sd_flags() -> RawControl {
        RawControl { ctype: "1.2.840.113556.1.4.801".into(), crit: true, val: Some(vec![0x30, 0x03, 0x02, 0x01, 0x07]) }
    }
    pub fn permissive_modify() -> RawControl {
        RawControl { ctype: "1.2.840.113556.1.4.1413".into(), crit: false, val: None }
    }
}

pub fn m_replace<S: AsRef<[u8]>>(attr: &str, vals: impl IntoIterator<Item = S>) -> Mod<Vec<u8>> {
    Mod::Replace(attr.as_bytes().to_vec(), vals.into_iter().map(|v| v.as_ref().to_vec()).collect())
}
pub fn m_add<S: AsRef<[u8]>>(attr: &str, vals: impl IntoIterator<Item = S>) -> Mod<Vec<u8>> {
    Mod::Add(attr.as_bytes().to_vec(), vals.into_iter().map(|v| v.as_ref().to_vec()).collect())
}
pub fn m_delete<S: AsRef<[u8]>>(attr: &str, vals: impl IntoIterator<Item = S>) -> Mod<Vec<u8>> {
    Mod::Delete(attr.as_bytes().to_vec(), vals.into_iter().map(|v| v.as_ref().to_vec()).collect())
}
pub fn m_clear(attr: &str) -> Mod<Vec<u8>> {
    Mod::Delete(attr.as_bytes().to_vec(), HashSet::new())
}

/// Constructeur d'attributs pour `add`.
#[derive(Default)]
pub struct AttrsBuilder(pub Vec<(Vec<u8>, HashSet<Vec<u8>>)>);

impl AttrsBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set<S: AsRef<[u8]>>(&mut self, attr: &str, vals: impl IntoIterator<Item = S>) -> &mut Self {
        let set: HashSet<Vec<u8>> =
            vals.into_iter().map(|v| v.as_ref().to_vec()).filter(|v: &Vec<u8>| !v.is_empty()).collect();
        if !set.is_empty() {
            self.0.retain(|(a, _)| !a.eq_ignore_ascii_case(attr.as_bytes()));
            self.0.push((attr.as_bytes().to_vec(), set));
        }
        self
    }
    pub fn one(&mut self, attr: &str, val: &str) -> &mut Self {
        self.set(attr, [val.trim()])
    }
    pub fn build(self) -> Vec<(Vec<u8>, HashSet<Vec<u8>>)> {
        self.0
    }
}

#[derive(Clone)]
pub struct Dir {
    pub ldap: Ldap,
    pub info: Arc<ServerInfo>,
    pub profile: Arc<DirectoryProfile>,
}

impl Dir {
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.profile.timeout_secs.max(2))
    }

    pub fn base(&self) -> &str {
        &self.info.base_dn
    }

    pub fn is_ad(&self) -> bool {
        self.info.flavor.is_ad()
    }

    fn handle(&self, ctrls: Vec<RawControl>) -> Ldap {
        let mut l = self.ldap.clone();
        l.with_timeout(self.timeout());
        if !ctrls.is_empty() {
            l.with_controls(ctrls);
        }
        l
    }

    pub async fn search(&mut self, base: &str, scope: Scope, filter: &str, attrs: &[&str]) -> AppResult<Vec<Entry>> {
        self.search_ctrl(base, scope, filter, attrs, vec![]).await
    }

    pub async fn search_ctrl(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: &[&str],
        ctrls: Vec<RawControl>,
    ) -> AppResult<Vec<Entry>> {
        let attrs: Vec<String> = attrs.iter().map(|s| s.to_string()).collect();
        let mut l = self.handle(ctrls);
        let SearchResult(entries, result) = l.search(base, scope, filter, attrs).await?;
        match result.rc {
            0 | 4 | 10 => {}
            _ => return Err(LdapError::LdapResult { result }.into()),
        }
        Ok(entries.into_iter().filter_map(Entry::from_result).collect())
    }

    /// Recherche paginée (contrôle « simple paged results ») plafonnée à `limit` entrées.
    /// Renvoie aussi un indicateur de troncature.
    pub async fn search_paged(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: &[&str],
        limit: usize,
    ) -> AppResult<(Vec<Entry>, bool)> {
        self.search_paged_ctrl(base, scope, filter, attrs, limit, vec![]).await
    }

    pub async fn search_paged_ctrl(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: &[&str],
        limit: usize,
        ctrls: Vec<RawControl>,
    ) -> AppResult<(Vec<Entry>, bool)> {
        if !self.info.supports_paging() {
            let mut v = self.search_ctrl(base, scope, filter, attrs, ctrls).await?;
            let truncated = v.len() > limit;
            v.truncate(limit);
            return Ok((v, truncated));
        }
        let attrs: Vec<String> = attrs.iter().map(|s| s.to_string()).collect();
        let mut l = self.handle(ctrls);
        let adapters: Vec<Box<dyn Adapter<'_, String, Vec<String>>>> =
            vec![Box::new(EntriesOnly::new()), Box::new(PagedResults::new(500))];
        let mut stream = l.streaming_search_with(adapters, base, scope, filter, attrs).await?;
        let mut out = Vec::new();
        let mut truncated = false;
        while let Some(re) = stream.next().await? {
            if let Some(e) = Entry::from_result(re) {
                out.push(e);
                if out.len() >= limit {
                    truncated = true;
                    break;
                }
            }
        }
        let msgid = stream.ldap_handle().last_id();
        let res = stream.finish().await;
        if truncated {
            let _ = self.ldap.clone().abandon(msgid).await;
        } else {
            match res.rc {
                0 | 4 | 10 => {}
                _ => return Err(LdapError::LdapResult { result: res }.into()),
            }
        }
        Ok((out, truncated))
    }

    /// Nombre d'entrées correspondant au filtre (attributs « 1.1 », plafonné).
    pub async fn count(&mut self, base: &str, filter: &str, cap: usize) -> AppResult<(usize, bool)> {
        let (v, t) = self.search_paged(base, Scope::Subtree, filter, &["1.1"], cap).await?;
        Ok((v.len(), t))
    }

    pub async fn read(&mut self, dn: &str, attrs: &[&str]) -> AppResult<Option<Entry>> {
        self.read_ctrl(dn, attrs, vec![]).await
    }

    pub async fn read_ctrl(&mut self, dn: &str, attrs: &[&str], ctrls: Vec<RawControl>) -> AppResult<Option<Entry>> {
        match self.search_ctrl(dn, Scope::Base, "(objectClass=*)", attrs, ctrls).await {
            Ok(mut v) => Ok(v.pop()),
            Err(e) if e.is_ldap(32) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn read_req(&mut self, dn: &str, attrs: &[&str]) -> AppResult<Entry> {
        self.read(dn, attrs).await?.ok_or_else(|| AppError::not_found(format!("objet introuvable : {dn}")))
    }

    /// Lecture de toutes les valeurs d'un attribut, avec récupération par plages
    /// (« member;range=0-1499 ») pour les grands groupes AD.
    pub async fn read_all_values(&mut self, dn: &str, attr: &str) -> AppResult<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        let mut start = 0usize;
        loop {
            let req = if start == 0 && !self.is_ad() { attr.to_string() } else { format!("{attr};range={start}-*") };
            let Some(e) = self.read(dn, &[req.as_str()]).await? else { return Ok(out) };
            let mut next = None;
            let mut found = false;
            for (name, vals) in &e.attrs {
                if !super::entry::base_attr(name).eq_ignore_ascii_case(attr) {
                    continue;
                }
                found = true;
                out.extend(vals.iter().cloned());
                if let Some(r) = name.split(';').find_map(|o| o.strip_prefix("range=")) {
                    if let Some((_, end)) = r.split_once('-') {
                        if end != "*" {
                            next = end.parse::<usize>().ok().map(|x| x + 1);
                        }
                    }
                }
            }
            if !found && start == 0 && self.is_ad() {
                // Pas de plage : l'attribut est vide ou peu volumineux.
                if let Some(e) = self.read(dn, &[attr]).await? {
                    out = e.bins(attr).into_iter().map(|b| b.to_vec()).collect();
                }
                return Ok(out);
            }
            match next {
                Some(n) if n > start => start = n,
                _ => return Ok(out),
            }
        }
    }

    pub async fn modify(&mut self, dn: &str, mods: Mods) -> AppResult<()> {
        if mods.is_empty() {
            return Ok(());
        }
        self.handle(vec![]).modify(dn, mods).await?.success()?;
        Ok(())
    }

    pub async fn modify_ctrl(&mut self, dn: &str, mods: Mods, ctrls: Vec<RawControl>) -> AppResult<()> {
        if mods.is_empty() {
            return Ok(());
        }
        self.handle(ctrls).modify(dn, mods).await?.success()?;
        Ok(())
    }

    /// Modification tolérante (ajout d'une valeur déjà présente, suppression d'une valeur absente).
    pub async fn modify_permissive(&mut self, dn: &str, mods: Mods) -> AppResult<()> {
        let ctrls = if self.info.supports_control("1.2.840.113556.1.4.1413") {
            vec![ctrl::permissive_modify()]
        } else {
            vec![]
        };
        match self.handle(ctrls).modify(dn, mods).await?.success() {
            Ok(_) => Ok(()),
            Err(LdapError::LdapResult { result }) if result.rc == 20 || result.rc == 16 => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn add(&mut self, dn: &str, attrs: Vec<(Vec<u8>, HashSet<Vec<u8>>)>) -> AppResult<()> {
        self.handle(vec![]).add(dn, attrs).await?.success()?;
        Ok(())
    }

    pub async fn delete(&mut self, dn: &str) -> AppResult<()> {
        self.handle(vec![]).delete(dn).await?.success()?;
        Ok(())
    }

    /// Suppression d'un objet et de son sous-arbre (contrôle « tree delete » sur AD,
    /// suppression récursive ailleurs).
    pub async fn delete_tree(&mut self, dn: &str) -> AppResult<()> {
        if self.is_ad() && self.info.supports_control("1.2.840.113556.1.4.805") {
            self.handle(vec![ctrl::tree_delete()]).delete(dn).await?.success()?;
            return Ok(());
        }
        let (mut all, truncated) = self.search_paged(dn, Scope::Subtree, "(objectClass=*)", &["1.1"], 100_000).await?;
        if truncated {
            return Err(AppError::bad_request("sous-arbre trop volumineux pour une suppression récursive"));
        }
        // Supprimer les plus profonds d'abord.
        all.sort_by_key(|e| std::cmp::Reverse(super::dn::split_rdns(&e.dn).len()));
        for e in all {
            self.delete(&e.dn).await?;
        }
        Ok(())
    }

    /// Renomme et/ou déplace un objet ; renvoie le nouveau DN.
    pub async fn rename(&mut self, dn: &str, new_rdn: &str, new_parent: Option<&str>) -> AppResult<String> {
        self.handle(vec![]).modifydn(dn, new_rdn, true, new_parent).await?.success()?;
        let parent = match new_parent {
            Some(p) => p.to_string(),
            None => super::dn::parent(dn),
        };
        Ok(if parent.is_empty() { new_rdn.to_string() } else { format!("{new_rdn},{parent}") })
    }

    pub async fn passmod(&mut self, dn: &str, new_pw: &str) -> AppResult<()> {
        use ldap3::exop::PasswordModify;
        self.handle(vec![])
            .extended(PasswordModify { user_id: Some(dn), old_pass: None, new_pass: Some(new_pw) })
            .await?
            .success()?;
        Ok(())
    }
}
