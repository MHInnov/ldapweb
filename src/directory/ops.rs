//! Opérations d'administration abstraites par type de serveur : création d'objets,
//! mots de passe, activation, verrouillage, appartenance aux groupes.

use super::kinds::{Kind, PPOLICY_PERMANENT_LOCK};
use crate::config::GroupStyle;
use crate::error::{AppError, AppResult};
use crate::ldap::codec::{filter_escape, group_type, sid_from_string, uac};
use crate::ldap::dir::{AttrsBuilder, m_add, m_clear, m_delete, m_replace};
use crate::ldap::{Dir, Entry, Flavor, dn};
use base64::Engine;
use futures::stream::{self, StreamExt};
use ldap3::Scope;
use sha1::{Digest, Sha1};

// ---------------------------------------------------------------- mots de passe

/// Valeur unicodePwd attendue par AD : « "motdepasse" » en UTF-16LE.
pub fn ad_unicode_pwd(pw: &str) -> Vec<u8> {
    format!("\"{pw}\"").encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// Empreinte {SSHA} (repli si l'extension Password Modify n'est pas disponible).
pub fn ssha(pw: &str) -> String {
    let mut salt = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut salt);
    let mut h = Sha1::new();
    h.update(pw.as_bytes());
    h.update(salt);
    let mut out = h.finalize().to_vec();
    out.extend_from_slice(&salt);
    format!("{{SSHA}}{}", base64::engine::general_purpose::STANDARD.encode(out))
}

/// Générateur de mot de passe robuste (complexité AD satisfaite).
pub fn generate_password(len: usize) -> String {
    use rand::seq::{IndexedRandom, SliceRandom};
    const LOW: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
    const UP: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
    const DIG: &[u8] = b"23456789";
    const SYM: &[u8] = b"!#%+-=?@_";
    let mut rng = rand::rng();
    let all: Vec<u8> = [LOW, UP, DIG, SYM].concat();
    let mut v: Vec<u8> = vec![
        *LOW.choose(&mut rng).unwrap(),
        *UP.choose(&mut rng).unwrap(),
        *DIG.choose(&mut rng).unwrap(),
        *SYM.choose(&mut rng).unwrap(),
    ];
    while v.len() < len.max(12) {
        v.push(*all.choose(&mut rng).unwrap());
    }
    v.shuffle(&mut rng);
    String::from_utf8(v).unwrap()
}

pub async fn set_password(
    dir: &mut Dir,
    target: &str,
    pw: &str,
    must_change: bool,
    unlock: bool,
) -> AppResult<Vec<String>> {
    let mut warnings = Vec::new();
    if dir.is_ad() {
        if !dir.info.tls {
            return Err(AppError::bad_request(
                "Active Directory n'accepte les changements de mot de passe que sur une connexion chiffrée (ldaps:// ou StartTLS)",
            ));
        }
        let mut mods = vec![m_replace("unicodePwd", [ad_unicode_pwd(pw)])];
        mods.push(m_replace("pwdLastSet", [if must_change { "0" } else { "-1" }]));
        if unlock {
            mods.push(m_replace("lockoutTime", ["0"]));
        }
        dir.modify(target, mods).await?;
        return Ok(warnings);
    }
    if dir.info.supports_passmod() {
        dir.passmod(target, pw).await?;
    } else {
        dir.modify(target, vec![m_replace("userPassword", [ssha(pw)])]).await?;
        warnings.push("extension Password Modify indisponible : empreinte {SSHA} calculée par Arbor".into());
    }
    if must_change {
        if let Err(e) = dir.modify(target, vec![m_replace("pwdReset", ["TRUE"])]).await {
            warnings.push(format!("« changement obligatoire » non appliqué (ppolicy absent ?) : {}", e.message));
        }
    }
    if unlock {
        if let Ok(Some(e)) = dir.read(target, &["pwdAccountLockedTime"]).await {
            if let Some(v) = e.str("pwdAccountLockedTime") {
                if v != PPOLICY_PERMANENT_LOCK {
                    dir.modify(target, vec![m_clear("pwdAccountLockedTime")]).await?;
                }
            }
        }
    }
    Ok(warnings)
}

// ---------------------------------------------------------------- état des comptes

pub async fn set_enabled(dir: &mut Dir, target: &str, enable: bool) -> AppResult<()> {
    match dir.info.flavor {
        Flavor::ActiveDirectory | Flavor::SambaAd => {
            let e = dir.read_req(target, &["userAccountControl"]).await?;
            let u =
                e.int("userAccountControl").ok_or_else(|| AppError::bad_request("cet objet n'est pas un compte"))?;
            let nu = if enable { u & !uac::ACCOUNTDISABLE } else { u | uac::ACCOUNTDISABLE };
            if nu != u {
                dir.modify(target, vec![m_replace("userAccountControl", [nu.to_string()])]).await?;
            }
            Ok(())
        }
        Flavor::Ds389 => {
            let m = if enable { m_clear("nsAccountLock") } else { m_replace("nsAccountLock", ["TRUE"]) };
            dir.modify_permissive(target, vec![m]).await
        }
        _ => {
            let e = dir.read_req(target, &["pwdAccountLockedTime"]).await?;
            if enable {
                if e.has("pwdAccountLockedTime") {
                    dir.modify(target, vec![m_clear("pwdAccountLockedTime")]).await?;
                }
                Ok(())
            } else {
                dir.modify(target, vec![m_replace("pwdAccountLockedTime", [PPOLICY_PERMANENT_LOCK])]).await.map_err(
                    |e| {
                        if e.is_ldap(17) || e.is_ldap(21) || e.is_ldap(65) {
                            AppError::bad_request(
                                "la désactivation nécessite l'overlay ppolicy (pwdAccountLockedTime) sur OpenLDAP",
                            )
                        } else {
                            e
                        }
                    },
                )
            }
        }
    }
}

pub async fn unlock(dir: &mut Dir, target: &str) -> AppResult<()> {
    if dir.is_ad() {
        return dir.modify(target, vec![m_replace("lockoutTime", ["0"])]).await;
    }
    let e = dir.read_req(target, &["pwdAccountLockedTime"]).await?;
    match e.str("pwdAccountLockedTime") {
        Some(v) if v != PPOLICY_PERMANENT_LOCK => dir.modify(target, vec![m_clear("pwdAccountLockedTime")]).await,
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------- allocation POSIX

async fn next_id(dir: &mut Dir, attr: &str, start: u32) -> AppResult<u32> {
    let filter = format!("({attr}=*)");
    let base = dir.base().to_string();
    let (v, _) = dir.search_paged(&base, Scope::Subtree, &filter, &[attr], 500_000).await?;
    let max = v.iter().filter_map(|e| e.int(attr)).filter(|n| *n >= start as i64 && *n < 2_000_000_000).max();
    Ok(match max {
        Some(m) => (m + 1) as u32,
        None => start,
    })
}

pub async fn next_uid(dir: &mut Dir) -> AppResult<u32> {
    let start = dir.profile.posix.uid_number_start;
    next_id(dir, "uidNumber", start).await
}

pub async fn next_gid(dir: &mut Dir) -> AppResult<u32> {
    let start = dir.profile.posix.gid_number_start;
    next_id(dir, "gidNumber", start).await
}

// ---------------------------------------------------------------- création

pub struct NewUser {
    pub parent: String,
    pub given: String,
    pub initials: String,
    pub sn: String,
    pub full_name: String,
    pub login: String,
    pub upn_suffix: String,
    pub password: String,
    pub must_change: bool,
    pub never_expires: bool,
    pub disabled: bool,
    pub mail: String,
    pub description: String,
    pub posix: bool,
    pub uid_number: Option<u32>,
    pub gid_number: Option<u32>,
    pub home: String,
    pub shell: String,
}

pub async fn create_user(dir: &mut Dir, u: &NewUser) -> AppResult<(String, Vec<String>)> {
    let mut warnings = Vec::new();
    let cn =
        if u.full_name.is_empty() { format!("{} {}", u.given, u.sn).trim().to_string() } else { u.full_name.clone() };
    if u.login.is_empty() {
        return Err(AppError::bad_request("le nom d'ouverture de session est obligatoire"));
    }
    if dir.is_ad() {
        if u.login.len() > 20 {
            return Err(AppError::bad_request(
                "le nom antérieur à Windows 2000 (sAMAccountName) est limité à 20 caractères",
            ));
        }
        let cn = if cn.is_empty() { u.login.clone() } else { cn };
        let new_dn = dn::child("CN", &cn, &u.parent);
        let mut a = AttrsBuilder::new();
        a.set("objectClass", ["top", "person", "organizationalPerson", "user"]);
        a.one("cn", &cn);
        a.one("sAMAccountName", &u.login);
        let suffix = if u.upn_suffix.is_empty() { dir.info.domain_dns.clone() } else { u.upn_suffix.clone() };
        a.one("userPrincipalName", &format!("{}@{}", u.login, suffix));
        a.one("givenName", &u.given);
        a.one("initials", &u.initials);
        a.one("sn", &u.sn);
        a.one("displayName", &cn);
        a.one("mail", &u.mail);
        a.one("description", &u.description);
        a.one("userAccountControl", &(uac::NORMAL_ACCOUNT | uac::ACCOUNTDISABLE).to_string());
        if u.posix {
            let uid = match u.uid_number {
                Some(n) => n,
                None => next_uid(dir).await?,
            };
            a.one("uid", &u.login);
            a.one("uidNumber", &uid.to_string());
            if let Some(g) = u.gid_number.or(dir.profile.posix.default_gid_number) {
                a.one("gidNumber", &g.to_string());
            }
            a.one("unixHomeDirectory", &u.home.replace("{uid}", &u.login));
            a.one("loginShell", &u.shell);
        }
        dir.add(&new_dn, a.build()).await?;
        if !u.password.is_empty() {
            if let Err(e) = set_password(dir, &new_dn, &u.password, u.must_change, false).await {
                return Err(AppError::bad_request(format!(
                    "le compte a été créé mais reste désactivé : le mot de passe a été refusé ({})",
                    e.message
                )));
            }
        } else if u.must_change {
            let _ = dir.modify(&new_dn, vec![m_replace("pwdLastSet", ["0"])]).await;
        }
        let mut flags = uac::NORMAL_ACCOUNT;
        if u.disabled {
            flags |= uac::ACCOUNTDISABLE;
        }
        if u.never_expires {
            flags |= uac::DONT_EXPIRE_PASSWORD;
        }
        if flags != uac::NORMAL_ACCOUNT | uac::ACCOUNTDISABLE {
            if let Err(e) = dir.modify(&new_dn, vec![m_replace("userAccountControl", [flags.to_string()])]).await {
                warnings.push(format!("le compte n'a pas pu être activé : {}", e.message));
            }
        }
        return Ok((new_dn, warnings));
    }

    // OpenLDAP / 389-DS / générique : inetOrgPerson + posixAccount
    let new_dn = dn::child("uid", &u.login, &u.parent);
    let cn = if cn.is_empty() { u.login.clone() } else { cn };
    let mut a = AttrsBuilder::new();
    let mut classes = vec!["top", "person", "organizationalPerson", "inetOrgPerson"];
    if u.posix {
        classes.push("posixAccount");
    }
    a.set("objectClass", classes);
    a.one("uid", &u.login);
    a.one("cn", &cn);
    a.one("sn", if u.sn.is_empty() { &u.login } else { &u.sn });
    a.one("givenName", &u.given);
    a.one("initials", &u.initials);
    a.one("displayName", &cn);
    a.one("mail", &u.mail);
    a.one("description", &u.description);
    if u.posix {
        let uid = match u.uid_number {
            Some(n) => n,
            None => next_uid(dir).await?,
        };
        let gid = u.gid_number.or(dir.profile.posix.default_gid_number).unwrap_or(uid);
        a.one("uidNumber", &uid.to_string());
        a.one("gidNumber", &gid.to_string());
        a.one("homeDirectory", &u.home.replace("{uid}", &u.login));
        a.one("loginShell", &u.shell);
    }
    if u.disabled && dir.info.flavor == Flavor::Ds389 {
        a.one("nsAccountLock", "TRUE");
    }
    dir.add(&new_dn, a.build()).await?;
    if !u.password.is_empty() {
        match set_password(dir, &new_dn, &u.password, u.must_change, false).await {
            Ok(w) => warnings.extend(w),
            Err(e) => warnings.push(format!("mot de passe non défini : {}", e.message)),
        }
    }
    if u.disabled && dir.info.flavor != Flavor::Ds389 {
        if let Err(e) = set_enabled(dir, &new_dn, false).await {
            warnings.push(e.message);
        }
    }
    Ok((new_dn, warnings))
}

pub fn group_style(dir: &Dir) -> GroupStyle {
    dir.profile.posix.group_style.unwrap_or(GroupStyle::GroupOfNames)
}

pub struct NewGroup {
    pub parent: String,
    pub name: String,
    pub sam: String,
    pub group_type: i64,
    pub description: String,
    pub mail: String,
    pub gid_number: Option<u32>,
    pub posix: bool,
    pub creator_dn: String,
}

pub async fn create_group(dir: &mut Dir, g: &NewGroup) -> AppResult<String> {
    if g.name.is_empty() {
        return Err(AppError::bad_request("nom de groupe requis"));
    }
    if dir.is_ad() {
        let new_dn = dn::child("CN", &g.name, &g.parent);
        let mut a = AttrsBuilder::new();
        a.set("objectClass", ["top", "group"]);
        a.one("cn", &g.name);
        a.one("sAMAccountName", if g.sam.is_empty() { &g.name } else { &g.sam });
        a.one("groupType", &(g.group_type as i32).to_string());
        a.one("description", &g.description);
        a.one("mail", &g.mail);
        if g.posix {
            let gid = match g.gid_number {
                Some(n) => n,
                None => next_gid(dir).await?,
            };
            a.one("gidNumber", &gid.to_string());
        }
        dir.add(&new_dn, a.build()).await?;
        return Ok(new_dn);
    }
    let new_dn = dn::child("cn", &g.name, &g.parent);
    let style = group_style(dir);
    // gidNumber n'est autorisé que si posixGroup fait partie des classes du groupe.
    let needs_posix = matches!(style, GroupStyle::PosixGroup | GroupStyle::Rfc2307bis);
    let gid = if needs_posix {
        Some(match g.gid_number {
            Some(n) => n,
            None => next_gid(dir).await?,
        })
    } else {
        None
    };
    let mut a = AttrsBuilder::new();
    // groupOfNames exige au moins un membre sur OpenLDAP : on utilise le DN du groupe
    // lui-même comme valeur d'attente (masquée dans l'interface).
    let placeholder = dir.info.flavor != Flavor::Ds389;
    match style {
        GroupStyle::GroupOfNames => {
            a.set("objectClass", ["top", "groupOfNames"]);
            if placeholder {
                a.one("member", &new_dn);
            }
        }
        GroupStyle::GroupOfUniqueNames => {
            a.set("objectClass", ["top", "groupOfUniqueNames"]);
            if placeholder {
                a.one("uniqueMember", &new_dn);
            }
        }
        GroupStyle::PosixGroup => {
            a.set("objectClass", ["top", "posixGroup"]);
        }
        GroupStyle::Rfc2307bis => {
            a.set("objectClass", ["top", "groupOfNames", "posixGroup"]);
            if placeholder {
                a.one("member", &new_dn);
            }
        }
    }
    a.one("cn", &g.name);
    a.one("description", &g.description);
    if let Some(gid) = gid {
        a.one("gidNumber", &gid.to_string());
    }
    let _ = &g.creator_dn;
    dir.add(&new_dn, a.build()).await?;
    Ok(new_dn)
}

pub async fn create_ou(dir: &mut Dir, parent: &str, name: &str, description: &str) -> AppResult<String> {
    if name.is_empty() {
        return Err(AppError::bad_request("nom requis"));
    }
    let new_dn = dn::child(if dir.is_ad() { "OU" } else { "ou" }, name, parent);
    let mut a = AttrsBuilder::new();
    a.set("objectClass", ["top", "organizationalUnit"]);
    a.one("ou", name);
    a.one("description", description);
    dir.add(&new_dn, a.build()).await?;
    Ok(new_dn)
}

pub async fn create_computer(dir: &mut Dir, parent: &str, name: &str, description: &str) -> AppResult<String> {
    if !dir.is_ad() {
        return Err(AppError::bad_request(
            "la création d'ordinateurs n'est disponible que pour Active Directory / Samba",
        ));
    }
    let name = name.trim().trim_end_matches('$');
    if name.is_empty() || name.len() > 15 {
        return Err(AppError::bad_request("nom d'ordinateur invalide (1 à 15 caractères)"));
    }
    let new_dn = dn::child("CN", name, parent);
    let mut a = AttrsBuilder::new();
    a.set("objectClass", ["top", "person", "organizationalPerson", "user", "computer"]);
    a.one("cn", name);
    a.one("sAMAccountName", &format!("{}$", name.to_uppercase()));
    a.one("userAccountControl", &(uac::WORKSTATION_TRUST_ACCOUNT | uac::PASSWD_NOTREQD).to_string());
    a.one("dNSHostName", &format!("{}.{}", name.to_lowercase(), dir.info.domain_dns));
    a.one("description", description);
    dir.add(&new_dn, a.build()).await?;
    Ok(new_dn)
}

pub async fn create_contact(
    dir: &mut Dir,
    parent: &str,
    given: &str,
    sn: &str,
    display: &str,
    mail: &str,
) -> AppResult<String> {
    let cn = if display.is_empty() { format!("{given} {sn}").trim().to_string() } else { display.to_string() };
    if cn.is_empty() {
        return Err(AppError::bad_request("nom requis"));
    }
    let new_dn = dn::child(if dir.is_ad() { "CN" } else { "cn" }, &cn, parent);
    let mut a = AttrsBuilder::new();
    if dir.is_ad() {
        a.set("objectClass", ["top", "person", "organizationalPerson", "contact"]);
    } else {
        a.set("objectClass", ["top", "person", "organizationalPerson", "inetOrgPerson"]);
    }
    a.one("cn", &cn);
    a.one("sn", if sn.is_empty() { &cn } else { sn });
    a.one("givenName", given);
    a.one("displayName", &cn);
    a.one("mail", mail);
    dir.add(&new_dn, a.build()).await?;
    Ok(new_dn)
}

// ---------------------------------------------------------------- groupes

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberAttr {
    Member,
    UniqueMember,
    MemberUid,
}

impl MemberAttr {
    pub fn name(self) -> &'static str {
        match self {
            MemberAttr::Member => "member",
            MemberAttr::UniqueMember => "uniqueMember",
            MemberAttr::MemberUid => "memberUid",
        }
    }
}

pub fn member_attr(group: &Entry) -> MemberAttr {
    if group.has_class("group") || group.has_class("groupOfNames") {
        MemberAttr::Member
    } else if group.has_class("groupOfUniqueNames") {
        MemberAttr::UniqueMember
    } else if group.has_class("posixGroup") {
        MemberAttr::MemberUid
    } else {
        MemberAttr::Member
    }
}

#[derive(Debug, Clone)]
pub struct MemberRow {
    pub dn: String,
    pub name: String,
    pub kind: Kind,
    pub detail: String,
    pub primary: bool,
}

async fn uid_of(dir: &mut Dir, dn_: &str) -> AppResult<String> {
    let e = dir.read_req(dn_, &["uid"]).await?;
    e.str("uid").ok_or_else(|| AppError::bad_request(format!("{dn_} n'a pas d'attribut uid (requis pour memberUid)")))
}

pub async fn add_members(dir: &mut Dir, group_dn: &str, members: &[String]) -> AppResult<()> {
    if members.is_empty() {
        return Ok(());
    }
    let g = dir.read_req(group_dn, &["objectClass", "member", "uniqueMember"]).await?;
    let attr = member_attr(&g);
    match attr {
        MemberAttr::MemberUid => {
            let mut uids = Vec::new();
            for m in members {
                uids.push(uid_of(dir, m).await?);
            }
            dir.modify_permissive(group_dn, vec![m_add("memberUid", uids)]).await
        }
        _ => {
            let mut mods = vec![m_add(attr.name(), members.iter())];
            // retirer la valeur d'attente (DN du groupe lui-même)
            if !dir.is_ad() && g.strs(attr.name()).iter().any(|v| dn::eq(v, group_dn)) {
                mods.push(m_delete(attr.name(), [group_dn]));
            }
            dir.modify_permissive(group_dn, mods).await
        }
    }
}

pub async fn remove_members(dir: &mut Dir, group_dn: &str, members: &[String]) -> AppResult<()> {
    if members.is_empty() {
        return Ok(());
    }
    let g = dir.read_req(group_dn, &["objectClass", "member", "uniqueMember", "memberUid"]).await?;
    let attr = member_attr(&g);
    match attr {
        MemberAttr::MemberUid => {
            // les « membres » d'un posixGroup sont transmis sous forme uid ou DN
            let mut uids = Vec::new();
            for m in members {
                if m.contains('=') {
                    uids.push(uid_of(dir, m).await.unwrap_or_else(|_| dn::rdn_value(m)));
                } else {
                    uids.push(m.clone());
                }
            }
            dir.modify_permissive(group_dn, vec![m_delete("memberUid", uids)]).await
        }
        _ => {
            let current = g.strs(attr.name());
            let remaining = current.iter().filter(|c| !members.iter().any(|m| dn::eq(m, c))).count();
            let needs_placeholder = !dir.is_ad()
                && dir.info.flavor != Flavor::Ds389
                && remaining == 0
                && g.has_class(if attr == MemberAttr::Member { "groupOfNames" } else { "groupOfUniqueNames" });
            if needs_placeholder {
                dir.modify(group_dn, vec![m_replace(attr.name(), [group_dn])]).await
            } else {
                dir.modify_permissive(group_dn, vec![m_delete(attr.name(), members.iter())]).await
            }
        }
    }
}

/// Membres d'un groupe (avec type d'objet), groupe principal AD inclus.
pub async fn list_members(dir: &mut Dir, group: &Entry) -> AppResult<Vec<MemberRow>> {
    let mut rows = Vec::new();
    let attr = member_attr(group);
    if dir.is_ad() {
        let base = dir.base().to_string();
        let f = format!("(memberOf={})", filter_escape(&group.dn));
        let attrs = ["objectClass", "cn", "name", "displayName", "sAMAccountName", "description"];
        let (v, _) = dir.search_paged(&base, Scope::Subtree, &f, &attrs, 20_000).await?;
        for e in v {
            rows.push(MemberRow {
                name: e.display_name(),
                kind: Kind::of(&e),
                detail: e.s("sAMAccountName"),
                dn: e.dn,
                primary: false,
            });
        }
        // Membres hors du domaine courant / non indexés : compléter depuis l'attribut member
        let all = dir.read_all_values(&group.dn, "member").await?;
        for m in all {
            let m = String::from_utf8_lossy(&m).into_owned();
            if !rows.iter().any(|r| dn::eq(&r.dn, &m)) {
                rows.push(MemberRow {
                    name: dn::rdn_value(&m),
                    kind: Kind::Other,
                    detail: String::new(),
                    dn: m,
                    primary: false,
                });
            }
        }
        // Groupe principal
        if let Some(rid) = group.bin("objectSid").and_then(crate::ldap::codec::sid_rid) {
            let f = format!("(primaryGroupID={rid})");
            let (v, _) = dir.search_paged(&base, Scope::Subtree, &f, &attrs, 20_000).await?;
            for e in v {
                rows.push(MemberRow {
                    name: e.display_name(),
                    kind: Kind::of(&e),
                    detail: e.s("sAMAccountName"),
                    dn: e.dn,
                    primary: true,
                });
            }
        }
    } else if attr == MemberAttr::MemberUid {
        let uids = group.strs("memberUid");
        let base = dir.base().to_string();
        for chunk in uids.chunks(40) {
            let f: String = chunk.iter().map(|u| format!("(uid={})", filter_escape(u))).collect();
            let v = dir
                .search(&base, Scope::Subtree, &format!("(|{f})"), &["objectClass", "uid", "cn", "displayName"])
                .await
                .unwrap_or_default();
            for u in chunk {
                match v.iter().find(|e| e.s("uid") == *u) {
                    Some(e) => rows.push(MemberRow {
                        name: e.display_name(),
                        kind: Kind::of(e),
                        detail: u.clone(),
                        dn: e.dn.clone(),
                        primary: false,
                    }),
                    None => rows.push(MemberRow {
                        name: u.clone(),
                        kind: Kind::Other,
                        detail: "uid non trouvé dans l'annuaire".into(),
                        dn: u.clone(),
                        primary: false,
                    }),
                }
            }
        }
    } else {
        let values: Vec<String> = group.strs(attr.name()).into_iter().filter(|v| !dn::eq(v, &group.dn)).collect();
        let resolve = values.len() <= 500;
        let d = dir.clone();
        let fetched: Vec<MemberRow> = stream::iter(values)
            .map(|m| {
                let mut d = d.clone();
                async move {
                    if resolve {
                        if let Ok(Some(e)) = d.read(&m, &["objectClass", "cn", "displayName", "uid"]).await {
                            return MemberRow {
                                name: e.display_name(),
                                kind: Kind::of(&e),
                                detail: e.s("uid"),
                                dn: m,
                                primary: false,
                            };
                        }
                    }
                    MemberRow {
                        name: dn::rdn_value(&m),
                        kind: Kind::Other,
                        detail: String::new(),
                        dn: m,
                        primary: false,
                    }
                }
            })
            .buffer_unordered(16)
            .collect()
            .await;
        rows.extend(fetched);
    }
    rows.sort_by(|a, b| a.kind.order().cmp(&b.kind.order()).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    Ok(rows)
}

/// Groupes dont l'objet est membre. `nested` : appartenance effective (AD).
pub async fn member_of(dir: &mut Dir, obj: &Entry, nested: bool) -> AppResult<Vec<MemberRow>> {
    let base = dir.base().to_string();
    let attrs = ["objectClass", "cn", "description", "groupType", "objectSid"];
    let mut rows = Vec::new();
    if dir.is_ad() {
        let f = if nested {
            format!("(member:1.2.840.113556.1.4.1941:={})", filter_escape(&obj.dn))
        } else {
            format!("(member={})", filter_escape(&obj.dn))
        };
        let (v, _) = dir.search_paged(&base, Scope::Subtree, &f, &attrs, 5000).await?;
        for e in v {
            let gt = e.int("groupType").unwrap_or(0);
            rows.push(MemberRow {
                name: e.display_name(),
                kind: Kind::Group,
                detail: format!("{} · {}", group_type::scope_label(gt), group_type::type_label(gt)),
                dn: e.dn,
                primary: false,
            });
        }
        // groupe principal
        if let (Some(pg), Some(sid)) = (obj.int("primaryGroupID"), dir.info.domain_sid.clone()) {
            if let Some(b) = sid_from_string(&format!("{sid}-{pg}")) {
                let f = format!("(objectSid={})", crate::ldap::codec::filter_escape_bytes(&b));
                if let Ok(v) = dir.search(&base, Scope::Subtree, &f, &attrs).await {
                    for e in v {
                        if !rows.iter().any(|r| dn::eq(&r.dn, &e.dn)) {
                            rows.push(MemberRow {
                                name: e.display_name(),
                                kind: Kind::Group,
                                detail: "groupe principal".into(),
                                dn: e.dn,
                                primary: true,
                            });
                        } else if let Some(r) = rows.iter_mut().find(|r| dn::eq(&r.dn, &e.dn)) {
                            r.primary = true;
                        }
                    }
                }
            }
        }
    } else {
        let uid = obj.str("uid").unwrap_or_default();
        let mut f = format!("(member={0})(uniqueMember={0})", filter_escape(&obj.dn));
        if !uid.is_empty() {
            f.push_str(&format!("(memberUid={})", filter_escape(&uid)));
        }
        let (v, _) = dir.search_paged(&base, Scope::Subtree, &format!("(|{f})"), &attrs, 5000).await?;
        for e in v {
            rows.push(MemberRow {
                name: e.display_name(),
                kind: Kind::Group,
                detail: e.s("description"),
                dn: e.dn,
                primary: false,
            });
        }
        if let Some(gid) = obj.int("gidNumber") {
            if let Ok(v) = dir
                .search(&base, Scope::Subtree, &format!("(&(objectClass=posixGroup)(gidNumber={gid}))"), &attrs)
                .await
            {
                for e in v {
                    match rows.iter_mut().find(|r| dn::eq(&r.dn, &e.dn)) {
                        Some(r) => r.primary = true,
                        None => rows.push(MemberRow {
                            name: e.display_name(),
                            kind: Kind::Group,
                            detail: "groupe principal (gidNumber)".into(),
                            dn: e.dn,
                            primary: true,
                        }),
                    }
                }
            }
        }
    }
    rows.sort_by_key(|r| r.name.to_lowercase());
    Ok(rows)
}
