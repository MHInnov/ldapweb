//! Stratégies de groupe (AD / Samba AD) : objets GPC dans l'annuaire, liens gPLink,
//! blocage d'héritage, calcul de l'héritage effectif, création / suppression (GPT dans SYSVOL).

use crate::error::{AppError, AppResult};
use crate::ldap::codec::{filter_escape, parse_generalized};
use crate::ldap::dir::{AttrsBuilder, m_clear, m_replace};
use crate::ldap::{Dir, Entry, dn};
use chrono::{DateTime, Utc};
use ldap3::Scope;
use std::path::Path;

pub const DEFAULT_DOMAIN_POLICY: &str = "{31B2F340-016D-11D2-945F-00C04FB984F9}";
pub const DEFAULT_DC_POLICY: &str = "{6AC1786C-016F-11D2-945F-00C04FB984F9}";

#[derive(Debug, Clone)]
pub struct Gpo {
    pub guid: String,
    pub dn: String,
    pub name: String,
    pub flags: i64,
    pub version: i64,
    pub path: String,
    pub machine_ext: String,
    pub user_ext: String,
    pub wmi: String,
    pub created: Option<DateTime<Utc>>,
    pub changed: Option<DateTime<Utc>>,
}

impl Gpo {
    pub fn from_entry(e: &Entry) -> Gpo {
        Gpo {
            guid: e.s("cn").to_uppercase(),
            dn: e.dn.clone(),
            name: e.str("displayName").unwrap_or_else(|| e.s("cn")),
            flags: e.int("flags").unwrap_or(0),
            version: e.int("versionNumber").unwrap_or(0),
            path: e.s("gPCFileSysPath"),
            machine_ext: e.s("gPCMachineExtensionNames"),
            user_ext: e.s("gPCUserExtensionNames"),
            wmi: e.s("gPCWQLFilter"),
            created: e.str("whenCreated").and_then(|v| parse_generalized(&v)),
            changed: e.str("whenChanged").and_then(|v| parse_generalized(&v)),
        }
    }
    pub fn user_version(&self) -> i64 {
        (self.version >> 16) & 0xFFFF
    }
    pub fn computer_version(&self) -> i64 {
        self.version & 0xFFFF
    }
    pub fn is_default(&self) -> bool {
        self.guid.eq_ignore_ascii_case(DEFAULT_DOMAIN_POLICY) || self.guid.eq_ignore_ascii_case(DEFAULT_DC_POLICY)
    }
}

pub fn status_label(flags: i64) -> &'static str {
    match flags & 3 {
        0 => "Activé",
        1 => "Paramètres utilisateur désactivés",
        2 => "Paramètres ordinateur désactivés",
        _ => "Tous les paramètres désactivés",
    }
}

pub const GPO_ATTRS: &[&str] = &[
    "cn",
    "displayName",
    "flags",
    "versionNumber",
    "gPCFileSysPath",
    "gPCMachineExtensionNames",
    "gPCUserExtensionNames",
    "gPCWQLFilter",
    "whenCreated",
    "whenChanged",
];

pub fn policies_dn(base: &str) -> String {
    format!("CN=Policies,CN=System,{base}")
}

pub async fn list(dir: &mut Dir) -> AppResult<Vec<Gpo>> {
    let base = policies_dn(dir.base());
    let mut v: Vec<Gpo> = dir
        .search(&base, Scope::OneLevel, "(objectClass=groupPolicyContainer)", GPO_ATTRS)
        .await?
        .iter()
        .map(Gpo::from_entry)
        .collect();
    v.sort_by_key(|g| g.name.to_lowercase());
    Ok(v)
}

pub async fn get(dir: &mut Dir, guid: &str) -> AppResult<Gpo> {
    let base = policies_dn(dir.base());
    let target = format!("CN={},{base}", guid_norm(guid)?);
    let e = dir.read_req(&target, GPO_ATTRS).await?;
    Ok(Gpo::from_entry(&e))
}

pub fn guid_norm(g: &str) -> AppResult<String> {
    let inner: String = g.trim().trim_start_matches('{').trim_end_matches('}').to_uppercase();
    let ok = inner.len() == 36 && inner.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    if !ok {
        return Err(AppError::bad_request("GUID de GPO invalide"));
    }
    Ok(format!("{{{inner}}}"))
}

// ---------------------------------------------------------------- gPLink

#[derive(Debug, Clone, PartialEq)]
pub struct Link {
    pub gpo_dn: String,
    pub options: i64,
}

impl Link {
    pub fn enabled(&self) -> bool {
        self.options & 1 == 0
    }
    pub fn enforced(&self) -> bool {
        self.options & 2 != 0
    }
    pub fn guid(&self) -> String {
        let r = dn::rdn_value(&self.gpo_dn);
        r.to_uppercase()
    }
}

/// Analyse gPLink : « [LDAP://cn={GUID},cn=policies,...;0][...;2] ».
/// Renvoie les liens par ordre de liaison (1 = priorité la plus haute), c.-à-d.
/// dans l'ordre inverse de la chaîne.
pub fn parse_gplink(s: &str) -> Vec<Link> {
    let mut out = Vec::new();
    for part in s.split('[').filter(|p| !p.trim().is_empty()) {
        let part = part.trim_end_matches(']').trim_end_matches(']');
        let (path, opts) = match part.rsplit_once(';') {
            Some((p, o)) => (p, o.trim().parse::<i64>().unwrap_or(0)),
            None => (part, 0),
        };
        let path = path.trim();
        let dn_ = path.strip_prefix("LDAP://").or_else(|| path.strip_prefix("ldap://")).unwrap_or(path).to_string();
        if !dn_.is_empty() {
            out.push(Link { gpo_dn: dn_, options: opts });
        }
    }
    out.reverse();
    out
}

pub fn format_gplink(links: &[Link]) -> String {
    links.iter().rev().map(|l| format!("[LDAP://{};{}]", l.gpo_dn, l.options)).collect()
}

pub async fn read_links(dir: &mut Dir, container: &str) -> AppResult<(Vec<Link>, bool)> {
    let e = dir.read_req(container, &["gPLink", "gPOptions"]).await?;
    Ok((parse_gplink(&e.s("gPLink")), e.int("gPOptions").unwrap_or(0) & 1 != 0))
}

pub async fn write_links(dir: &mut Dir, container: &str, links: &[Link]) -> AppResult<()> {
    let v = format_gplink(links);
    let m = if v.is_empty() { m_clear("gPLink") } else { m_replace("gPLink", [v]) };
    match dir.modify(container, vec![m]).await {
        Err(e) if e.is_ldap(16) && links.is_empty() => Ok(()),
        r => r,
    }
}

/// Conteneurs (domaine, OU, sites) liant ce GPO.
pub async fn links_of(dir: &mut Dir, guid: &str) -> AppResult<Vec<(String, Link)>> {
    let f = format!("(gPLink=*{}*)", filter_escape(guid));
    let mut bases = vec![dir.base().to_string()];
    if let Some(c) = &dir.info.config_nc {
        bases.push(format!("CN=Sites,{c}"));
    }
    let mut out = Vec::new();
    for b in bases {
        for e in dir.search(&b, Scope::Subtree, &f, &["gPLink"]).await.unwrap_or_default() {
            for l in parse_gplink(&e.s("gPLink")) {
                if l.guid().eq_ignore_ascii_case(guid) {
                    out.push((e.dn.clone(), l));
                }
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- héritage

#[derive(Debug, Clone)]
pub struct Applied {
    pub precedence: usize,
    pub gpo_dn: String,
    pub from: String,
    pub enforced: bool,
}

/// Calcule la liste de priorité des GPO appliqués à un conteneur (onglet
/// « Héritage de stratégie de groupe » de la GPMC). Les liens de site ne sont pas inclus.
pub async fn inheritance(dir: &mut Dir, container: &str) -> AppResult<Vec<Applied>> {
    let base = dir.base().to_string();
    // chaîne du domaine vers le conteneur
    let mut chain = Vec::new();
    let mut cur = container.to_string();
    loop {
        chain.push(cur.clone());
        if dn::eq(&cur, &base) || cur.is_empty() {
            break;
        }
        cur = dn::parent(&cur);
        if !dn::is_under(&cur, &base) {
            break;
        }
    }
    chain.reverse();
    let mut soms = Vec::new();
    for c in &chain {
        let (links, block) = read_links(dir, c).await.unwrap_or((vec![], false));
        soms.push((c.clone(), links, block));
    }
    let n = soms.len();
    let mut enforced = Vec::new();
    let mut normal = Vec::new();
    for (i, (c, links, _)) in soms.iter().enumerate() {
        let blocked_below = soms[i + 1..n].iter().any(|(_, _, b)| *b);
        for l in links.iter().filter(|l| l.enabled()) {
            if l.enforced() {
                enforced.push((c.clone(), l.clone()));
            } else if !blocked_below {
                normal.push((i, c.clone(), l.clone()));
            }
        }
    }
    // non forcés : le conteneur le plus proche d'abord, ordre de liaison conservé
    normal.sort_by_key(|x| std::cmp::Reverse(x.0));
    let mut out = Vec::new();
    for (c, l) in enforced {
        out.push(Applied { precedence: 0, gpo_dn: l.gpo_dn, from: c, enforced: true });
    }
    for (_, c, l) in normal {
        out.push(Applied { precedence: 0, gpo_dn: l.gpo_dn, from: c, enforced: false });
    }
    for (i, a) in out.iter_mut().enumerate() {
        a.precedence = i + 1;
    }
    Ok(out)
}

// ---------------------------------------------------------------- création / suppression

pub fn gpt_ini(version: i64, name: &str) -> String {
    format!("[General]\r\nVersion={version}\r\ndisplayName={name}\r\n")
}

/// Lit la version du GPT.INI dans SYSVOL.
pub fn sysvol_version(sysvol: &Path, guid: &str) -> Option<i64> {
    let p = sysvol.join(guid).join("GPT.INI");
    let txt = std::fs::read(&p).ok()?;
    let s = String::from_utf8_lossy(&txt);
    s.lines().find_map(|l| l.trim().strip_prefix("Version=").and_then(|v| v.trim().parse().ok()))
}

pub async fn create(dir: &mut Dir, name: &str, sysvol: Option<&Path>) -> AppResult<(Gpo, Vec<String>)> {
    if name.trim().is_empty() {
        return Err(AppError::bad_request("nom requis"));
    }
    let mut warnings = Vec::new();
    let guid = format!("{{{}}}", uuid::Uuid::new_v4().to_string().to_uppercase());
    let base = dir.base().to_string();
    let domain = dir.info.domain_dns.clone();
    let gpo_dn = format!("CN={guid},{}", policies_dn(&base));
    let mut a = AttrsBuilder::new();
    a.set("objectClass", ["top", "container", "groupPolicyContainer"]);
    a.one("cn", &guid);
    a.one("displayName", name.trim());
    a.one("gPCFileSysPath", &format!("\\\\{domain}\\SysVol\\{domain}\\Policies\\{guid}"));
    a.one("versionNumber", "0");
    a.one("flags", "0");
    a.one("gPCFunctionalityVersion", "2");
    dir.add(&gpo_dn, a.build()).await?;
    for child in ["User", "Machine"] {
        let mut c = AttrsBuilder::new();
        c.set("objectClass", ["top", "container"]);
        c.one("cn", child);
        if let Err(e) = dir.add(&format!("CN={child},{gpo_dn}"), c.build()).await {
            let _ = dir.delete_tree(&gpo_dn).await;
            return Err(e);
        }
    }
    match sysvol {
        Some(root) => {
            let dirp = root.join(&guid);
            let r = (|| -> std::io::Result<()> {
                std::fs::create_dir_all(dirp.join("Machine"))?;
                std::fs::create_dir_all(dirp.join("User"))?;
                std::fs::write(dirp.join("GPT.INI"), gpt_ini(0, name.trim()))?;
                Ok(())
            })();
            if let Err(e) = r {
                let _ = dir.delete_tree(&gpo_dn).await;
                return Err(AppError::internal(format!("création du modèle dans SYSVOL impossible ({}) : {e}", dirp.display())));
            }
            if dir.info.flavor == crate::ldap::Flavor::SambaAd {
                warnings.push("Samba : exécutez « samba-tool ntacl sysvolreset » pour appliquer les ACL du nouveau GPO dans SYSVOL".into());
            }
        }
        None => warnings.push(
            "SYSVOL non configuré (gpo.sysvol_path) : seul l'objet annuaire a été créé ; le dossier du GPO doit être créé dans SYSVOL".into(),
        ),
    }
    let g = get(dir, &guid).await?;
    Ok((g, warnings))
}

pub async fn delete(dir: &mut Dir, guid: &str, sysvol: Option<&Path>) -> AppResult<Vec<String>> {
    let guid = guid_norm(guid)?;
    let g = get(dir, &guid).await?;
    if g.is_default() {
        return Err(AppError::bad_request("les GPO par défaut du domaine ne peuvent pas être supprimés"));
    }
    let mut warnings = Vec::new();
    for (container, _) in links_of(dir, &guid).await? {
        let (mut links, _) = read_links(dir, &container).await?;
        links.retain(|l| !l.guid().eq_ignore_ascii_case(&guid));
        write_links(dir, &container, &links).await?;
    }
    dir.delete_tree(&g.dn).await?;
    if let Some(root) = sysvol {
        let p = root.join(&guid);
        if p.exists() {
            if let Err(e) = std::fs::remove_dir_all(&p) {
                warnings.push(format!("dossier SYSVOL non supprimé ({}) : {e}", p.display()));
            }
        }
    }
    Ok(warnings)
}

/// Noms des extensions côté client (CSE) les plus courantes.
pub fn cse_name(guid: &str) -> Option<&'static str> {
    Some(match guid.to_uppercase().as_str() {
        "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" => "Modèles d'administration (Registre)",
        "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" => "Paramètres de sécurité",
        "{42B5FAAE-6536-11D2-AE5A-0000F87571E3}" => "Scripts",
        "{25537BA6-77A8-11D2-9B6C-0000F8080861}" => "Redirection de dossiers",
        "{C6DC5466-785A-11D2-84D0-00C04FB169F7}" => "Installation de logiciels",
        "{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}" => "Récupération EFS",
        "{E437BC1C-AA7D-11D2-A382-00C04F991E27}" => "Sécurité IP",
        "{F3CCC681-B74C-4060-9F26-CD84525DCA2A}" => "Stratégie d'audit avancée",
        "{0ACDD40C-75AC-47AB-BAA0-BF6DE7E7FE63}" => "Réseau sans fil",
        "{A2E30F80-D7DE-11D2-BBDE-00C04F86AE3B}" => "Maintenance d'Internet Explorer",
        "{5794DAFD-BE60-433F-88A2-1A31939AC01F}" => "Préférences : lecteurs",
        "{6232C319-91AC-4931-9385-E70C2B099F0E}" => "Préférences : dossiers",
        "{7150F9BF-48AD-4DA4-A49C-29EF4A8369BA}" => "Préférences : fichiers",
        "{74EE6C03-5363-4554-B161-627540339CAB}" => "Préférences : fichiers INI",
        "{B087BE9D-ED37-454F-AF9C-04291E351182}" => "Préférences : registre",
        "{17D89FEC-5C44-4972-B12D-241CAEF74509}" => "Préférences : utilisateurs et groupes locaux",
        "{91FBB303-0CD5-4055-BF42-E512A681B325}" => "Préférences : services",
        "{AADCED64-746C-4633-A97C-D61349046527}" => "Préférences : tâches planifiées",
        "{BC75B1ED-5833-4858-9BB8-CBF0B166DF9D}" => "Préférences : imprimantes",
        "{C418DD9D-0D14-4EFB-8FBF-CFE535C8FAC7}" => "Préférences : raccourcis",
        "{E62688F0-25FD-4C90-BFF5-F508B9D2E31F}" => "Préférences : options d'alimentation",
        "{6A4C88C6-C502-4F74-8F60-2CB23EDC24E2}" => "Préférences : partages réseau",
        "{728EE579-943C-4519-9EF7-AB56765798ED}" => "Préférences : sources de données",
        "{3A0DBA37-F8B2-4356-83DE-3E90BD5C261F}" => "Préférences : options réseau",
        "{E47248BA-94CC-49C4-BBB5-9EB7F05183D0}" => "Préférences : paramètres Internet",
        "{A3F3E39B-5D83-4940-B954-28315B82F0A8}" => "Préférences : options des dossiers",
        "{D76B9641-3288-4F75-942D-087DE603E3EA}" => "LAPS (hérité)",
        "{4BCD6CDE-777B-48B6-9804-43568E23545D}" => "Windows LAPS",
        "{9650FDBC-053A-4715-AD14-FC2DC65E8330}" => "Hyper-V / Device Guard",
        "{CDEAFC3D-948D-49DD-AB12-E578BA4AF7AA}" => "TCP/IP",
        "{FB2CA36D-0B40-4307-821B-A13B252DE56C}" => "Mise en cache de stratégie",
        _ => return None,
    })
}

/// Extensions listées dans gPCMachineExtensionNames / gPCUserExtensionNames.
pub fn extensions(s: &str) -> Vec<String> {
    s.split('[')
        .filter_map(|p| {
            let g = p.split('}').next()?.trim_start_matches('{');
            if g.len() < 30 {
                return None;
            }
            let g = format!("{{{}}}", g.to_uppercase());
            Some(cse_name(&g).map(|n| n.to_string()).unwrap_or(g))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gplink_roundtrip() {
        let s = "[LDAP://cn={AAA},cn=policies,cn=system,DC=x;0][LDAP://cn={31B2F340-016D-11D2-945F-00C04FB984F9},cn=policies,cn=system,DC=x;2]";
        let l = parse_gplink(s);
        assert_eq!(l.len(), 2);
        // le dernier élément de la chaîne a l'ordre de liaison 1
        assert_eq!(l[0].guid(), DEFAULT_DOMAIN_POLICY);
        assert!(l[0].enforced());
        assert_eq!(format_gplink(&l), s);
    }

    #[test]
    fn ext_names() {
        let e = extensions(
            "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{53D6AB1B-2488-11D1-A28C-00C04FB94F17}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]",
        );
        assert_eq!(e, vec!["Modèles d'administration (Registre)", "Paramètres de sécurité"]);
    }
}
