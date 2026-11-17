//! Détection du type de serveur (Active Directory, Samba AD, OpenLDAP, 389-DS)
//! et des informations du domaine à partir du RootDSE.

use super::dir::Dir;
use super::dn;
use super::entry::Entry;
use crate::config::{DirectoryProfile, FlavorSetting};
use crate::error::AppResult;
use ldap3::{Ldap, Scope};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    ActiveDirectory,
    SambaAd,
    OpenLdap,
    Ds389,
    Generic,
}

impl Flavor {
    pub fn is_ad(self) -> bool {
        matches!(self, Flavor::ActiveDirectory | Flavor::SambaAd)
    }
    pub fn label(self) -> &'static str {
        match self {
            Flavor::ActiveDirectory => "Active Directory",
            Flavor::SambaAd => "Samba AD",
            Flavor::OpenLdap => "OpenLDAP",
            Flavor::Ds389 => "389 Directory Server",
            Flavor::Generic => "LDAP générique",
        }
    }
    pub fn short(self) -> &'static str {
        match self {
            Flavor::ActiveDirectory => "ad",
            Flavor::SambaAd => "samba",
            Flavor::OpenLdap => "openldap",
            Flavor::Ds389 => "389ds",
            Flavor::Generic => "ldap",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub flavor: Flavor,
    pub vendor: String,
    pub url: String,
    pub tls: bool,
    pub base_dn: String,
    pub naming_contexts: Vec<String>,
    pub config_nc: Option<String>,
    pub schema_nc: Option<String>,
    pub root_domain_nc: Option<String>,
    pub dns_host_name: Option<String>,
    pub server_dn: Option<String>,
    pub domain_dns: String,
    pub netbios: Option<String>,
    pub realm: String,
    pub domain_level: Option<i64>,
    pub forest_level: Option<i64>,
    pub dc_level: Option<i64>,
    pub subschema: Option<String>,
    pub controls: Vec<String>,
    pub extensions: Vec<String>,
    pub sasl_mechs: Vec<String>,
    pub domain_sid: Option<String>,
    pub recycle_bin: bool,
    pub upn_suffixes: Vec<String>,
    pub dns_partitions: Vec<String>,
}

pub const OID_AD_CAP: &str = "1.2.840.113556.1.4.800";
pub const OID_PAGED: &str = "1.2.840.113556.1.4.319";
pub const OID_PASSMOD: &str = "1.3.6.1.4.1.4203.1.11.1";

pub fn functional_level_label(v: i64) -> &'static str {
    match v {
        0 => "Windows 2000",
        1 => "Windows Server 2003 (intermédiaire)",
        2 => "Windows Server 2003",
        3 => "Windows Server 2008",
        4 => "Windows Server 2008 R2",
        5 => "Windows Server 2012",
        6 => "Windows Server 2012 R2",
        7 => "Windows Server 2016",
        10 => "Windows Server 2025",
        _ => "inconnu",
    }
}

impl ServerInfo {
    pub fn supports_control(&self, oid: &str) -> bool {
        self.controls.iter().any(|c| c == oid)
    }
    pub fn supports_passmod(&self) -> bool {
        self.extensions.iter().any(|c| c == OID_PASSMOD)
    }
    pub fn supports_paging(&self) -> bool {
        self.supports_control(OID_PAGED)
    }
    pub fn host(&self) -> String {
        if let Some(h) = &self.dns_host_name {
            return h.clone();
        }
        url_host(&self.url).0
    }
    /// Partition des zones DNS du domaine (« DC=DomainDnsZones,... »).
    pub fn domain_dns_zones(&self) -> Option<&String> {
        self.dns_partitions.iter().find(|p| p.to_ascii_lowercase().starts_with("dc=domaindnszones"))
    }
    pub fn forest_dns_zones(&self) -> Option<&String> {
        self.dns_partitions.iter().find(|p| p.to_ascii_lowercase().starts_with("dc=forestdnszones"))
    }
}

/// Hôte et port d'une URL LDAP.
pub fn url_host(url: &str) -> (String, u16) {
    let secure = url.starts_with("ldaps://");
    let rest = url.split("://").nth(1).unwrap_or(url);
    let hostport = rest.split('/').next().unwrap_or(rest);
    if let Some(stripped) = hostport.strip_prefix('[') {
        // IPv6
        let (h, p) = stripped.split_once(']').unwrap_or((stripped, ""));
        let port = p.trim_start_matches(':').parse().unwrap_or(if secure { 636 } else { 389 });
        return (h.to_string(), port);
    }
    match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(if secure { 636 } else { 389 })),
        None => (hostport.to_string(), if secure { 636 } else { 389 }),
    }
}

/// Lecture du RootDSE (possible avant authentification).
pub async fn read_root_dse(ldap: &mut Ldap, timeout: Duration) -> AppResult<Entry> {
    let attrs = vec![
        "*",
        "+",
        "namingContexts",
        "defaultNamingContext",
        "configurationNamingContext",
        "schemaNamingContext",
        "rootDomainNamingContext",
        "supportedControl",
        "supportedExtension",
        "supportedSASLMechanisms",
        "supportedCapabilities",
        "subschemaSubentry",
        "vendorName",
        "vendorVersion",
        "dnsHostName",
        "serverName",
        "domainFunctionality",
        "forestFunctionality",
        "domainControllerFunctionality",
        "objectClass",
    ];
    let res = ldap.with_timeout(timeout).search("", Scope::Base, "(objectClass=*)", attrs).await?;
    let (entries, _) = res.success()?;
    Ok(entries.into_iter().filter_map(Entry::from_result).next().unwrap_or_default())
}

pub fn initial_info(root: &Entry, profile: &DirectoryProfile, url: &str) -> ServerInfo {
    let caps = root.strs("supportedCapabilities");
    let classes = root.strs("objectClass");
    let vendor_name = root.s("vendorName");
    let auto = if caps.iter().any(|c| c == OID_AD_CAP) {
        if vendor_name.contains("Samba") { Flavor::SambaAd } else { Flavor::ActiveDirectory }
    } else if classes.iter().any(|c| c.eq_ignore_ascii_case("OpenLDAProotDSE")) || root.has("configContext") {
        Flavor::OpenLdap
    } else if vendor_name.contains("389") || vendor_name.contains("Red Hat") || vendor_name.contains("Fedora") {
        Flavor::Ds389
    } else {
        Flavor::Generic
    };
    let flavor = match profile.flavor {
        FlavorSetting::Auto => auto,
        FlavorSetting::ActiveDirectory => Flavor::ActiveDirectory,
        FlavorSetting::Samba => Flavor::SambaAd,
        FlavorSetting::Openldap => Flavor::OpenLdap,
        FlavorSetting::Ds389 => Flavor::Ds389,
        FlavorSetting::Generic => Flavor::Generic,
    };
    let ncs = root.strs("namingContexts");
    let base_dn = profile
        .base_dn
        .clone()
        .or_else(|| root.str("defaultNamingContext"))
        .or_else(|| {
            ncs.iter()
                .find(|n| {
                    let l = n.to_ascii_lowercase();
                    !l.starts_with("cn=config") && !l.starts_with("cn=monitor") && !l.starts_with("o=netscaperoot")
                })
                .cloned()
        })
        .unwrap_or_default();
    let domain_dns = dn::dc_to_domain(&base_dn);
    let realm = profile.kerberos.realm.clone().unwrap_or_else(|| domain_dns.to_uppercase());
    let vendor = match (vendor_name.is_empty(), root.str("vendorVersion")) {
        (false, Some(v)) => format!("{vendor_name} {v}"),
        (false, None) => vendor_name.clone(),
        _ => flavor.label().to_string(),
    };
    let dns_partitions = ncs
        .iter()
        .filter(|n| {
            let l = n.to_ascii_lowercase();
            l.starts_with("dc=domaindnszones") || l.starts_with("dc=forestdnszones")
        })
        .cloned()
        .collect();
    ServerInfo {
        flavor,
        vendor,
        url: url.to_string(),
        tls: url.starts_with("ldaps://") || profile.starttls,
        base_dn,
        naming_contexts: ncs,
        config_nc: root.str("configurationNamingContext"),
        schema_nc: root.str("schemaNamingContext"),
        root_domain_nc: root.str("rootDomainNamingContext"),
        dns_host_name: root.str("dnsHostName"),
        server_dn: root.str("serverName"),
        domain_dns,
        netbios: None,
        realm,
        domain_level: root.int("domainFunctionality"),
        forest_level: root.int("forestFunctionality"),
        dc_level: root.int("domainControllerFunctionality"),
        subschema: root.str("subschemaSubentry"),
        controls: root.strs("supportedControl"),
        extensions: root.strs("supportedExtension"),
        sasl_mechs: root.strs("supportedSASLMechanisms"),
        domain_sid: None,
        recycle_bin: false,
        upn_suffixes: Vec::new(),
        dns_partitions,
    }
}

/// Compléments après authentification (AD : NetBIOS, SID du domaine, corbeille,
/// distinction Windows / Samba).
pub async fn enrich(dir: &mut Dir, info: &mut ServerInfo, forced: bool) {
    if !info.flavor.is_ad() {
        return;
    }
    if let Ok(Some(head)) = dir.read(&info.base_dn, &["objectSid"]).await {
        info.domain_sid = head.bin("objectSid").and_then(super::codec::sid_to_string);
    }
    if let Some(cfg) = info.config_nc.clone() {
        let partitions = format!("CN=Partitions,{cfg}");
        if let Ok(Some(p)) = dir.read(&partitions, &["uPNSuffixes", "msDS-EnabledFeature"]).await {
            info.upn_suffixes = p.strs("uPNSuffixes");
            info.recycle_bin = p
                .strs("msDS-EnabledFeature")
                .iter()
                .any(|f| f.to_ascii_lowercase().starts_with("cn=recycle bin feature"));
        }
        let filter = format!("(&(objectClass=crossRef)(nCName={}))", super::codec::filter_escape(&info.base_dn));
        if let Ok(v) = dir.search(&partitions, Scope::OneLevel, &filter, &["nETBIOSName", "dnsRoot"]).await {
            if let Some(e) = v.first() {
                info.netbios = e.str("nETBIOSName");
                if let Some(r) = e.str("dnsRoot") {
                    info.domain_dns = r.to_lowercase();
                }
            }
        }
    }
    if let Some(host) = info.dns_host_name.clone() {
        let filter = format!("(&(objectClass=computer)(dNSHostName={}))", super::codec::filter_escape(&host));
        if let Ok(v) =
            dir.search(&info.base_dn, Scope::Subtree, &filter, &["operatingSystem", "operatingSystemVersion"]).await
        {
            if let Some(e) = v.first() {
                let os = e.s("operatingSystem");
                let ver = e.s("operatingSystemVersion");
                if os.to_ascii_lowercase().contains("samba") {
                    if !forced {
                        info.flavor = Flavor::SambaAd;
                    }
                    info.vendor = os.replacen('-', " ", 1);
                } else if !os.is_empty() {
                    info.vendor = format!("{os} {ver}").trim().to_string();
                }
            }
        }
    }
    if info.realm.is_empty() {
        info.realm = info.domain_dns.to_uppercase();
    }
}
