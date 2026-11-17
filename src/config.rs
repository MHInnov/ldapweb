//! Configuration (fichier TOML). Un fichier peut déclarer plusieurs annuaires
//! (« profils »), chacun avec ses services connexes (DNS, DHCP, GPO...).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default, rename = "directory")]
    pub directories: Vec<DirectoryProfile>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TlsMode {
    /// Certificat auto-signé généré au premier démarrage dans `data_dir`.
    SelfSigned,
    /// Certificat et clé fournis (`tls_cert`, `tls_key`).
    Files,
    /// HTTP en clair (uniquement derrière un reverse-proxy TLS).
    Off,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default = "d_listen")]
    pub listen: String,
    #[serde(default = "d_tls")]
    pub tls: TlsMode,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    #[serde(default = "d_data_dir")]
    pub data_dir: PathBuf,
    /// Faire confiance à l'en-tête X-Forwarded-For (reverse-proxy).
    #[serde(default)]
    pub trust_proxy_headers: bool,
    #[serde(default = "d_title")]
    pub title: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: d_listen(),
            tls: d_tls(),
            tls_cert: None,
            tls_key: None,
            data_dir: d_data_dir(),
            trust_proxy_headers: false,
            title: d_title(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    #[serde(default = "d_idle")]
    pub session_idle_minutes: u64,
    #[serde(default = "d_max")]
    pub session_max_hours: u64,
    /// Nombre maximal d'échecs de connexion par IP sur 15 minutes.
    #[serde(default = "d_login_attempts")]
    pub max_login_failures: u32,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self { session_idle_minutes: d_idle(), session_max_hours: d_max(), max_login_failures: d_login_attempts() }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    #[serde(default = "d_true")]
    pub enabled: bool,
    pub path: Option<PathBuf>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self { enabled: true, path: None }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum FlavorSetting {
    #[default]
    Auto,
    ActiveDirectory,
    Samba,
    Openldap,
    #[serde(rename = "389ds")]
    Ds389,
    Generic,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum GroupStyle {
    /// groupOfNames + member (DN)
    GroupOfNames,
    /// groupOfUniqueNames + uniqueMember (DN)
    GroupOfUniqueNames,
    /// posixGroup + memberUid (RFC 2307)
    PosixGroup,
    /// groupOfNames + posixGroup auxiliaire (RFC 2307bis)
    Rfc2307bis,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryProfile {
    pub id: String,
    pub name: String,
    /// URLs LDAP essayées dans l'ordre (basculement automatique).
    pub urls: Vec<String>,
    #[serde(default)]
    pub starttls: bool,
    pub ca_file: Option<PathBuf>,
    /// Désactive la vérification du certificat du serveur (tests uniquement !).
    #[serde(default)]
    pub tls_insecure: bool,
    /// DN de base ; détecté via le RootDSE si absent.
    pub base_dn: Option<String>,
    #[serde(default)]
    pub flavor: FlavorSetting,
    #[serde(default = "d_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "d_max_entries")]
    pub max_list_entries: usize,
    #[serde(default)]
    pub login: LoginConfig,
    #[serde(default)]
    pub posix: PosixConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub gpo: GpoConfig,
    #[serde(default)]
    pub kerberos: KerberosConfig,
    #[serde(default)]
    pub dhcp: Vec<KeaServer>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct LoginConfig {
    /// AD : suffixe ajouté si l'utilisateur saisit un simple identifiant (ex. "corp.local").
    pub default_upn_suffix: Option<String>,
    /// LDAP : filtre de recherche de l'utilisateur, `{user}` est remplacé (ex. "(uid={user})").
    pub user_filter: Option<String>,
    /// LDAP : base de recherche des comptes.
    pub user_search_base: Option<String>,
    /// LDAP : compte de service utilisé pour retrouver le DN (si l'anonyme est interdit).
    pub lookup_bind_dn: Option<String>,
    pub lookup_bind_password: Option<String>,
    /// Restreindre l'accès aux membres de ce groupe (DN).
    pub required_group: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PosixConfig {
    /// Style de groupes pour OpenLDAP / 389-DS.
    pub group_style: Option<GroupStyle>,
    #[serde(default = "d_uid_start")]
    pub uid_number_start: u32,
    #[serde(default = "d_uid_start")]
    pub gid_number_start: u32,
    #[serde(default = "d_home")]
    pub home_template: String,
    #[serde(default = "d_shell")]
    pub default_shell: String,
    /// gidNumber par défaut des nouveaux utilisateurs.
    pub default_gid_number: Option<u32>,
    /// Ajouter les attributs POSIX aux nouveaux comptes AD (RFC 2307 / « Identity Management for Unix »).
    #[serde(default)]
    pub ad_posix_attributes: bool,
    /// Classes considérées comme conteneurs dans l'arborescence (remplace la liste par défaut).
    pub tree_container_classes: Option<Vec<String>>,
}

impl Default for PosixConfig {
    fn default() -> Self {
        Self {
            group_style: None,
            uid_number_start: d_uid_start(),
            gid_number_start: d_uid_start(),
            home_template: d_home(),
            default_shell: d_shell(),
            default_gid_number: None,
            ad_posix_attributes: false,
            tree_container_classes: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum DnsProviderKind {
    /// AD → MicrosoftDNS ; sinon dnszone si `dnszone_base` est défini.
    #[default]
    Auto,
    /// Zones intégrées à Active Directory / Samba AD (stockées dans l'annuaire).
    Ad,
    /// Schéma LDAP « dnszone » (BIND sdb/dlz-ldap, PowerDNS LDAP backend).
    Dnszone,
    None,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    #[serde(default)]
    pub provider: DnsProviderKind,
    /// Base des entrées dNSZone (provider dnszone).
    pub dnszone_base: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct GpoConfig {
    /// Chemin du dossier Policies de SYSVOL (local, monté ou UNC sous Windows),
    /// ex. '\\corp.local\SYSVOL\corp.local\Policies' ou '/var/lib/samba/sysvol/corp.local/Policies'.
    pub sysvol_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct KerberosConfig {
    /// Royaume Kerberos ; déduit du domaine DNS pour AD.
    pub realm: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeaServer {
    pub id: String,
    pub name: String,
    /// URL de l'agent de contrôle Kea ou du socket HTTP du serveur DHCP.
    pub url: String,
    /// "dhcp4" ou "dhcp6".
    #[serde(default = "d_dhcp4")]
    pub service: String,
    /// Ajouter le champ "service" aux commandes (nécessaire avec kea-ctrl-agent).
    #[serde(default = "d_true")]
    pub via_control_agent: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub ca_file: Option<PathBuf>,
    #[serde(default)]
    pub tls_insecure: bool,
}

fn d_listen() -> String {
    "0.0.0.0:8443".into()
}
fn d_tls() -> TlsMode {
    TlsMode::SelfSigned
}
fn d_data_dir() -> PathBuf {
    PathBuf::from("data")
}
fn d_title() -> String {
    "Arbor".into()
}
fn d_idle() -> u64 {
    30
}
fn d_max() -> u64 {
    10
}
fn d_login_attempts() -> u32 {
    10
}
fn d_true() -> bool {
    true
}
fn d_timeout() -> u64 {
    15
}
fn d_max_entries() -> usize {
    5000
}
fn d_uid_start() -> u32 {
    10000
}
fn d_home() -> String {
    "/home/{uid}".into()
}
fn d_shell() -> String {
    "/bin/bash".into()
}
fn d_dhcp4() -> String {
    "dhcp4".into()
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let txt = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("lecture de {} impossible : {e}", path.display()))?;
        let cfg: Config =
            toml::from_str(&txt).map_err(|e| anyhow::anyhow!("configuration invalide ({}) : {e}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.directories.is_empty() {
            anyhow::bail!("aucun annuaire déclaré (section [[directory]])");
        }
        let mut ids = std::collections::HashSet::new();
        for d in &self.directories {
            if !ids.insert(d.id.as_str()) {
                anyhow::bail!("identifiant d'annuaire en double : {}", d.id);
            }
            if d.urls.is_empty() {
                anyhow::bail!("annuaire {} : aucune URL", d.id);
            }
            for u in &d.urls {
                if !(u.starts_with("ldap://") || u.starts_with("ldaps://") || u.starts_with("ldapi://")) {
                    anyhow::bail!("annuaire {} : URL invalide {u}", d.id);
                }
            }
            let mut kea = std::collections::HashSet::new();
            for k in &d.dhcp {
                if !kea.insert(k.id.as_str()) {
                    anyhow::bail!("annuaire {} : serveur DHCP en double {}", d.id, k.id);
                }
                if k.service != "dhcp4" && k.service != "dhcp6" {
                    anyhow::bail!("serveur DHCP {} : service doit valoir dhcp4 ou dhcp6", k.id);
                }
            }
        }
        if self.server.tls == TlsMode::Files && (self.server.tls_cert.is_none() || self.server.tls_key.is_none()) {
            anyhow::bail!("tls = \"files\" exige tls_cert et tls_key");
        }
        Ok(())
    }

    pub fn audit_path(&self) -> PathBuf {
        self.audit.path.clone().unwrap_or_else(|| self.server.data_dir.join("audit.jsonl"))
    }
}

pub const EXAMPLE_CONFIG: &str = r#"# Arbor — configuration
# Documentation complète : README.md

[server]
listen = "0.0.0.0:8443"
# "self-signed" (généré dans data_dir), "files" (tls_cert/tls_key) ou "off" (derrière un reverse-proxy)
tls = "self-signed"
# tls_cert = "/etc/arbor/cert.pem"
# tls_key  = "/etc/arbor/key.pem"
data_dir = "data"
trust_proxy_headers = false
title = "Arbor"

[security]
session_idle_minutes = 30
session_max_hours = 10
max_login_failures = 10

[audit]
enabled = true
# path = "data/audit.jsonl"

# ---------------------------------------------------------------------------
# Active Directory / Samba AD
# ---------------------------------------------------------------------------
[[directory]]
id = "corp"
name = "CORP — Active Directory"
urls = ["ldaps://dc1.corp.example", "ldaps://dc2.corp.example"]
flavor = "auto"            # auto | active-directory | samba | openldap | 389ds | generic
# ca_file = "corp-root-ca.pem"
tls_insecure = false
timeout_secs = 15

[directory.login]
default_upn_suffix = "corp.example"
# required_group = "CN=Arbor-Admins,OU=Groupes,DC=corp,DC=example"

[directory.gpo]
# Windows : chemin UNC ; Samba (Arbor installé sur le DC) : chemin local
# sysvol_path = '\\corp.example\SYSVOL\corp.example\Policies'
# sysvol_path = "/var/lib/samba/sysvol/corp.example/Policies"

[directory.dns]
provider = "auto"          # auto | ad | dnszone | none

# Serveurs DHCP ISC Kea (API REST de kea-ctrl-agent)
# [[directory.dhcp]]
# id = "dhcp1"
# name = "DHCP site principal"
# url = "http://dhcp1.corp.example:8000"
# service = "dhcp4"
# username = "kea-api"
# password = "secret"

# ---------------------------------------------------------------------------
# OpenLDAP / 389-DS
# ---------------------------------------------------------------------------
# [[directory]]
# id = "lab"
# name = "Lab — OpenLDAP"
# urls = ["ldap://ldap.lab.example"]
# starttls = true
# base_dn = "dc=lab,dc=example"
#
# [directory.login]
# user_filter = "(|(uid={user})(mail={user}))"
# # lookup_bind_dn = "cn=lookup,ou=services,dc=lab,dc=example"
# # lookup_bind_password = "..."
#
# [directory.posix]
# group_style = "group-of-names"   # group-of-names | group-of-unique-names | posix-group | rfc2307bis
# uid_number_start = 10000
# gid_number_start = 10000
# home_template = "/home/{uid}"
# default_shell = "/bin/bash"
# default_gid_number = 10000
#
# [directory.dns]
# provider = "dnszone"
# dnszone_base = "ou=dns,dc=lab,dc=example"
"#;
