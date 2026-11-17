//! Classification des objets (utilisateur, groupe, OU...) indépendamment du
//! type de serveur, et état des comptes.

use crate::ldap::codec::{parse_generalized, uac};
use crate::ldap::{Entry, Flavor};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    User,
    Group,
    Computer,
    Contact,
    Ou,
    Container,
    Domain,
    Builtin,
    Gpo,
    ServiceAccount,
    ForeignPrincipal,
    DnsZone,
    DnsNode,
    Other,
}

impl Kind {
    pub fn of(e: &Entry) -> Kind {
        let cls: Vec<String> = e.classes().iter().map(|c| c.to_ascii_lowercase()).collect();
        let has = |c: &str| cls.iter().any(|x| x == c);
        if has("msds-groupmanagedserviceaccount")
            || has("msds-managedserviceaccount")
            || has("msds-delegatedmanagedserviceaccount")
        {
            Kind::ServiceAccount
        } else if has("computer") || has("device") || has("iphost") {
            Kind::Computer
        } else if has("contact") {
            Kind::Contact
        } else if has("user") || has("inetorgperson") || has("posixaccount") || has("person") || has("account") {
            Kind::User
        } else if has("group")
            || has("groupofnames")
            || has("groupofuniquenames")
            || has("posixgroup")
            || has("groupofurls")
        {
            Kind::Group
        } else if has("organizationalunit") {
            Kind::Ou
        } else if has("domaindns") || has("domain") || has("dcobject") || has("organization") {
            Kind::Domain
        } else if has("builtindomain") {
            Kind::Builtin
        } else if has("grouppolicycontainer") {
            Kind::Gpo
        } else if has("foreignsecurityprincipal") {
            Kind::ForeignPrincipal
        } else if has("dnszone") && !has("dnsnode") && e.has("dc") {
            Kind::DnsZone
        } else if has("dnsnode") {
            Kind::DnsNode
        } else if has("container") || has("lostandfound") || has("msds-quotacontainer") || has("nscontainer") {
            Kind::Container
        } else {
            Kind::Other
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            Kind::User => "user",
            Kind::Group => "group",
            Kind::Computer => "computer",
            Kind::Contact => "contact",
            Kind::Ou => "ou",
            Kind::Container | Kind::Builtin => "folder",
            Kind::Domain => "domain",
            Kind::Gpo => "gpo",
            Kind::ServiceAccount => "service",
            Kind::ForeignPrincipal => "foreign",
            Kind::DnsZone | Kind::DnsNode => "dns",
            Kind::Other => "object",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Kind::User => "Utilisateur",
            Kind::Group => "Groupe",
            Kind::Computer => "Ordinateur",
            Kind::Contact => "Contact",
            Kind::Ou => "Unité d'organisation",
            Kind::Container => "Conteneur",
            Kind::Domain => "Domaine",
            Kind::Builtin => "Conteneur intégré",
            Kind::Gpo => "Objet de stratégie de groupe",
            Kind::ServiceAccount => "Compte de service géré",
            Kind::ForeignPrincipal => "Principal de sécurité externe",
            Kind::DnsZone => "Zone DNS",
            Kind::DnsNode => "Nœud DNS",
            Kind::Other => "Objet",
        }
    }

    pub fn is_container(self) -> bool {
        matches!(self, Kind::Ou | Kind::Container | Kind::Domain | Kind::Builtin)
    }

    pub fn is_account(self) -> bool {
        matches!(self, Kind::User | Kind::Computer | Kind::ServiceAccount)
    }

    /// Ordre de tri dans les listes (conteneurs en premier).
    pub fn order(self) -> u8 {
        match self {
            Kind::Domain => 0,
            Kind::Ou => 1,
            Kind::Container | Kind::Builtin => 2,
            Kind::User => 3,
            Kind::Group => 4,
            Kind::Computer => 5,
            Kind::Contact => 6,
            _ => 7,
        }
    }

    pub fn from_param(s: &str) -> Option<Kind> {
        Some(match s {
            "user" => Kind::User,
            "group" => Kind::Group,
            "computer" => Kind::Computer,
            "contact" => Kind::Contact,
            "ou" => Kind::Ou,
            _ => return None,
        })
    }
}

/// Attributs nécessaires pour afficher un objet dans une liste.
pub const LIST_ATTRS: &[&str] = &[
    "objectClass",
    "cn",
    "name",
    "ou",
    "dc",
    "uid",
    "displayName",
    "description",
    "sAMAccountName",
    "userAccountControl",
    "lockoutTime",
    "groupType",
    "mail",
    "nsAccountLock",
    "pwdAccountLockedTime",
    "gidNumber",
    "uidNumber",
    "dNSHostName",
    "operatingSystem",
    "whenChanged",
    "modifyTimestamp",
];

#[derive(Debug, Clone, Default)]
pub struct AccountState {
    pub disabled: bool,
    pub locked: bool,
    pub expired: bool,
    pub pwd_expired: bool,
    pub must_change: bool,
    pub never_expires: bool,
    pub supported: bool,
}

/// Valeur « verrouillage administratif permanent » de ppolicy (OpenLDAP).
pub const PPOLICY_PERMANENT_LOCK: &str = "000001010000Z";

pub fn account_state(e: &Entry, flavor: Flavor) -> AccountState {
    let mut s = AccountState::default();
    if flavor.is_ad() {
        let Some(u) = e.int("userAccountControl") else { return s };
        s.supported = true;
        s.disabled = u & uac::ACCOUNTDISABLE != 0;
        s.never_expires = u & uac::DONT_EXPIRE_PASSWORD != 0;
        let computed = e.int("msDS-User-Account-Control-Computed");
        s.locked = match computed {
            Some(c) => c & uac::LOCKOUT != 0,
            None => e.int("lockoutTime").unwrap_or(0) > 0,
        };
        s.pwd_expired = computed.map(|c| c & uac::PASSWORD_EXPIRED != 0).unwrap_or(false);
        s.must_change = e.str("pwdLastSet").map(|v| v.trim() == "0").unwrap_or(false);
        if let Some(exp) = e.int("accountExpires") {
            if let Some(dt) = crate::ldap::codec::filetime_to_dt(exp) {
                s.expired = dt < chrono::Utc::now();
            }
        }
    } else {
        s.supported = matches!(flavor, Flavor::OpenLdap | Flavor::Ds389 | Flavor::Generic);
        if let Some(v) = e.str("nsAccountLock") {
            s.disabled = v.eq_ignore_ascii_case("true");
        }
        if let Some(v) = e.str("pwdAccountLockedTime") {
            if v == PPOLICY_PERMANENT_LOCK {
                s.disabled = true;
            } else {
                s.locked = true;
            }
        }
        s.must_change = e.bool("pwdReset").unwrap_or(false);
        if let Some(se) = e.int("shadowExpire") {
            if se > 0 && se * 86400 < chrono::Utc::now().timestamp() {
                s.expired = true;
            }
        }
        if let Some(t) = e.str("passwordExpirationTime").and_then(|t| parse_generalized(&t)) {
            s.pwd_expired = t < chrono::Utc::now();
        }
    }
    s
}

/// Badges d'état affichés dans les listes.
pub fn state_badges(e: &Entry, flavor: Flavor) -> Vec<(&'static str, &'static str)> {
    let k = Kind::of(e);
    let mut out = Vec::new();
    if !k.is_account() {
        return out;
    }
    let s = account_state(e, flavor);
    if s.disabled {
        out.push(("muted", "désactivé"));
    }
    if s.locked {
        out.push(("danger", "verrouillé"));
    }
    if s.expired {
        out.push(("warn", "expiré"));
    }
    out
}
