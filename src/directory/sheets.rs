//! Fiches de propriétés pilotées par données : chaque onglet décrit les attributs
//! affichés et modifiables, selon le type d'objet et la famille de serveur.
//! Les onglets « spéciaux » (compte, membres, Kerberos...) ont leur propre rendu.

use super::kinds::Kind;
use crate::ldap::Flavor;
use crate::ldap::codec::group_type;

#[derive(Debug, Clone, Copy)]
pub enum FK {
    Text,
    Area,
    Lines,
    Dn,
    Ro,
    Select(&'static [(&'static str, &'static str)]),
}

#[derive(Debug, Clone, Copy)]
pub struct Field {
    pub attr: &'static str,
    pub label: &'static str,
    pub kind: FK,
}

const fn f(attr: &'static str, label: &'static str) -> Field {
    Field { attr, label, kind: FK::Text }
}
const fn ro(attr: &'static str, label: &'static str) -> Field {
    Field { attr, label, kind: FK::Ro }
}
const fn area(attr: &'static str, label: &'static str) -> Field {
    Field { attr, label, kind: FK::Area }
}
const fn lines(attr: &'static str, label: &'static str) -> Field {
    Field { attr, label, kind: FK::Lines }
}
const fn dnf(attr: &'static str, label: &'static str) -> Field {
    Field { attr, label, kind: FK::Dn }
}

#[derive(Debug, Clone, Copy)]
pub struct Tab {
    pub id: &'static str,
    pub label: &'static str,
    /// Champs pour les onglets génériques ; vide pour un onglet spécial.
    pub fields: &'static [Field],
}

const fn tab(id: &'static str, label: &'static str, fields: &'static [Field]) -> Tab {
    Tab { id, label, fields }
}
const fn special(id: &'static str, label: &'static str) -> Tab {
    Tab { id, label, fields: &[] }
}

// ---------------------------------------------------------------- AD

const AD_USER_GENERAL: &[Field] = &[
    f("givenName", "Prénom"),
    f("initials", "Initiales"),
    f("sn", "Nom"),
    f("displayName", "Nom complet affiché"),
    f("description", "Description"),
    f("physicalDeliveryOfficeName", "Bureau"),
    f("telephoneNumber", "Téléphone"),
    lines("otherTelephone", "Autres téléphones"),
    f("mail", "Adresse de messagerie"),
    f("wWWHomePage", "Page web"),
];
const ADDRESS: &[Field] = &[
    area("streetAddress", "Rue"),
    f("postOfficeBox", "Boîte postale"),
    f("l", "Ville"),
    f("st", "Département / région"),
    f("postalCode", "Code postal"),
    f("c", "Pays (code ISO)"),
    f("co", "Pays"),
];
const AD_PROFILE: &[Field] = &[
    f("profilePath", "Chemin du profil"),
    f("scriptPath", "Script d'ouverture de session"),
    f("homeDrive", "Lecteur du dossier de base (ex. H:)"),
    f("homeDirectory", "Dossier de base"),
];
const TELEPHONES: &[Field] = &[
    f("homePhone", "Domicile"),
    f("pager", "Récepteur d'appel"),
    f("mobile", "Mobile"),
    f("facsimileTelephoneNumber", "Télécopie"),
    f("ipPhone", "Téléphone IP"),
    area("info", "Notes"),
];
const ORGANIZATION: &[Field] = &[
    f("title", "Fonction"),
    f("department", "Service"),
    f("company", "Société"),
    f("employeeID", "Matricule"),
    dnf("manager", "Responsable"),
];
const AD_UNIX: &[Field] = &[
    f("uid", "Identifiant UNIX (uid)"),
    f("uidNumber", "UID"),
    f("gidNumber", "GID du groupe principal"),
    f("unixHomeDirectory", "Répertoire de base"),
    f("loginShell", "Shell"),
    f("gecos", "GECOS"),
];
const AD_GROUP_GENERAL: &[Field] = &[
    ro("cn", "Nom"),
    f("sAMAccountName", "Nom (antérieur à Windows 2000)"),
    f("description", "Description"),
    f("mail", "Adresse de messagerie"),
    Field { attr: "groupType", label: "Étendue et type", kind: FK::Select(group_type::OPTIONS) },
    area("info", "Notes"),
];
const MANAGED_BY: &[Field] = &[dnf("managedBy", "Géré par")];
const AD_GROUP_UNIX: &[Field] = &[f("gidNumber", "GID"), lines("memberUid", "Membres UNIX (memberUid)")];
const AD_COMPUTER_GENERAL: &[Field] = &[
    ro("cn", "Nom"),
    ro("sAMAccountName", "Nom (antérieur à Windows 2000)"),
    f("dNSHostName", "Nom DNS"),
    f("description", "Description"),
    f("location", "Emplacement"),
];
const AD_COMPUTER_OS: &[Field] = &[
    ro("operatingSystem", "Système d'exploitation"),
    ro("operatingSystemVersion", "Version"),
    ro("operatingSystemServicePack", "Service pack"),
    ro("operatingSystemHotfix", "Correctif"),
];
const AD_CONTACT_GENERAL: &[Field] = &[
    f("givenName", "Prénom"),
    f("initials", "Initiales"),
    f("sn", "Nom"),
    f("displayName", "Nom affiché"),
    f("description", "Description"),
    f("physicalDeliveryOfficeName", "Bureau"),
    f("telephoneNumber", "Téléphone"),
    f("mail", "Adresse de messagerie"),
    f("wWWHomePage", "Page web"),
];
const OU_GENERAL: &[Field] = &[
    f("description", "Description"),
    area("street", "Rue"),
    f("l", "Ville"),
    f("st", "Département / région"),
    f("postalCode", "Code postal"),
    f("c", "Pays (code ISO)"),
];
const DESC_ONLY: &[Field] = &[f("description", "Description")];
const AD_SVC_GENERAL: &[Field] =
    &[ro("sAMAccountName", "Nom du compte"), f("dNSHostName", "Nom DNS"), f("description", "Description")];

// ---------------------------------------------------------------- LDAP

const LDAP_USER_GENERAL: &[Field] = &[
    f("cn", "Nom complet (cn)"),
    f("givenName", "Prénom"),
    f("sn", "Nom"),
    f("displayName", "Nom affiché"),
    f("description", "Description"),
    lines("mail", "Adresses de messagerie"),
    f("telephoneNumber", "Téléphone"),
    f("mobile", "Mobile"),
    f("title", "Fonction"),
    f("departmentNumber", "Service"),
    f("employeeNumber", "Matricule"),
    dnf("manager", "Responsable"),
];
const LDAP_POSIX: &[Field] = &[
    f("uid", "Identifiant (uid)"),
    f("uidNumber", "UID"),
    f("gidNumber", "GID du groupe principal"),
    f("homeDirectory", "Répertoire de base"),
    f("loginShell", "Shell"),
    f("gecos", "GECOS"),
];
const LDAP_ADDRESS: &[Field] = &[
    area("street", "Rue"),
    f("postalAddress", "Adresse postale"),
    f("l", "Ville"),
    f("st", "Département / région"),
    f("postalCode", "Code postal"),
];
const LDAP_GROUP_GENERAL: &[Field] =
    &[ro("cn", "Nom"), f("description", "Description"), f("gidNumber", "GID"), dnf("owner", "Propriétaire")];
const LDAP_CONTAINER: &[Field] = &[f("description", "Description")];

/// Onglets d'une fiche selon le type d'objet et le serveur.
pub fn tabs_for(kind: Kind, flavor: Flavor) -> Vec<Tab> {
    let ad = flavor.is_ad();
    let mut t = Vec::new();
    match (kind, ad) {
        (Kind::User, true) => {
            t.push(tab("general", "Général", AD_USER_GENERAL));
            t.push(special("account", "Compte"));
            t.push(tab("address", "Adresse", ADDRESS));
            t.push(tab("profile", "Profil", AD_PROFILE));
            t.push(tab("phones", "Téléphones", TELEPHONES));
            t.push(tab("org", "Organisation", ORGANIZATION));
            t.push(special("memberof", "Membre de"));
            t.push(special("kerberos", "Kerberos"));
            t.push(special("certs", "Certificats"));
            t.push(tab("unix", "Attributs UNIX", AD_UNIX));
        }
        (Kind::User, false) => {
            t.push(tab("general", "Général", LDAP_USER_GENERAL));
            t.push(special("account", "Compte"));
            t.push(tab("posix", "POSIX", LDAP_POSIX));
            t.push(tab("address", "Adresse", LDAP_ADDRESS));
            t.push(special("memberof", "Membre de"));
            t.push(special("certs", "Certificats"));
        }
        (Kind::Group, true) => {
            t.push(tab("general", "Général", AD_GROUP_GENERAL));
            t.push(special("members", "Membres"));
            t.push(special("memberof", "Membre de"));
            t.push(tab("managedby", "Géré par", MANAGED_BY));
            t.push(tab("unix", "Attributs UNIX", AD_GROUP_UNIX));
        }
        (Kind::Group, false) => {
            t.push(tab("general", "Général", LDAP_GROUP_GENERAL));
            t.push(special("members", "Membres"));
            t.push(special("memberof", "Membre de"));
        }
        (Kind::Computer, true) => {
            t.push(tab("general", "Général", AD_COMPUTER_GENERAL));
            t.push(tab("os", "Système d'exploitation", AD_COMPUTER_OS));
            t.push(special("account", "Compte"));
            t.push(special("memberof", "Membre de"));
            t.push(special("kerberos", "Délégation / Kerberos"));
            t.push(special("laps", "LAPS"));
            t.push(special("bitlocker", "BitLocker"));
            t.push(tab("managedby", "Géré par", MANAGED_BY));
            t.push(special("certs", "Certificats"));
        }
        (Kind::Computer, false) => {
            t.push(tab("general", "Général", LDAP_CONTAINER));
            t.push(special("certs", "Certificats"));
        }
        (Kind::ServiceAccount, _) => {
            t.push(tab("general", "Général", AD_SVC_GENERAL));
            t.push(special("account", "Compte"));
            t.push(special("memberof", "Membre de"));
            t.push(special("kerberos", "Kerberos"));
        }
        (Kind::Contact, true) => {
            t.push(tab("general", "Général", AD_CONTACT_GENERAL));
            t.push(tab("address", "Adresse", ADDRESS));
            t.push(tab("phones", "Téléphones", TELEPHONES));
            t.push(tab("org", "Organisation", ORGANIZATION));
            t.push(special("memberof", "Membre de"));
        }
        (Kind::Ou, true) => {
            t.push(tab("general", "Général", OU_GENERAL));
            t.push(tab("managedby", "Géré par", MANAGED_BY));
            t.push(special("gpo", "Stratégie de groupe"));
        }
        (Kind::Domain, true) => {
            t.push(tab("general", "Général", DESC_ONLY));
            t.push(special("gpo", "Stratégie de groupe"));
        }
        (Kind::Ou | Kind::Domain | Kind::Container | Kind::Builtin, _) => {
            t.push(tab("general", "Général", if ad { DESC_ONLY } else { LDAP_CONTAINER }));
        }
        (Kind::Contact, false) => {
            t.push(tab("general", "Général", LDAP_USER_GENERAL));
            t.push(tab("address", "Adresse", LDAP_ADDRESS));
            t.push(special("memberof", "Membre de"));
        }
        _ => {}
    }
    t.push(special("object", "Objet"));
    t.push(special("security", "Sécurité"));
    t.push(special("attrs", "Éditeur d'attributs"));
    if !ad {
        t.retain(|x| x.id != "security");
    }
    t
}

/// Attributs à lire pour afficher une fiche complète.
pub fn read_attrs(ad: bool) -> Vec<&'static str> {
    let mut v = vec!["*", "+"];
    if ad {
        v.extend_from_slice(&[
            "msDS-User-Account-Control-Computed",
            "msDS-UserPasswordExpiryTimeComputed",
            "msDS-KeyVersionNumber",
            "msDS-PrincipalName",
            "canonicalName",
            "allowedAttributesEffective",
            "createTimeStamp",
            "modifyTimeStamp",
            "primaryGroupID",
            "tokenGroups",
        ]);
    } else {
        v.extend_from_slice(&[
            "pwdAccountLockedTime",
            "pwdReset",
            "pwdChangedTime",
            "pwdFailureTime",
            "pwdPolicySubentry",
        ]);
    }
    v
}
