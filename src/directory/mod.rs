//! Modèle « Utilisateurs et ordinateurs » commun à tous les annuaires.

pub mod kinds;
pub mod ops;
pub mod sheets;

pub use kinds::Kind;

use crate::ldap::Flavor;

/// Filtre des conteneurs affichés dans l'arborescence.
pub fn container_filter(flavor: Flavor, custom: Option<&Vec<String>>, advanced: bool) -> String {
    let classes: Vec<String> = match custom {
        Some(c) if !c.is_empty() => c.clone(),
        _ => {
            let mut v = vec![
                "organizationalUnit",
                "container",
                "builtinDomain",
                "domainDNS",
                "organization",
                "domain",
                "dcObject",
            ];
            if advanced {
                v.extend(["lostAndFound", "msDS-QuotaContainer", "msTPM-InformationObjectsContainer", "nsContainer"]);
            }
            v.into_iter().map(String::from).collect()
        }
    };
    let or: String = classes.iter().map(|c| format!("(objectClass={c})")).collect();
    if flavor.is_ad() && !advanced { format!("(&(|{or})(!(showInAdvancedViewOnly=TRUE)))") } else { format!("(|{or})") }
}

/// Filtre des objets listés dans un conteneur.
pub fn list_filter(flavor: Flavor, advanced: bool, quick: &str) -> String {
    let base = if flavor.is_ad() && !advanced {
        "(!(showInAdvancedViewOnly=TRUE))".to_string()
    } else {
        "(objectClass=*)".to_string()
    };
    if quick.trim().is_empty() {
        return base;
    }
    let q = crate::ldap::codec::filter_escape(quick.trim());
    let mut or = format!("(cn=*{q}*)(displayName=*{q}*)(description=*{q}*)(mail=*{q}*)(ou=*{q}*)");
    if flavor.is_ad() {
        or.push_str(&format!("(sAMAccountName=*{q}*)"));
    } else {
        or.push_str(&format!("(uid=*{q}*)"));
    }
    format!("(&{base}(|{or}))")
}
