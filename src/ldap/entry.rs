//! Entrée LDAP conservant les valeurs brutes (octets) : la décision texte/binaire
//! est prise à l'utilisation (objectSid, objectGUID, certificats, dnsRecord...).

use ldap3::ResultEntry;

#[derive(Debug, Clone, Default)]
pub struct Entry {
    pub dn: String,
    pub attrs: Vec<(String, Vec<Vec<u8>>)>,
}

/// Nom d'attribut sans options (« member;range=0-1499 » → « member »).
pub fn base_attr(name: &str) -> &str {
    name.split(';').next().unwrap_or(name)
}

impl Entry {
    /// Construit une entrée depuis la réponse brute ; renvoie None pour les
    /// références (referrals) et messages intermédiaires.
    pub fn from_result(re: ResultEntry) -> Option<Entry> {
        if re.is_ref() || re.is_intermediate() {
            return None;
        }
        let tags = re.0.match_id(4)?.expect_constructed()?;
        let mut it = tags.into_iter();
        let dn = String::from_utf8_lossy(&it.next()?.expect_primitive()?).into_owned();
        let mut attrs = Vec::new();
        if let Some(list) = it.next().and_then(|t| t.expect_constructed()) {
            for a_v in list {
                let Some(parts) = a_v.expect_constructed() else { continue };
                let mut parts = parts.into_iter();
                let Some(name) = parts.next().and_then(|t| t.expect_primitive()) else { continue };
                let name = String::from_utf8_lossy(&name).into_owned();
                let vals: Vec<Vec<u8>> = parts
                    .next()
                    .and_then(|t| t.expect_constructed())
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|t| t.expect_primitive())
                    .collect();
                attrs.push((name, vals));
            }
        }
        Some(Entry { dn, attrs })
    }

    pub fn has(&self, name: &str) -> bool {
        self.attrs.iter().any(|(n, v)| base_attr(n).eq_ignore_ascii_case(name) && !v.is_empty())
    }

    /// Toutes les valeurs brutes d'un attribut (toutes options confondues).
    pub fn bins(&self, name: &str) -> Vec<&[u8]> {
        self.attrs
            .iter()
            .filter(|(n, _)| base_attr(n).eq_ignore_ascii_case(name))
            .flat_map(|(_, v)| v.iter().map(|x| x.as_slice()))
            .collect()
    }

    pub fn bin(&self, name: &str) -> Option<&[u8]> {
        self.attrs
            .iter()
            .find(|(n, _)| base_attr(n).eq_ignore_ascii_case(name))
            .and_then(|(_, v)| v.first())
            .map(|x| x.as_slice())
    }

    pub fn strs(&self, name: &str) -> Vec<String> {
        self.bins(name).into_iter().map(|b| String::from_utf8_lossy(b).into_owned()).collect()
    }

    pub fn str(&self, name: &str) -> Option<String> {
        self.bin(name).map(|b| String::from_utf8_lossy(b).into_owned())
    }

    /// Première valeur ou chaîne vide.
    pub fn s(&self, name: &str) -> String {
        self.str(name).unwrap_or_default()
    }

    pub fn int(&self, name: &str) -> Option<i64> {
        self.str(name).and_then(|s| s.trim().parse::<i64>().ok())
    }

    pub fn bool(&self, name: &str) -> Option<bool> {
        self.str(name).map(|s| s.eq_ignore_ascii_case("TRUE"))
    }

    pub fn classes(&self) -> Vec<String> {
        self.strs("objectClass")
    }

    pub fn has_class(&self, class: &str) -> bool {
        self.bins("objectClass").iter().any(|c| c.eq_ignore_ascii_case(class.as_bytes()))
    }

    /// Noms d'attributs présents (base, sans options), dans l'ordre et sans doublons.
    pub fn attr_names(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for (n, _) in &self.attrs {
            let b = base_attr(n);
            if !out.iter().any(|x| x.eq_ignore_ascii_case(b)) {
                out.push(b.to_string());
            }
        }
        out
    }

    /// Libellé d'affichage : displayName > name > cn > ou > uid > RDN.
    pub fn display_name(&self) -> String {
        for a in ["displayName", "name", "cn", "ou", "uid", "dc"] {
            if let Some(v) = self.str(a) {
                if !v.is_empty() {
                    return v;
                }
            }
        }
        super::dn::rdn_value(&self.dn)
    }

    /// Nom court (RDN) utilisé dans les listes.
    pub fn rdn_name(&self) -> String {
        super::dn::rdn_value(&self.dn)
    }
}
