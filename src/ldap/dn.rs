//! Manipulation de DN (RFC 4514) : découpage en RDN, parent, échappement.

/// Découpe un DN en RDN en respectant les échappements (`\,`) et les guillemets.
pub fn split_rdns(dn: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut esc = false;
    let mut quoted = false;
    for c in dn.chars() {
        if esc {
            cur.push(c);
            esc = false;
            continue;
        }
        match c {
            '\\' => {
                cur.push(c);
                esc = true;
            }
            '"' => {
                cur.push(c);
                quoted = !quoted;
            }
            ',' | ';' if !quoted => {
                out.push(cur.trim().to_string());
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

/// DN du parent (chaîne vide pour une racine).
pub fn parent(dn: &str) -> String {
    let rdns = split_rdns(dn);
    if rdns.len() <= 1 {
        return String::new();
    }
    rdns[1..].join(",")
}

/// Premier RDN brut (« CN=Jean Dupont »).
pub fn rdn(dn: &str) -> String {
    split_rdns(dn).into_iter().next().unwrap_or_default()
}

/// Attribut et valeur (non échappée) du premier RDN.
pub fn rdn_parts(dn: &str) -> (String, String) {
    let r = rdn(dn);
    match r.split_once('=') {
        Some((a, v)) => (a.trim().to_string(), unescape_value(v.trim())),
        None => (String::new(), r),
    }
}

pub fn rdn_value(dn: &str) -> String {
    rdn_parts(dn).1
}

/// Retire les échappements d'une valeur de RDN.
pub fn unescape_value(v: &str) -> String {
    let v = v.strip_prefix('"').and_then(|x| x.strip_suffix('"')).unwrap_or(v);
    let bytes = v.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            if i + 2 < bytes.len() + 1
                && i + 2 < bytes.len()
                && bytes[i + 1].is_ascii_hexdigit()
                && bytes[i + 2].is_ascii_hexdigit()
            {
                if let Ok(b) = u8::from_str_radix(&v[i + 1..i + 3], 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i + 1]);
            i += 2;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Échappe une valeur pour l'inclure dans un RDN (RFC 4514).
pub fn escape_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len() + 4);
    let n = v.chars().count();
    for (i, c) in v.chars().enumerate() {
        match c {
            ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=' => {
                out.push('\\');
                out.push(c);
            }
            '#' if i == 0 => out.push_str("\\#"),
            ' ' if i == 0 || i + 1 == n => out.push_str("\\ "),
            '\0' => out.push_str("\\00"),
            _ => out.push(c),
        }
    }
    out
}

/// Construit « attr=valeur,parent ».
pub fn child(attr: &str, value: &str, parent: &str) -> String {
    if parent.is_empty() {
        format!("{attr}={}", escape_value(value))
    } else {
        format!("{attr}={},{parent}", escape_value(value))
    }
}

/// Normalisation grossière pour comparaison (minuscules, sans espaces autour des séparateurs).
pub fn normalize(dn: &str) -> String {
    split_rdns(dn)
        .iter()
        .map(|r| match r.split_once('=') {
            Some((a, v)) => format!("{}={}", a.trim().to_ascii_lowercase(), v.trim().to_lowercase()),
            None => r.to_lowercase(),
        })
        .collect::<Vec<_>>()
        .join(",")
}

pub fn eq(a: &str, b: &str) -> bool {
    normalize(a) == normalize(b)
}

/// `dn` est-il `base` ou un descendant de `base` ?
pub fn is_under(dn: &str, base: &str) -> bool {
    if base.is_empty() {
        return true;
    }
    let d = normalize(dn);
    let b = normalize(base);
    d == b || d.ends_with(&format!(",{b}"))
}

/// « DC=corp,DC=example » → « corp.example ».
pub fn dc_to_domain(dn: &str) -> String {
    split_rdns(dn)
        .iter()
        .filter_map(|r| {
            let (a, v) = r.split_once('=')?;
            if a.trim().eq_ignore_ascii_case("dc") { Some(unescape_value(v.trim())) } else { None }
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Nom canonique façon AD : « corp.example/Utilisateurs/Jean ».
pub fn canonical(dn: &str) -> String {
    let rdns = split_rdns(dn);
    let mut domain = Vec::new();
    let mut path = Vec::new();
    for r in rdns.iter().rev() {
        if let Some((a, v)) = r.split_once('=') {
            if a.trim().eq_ignore_ascii_case("dc") && path.is_empty() {
                domain.insert(0, unescape_value(v.trim()));
            } else {
                path.push(unescape_value(v.trim()));
            }
        }
    }
    let mut s = domain.join(".");
    for p in path {
        s.push('/');
        s.push_str(&p);
    }
    s
}

/// Fil d'Ariane : liste (DN, libellé) depuis `base` jusqu'à `dn`.
pub fn breadcrumb(dn: &str, base: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut cur = dn.to_string();
    loop {
        let label = if eq(&cur, base) { dc_to_domain(&cur) } else { rdn_value(&cur) };
        let label = if label.is_empty() { cur.clone() } else { label };
        out.push((cur.clone(), label));
        if eq(&cur, base) || cur.is_empty() {
            break;
        }
        let p = parent(&cur);
        if p.is_empty() || !is_under(&p, base) {
            break;
        }
        cur = p;
    }
    out.reverse();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_and_parent() {
        let dn = r"CN=Dupont\, Jean,OU=Ventes,DC=corp,DC=example";
        let r = split_rdns(dn);
        assert_eq!(r.len(), 4);
        assert_eq!(rdn_value(dn), "Dupont, Jean");
        assert_eq!(parent(dn), "OU=Ventes,DC=corp,DC=example");
        assert_eq!(dc_to_domain(dn), "corp.example");
        assert_eq!(canonical(dn), "corp.example/Ventes/Dupont, Jean");
    }

    #[test]
    fn escaping_roundtrip() {
        let v = " #Test, \"x\" ";
        let e = escape_value(v);
        assert_eq!(unescape_value(&e), v);
        assert_eq!(unescape_value(r"caf\c3\a9"), "café");
    }

    #[test]
    fn under() {
        assert!(is_under("CN=a,OU=b,DC=x", "dc=X"));
        assert!(!is_under("CN=a,OU=b,DC=xy", "DC=y"));
    }
}
