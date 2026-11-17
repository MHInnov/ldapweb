//! Décodage/encodage des formats propres aux annuaires : SID, GUID, FILETIME,
//! GeneralizedTime, userAccountControl, groupType, intervalles AD.

use chrono::{DateTime, Local, NaiveDateTime, TimeZone, Utc};

// ---------------------------------------------------------------- SID

pub fn sid_to_string(b: &[u8]) -> Option<String> {
    if b.len() < 8 {
        return None;
    }
    let rev = b[0];
    let count = b[1] as usize;
    if b.len() < 8 + count * 4 {
        return None;
    }
    let mut auth: u64 = 0;
    for x in &b[2..8] {
        auth = (auth << 8) | *x as u64;
    }
    let mut s = format!("S-{rev}-{auth}");
    for i in 0..count {
        let o = 8 + i * 4;
        let sub = u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        s.push_str(&format!("-{sub}"));
    }
    Some(s)
}

pub fn sid_from_string(s: &str) -> Option<Vec<u8>> {
    let mut parts = s.trim().split('-');
    if !parts.next()?.eq_ignore_ascii_case("S") {
        return None;
    }
    let rev: u8 = parts.next()?.parse().ok()?;
    let auth: u64 = parts.next()?.parse().ok()?;
    let subs: Vec<u32> = parts.map(|p| p.parse().ok()).collect::<Option<Vec<_>>>()?;
    let mut out = vec![rev, subs.len() as u8];
    out.extend_from_slice(&auth.to_be_bytes()[2..8]);
    for s in subs {
        out.extend_from_slice(&s.to_le_bytes());
    }
    Some(out)
}

/// RID (dernier sous-autorité) d'un SID binaire.
pub fn sid_rid(b: &[u8]) -> Option<u32> {
    let count = *b.get(1)? as usize;
    if count == 0 || b.len() < 8 + count * 4 {
        return None;
    }
    let o = 8 + (count - 1) * 4;
    Some(u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]))
}

// ---------------------------------------------------------------- GUID

/// GUID AD (ordre d'octets mixte) → « xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx ».
pub fn guid_to_string(b: &[u8]) -> Option<String> {
    if b.len() != 16 {
        return None;
    }
    Some(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    ))
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn guid_from_string(s: &str) -> Option<Vec<u8>> {
    let h: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if h.len() != 32 {
        return None;
    }
    let raw = hex::decode(h).ok()?;
    Some(vec![
        raw[3], raw[2], raw[1], raw[0], raw[5], raw[4], raw[7], raw[6], raw[8], raw[9], raw[10], raw[11], raw[12],
        raw[13], raw[14], raw[15],
    ])
}

/// Échappement d'une valeur binaire pour un filtre LDAP (« \01\05... »).
pub fn filter_escape_bytes(b: &[u8]) -> String {
    b.iter().map(|x| format!("\\{x:02x}")).collect()
}

/// Échappement d'une valeur texte pour un filtre LDAP (RFC 4515).
pub fn filter_escape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\\' => out.push_str("\\5c"),
            '\0' => out.push_str("\\00"),
            _ => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------- Dates

const FILETIME_UNIX_DIFF: i64 = 116_444_736_000_000_000;

/// FILETIME (100 ns depuis 1601) → date ; 0 et i64::MAX signifient « jamais ».
pub fn filetime_to_dt(ft: i64) -> Option<DateTime<Utc>> {
    if ft <= 0 || ft == i64::MAX {
        return None;
    }
    let unix_100ns = ft - FILETIME_UNIX_DIFF;
    let secs = unix_100ns.div_euclid(10_000_000);
    let nanos = (unix_100ns.rem_euclid(10_000_000) * 100) as u32;
    Utc.timestamp_opt(secs, nanos).single()
}

pub fn dt_to_filetime(dt: DateTime<Utc>) -> i64 {
    dt.timestamp() * 10_000_000 + (dt.timestamp_subsec_nanos() / 100) as i64 + FILETIME_UNIX_DIFF
}

/// GeneralizedTime (« 20261117123312.0Z », « 20261117123312+0100 »...).
pub fn parse_generalized(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    if s.len() < 14 {
        return None;
    }
    let (main, rest) = s.split_at(14);
    let naive = NaiveDateTime::parse_from_str(main, "%Y%m%d%H%M%S").ok()?;
    // ignorer la fraction éventuelle
    let rest = rest.trim_start_matches(|c: char| c == '.' || c == ',' || c.is_ascii_digit());
    if rest.is_empty() || rest == "Z" {
        return Some(Utc.from_utc_datetime(&naive));
    }
    let sign = if rest.starts_with('-') { -1 } else { 1 };
    let digits = rest.trim_start_matches(['+', '-']);
    if digits.len() >= 2 {
        let h: i64 = digits[0..2].parse().ok()?;
        let m: i64 = digits.get(2..4).and_then(|x| x.parse().ok()).unwrap_or(0);
        let off = sign * (h * 3600 + m * 60);
        return Some(Utc.from_utc_datetime(&(naive - chrono::Duration::seconds(off))));
    }
    Some(Utc.from_utc_datetime(&naive))
}

#[allow(dead_code)]
pub fn to_generalized(dt: DateTime<Utc>) -> String {
    dt.format("%Y%m%d%H%M%SZ").to_string()
}

/// Affichage en heure locale du serveur.
pub fn fmt_dt(dt: DateTime<Utc>) -> String {
    dt.with_timezone(&Local).format("%d/%m/%Y %H:%M").to_string()
}

pub fn fmt_dt_opt(dt: Option<DateTime<Utc>>) -> String {
    dt.map(fmt_dt).unwrap_or_else(|| "—".into())
}

/// Âge relatif lisible (« il y a 3 j »).
pub fn ago(dt: DateTime<Utc>) -> String {
    let d = Utc::now().signed_duration_since(dt);
    if d.num_seconds() < 0 {
        let f = -d;
        if f.num_days() >= 1 {
            return format!("dans {} j", f.num_days());
        }
        return format!("dans {} h", f.num_hours().max(1));
    }
    if d.num_days() >= 365 {
        format!("il y a {} an(s)", d.num_days() / 365)
    } else if d.num_days() >= 1 {
        format!("il y a {} j", d.num_days())
    } else if d.num_hours() >= 1 {
        format!("il y a {} h", d.num_hours())
    } else {
        format!("il y a {} min", d.num_minutes().max(0))
    }
}

/// Intervalle AD (valeur négative en 100 ns) → secondes.
pub fn ad_interval_secs(v: i64) -> Option<i64> {
    if v == i64::MIN || v == 0 {
        return None; // jamais / non défini
    }
    Some(v.abs() / 10_000_000)
}

pub fn secs_to_ad_interval(secs: i64) -> i64 {
    if secs <= 0 { i64::MIN } else { -(secs * 10_000_000) }
}

pub fn fmt_duration(secs: i64) -> String {
    if secs <= 0 {
        return "—".into();
    }
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    match (d, h, m) {
        (0, 0, m) => format!("{m} min"),
        (0, h, 0) => format!("{h} h"),
        (0, h, m) => format!("{h} h {m} min"),
        (d, 0, 0) => format!("{d} jour(s)"),
        (d, h, _) => format!("{d} j {h} h"),
    }
}

// ---------------------------------------------------------------- userAccountControl

pub mod uac {
    pub const SCRIPT: i64 = 0x1;
    pub const ACCOUNTDISABLE: i64 = 0x2;
    pub const HOMEDIR_REQUIRED: i64 = 0x8;
    pub const LOCKOUT: i64 = 0x10;
    pub const PASSWD_NOTREQD: i64 = 0x20;
    pub const PASSWD_CANT_CHANGE: i64 = 0x40;
    pub const ENCRYPTED_TEXT_PWD_ALLOWED: i64 = 0x80;
    pub const NORMAL_ACCOUNT: i64 = 0x200;
    pub const INTERDOMAIN_TRUST_ACCOUNT: i64 = 0x800;
    pub const WORKSTATION_TRUST_ACCOUNT: i64 = 0x1000;
    pub const SERVER_TRUST_ACCOUNT: i64 = 0x2000;
    pub const DONT_EXPIRE_PASSWORD: i64 = 0x10000;
    pub const SMARTCARD_REQUIRED: i64 = 0x40000;
    pub const TRUSTED_FOR_DELEGATION: i64 = 0x80000;
    pub const NOT_DELEGATED: i64 = 0x100000;
    pub const USE_DES_KEY_ONLY: i64 = 0x200000;
    pub const DONT_REQ_PREAUTH: i64 = 0x400000;
    pub const PASSWORD_EXPIRED: i64 = 0x800000;
    pub const TRUSTED_TO_AUTH_FOR_DELEGATION: i64 = 0x1000000;
    pub const PARTIAL_SECRETS_ACCOUNT: i64 = 0x4000000;

    pub const LABELS: &[(i64, &str)] = &[
        (SCRIPT, "Script de connexion exécuté"),
        (ACCOUNTDISABLE, "Compte désactivé"),
        (HOMEDIR_REQUIRED, "Dossier de base requis"),
        (LOCKOUT, "Verrouillé"),
        (PASSWD_NOTREQD, "Mot de passe non requis"),
        (PASSWD_CANT_CHANGE, "L'utilisateur ne peut pas changer le mot de passe"),
        (ENCRYPTED_TEXT_PWD_ALLOWED, "Chiffrement réversible du mot de passe"),
        (NORMAL_ACCOUNT, "Compte normal"),
        (INTERDOMAIN_TRUST_ACCOUNT, "Compte d'approbation inter-domaines"),
        (WORKSTATION_TRUST_ACCOUNT, "Compte de station de travail"),
        (SERVER_TRUST_ACCOUNT, "Contrôleur de domaine"),
        (DONT_EXPIRE_PASSWORD, "Le mot de passe n'expire jamais"),
        (SMARTCARD_REQUIRED, "Carte à puce requise"),
        (TRUSTED_FOR_DELEGATION, "Approuvé pour la délégation (non contrainte)"),
        (NOT_DELEGATED, "Compte sensible, ne peut pas être délégué"),
        (USE_DES_KEY_ONLY, "Types DES uniquement"),
        (DONT_REQ_PREAUTH, "Pré-authentification Kerberos non requise"),
        (PASSWORD_EXPIRED, "Mot de passe expiré"),
        (TRUSTED_TO_AUTH_FOR_DELEGATION, "Délégation avec transition de protocole"),
        (PARTIAL_SECRETS_ACCOUNT, "Contrôleur de domaine en lecture seule"),
    ];

    pub fn labels(v: i64) -> Vec<&'static str> {
        LABELS.iter().filter(|(f, _)| v & f != 0).map(|(_, l)| *l).collect()
    }
}

// ---------------------------------------------------------------- groupType

#[cfg_attr(not(test), allow(dead_code))]
pub mod group_type {
    pub const BUILTIN: i64 = 0x1;
    pub const GLOBAL: i64 = 0x2;
    pub const DOMAIN_LOCAL: i64 = 0x4;
    pub const UNIVERSAL: i64 = 0x8;
    pub const SECURITY: i64 = 0x8000_0000;

    /// Valeur signée 32 bits telle que stockée dans AD.
    pub fn value(scope: i64, security: bool) -> i32 {
        let v = scope | if security { SECURITY } else { 0 };
        v as u32 as i32
    }

    pub fn scope_label(v: i64) -> &'static str {
        let v = v & 0xF;
        if v & BUILTIN != 0 {
            "Domaine local (intégré)"
        } else if v & GLOBAL != 0 {
            "Globale"
        } else if v & DOMAIN_LOCAL != 0 {
            "Domaine local"
        } else if v & UNIVERSAL != 0 {
            "Universelle"
        } else {
            "?"
        }
    }

    pub fn is_security(v: i64) -> bool {
        (v as i32) < 0
    }

    pub fn type_label(v: i64) -> &'static str {
        if is_security(v) { "Sécurité" } else { "Distribution" }
    }

    pub const OPTIONS: &[(&str, &str)] = &[
        ("-2147483646", "Globale — Sécurité"),
        ("-2147483644", "Domaine local — Sécurité"),
        ("-2147483640", "Universelle — Sécurité"),
        ("2", "Globale — Distribution"),
        ("4", "Domaine local — Distribution"),
        ("8", "Universelle — Distribution"),
    ];
}

/// Types de chiffrement Kerberos (msDS-SupportedEncryptionTypes).
pub mod enctypes {
    pub const LABELS: &[(i64, &str)] = &[
        (0x1, "DES-CBC-CRC (obsolète)"),
        (0x2, "DES-CBC-MD5 (obsolète)"),
        (0x4, "RC4-HMAC"),
        (0x8, "AES128-CTS-HMAC-SHA1-96"),
        (0x10, "AES256-CTS-HMAC-SHA1-96"),
        (0x20, "AES256-CTS-HMAC-SHA1-96-SK (clé de session AES)"),
    ];
}

/// Décodage « lisible » d'une valeur d'attribut connue (pour l'éditeur d'attributs).
pub fn decode_known(attr: &str, raw: &[u8]) -> Option<String> {
    let a = attr.to_ascii_lowercase();
    match a.as_str() {
        "objectsid" | "securityidentifier" | "sidhistory" | "tokengroups" => sid_to_string(raw),
        "objectguid" | "msexchmailboxguid" | "schemaidguid" | "attributesecurityguid" | "rightsguid" => {
            guid_to_string(raw).or_else(|| Some(String::from_utf8_lossy(raw).into_owned()))
        }
        "pwdlastset"
        | "lastlogon"
        | "lastlogontimestamp"
        | "lastlogoff"
        | "badpasswordtime"
        | "lockouttime"
        | "accountexpires"
        | "ms-mcs-admpwdexpirationtime"
        | "mslaps-passwordexpirationtime"
        | "creationtime" => {
            let s = std::str::from_utf8(raw).ok()?;
            let v: i64 = s.trim().parse().ok()?;
            Some(match filetime_to_dt(v) {
                Some(dt) => format!("{v} ({})", fmt_dt(dt)),
                None => format!("{v} (jamais)"),
            })
        }
        "whencreated"
        | "whenchanged"
        | "createtimestamp"
        | "modifytimestamp"
        | "pwdchangedtime"
        | "pwdaccountlockedtime"
        | "dscorepropagationdata" => {
            let s = std::str::from_utf8(raw).ok()?;
            parse_generalized(s).map(|dt| format!("{s} ({})", fmt_dt(dt)))
        }
        "useraccountcontrol" => {
            let s = std::str::from_utf8(raw).ok()?;
            let v: i64 = s.trim().parse().ok()?;
            Some(format!("{v} (0x{v:x} : {})", uac::labels(v).join(", ")))
        }
        "grouptype" => {
            let s = std::str::from_utf8(raw).ok()?;
            let v: i64 = s.trim().parse().ok()?;
            Some(format!("{v} ({} / {})", group_type::scope_label(v), group_type::type_label(v)))
        }
        "msds-supportedencryptiontypes" => {
            let s = std::str::from_utf8(raw).ok()?;
            let v: i64 = s.trim().parse().ok()?;
            let l: Vec<&str> = enctypes::LABELS.iter().filter(|(f, _)| v & f != 0).map(|(_, l)| *l).collect();
            Some(format!("{v} ({})", l.join(", ")))
        }
        "maxpwdage"
        | "minpwdage"
        | "lockoutduration"
        | "lockoutobservationwindow"
        | "forcelogoff"
        | "msds-maximumpasswordage"
        | "msds-minimumpasswordage"
        | "msds-lockoutduration"
        | "msds-lockoutobservationwindow" => {
            let s = std::str::from_utf8(raw).ok()?;
            let v: i64 = s.trim().parse().ok()?;
            Some(match ad_interval_secs(v) {
                Some(secs) => format!("{v} ({})", fmt_duration(secs)),
                None => format!("{v} (aucun)"),
            })
        }
        _ => None,
    }
}

/// Un attribut doit-il être traité comme binaire (affichage hexadécimal) ?
pub fn is_binary_attr(attr: &str) -> bool {
    let a = attr.to_ascii_lowercase();
    let a = a.split(';').next().unwrap_or("");
    matches!(
        a,
        "objectsid"
            | "objectguid"
            | "sidhistory"
            | "tokengroups"
            | "securityidentifier"
            | "ntsecuritydescriptor"
            | "msds-allowedtoactonbehalfofotheridentity"
            | "msds-generationid"
            | "usercertificate"
            | "cacertificate"
            | "crosscertificatepair"
            | "certificaterevocationlist"
            | "authorityrevocationlist"
            | "deltarevocationlist"
            | "usersmimecertificate"
            | "jpegphoto"
            | "thumbnailphoto"
            | "photo"
            | "logonhours"
            | "dnsrecord"
            | "dnsproperty"
            | "replpropertymetadata"
            | "repluptodatevector"
            | "repsfrom"
            | "repsto"
            | "schemaidguid"
            | "attributesecurityguid"
            | "msexchmailboxguid"
            | "msds-managedpasswordid"
            | "msds-managedpassword"
            | "pkiexpirationperiod"
            | "pkioverlapperiod"
            | "pkikeyusage"
            | "pkicriticalextensions"
            | "mstpm-ownerinformation"
            | "msfve-keypackage"
            | "msfve-volumeguid"
            | "msfve-recoveryguid"
            | "auditingpolicy"
            | "msds-trustforesttrustinfo"
            | "trustauthincoming"
            | "trustauthoutgoing"
            | "userpassword"
            | "unicodepwd"
            | "dbcspwd"
            | "ntpwdhistory"
            | "lmpwdhistory"
            | "supplementalcredentials"
            | "msds-keycredentiallink"
    )
}

pub fn looks_binary(raw: &[u8]) -> bool {
    match std::str::from_utf8(raw) {
        Ok(s) => s.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t'),
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_roundtrip() {
        let s = "S-1-5-21-1972439149-2353034314-1712914230-500";
        let b = sid_from_string(s).unwrap();
        assert_eq!(sid_to_string(&b).unwrap(), s);
        assert_eq!(sid_rid(&b), Some(500));
    }

    #[test]
    fn guid_roundtrip() {
        let g = "31b2f340-016d-11d2-945f-00c04fb984f9";
        let b = guid_from_string(g).unwrap();
        assert_eq!(guid_to_string(&b).unwrap(), g);
    }

    #[test]
    fn filetime() {
        let dt = filetime_to_dt(133_000_000_000_000_000).unwrap();
        assert_eq!(dt_to_filetime(dt), 133_000_000_000_000_000);
        assert!(filetime_to_dt(0).is_none());
        assert!(filetime_to_dt(i64::MAX).is_none());
    }

    #[test]
    fn generalized() {
        let a = parse_generalized("20261117123312.0Z").unwrap();
        let b = parse_generalized("20261117133312+0100").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn group_types() {
        assert_eq!(group_type::value(group_type::GLOBAL, true), -2147483646);
        assert_eq!(group_type::scope_label(-2147483644), "Domaine local");
        assert!(group_type::is_security(-2147483640));
        assert!(!group_type::is_security(8));
    }
}
