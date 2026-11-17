//! DNS : modèle commun (zones, enregistrements) et fournisseurs
//! - `ad` : zones intégrées à Active Directory / Samba AD (MicrosoftDNS, attribut dnsRecord) ;
//! - `dnszone` : schéma LDAP « dnszone » (BIND sdb/dlz-ldap, PowerDNS LDAP backend).

pub mod ad;
pub mod dnszone;

use crate::config::{DirectoryProfile, DnsProviderKind};
use crate::error::{AppError, AppResult};
use crate::ldap::{Dir, ServerInfo};
use chrono::{DateTime, Utc};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Ad,
    Dnszone,
}

pub fn provider_kind(profile: &DirectoryProfile, info: &ServerInfo) -> Option<Provider> {
    match profile.dns.provider {
        DnsProviderKind::None => None,
        DnsProviderKind::Ad => Some(Provider::Ad),
        DnsProviderKind::Dnszone => Some(Provider::Dnszone),
        DnsProviderKind::Auto => {
            if info.flavor.is_ad() {
                Some(Provider::Ad)
            } else if profile.dns.dnszone_base.is_some() {
                Some(Provider::Dnszone)
            } else {
                None
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Zone {
    pub id: String,
    pub name: String,
    pub location: String,
    pub reverse: bool,
    pub dynamic_update: String,
    pub system: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Ns(String),
    Ptr(String),
    Mx(u16, String),
    Srv { priority: u16, weight: u16, port: u16, target: String },
    Txt(Vec<String>),
    Soa { mname: String, rname: String, serial: u32, refresh: u32, retry: u32, expire: u32, minimum: u32 },
    Other(u16, Vec<u8>),
}

pub const EDITABLE_TYPES: &[&str] = &["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "PTR", "NS"];

impl RData {
    pub fn type_name(&self) -> String {
        match self {
            RData::A(_) => "A".into(),
            RData::Aaaa(_) => "AAAA".into(),
            RData::Cname(_) => "CNAME".into(),
            RData::Ns(_) => "NS".into(),
            RData::Ptr(_) => "PTR".into(),
            RData::Mx(..) => "MX".into(),
            RData::Srv { .. } => "SRV".into(),
            RData::Txt(_) => "TXT".into(),
            RData::Soa { .. } => "SOA".into(),
            RData::Other(t, _) => format!("TYPE{t}"),
        }
    }

    pub fn type_code(&self) -> u16 {
        match self {
            RData::A(_) => 1,
            RData::Ns(_) => 2,
            RData::Cname(_) => 5,
            RData::Soa { .. } => 6,
            RData::Ptr(_) => 12,
            RData::Mx(..) => 15,
            RData::Txt(_) => 16,
            RData::Aaaa(_) => 28,
            RData::Srv { .. } => 33,
            RData::Other(t, _) => *t,
        }
    }

    /// Représentation « fichier de zone ».
    pub fn display(&self) -> String {
        match self {
            RData::A(ip) => ip.to_string(),
            RData::Aaaa(ip) => ip.to_string(),
            RData::Cname(n) | RData::Ns(n) | RData::Ptr(n) => n.clone(),
            RData::Mx(p, n) => format!("{p} {n}"),
            RData::Srv { priority, weight, port, target } => format!("{priority} {weight} {port} {target}"),
            RData::Txt(v) => v.iter().map(|s| format!("\"{}\"", s.replace('"', "\\\""))).collect::<Vec<_>>().join(" "),
            RData::Soa { mname, rname, serial, refresh, retry, expire, minimum } => {
                format!("{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}")
            }
            RData::Other(_, b) => format!("\\# {} {}", b.len(), hex::encode(b)),
        }
    }

    /// Analyse d'une valeur au format fichier de zone (pour le fournisseur dnszone).
    pub fn parse_text(rtype: &str, v: &str, origin: &str) -> AppResult<RData> {
        let f: Vec<&str> = v.split_whitespace().collect();
        let n = |s: &str| qualify(s, origin);
        let num = |s: &str| s.parse::<u32>().map_err(|_| AppError::bad_request(format!("nombre invalide : {s}")));
        Ok(match rtype.to_ascii_uppercase().as_str() {
            "A" => RData::A(v.trim().parse().map_err(|_| AppError::bad_request("adresse IPv4 invalide"))?),
            "AAAA" => RData::Aaaa(v.trim().parse().map_err(|_| AppError::bad_request("adresse IPv6 invalide"))?),
            "CNAME" => RData::Cname(n(v.trim())),
            "NS" => RData::Ns(n(v.trim())),
            "PTR" => RData::Ptr(n(v.trim())),
            "MX" if f.len() == 2 => RData::Mx(num(f[0])? as u16, n(f[1])),
            "SRV" if f.len() == 4 => RData::Srv {
                priority: num(f[0])? as u16,
                weight: num(f[1])? as u16,
                port: num(f[2])? as u16,
                target: n(f[3]),
            },
            "TXT" => RData::Txt(parse_txt(v)),
            "SOA" if f.len() == 7 => RData::Soa {
                mname: n(f[0]),
                rname: n(f[1]),
                serial: num(f[2])?,
                refresh: num(f[3])?,
                retry: num(f[4])?,
                expire: num(f[5])?,
                minimum: num(f[6])?,
            },
            t => return Err(AppError::bad_request(format!("valeur invalide pour un enregistrement {t}"))),
        })
    }

    /// Construction depuis le formulaire d'édition.
    pub fn from_form(f: &crate::web::form::FormData, origin: &str) -> AppResult<RData> {
        let t = f.s("rtype").to_ascii_uppercase();
        let n = |k: &str| qualify(&f.s(k), origin);
        let u16f = |k: &str| {
            f.s(k).parse::<u16>().map_err(|_| AppError::bad_request(format!("valeur numérique invalide ({k})")))
        };
        let r = match t.as_str() {
            "A" => RData::A(f.s("ip").parse().map_err(|_| AppError::bad_request("adresse IPv4 invalide"))?),
            "AAAA" => RData::Aaaa(f.s("ip6").parse().map_err(|_| AppError::bad_request("adresse IPv6 invalide"))?),
            "CNAME" => RData::Cname(n("target")),
            "NS" => RData::Ns(n("target")),
            "PTR" => RData::Ptr(n("target")),
            "MX" => RData::Mx(u16f("priority")?, n("target")),
            "SRV" => RData::Srv {
                priority: u16f("priority")?,
                weight: u16f("weight")?,
                port: u16f("port")?,
                target: n("target"),
            },
            "TXT" => {
                let lines = f.lines("text");
                if lines.is_empty() {
                    return Err(AppError::bad_request("texte requis"));
                }
                RData::Txt(lines.iter().flat_map(|l| split_txt(l)).collect())
            }
            "SOA" => RData::Soa {
                mname: n("mname"),
                rname: n("rname"),
                serial: f.s("serial").parse().map_err(|_| AppError::bad_request("numéro de série invalide"))?,
                refresh: f.s("refresh").parse().unwrap_or(900),
                retry: f.s("retry").parse().unwrap_or(600),
                expire: f.s("expire").parse().unwrap_or(86400),
                minimum: f.s("minimum").parse().unwrap_or(3600),
            },
            _ => return Err(AppError::bad_request("type d'enregistrement non pris en charge")),
        };
        if let RData::Cname(t) | RData::Ns(t) | RData::Ptr(t) | RData::Mx(_, t) | RData::Srv { target: t, .. } = &r {
            if t.trim_matches('.').is_empty() {
                return Err(AppError::bad_request("nom cible requis"));
            }
        }
        Ok(r)
    }
}

fn split_txt(s: &str) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= 255 {
        return vec![s.to_string()];
    }
    chars.chunks(255).map(|c| c.iter().collect()).collect()
}

fn parse_txt(v: &str) -> Vec<String> {
    let t = v.trim();
    if !t.starts_with('"') {
        return vec![t.to_string()];
    }
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut inq = false;
    let mut esc = false;
    for c in t.chars() {
        if esc {
            cur.push(c);
            esc = false;
        } else if c == '\\' {
            esc = true;
        } else if c == '"' {
            if inq {
                out.push(std::mem::take(&mut cur));
            }
            inq = !inq;
        } else if inq {
            cur.push(c);
        }
    }
    out
}

/// Nom absolu : « www » → « www.zone. », « hote.autre.tld. » inchangé.
pub fn qualify(name: &str, origin: &str) -> String {
    let name = name.trim();
    let origin = origin.trim_end_matches('.');
    if name.is_empty() || name == "@" {
        return format!("{origin}.");
    }
    if name.ends_with('.') {
        return name.to_string();
    }
    if name.eq_ignore_ascii_case(origin)
        || name.to_ascii_lowercase().ends_with(&format!(".{}", origin.to_ascii_lowercase()))
    {
        return format!("{name}.");
    }
    format!("{name}.{origin}.")
}

/// Nom relatif du nœud pour une saisie utilisateur (« @ » pour l'apex).
pub fn relative(name: &str, origin: &str) -> String {
    let n = name.trim().trim_end_matches('.');
    let o = origin.trim_end_matches('.');
    if n.is_empty() || n == "@" || n.eq_ignore_ascii_case(o) {
        return "@".into();
    }
    let suffix = format!(".{}", o.to_ascii_lowercase());
    if n.to_ascii_lowercase().ends_with(&suffix) {
        return n[..n.len() - suffix.len()].to_string();
    }
    n.to_string()
}

#[derive(Debug, Clone)]
pub struct Record {
    pub name: String,
    pub rdata: RData,
    pub ttl: u32,
    pub timestamp: Option<DateTime<Utc>>,
    pub id: String,
}

pub fn encode_id(parts: &[&[u8]]) -> String {
    use base64::Engine;
    let mut v = Vec::new();
    for p in parts {
        v.extend_from_slice(&(p.len() as u32).to_be_bytes());
        v.extend_from_slice(p);
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v)
}

pub fn decode_id(id: &str) -> AppResult<Vec<Vec<u8>>> {
    use base64::Engine;
    let v = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(id)
        .map_err(|_| AppError::bad_request("identifiant invalide"))?;
    let mut out = Vec::new();
    let mut p = 0;
    while p + 4 <= v.len() {
        let l = u32::from_be_bytes([v[p], v[p + 1], v[p + 2], v[p + 3]]) as usize;
        p += 4;
        if p + l > v.len() {
            return Err(AppError::bad_request("identifiant invalide"));
        }
        out.push(v[p..p + l].to_vec());
        p += l;
    }
    Ok(out)
}

/// Nom de zone inverse d'une adresse (PTR) : 10.1.2.3 → (3, « 2.1.10.in-addr.arpa »...).
pub fn reverse_name(ip: &std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        std::net::IpAddr::V6(v6) => {
            let h = hex::encode(v6.octets());
            let mut s: Vec<String> = h.chars().rev().map(|c| c.to_string()).collect();
            s.push("ip6.arpa".into());
            s.join(".")
        }
    }
}

// ---------------------------------------------------------------- répartition par fournisseur

pub async fn zones(dir: &mut Dir, p: Provider) -> AppResult<Vec<Zone>> {
    match p {
        Provider::Ad => ad::zones(dir).await,
        Provider::Dnszone => dnszone::zones(dir).await,
    }
}

pub async fn records(dir: &mut Dir, p: Provider, zone: &str) -> AppResult<(Zone, Vec<Record>)> {
    match p {
        Provider::Ad => ad::records(dir, zone).await,
        Provider::Dnszone => dnszone::records(dir, zone).await,
    }
}

pub async fn add(dir: &mut Dir, p: Provider, zone: &str, name: &str, rd: &RData, ttl: u32) -> AppResult<()> {
    match p {
        Provider::Ad => ad::add(dir, zone, name, rd, ttl).await,
        Provider::Dnszone => dnszone::add(dir, zone, name, rd, ttl).await,
    }
}

pub async fn delete(dir: &mut Dir, p: Provider, zone: &str, id: &str) -> AppResult<()> {
    match p {
        Provider::Ad => ad::delete(dir, zone, id).await,
        Provider::Dnszone => dnszone::delete(dir, zone, id).await,
    }
}

pub async fn replace(dir: &mut Dir, p: Provider, zone: &str, id: &str, rd: &RData, ttl: u32) -> AppResult<()> {
    match p {
        Provider::Ad => ad::replace(dir, zone, id, rd, ttl).await,
        Provider::Dnszone => dnszone::replace(dir, zone, id, rd, ttl).await,
    }
}

pub async fn create_zone(dir: &mut Dir, p: Provider, name: &str, location: &str, dyn_update: u8) -> AppResult<String> {
    match p {
        Provider::Ad => ad::create_zone(dir, name, location, dyn_update).await,
        Provider::Dnszone => dnszone::create_zone(dir, name).await,
    }
}

pub async fn delete_zone(dir: &mut Dir, p: Provider, zone: &str) -> AppResult<()> {
    match p {
        Provider::Ad => ad::delete_zone(dir, zone).await,
        Provider::Dnszone => dnszone::delete_zone(dir, zone).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn names() {
        assert_eq!(qualify("www", "corp.example"), "www.corp.example.");
        assert_eq!(qualify("www.corp.example", "corp.example"), "www.corp.example.");
        assert_eq!(qualify("other.org.", "corp.example"), "other.org.");
        assert_eq!(qualify("@", "corp.example"), "corp.example.");
        assert_eq!(relative("www.corp.example.", "corp.example"), "www");
        assert_eq!(relative("corp.example", "corp.example"), "@");
        assert_eq!(reverse_name(&"10.1.2.3".parse().unwrap()), "3.2.1.10.in-addr.arpa");
    }
    #[test]
    fn txt() {
        assert_eq!(parse_txt("\"a b\" \"c\""), vec!["a b", "c"]);
        assert_eq!(RData::Txt(vec!["v=spf1 -all".into()]).display(), "\"v=spf1 -all\"");
    }
    #[test]
    fn ids() {
        let id = encode_id(&[b"DC=www,DC=zone", &[1, 2, 3]]);
        let p = decode_id(&id).unwrap();
        assert_eq!(p[0], b"DC=www,DC=zone");
        assert_eq!(p[1], vec![1, 2, 3]);
    }
}
