//! Zones DNS intégrées à Active Directory (MS-DNSP) : objets dnsZone / dnsNode
//! et encodage binaire de l'attribut dnsRecord (DNS_RPC_RECORD).

use super::{RData, Record, Zone, decode_id, encode_id};
use crate::error::{AppError, AppResult};
use crate::ldap::codec::filetime_to_dt;
use crate::ldap::dir::{AttrsBuilder, Mods, m_add, m_delete, m_replace};
use crate::ldap::{Dir, Entry, dn};
use chrono::{DateTime, TimeZone, Utc};
use ldap3::Scope;

const RANK_ZONE: u8 = 0xF0;

// ---------------------------------------------------------------- codec

fn put_name(out: &mut Vec<u8>, fqdn: &str) {
    let labels: Vec<&str> = fqdn.trim_end_matches('.').split('.').filter(|l| !l.is_empty()).collect();
    let mut raw = Vec::new();
    for l in &labels {
        let b = l.as_bytes();
        raw.push(b.len().min(63) as u8);
        raw.extend_from_slice(&b[..b.len().min(63)]);
    }
    raw.push(0);
    out.push(raw.len() as u8);
    out.push(labels.len() as u8);
    out.extend(raw);
}

fn get_name(b: &[u8], p: &mut usize) -> Option<String> {
    let len = *b.get(*p)? as usize;
    let count = *b.get(*p + 1)? as usize;
    let raw = b.get(*p + 2..*p + 2 + len)?;
    *p += 2 + len;
    let mut labels = Vec::new();
    let mut i = 0;
    for _ in 0..count {
        let l = *raw.get(i)? as usize;
        labels.push(String::from_utf8_lossy(raw.get(i + 1..i + 1 + l)?).into_owned());
        i += 1 + l;
    }
    Some(format!("{}.", labels.join(".")))
}

fn be16(b: &[u8], p: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(p)?, *b.get(p + 1)?]))
}
fn be32(b: &[u8], p: usize) -> Option<u32> {
    Some(u32::from_be_bytes([*b.get(p)?, *b.get(p + 1)?, *b.get(p + 2)?, *b.get(p + 3)?]))
}
fn le32(b: &[u8], p: usize) -> Option<u32> {
    Some(u32::from_le_bytes([*b.get(p)?, *b.get(p + 1)?, *b.get(p + 2)?, *b.get(p + 3)?]))
}

pub struct Blob {
    pub rtype: u16,
    #[allow(dead_code)]
    pub serial: u32,
    pub ttl: u32,
    pub timestamp: u32,
    pub rdata: RData,
}

/// Décode une valeur de l'attribut dnsRecord.
pub fn decode(b: &[u8]) -> Option<Blob> {
    if b.len() < 24 {
        return None;
    }
    let dlen = u16::from_le_bytes([b[0], b[1]]) as usize;
    let rtype = u16::from_le_bytes([b[2], b[3]]);
    let serial = le32(b, 8)?;
    let ttl = be32(b, 12)?;
    let timestamp = le32(b, 20)?;
    let d = b.get(24..24 + dlen)?;
    let mut p = 0usize;
    let rdata = match rtype {
        1 if d.len() >= 4 => RData::A(std::net::Ipv4Addr::new(d[0], d[1], d[2], d[3])),
        28 if d.len() >= 16 => RData::Aaaa(std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&d[..16]).ok()?)),
        2 => RData::Ns(get_name(d, &mut p)?),
        5 => RData::Cname(get_name(d, &mut p)?),
        12 => RData::Ptr(get_name(d, &mut p)?),
        15 => {
            let pref = be16(d, 0)?;
            p = 2;
            RData::Mx(pref, get_name(d, &mut p)?)
        }
        33 => {
            let (priority, weight, port) = (be16(d, 0)?, be16(d, 2)?, be16(d, 4)?);
            p = 6;
            RData::Srv { priority, weight, port, target: get_name(d, &mut p)? }
        }
        16 => {
            let mut v = Vec::new();
            while p < d.len() {
                let l = d[p] as usize;
                v.push(String::from_utf8_lossy(d.get(p + 1..p + 1 + l)?).into_owned());
                p += 1 + l;
            }
            RData::Txt(v)
        }
        6 => {
            let serial = be32(d, 0)?;
            let refresh = be32(d, 4)?;
            let retry = be32(d, 8)?;
            let expire = be32(d, 12)?;
            let minimum = be32(d, 16)?;
            p = 20;
            let mname = get_name(d, &mut p)?;
            let rname = get_name(d, &mut p)?;
            RData::Soa { mname, rname, serial, refresh, retry, expire, minimum }
        }
        t => RData::Other(t, d.to_vec()),
    };
    Some(Blob { rtype, serial, ttl, timestamp, rdata })
}

/// Encode un enregistrement (statique : horodatage 0).
pub fn encode(rd: &RData, ttl: u32, serial: u32) -> Vec<u8> {
    let mut d = Vec::new();
    match rd {
        RData::A(ip) => d.extend_from_slice(&ip.octets()),
        RData::Aaaa(ip) => d.extend_from_slice(&ip.octets()),
        RData::Ns(n) | RData::Cname(n) | RData::Ptr(n) => put_name(&mut d, n),
        RData::Mx(pref, n) => {
            d.extend_from_slice(&pref.to_be_bytes());
            put_name(&mut d, n);
        }
        RData::Srv { priority, weight, port, target } => {
            d.extend_from_slice(&priority.to_be_bytes());
            d.extend_from_slice(&weight.to_be_bytes());
            d.extend_from_slice(&port.to_be_bytes());
            put_name(&mut d, target);
        }
        RData::Txt(v) => {
            for s in v {
                let b = s.as_bytes();
                let b = &b[..b.len().min(255)];
                d.push(b.len() as u8);
                d.extend_from_slice(b);
            }
        }
        RData::Soa { mname, rname, serial, refresh, retry, expire, minimum } => {
            for x in [serial, refresh, retry, expire, minimum] {
                d.extend_from_slice(&x.to_be_bytes());
            }
            put_name(&mut d, mname);
            put_name(&mut d, rname);
        }
        RData::Other(_, b) => d.extend_from_slice(b),
    }
    let mut out = Vec::with_capacity(24 + d.len());
    out.extend_from_slice(&(d.len() as u16).to_le_bytes());
    out.extend_from_slice(&rd.type_code().to_le_bytes());
    out.push(5); // version
    out.push(RANK_ZONE);
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&serial.to_le_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // réservé
    out.extend_from_slice(&0u32.to_le_bytes()); // horodatage (statique)
    out.extend(d);
    out
}

/// Horodatage MS-DNSP : heures depuis le 01/01/1601.
fn ts_to_dt(hours: u32) -> Option<DateTime<Utc>> {
    if hours == 0 {
        return None;
    }
    filetime_to_dt(hours as i64 * 3600 * 10_000_000).or_else(|| Utc.timestamp_opt(0, 0).single())
}

// ---------------------------------------------------------------- dnsProperty

fn property(id: u32, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&(data.len() as u32).to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes()); // NameLength
    v.extend_from_slice(&0u32.to_le_bytes()); // Flag
    v.extend_from_slice(&1u32.to_le_bytes()); // Version
    v.extend_from_slice(&id.to_le_bytes());
    v.extend_from_slice(data);
    v.push(0); // Name
    v
}

fn read_property(b: &[u8]) -> Option<(u32, Vec<u8>)> {
    let len = le32(b, 0)? as usize;
    let id = le32(b, 16)?;
    Some((id, b.get(20..20 + len)?.to_vec()))
}

fn update_label(props: &[&[u8]]) -> String {
    for p in props {
        if let Some((2, d)) = read_property(p) {
            return match d.first().copied().unwrap_or(0) {
                0 => "aucune".into(),
                1 => "non sécurisées et sécurisées".into(),
                2 => "sécurisées uniquement".into(),
                x => format!("{x}"),
            };
        }
    }
    "—".into()
}

// ---------------------------------------------------------------- opérations

fn containers(dir: &Dir) -> Vec<(String, String)> {
    let mut v = Vec::new();
    if let Some(p) = dir.info.domain_dns_zones() {
        v.push((format!("CN=MicrosoftDNS,{p}"), "Domaine (DomainDnsZones)".to_string()));
    }
    if let Some(p) = dir.info.forest_dns_zones() {
        v.push((format!("CN=MicrosoftDNS,{p}"), "Forêt (ForestDnsZones)".to_string()));
    }
    v.push((format!("CN=MicrosoftDNS,CN=System,{}", dir.base()), "Hérité (System, Windows 2000)".to_string()));
    v
}

fn zone_of(e: &Entry, location: &str) -> Zone {
    let name = e.str("dc").unwrap_or_else(|| dn::rdn_value(&e.dn));
    let props = e.bins("dnsProperty");
    Zone {
        id: e.dn.clone(),
        reverse: name.ends_with(".in-addr.arpa") || name.ends_with(".ip6.arpa"),
        system: name == "RootDNSServers" || name.starts_with(".."),
        dynamic_update: update_label(&props),
        location: location.to_string(),
        name,
    }
}

pub async fn zones(dir: &mut Dir) -> AppResult<Vec<Zone>> {
    let mut out = Vec::new();
    for (base, label) in containers(dir) {
        if let Ok(v) = dir.search(&base, Scope::OneLevel, "(objectClass=dnsZone)", &["dc", "dnsProperty"]).await {
            out.extend(v.iter().map(|e| zone_of(e, &label)));
        }
    }
    out.retain(|z| !z.name.starts_with(".."));
    out.sort_by(|a, b| a.system.cmp(&b.system).then(a.reverse.cmp(&b.reverse)).then(a.name.cmp(&b.name)));
    Ok(out)
}

async fn zone_entry(dir: &mut Dir, zone_dn: &str) -> AppResult<Zone> {
    let e = dir.read_req(zone_dn, &["dc", "dnsProperty", "objectClass"]).await?;
    if !e.has_class("dnsZone") {
        return Err(AppError::bad_request("cet objet n'est pas une zone DNS"));
    }
    let loc =
        containers(dir).into_iter().find(|(b, _)| dn::eq(&dn::parent(zone_dn), b)).map(|(_, l)| l).unwrap_or_default();
    Ok(zone_of(&e, &loc))
}

pub async fn records(dir: &mut Dir, zone_dn: &str) -> AppResult<(Zone, Vec<Record>)> {
    let z = zone_entry(dir, zone_dn).await?;
    let (nodes, _) = dir
        .search_paged(zone_dn, Scope::OneLevel, "(objectClass=dnsNode)", &["dc", "dnsRecord", "dNSTombstoned"], 200_000)
        .await?;
    let mut out = Vec::new();
    for n in nodes {
        if n.bool("dNSTombstoned").unwrap_or(false) {
            continue;
        }
        let name = n.str("dc").unwrap_or_else(|| dn::rdn_value(&n.dn));
        for raw in n.bins("dnsRecord") {
            let Some(b) = decode(raw) else { continue };
            if b.rtype == 0 {
                continue; // tombstone
            }
            out.push(Record {
                name: name.clone(),
                rdata: b.rdata,
                ttl: b.ttl,
                timestamp: ts_to_dt(b.timestamp),
                id: encode_id(&[n.dn.as_bytes(), raw]),
            });
        }
    }
    out.sort_by(|a, b| {
        let ka = (a.name != "@", a.name.to_lowercase(), a.rdata.type_code());
        let kb = (b.name != "@", b.name.to_lowercase(), b.rdata.type_code());
        ka.cmp(&kb)
    });
    Ok((z, out))
}

/// Incrémente le numéro de série du SOA de la zone ; renvoie le nouveau numéro.
async fn bump_serial(dir: &mut Dir, zone_dn: &str) -> AppResult<u32> {
    let apex = format!("DC=@,{zone_dn}");
    let Some(e) = dir.read(&apex, &["dnsRecord"]).await? else { return Ok(1) };
    for raw in e.bins("dnsRecord") {
        if let Some(b) = decode(raw) {
            if let RData::Soa { mname, rname, serial, refresh, retry, expire, minimum } = b.rdata {
                let ns = serial.wrapping_add(1).max(1);
                let new = RData::Soa { mname, rname, serial: ns, refresh, retry, expire, minimum };
                let blob = encode(&new, b.ttl, ns);
                dir.modify(&apex, vec![m_delete("dnsRecord", [raw]), m_add("dnsRecord", [blob])]).await?;
                return Ok(ns);
            }
        }
    }
    Ok(1)
}

fn node_dn(zone_dn: &str, name: &str) -> String {
    let n = if name.is_empty() { "@" } else { name };
    dn::child("DC", n, zone_dn)
}

pub async fn add(dir: &mut Dir, zone_dn: &str, name: &str, rd: &RData, ttl: u32) -> AppResult<()> {
    let z = zone_entry(dir, zone_dn).await?;
    let rel = super::relative(name, &z.name);
    if matches!(rd, RData::Cname(_)) && rel == "@" {
        return Err(AppError::bad_request("un CNAME ne peut pas être placé à l'apex de la zone"));
    }
    let serial = bump_serial(dir, zone_dn).await?;
    let blob = encode(rd, ttl, serial);
    let node = node_dn(zone_dn, &rel);
    match dir.read(&node, &["dnsRecord", "dNSTombstoned"]).await? {
        Some(e) => {
            let existing: Vec<Blob> =
                e.bins("dnsRecord").into_iter().filter_map(decode).filter(|b| b.rtype != 0).collect();
            let tomb = e.bool("dNSTombstoned").unwrap_or(false) || existing.is_empty();
            if !tomb {
                if matches!(rd, RData::Cname(_)) && !existing.is_empty() {
                    return Err(AppError::bad_request(
                        "un CNAME ne peut pas coexister avec d'autres enregistrements pour ce nom",
                    ));
                }
                if existing.iter().any(|b| matches!(b.rdata, RData::Cname(_))) {
                    return Err(AppError::bad_request("ce nom porte déjà un CNAME"));
                }
                if existing.iter().any(|b| b.rdata == *rd) {
                    return Err(AppError::bad_request("cet enregistrement existe déjà"));
                }
            }
            let mut mods: Mods = Vec::new();
            if tomb {
                mods.push(m_replace("dnsRecord", [blob]));
                mods.push(m_replace("dNSTombstoned", ["FALSE"]));
            } else {
                mods.push(m_add("dnsRecord", [blob]));
            }
            dir.modify(&node, mods).await
        }
        None => {
            let mut a = AttrsBuilder::new();
            a.set("objectClass", ["top", "dnsNode"]);
            a.one("dc", &rel);
            a.set("dnsRecord", [blob]);
            dir.add(&node, a.build()).await
        }
    }
}

fn parse_id(zone_dn: &str, id: &str) -> AppResult<(String, Vec<u8>)> {
    let p = decode_id(id)?;
    if p.len() != 2 {
        return Err(AppError::bad_request("identifiant d'enregistrement invalide"));
    }
    let node = String::from_utf8_lossy(&p[0]).into_owned();
    if !dn::eq(&dn::parent(&node), zone_dn) {
        return Err(AppError::bad_request("enregistrement hors de la zone"));
    }
    Ok((node, p[1].clone()))
}

pub async fn delete(dir: &mut Dir, zone_dn: &str, id: &str) -> AppResult<()> {
    let (node, raw) = parse_id(zone_dn, id)?;
    if let Some(b) = decode(&raw) {
        if matches!(b.rdata, RData::Soa { .. }) {
            return Err(AppError::bad_request("l'enregistrement SOA ne peut pas être supprimé"));
        }
    }
    let e = dir.read_req(&node, &["dnsRecord"]).await?;
    let remaining = e.bins("dnsRecord").iter().filter(|v| **v != raw.as_slice()).count();
    if remaining == 0 && !dn::rdn_value(&node).eq("@") {
        dir.delete(&node).await?;
    } else {
        dir.modify(&node, vec![m_delete("dnsRecord", [raw])]).await?;
    }
    let _ = bump_serial(dir, zone_dn).await;
    Ok(())
}

pub async fn replace(dir: &mut Dir, zone_dn: &str, id: &str, rd: &RData, ttl: u32) -> AppResult<()> {
    let (node, raw) = parse_id(zone_dn, id)?;
    let old = decode(&raw).ok_or_else(|| AppError::bad_request("enregistrement illisible"))?;
    if std::mem::discriminant(&old.rdata) != std::mem::discriminant(rd) {
        return Err(AppError::bad_request("le type d'un enregistrement ne peut pas être modifié"));
    }
    let serial = if matches!(rd, RData::Soa { .. }) {
        if let RData::Soa { serial, .. } = rd { *serial } else { 0 }
    } else {
        bump_serial(dir, zone_dn).await?
    };
    let blob = encode(rd, ttl, serial);
    dir.modify(&node, vec![m_delete("dnsRecord", [raw]), m_add("dnsRecord", [blob])]).await
}

pub async fn create_zone(dir: &mut Dir, name: &str, location: &str, dyn_update: u8) -> AppResult<String> {
    let name = name.trim().trim_end_matches('.').to_lowercase();
    if name.is_empty() || name.contains(' ') {
        return Err(AppError::bad_request("nom de zone invalide"));
    }
    let base = containers(dir)
        .into_iter()
        .find(|(_, l)| l.starts_with(location))
        .map(|(b, _)| b)
        .ok_or_else(|| AppError::bad_request("partition d'application DNS introuvable"))?;
    let zone_dn = dn::child("DC", &name, &base);
    let mut a = AttrsBuilder::new();
    a.set("objectClass", ["top", "dnsZone"]);
    a.one("dc", &name);
    a.set(
        "dnsProperty",
        [
            property(0x01, &1u32.to_le_bytes()),
            property(0x02, &[dyn_update.min(2)]),
            property(0x10, &168u32.to_le_bytes()),
            property(0x20, &168u32.to_le_bytes()),
            property(0x40, &0u32.to_le_bytes()),
        ],
    );
    dir.add(&zone_dn, a.build()).await?;
    let host = format!("{}.", dir.info.host().trim_end_matches('.'));
    let soa = RData::Soa {
        mname: host.clone(),
        rname: format!("hostmaster.{name}."),
        serial: 1,
        refresh: 900,
        retry: 600,
        expire: 86400,
        minimum: 3600,
    };
    let mut apex = AttrsBuilder::new();
    apex.set("objectClass", ["top", "dnsNode"]);
    apex.one("dc", "@");
    apex.set("dnsRecord", [encode(&soa, 3600, 1), encode(&RData::Ns(host), 3600, 1)]);
    if let Err(e) = dir.add(&format!("DC=@,{zone_dn}"), apex.build()).await {
        let _ = dir.delete_tree(&zone_dn).await;
        return Err(e);
    }
    Ok(zone_dn)
}

pub async fn delete_zone(dir: &mut Dir, zone_dn: &str) -> AppResult<()> {
    let z = zone_entry(dir, zone_dn).await?;
    let domain = dir.info.domain_dns.to_lowercase();
    if z.name == domain || z.name == format!("_msdcs.{domain}") || z.system {
        return Err(AppError::bad_request("les zones système du domaine ne peuvent pas être supprimées depuis Arbor"));
    }
    dir.delete_tree(zone_dn).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_types() {
        let samples = vec![
            RData::A("10.1.2.3".parse().unwrap()),
            RData::Aaaa("2001:db8::1".parse().unwrap()),
            RData::Cname("www.corp.example.".into()),
            RData::Ns("dc1.corp.example.".into()),
            RData::Ptr("host.corp.example.".into()),
            RData::Mx(10, "mail.corp.example.".into()),
            RData::Srv { priority: 0, weight: 100, port: 389, target: "dc1.corp.example.".into() },
            RData::Txt(vec!["v=spf1 -all".into(), "x".into()]),
            RData::Soa {
                mname: "dc1.corp.example.".into(),
                rname: "hostmaster.corp.example.".into(),
                serial: 42,
                refresh: 900,
                retry: 600,
                expire: 86400,
                minimum: 3600,
            },
        ];
        for s in samples {
            let b = encode(&s, 3600, 7);
            let d = decode(&b).unwrap();
            assert_eq!(d.rdata, s);
            assert_eq!(d.ttl, 3600);
            assert_eq!(d.serial, 7);
            assert_eq!(d.timestamp, 0);
        }
    }

    #[test]
    fn known_a_blob() {
        // Enregistrement A 192.168.1.10, TTL 3600 (0x0e10 gros-boutiste), série 1
        let b = encode(&RData::A("192.168.1.10".parse().unwrap()), 3600, 1);
        assert_eq!(&b[0..4], &[4, 0, 1, 0]);
        assert_eq!(b[4], 5);
        assert_eq!(b[5], 0xF0);
        assert_eq!(&b[12..16], &[0, 0, 0x0e, 0x10]);
        assert_eq!(&b[24..], &[192, 168, 1, 10]);
    }
}
