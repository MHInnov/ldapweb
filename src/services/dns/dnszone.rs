//! Fournisseur DNS « dnszone » : schéma LDAP utilisé par BIND (sdb-ldap, dlz-ldap)
//! et le backend LDAP de PowerDNS (classe dNSZone, attributs aRecord, mXRecord...).

use super::{RData, Record, Zone, decode_id, encode_id};
use crate::error::{AppError, AppResult};
use crate::ldap::codec::filter_escape;
use crate::ldap::dir::{AttrsBuilder, m_add, m_delete, m_replace};
use crate::ldap::{Dir, Entry, dn};
use ldap3::Scope;

const RECORD_ATTRS: &[(&str, &str)] = &[
    ("aRecord", "A"),
    ("aAAARecord", "AAAA"),
    ("cNAMERecord", "CNAME"),
    ("mXRecord", "MX"),
    ("nSRecord", "NS"),
    ("pTRRecord", "PTR"),
    ("sOARecord", "SOA"),
    ("sRVRecord", "SRV"),
    ("tXTRecord", "TXT"),
];

fn attr_for(rd: &RData) -> AppResult<&'static str> {
    let t = rd.type_name();
    RECORD_ATTRS
        .iter()
        .find(|(_, x)| *x == t)
        .map(|(a, _)| *a)
        .ok_or_else(|| AppError::bad_request("type non pris en charge"))
}

fn base(dir: &Dir) -> AppResult<String> {
    dir.profile.dns.dnszone_base.clone().ok_or_else(|| AppError::bad_request("dns.dnszone_base n'est pas configuré"))
}

pub async fn zones(dir: &mut Dir) -> AppResult<Vec<Zone>> {
    let b = base(dir)?;
    let v = dir.search(&b, Scope::Subtree, "(&(objectClass=dNSZone)(relativeDomainName=@))", &["zoneName"]).await?;
    let mut out: Vec<Zone> = Vec::new();
    for e in v {
        let name = e.s("zoneName");
        if name.is_empty() || out.iter().any(|z| z.name.eq_ignore_ascii_case(&name)) {
            continue;
        }
        out.push(Zone {
            id: name.clone(),
            reverse: name.ends_with(".in-addr.arpa") || name.ends_with(".ip6.arpa"),
            location: dn::parent(&e.dn),
            dynamic_update: "—".into(),
            system: false,
            name,
        });
    }
    out.sort_by(|a, b| a.reverse.cmp(&b.reverse).then(a.name.cmp(&b.name)));
    Ok(out)
}

async fn entries(dir: &mut Dir, zone: &str) -> AppResult<Vec<Entry>> {
    let b = base(dir)?;
    let mut attrs: Vec<&str> = vec!["relativeDomainName", "zoneName", "dNSTTL"];
    attrs.extend(RECORD_ATTRS.iter().map(|(a, _)| *a));
    let f = format!("(&(objectClass=dNSZone)(zoneName={}))", filter_escape(zone));
    Ok(dir.search_paged(&b, Scope::Subtree, &f, &attrs, 200_000).await?.0)
}

pub async fn records(dir: &mut Dir, zone: &str) -> AppResult<(Zone, Vec<Record>)> {
    let es = entries(dir, zone).await?;
    let apex =
        es.iter().find(|e| e.s("relativeDomainName") == "@").ok_or_else(|| AppError::not_found("zone introuvable"))?;
    let z = Zone {
        id: zone.into(),
        name: zone.into(),
        location: dn::parent(&apex.dn),
        reverse: zone.ends_with(".arpa"),
        dynamic_update: "—".into(),
        system: false,
    };
    let mut out = Vec::new();
    for e in &es {
        let ttl = e.int("dNSTTL").unwrap_or(3600) as u32;
        for name in e.strs("relativeDomainName") {
            for (attr, t) in RECORD_ATTRS {
                for v in e.strs(attr) {
                    let rd = RData::parse_text(t, &v, zone).unwrap_or(RData::Other(0, v.as_bytes().to_vec()));
                    out.push(Record {
                        name: name.clone(),
                        rdata: rd,
                        ttl,
                        timestamp: None,
                        id: encode_id(&[e.dn.as_bytes(), attr.as_bytes(), v.as_bytes()]),
                    });
                }
            }
        }
    }
    out.sort_by(|a, b| {
        (a.name != "@", a.name.to_lowercase(), a.rdata.type_code()).cmp(&(
            b.name != "@",
            b.name.to_lowercase(),
            b.rdata.type_code(),
        ))
    });
    Ok((z, out))
}

fn value_of(rd: &RData) -> String {
    match rd {
        RData::Txt(v) => v.iter().map(|s| format!("\"{}\"", s.replace('"', "\\\""))).collect::<Vec<_>>().join(" "),
        other => other.display(),
    }
}

async fn bump_serial(dir: &mut Dir, zone: &str) -> AppResult<()> {
    let es = entries(dir, zone).await?;
    if let Some(apex) = es.iter().find(|e| e.s("relativeDomainName") == "@") {
        if let Some(soa) = apex.str("sOARecord") {
            let mut f: Vec<String> = soa.split_whitespace().map(String::from).collect();
            if f.len() == 7 {
                let today: u32 = chrono::Utc::now().format("%Y%m%d00").to_string().parse().unwrap_or(0);
                let cur: u32 = f[2].parse().unwrap_or(0);
                f[2] = cur.saturating_add(1).max(today).to_string();
                dir.modify(&apex.dn, vec![m_replace("sOARecord", [f.join(" ")])]).await?;
            }
        }
    }
    Ok(())
}

pub async fn add(dir: &mut Dir, zone: &str, name: &str, rd: &RData, ttl: u32) -> AppResult<()> {
    let rel = super::relative(name, zone);
    let attr = attr_for(rd)?;
    let es = entries(dir, zone).await?;
    let apex = es
        .iter()
        .find(|e| e.s("relativeDomainName") == "@")
        .ok_or_else(|| AppError::not_found("zone introuvable"))?
        .clone();
    let value = value_of(rd);
    if let Some(e) = es.iter().find(|e| e.strs("relativeDomainName").iter().any(|r| r.eq_ignore_ascii_case(&rel))) {
        dir.modify(&e.dn, vec![m_add(attr, [value.as_str()])]).await?;
    } else {
        let (apex_attr, _) = dn::rdn_parts(&apex.dn);
        let container =
            if apex_attr.eq_ignore_ascii_case("relativeDomainName") { dn::parent(&apex.dn) } else { apex.dn.clone() };
        let new_dn = dn::child("relativeDomainName", &rel, &container);
        let mut a = AttrsBuilder::new();
        a.set("objectClass", ["top", "dNSZone"]);
        a.one("zoneName", zone);
        a.one("relativeDomainName", &rel);
        a.one("dNSTTL", &ttl.to_string());
        a.one("dNSClass", "IN");
        a.one(attr, &value);
        dir.add(&new_dn, a.build()).await?;
    }
    bump_serial(dir, zone).await
}

fn parse_id(id: &str) -> AppResult<(String, String, String)> {
    let p = decode_id(id)?;
    if p.len() != 3 {
        return Err(AppError::bad_request("identifiant invalide"));
    }
    Ok((
        String::from_utf8_lossy(&p[0]).into_owned(),
        String::from_utf8_lossy(&p[1]).into_owned(),
        String::from_utf8_lossy(&p[2]).into_owned(),
    ))
}

pub async fn delete(dir: &mut Dir, zone: &str, id: &str) -> AppResult<()> {
    let (entry_dn, attr, value) = parse_id(id)?;
    if attr == "sOARecord" {
        return Err(AppError::bad_request("l'enregistrement SOA ne peut pas être supprimé"));
    }
    let mut attrs: Vec<&str> = vec!["relativeDomainName"];
    attrs.extend(RECORD_ATTRS.iter().map(|(a, _)| *a));
    let e = dir.read_req(&entry_dn, &attrs).await?;
    let remaining: usize = RECORD_ATTRS.iter().map(|(a, _)| e.strs(a).len()).sum::<usize>() - 1;
    if remaining == 0 && e.s("relativeDomainName") != "@" {
        dir.delete(&entry_dn).await?;
    } else {
        dir.modify(&entry_dn, vec![m_delete(&attr, [value.as_str()])]).await?;
    }
    bump_serial(dir, zone).await
}

pub async fn replace(dir: &mut Dir, zone: &str, id: &str, rd: &RData, ttl: u32) -> AppResult<()> {
    let (entry_dn, attr, value) = parse_id(id)?;
    if attr_for(rd)? != attr {
        return Err(AppError::bad_request("le type d'un enregistrement ne peut pas être modifié"));
    }
    let new = value_of(rd);
    dir.modify(
        &entry_dn,
        vec![m_delete(&attr, [value.as_str()]), m_add(&attr, [new.as_str()]), m_replace("dNSTTL", [ttl.to_string()])],
    )
    .await?;
    if attr != "sOARecord" {
        bump_serial(dir, zone).await?;
    }
    Ok(())
}

pub async fn create_zone(dir: &mut Dir, name: &str) -> AppResult<String> {
    let b = base(dir)?;
    let name = name.trim().trim_end_matches('.').to_lowercase();
    let host = dir.info.host();
    let host = if host.parse::<std::net::IpAddr>().is_ok() { format!("ns1.{name}") } else { host };
    let new_dn = dn::child("zoneName", &name, &b);
    let serial = chrono::Utc::now().format("%Y%m%d01").to_string();
    let mut a = AttrsBuilder::new();
    a.set("objectClass", ["top", "dNSZone"]);
    a.one("zoneName", &name);
    a.one("relativeDomainName", "@");
    a.one("dNSTTL", "3600");
    a.one("dNSClass", "IN");
    a.one("sOARecord", &format!("{host}. hostmaster.{name}. {serial} 3600 900 604800 86400"));
    a.one("nSRecord", &format!("{host}."));
    dir.add(&new_dn, a.build()).await?;
    Ok(name)
}

pub async fn delete_zone(dir: &mut Dir, zone: &str) -> AppResult<()> {
    let mut es = entries(dir, zone).await?;
    es.sort_by_key(|e| std::cmp::Reverse(dn::split_rdns(&e.dn).len()));
    for e in es {
        dir.delete_tree(&e.dn).await?;
    }
    Ok(())
}
