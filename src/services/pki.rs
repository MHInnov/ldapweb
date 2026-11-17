//! PKI : décodage de certificats X.509, inventaire AD CS (autorités, services
//! d'inscription, modèles), analyse de risque des modèles, sonde LDAPS.

use crate::error::AppResult;
use crate::ldap::codec::{fmt_dt, guid_to_string};
use crate::ldap::dir::ctrl;
use crate::ldap::{Dir, Entry, security};
use chrono::{DateTime, TimeZone, Utc};
use ldap3::Scope;
use sha1::{Digest, Sha1};
use x509_parser::prelude::*;

#[derive(Debug, Clone)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub san: Vec<String>,
    pub eku: Vec<String>,
    pub key: String,
    pub sig_alg: String,
    pub is_ca: bool,
    pub self_signed: bool,
    pub sha1: String,
    pub sha256: String,
}

pub fn eku_name(oid: &str) -> String {
    let n = match oid {
        "1.3.6.1.5.5.7.3.1" => "Authentification du serveur",
        "1.3.6.1.5.5.7.3.2" => "Authentification du client",
        "1.3.6.1.5.5.7.3.3" => "Signature du code",
        "1.3.6.1.5.5.7.3.4" => "Messagerie sécurisée",
        "1.3.6.1.5.5.7.3.8" => "Horodatage",
        "1.3.6.1.5.5.7.3.9" => "Signature OCSP",
        "1.3.6.1.4.1.311.20.2.2" => "Ouverture de session par carte à puce",
        "1.3.6.1.5.2.3.4" => "Authentification client PKINIT",
        "1.3.6.1.5.2.3.5" => "KDC PKINIT",
        "1.3.6.1.4.1.311.20.2.1" => "Agent de demande de certificat",
        "1.3.6.1.4.1.311.10.3.4" => "Système de fichiers EFS",
        "1.3.6.1.4.1.311.10.3.4.1" => "Récupération de fichiers EFS",
        "1.3.6.1.4.1.311.10.3.12" => "Signature de document",
        "1.3.6.1.4.1.311.21.6" => "Agent de récupération de clé",
        "1.3.6.1.4.1.311.10.3.1" => "Signature de liste de confiance",
        "1.3.6.1.4.1.311.54.1.2" => "Authentification Bureau à distance",
        "1.3.6.1.5.5.8.2.2" => "IKE intermédiaire IPsec",
        "2.5.29.37.0" => "Tout usage",
        _ => return oid.to_string(),
    };
    n.to_string()
}

pub const CLIENT_AUTH_EKUS: &[&str] =
    &["1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2", "1.3.6.1.5.2.3.4", "2.5.29.37.0"];

fn asn1_dt(t: &ASN1Time) -> DateTime<Utc> {
    Utc.timestamp_opt(t.timestamp(), 0).single().unwrap_or_else(Utc::now)
}

impl CertInfo {
    pub fn parse(der: &[u8]) -> Option<CertInfo> {
        let (_, c) = X509Certificate::from_der(der).ok()?;
        let mut san = Vec::new();
        if let Ok(Some(ext)) = c.subject_alternative_name() {
            for g in &ext.value.general_names {
                san.push(match g {
                    GeneralName::DNSName(s) => format!("DNS:{s}"),
                    GeneralName::RFC822Name(s) => format!("Courriel:{s}"),
                    GeneralName::URI(s) => format!("URI:{s}"),
                    GeneralName::IPAddress(b) => match b.len() {
                        4 => format!("IP:{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
                        16 => format!("IP:{}", std::net::Ipv6Addr::from(<[u8; 16]>::try_from(*b).unwrap_or([0; 16]))),
                        _ => "IP:?".into(),
                    },
                    GeneralName::OtherName(oid, v) => {
                        if oid.to_id_string() == "1.3.6.1.4.1.311.20.2.3" {
                            // UPN : [0] UTF8String
                            let s = String::from_utf8_lossy(v);
                            let clean: String = s.chars().filter(|c| !c.is_control()).collect();
                            format!("UPN:{}", clean.trim_start_matches(|c: char| !c.is_alphanumeric()))
                        } else {
                            format!("Autre:{}", oid.to_id_string())
                        }
                    }
                    GeneralName::DirectoryName(n) => format!("DN:{n}"),
                    _ => "?".into(),
                });
            }
        }
        let mut eku = Vec::new();
        if let Ok(Some(ext)) = c.extended_key_usage() {
            let e = ext.value;
            if e.any {
                eku.push("2.5.29.37.0".to_string());
            }
            if e.server_auth {
                eku.push("1.3.6.1.5.5.7.3.1".into());
            }
            if e.client_auth {
                eku.push("1.3.6.1.5.5.7.3.2".into());
            }
            if e.code_signing {
                eku.push("1.3.6.1.5.5.7.3.3".into());
            }
            if e.email_protection {
                eku.push("1.3.6.1.5.5.7.3.4".into());
            }
            if e.time_stamping {
                eku.push("1.3.6.1.5.5.7.3.8".into());
            }
            if e.ocsp_signing {
                eku.push("1.3.6.1.5.5.7.3.9".into());
            }
            for o in &e.other {
                eku.push(o.to_id_string());
            }
        }
        let is_ca = c.basic_constraints().ok().flatten().map(|b| b.value.ca).unwrap_or(false);
        let key = match c.public_key().parsed() {
            Ok(x509_parser::public_key::PublicKey::RSA(r)) => format!("RSA {}", r.key_size()),
            Ok(x509_parser::public_key::PublicKey::EC(e)) => format!("ECC {}", e.key_size()),
            Ok(_) => "autre".into(),
            Err(_) => "?".into(),
        };
        let sig = c.signature_algorithm.algorithm.clone();
        let sig_alg = x509_parser::objects::oid2sn(&sig, x509_parser::objects::oid_registry())
            .map(|s| s.to_string())
            .unwrap_or_else(|_| sig.to_id_string());
        let mut h1 = Sha1::new();
        h1.update(der);
        let mut h2 = sha2::Sha256::new();
        h2.update(der);
        Some(CertInfo {
            subject: c.subject().to_string(),
            issuer: c.issuer().to_string(),
            serial: c.raw_serial_as_string(),
            not_before: asn1_dt(&c.validity().not_before),
            not_after: asn1_dt(&c.validity().not_after),
            self_signed: c.subject() == c.issuer(),
            san,
            eku,
            key,
            sig_alg,
            is_ca,
            sha1: hex::encode(h1.finalize()),
            sha256: hex::encode(h2.finalize()),
        })
    }

    pub fn days_left(&self) -> i64 {
        self.not_after.signed_duration_since(Utc::now()).num_days()
    }

    /// (niveau, libellé) de l'état de validité.
    pub fn status(&self) -> (&'static str, String) {
        let d = self.days_left();
        if Utc::now() < self.not_before {
            ("warn", "pas encore valide".into())
        } else if d < 0 {
            ("danger", format!("expiré depuis {} j", -d))
        } else if d < 30 {
            ("danger", format!("expire dans {d} j"))
        } else if d < 90 {
            ("warn", format!("expire dans {d} j"))
        } else {
            ("ok", format!("valide ({d} j)"))
        }
    }

    pub fn validity(&self) -> String {
        format!("{} → {}", fmt_dt(self.not_before), fmt_dt(self.not_after))
    }

    /// Nom court (CN du sujet).
    pub fn short_subject(&self) -> String {
        short_name(&self.subject)
    }

    pub fn short_issuer(&self) -> String {
        short_name(&self.issuer)
    }
}

fn short_name(name: &str) -> String {
    name.split(',')
        .find_map(|p| p.trim().strip_prefix("CN="))
        .map(|s| s.to_string())
        .unwrap_or_else(|| name.to_string())
}

/// Lit des certificats PEM (un ou plusieurs) ou DER.
pub fn parse_upload(data: &[u8]) -> Vec<Vec<u8>> {
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject;
    let text = String::from_utf8_lossy(data);
    if text.contains("-----BEGIN") {
        CertificateDer::pem_slice_iter(data).filter_map(|c| c.ok()).map(|c| c.as_ref().to_vec()).collect()
    } else if CertInfo::parse(data).is_some() {
        vec![data.to_vec()]
    } else {
        vec![]
    }
}

pub fn to_pem(der: &[u8]) -> String {
    use base64::Engine;
    let b = base64::engine::general_purpose::STANDARD.encode(der);
    let mut s = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        s.push('\n');
    }
    s.push_str("-----END CERTIFICATE-----\n");
    s
}

/// Attributs contenant des certificats.
pub const CERT_ATTRS: &[&str] = &["userCertificate", "userSMIMECertificate", "cACertificate"];

// ---------------------------------------------------------------- AD CS

pub struct Template {
    pub name: String,
    pub display: String,
    pub dn: String,
    pub schema_version: i64,
    pub validity: String,
    pub ekus: Vec<String>,
    pub published_on: Vec<String>,
    pub risks: Vec<(&'static str, String)>,
}

pub struct EnrollmentService {
    pub name: String,
    pub host: String,
    pub templates: Vec<String>,
    pub cert: Option<CertInfo>,
}

pub struct AdPki {
    pub cas: Vec<(String, Option<CertInfo>)>,
    pub services: Vec<EnrollmentService>,
    pub templates: Vec<Template>,
    pub ntauth: Vec<CertInfo>,
}

/// Période AD (pKIExpirationPeriod) : intervalle négatif en 100 ns, petit-boutiste.
pub fn pki_period(b: &[u8]) -> String {
    if b.len() != 8 {
        return "?".into();
    }
    let v = i64::from_le_bytes(b.try_into().unwrap());
    let secs = v.unsigned_abs() / 10_000_000;
    let days = secs / 86400;
    if days >= 365 && days % 365 == 0 {
        format!("{} an(s)", days / 365)
    } else if days >= 7 && days % 7 == 0 {
        format!("{} semaine(s)", days / 7)
    } else if days > 0 {
        format!("{days} jour(s)")
    } else {
        format!("{} h", secs / 3600)
    }
}

const ENROLL_GUID: &str = "0e10c968-78fb-11d2-90d4-00c04f79dc55";
const AUTOENROLL_GUID: &str = "a05b8cc2-17bc-4802-a710-e7c15ab866a2";

fn broad_principal(sid: &str) -> bool {
    sid == "S-1-1-0" || sid == "S-1-5-11" || sid.ends_with("-513") || sid.ends_with("-515") || sid == "S-1-5-7"
}

pub async fn load_ad_pki(dir: &mut Dir) -> AppResult<Option<AdPki>> {
    let Some(cfg) = dir.info.config_nc.clone() else { return Ok(None) };
    let base = format!("CN=Public Key Services,CN=Services,{cfg}");
    if dir.read(&base, &["1.1"]).await?.is_none() {
        return Ok(None);
    }
    let cas = dir
        .search(
            &format!("CN=Certification Authorities,{base}"),
            Scope::OneLevel,
            "(objectClass=certificationAuthority)",
            &["cn", "cACertificate"],
        )
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|e| (e.s("cn"), e.bin("cACertificate").and_then(CertInfo::parse)))
        .collect();
    let services: Vec<EnrollmentService> = dir
        .search(
            &format!("CN=Enrollment Services,{base}"),
            Scope::OneLevel,
            "(objectClass=pKIEnrollmentService)",
            &["cn", "dNSHostName", "certificateTemplates", "cACertificate"],
        )
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|e| EnrollmentService {
            name: e.s("cn"),
            host: e.s("dNSHostName"),
            templates: e.strs("certificateTemplates"),
            cert: e.bin("cACertificate").and_then(CertInfo::parse),
        })
        .collect();
    let tpl_entries = dir
        .search_ctrl(
            &format!("CN=Certificate Templates,{base}"),
            Scope::OneLevel,
            "(objectClass=pKICertificateTemplate)",
            &[
                "cn",
                "displayName",
                "msPKI-Template-Schema-Version",
                "pKIExpirationPeriod",
                "pKIExtendedKeyUsage",
                "msPKI-Certificate-Name-Flag",
                "msPKI-Enrollment-Flag",
                "msPKI-RA-Signature",
                "msPKI-Certificate-Application-Policy",
                "nTSecurityDescriptor",
            ],
            vec![ctrl::sd_flags()],
        )
        .await
        .unwrap_or_default();
    let mut templates = Vec::new();
    for e in tpl_entries {
        templates.push(analyze_template(&e, &services));
    }
    templates.sort_by(|a, b| b.published_on.len().cmp(&a.published_on.len()).then(a.display.cmp(&b.display)));
    let ntauth = dir
        .read(&format!("CN=NTAuthCertificates,{base}"), &["cACertificate"])
        .await
        .ok()
        .flatten()
        .map(|e| e.bins("cACertificate").into_iter().filter_map(CertInfo::parse).collect())
        .unwrap_or_default();
    Ok(Some(AdPki { cas, services, templates, ntauth }))
}

fn analyze_template(e: &Entry, services: &[EnrollmentService]) -> Template {
    let name = e.s("cn");
    let mut ekus = e.strs("pKIExtendedKeyUsage");
    for p in e.strs("msPKI-Certificate-Application-Policy") {
        if !ekus.contains(&p) {
            ekus.push(p);
        }
    }
    let name_flag = e.int("msPKI-Certificate-Name-Flag").unwrap_or(0) as u32 as i64;
    let enroll_flag = e.int("msPKI-Enrollment-Flag").unwrap_or(0);
    let ra = e.int("msPKI-RA-Signature").unwrap_or(0);
    let published_on: Vec<String> = services
        .iter()
        .filter(|s| s.templates.iter().any(|t| t.eq_ignore_ascii_case(&name)))
        .map(|s| s.name.clone())
        .collect();
    let mut risks = Vec::new();
    let supplies_subject = name_flag & 0x1 != 0;
    let approval = enroll_flag & 0x2 != 0;
    let client_auth = ekus.is_empty() || ekus.iter().any(|x| CLIENT_AUTH_EKUS.contains(&x.as_str()));
    let any_purpose = ekus.is_empty() || ekus.iter().any(|x| x == "2.5.29.37.0");
    let agent = ekus.iter().any(|x| x == "1.3.6.1.4.1.311.20.2.1");
    // Droits d'inscription accordés largement
    let mut broad_enroll = false;
    let mut broad_write = false;
    if let Some(sd) = e.bin("nTSecurityDescriptor").and_then(security::parse_sd) {
        for ace in sd.dacl.iter().filter(|a| a.is_allow() && broad_principal(&a.sid)) {
            let ext = ace.mask & 0x100 != 0
                && ace.object_type.as_deref().map(|o| o == ENROLL_GUID || o == AUTOENROLL_GUID).unwrap_or(true);
            if ext || ace.mask & 0x1000_0000 != 0 || ace.mask & 0x000F_01FF == 0x000F_01FF {
                broad_enroll = true;
            }
            if ace.mask & (0x0004_0000 | 0x0008_0000 | 0x4000_0000 | 0x1000_0000) != 0
                || (ace.mask & 0x20 != 0 && ace.object_type.is_none())
            {
                broad_write = true;
            }
        }
    }
    if !published_on.is_empty() {
        if supplies_subject && client_auth && !approval && ra == 0 && broad_enroll {
            risks.push(("danger", "ESC1 : le demandeur fournit le sujet d'un certificat d'authentification".into()));
        } else if supplies_subject && client_auth && !approval && ra == 0 {
            risks.push(("warn", "Sujet fourni par le demandeur (vérifier les droits d'inscription)".into()));
        }
        if any_purpose && !approval && ra == 0 && broad_enroll {
            risks.push(("danger", "ESC2 : usage illimité (aucun EKU ou « Tout usage »)".into()));
        }
        if agent && !approval && ra == 0 && broad_enroll {
            risks.push(("danger", "ESC3 : agent de demande de certificat inscriptible largement".into()));
        }
    }
    if broad_write {
        risks.push(("danger", "ESC4 : modèle modifiable par un groupe étendu".into()));
    }
    Template {
        display: e.str("displayName").unwrap_or_else(|| name.clone()),
        dn: e.dn.clone(),
        schema_version: e.int("msPKI-Template-Schema-Version").unwrap_or(1),
        validity: e.bin("pKIExpirationPeriod").map(pki_period).unwrap_or_default(),
        ekus,
        published_on,
        risks,
        name,
    }
}

#[allow(dead_code)]
pub fn guid_str(b: &[u8]) -> String {
    guid_to_string(b).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_generated_cert() {
        let ck = rcgen::generate_simple_self_signed(vec!["web.example".to_string()]).unwrap();
        let der = ck.cert.der().to_vec();
        let c = CertInfo::parse(&der).unwrap();
        assert!(c.san.iter().any(|s| s == "DNS:web.example"));
        assert!(c.days_left() > 300);
        let pem = to_pem(&der);
        assert_eq!(parse_upload(pem.as_bytes()), vec![der]);
    }

    #[test]
    fn period() {
        // 1 an = -315360000000000 (100 ns)
        let v: i64 = -315_360_000_000_000;
        assert_eq!(pki_period(&v.to_le_bytes()), "1 an(s)");
    }
}
