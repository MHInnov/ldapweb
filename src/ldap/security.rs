//! Descripteurs de sécurité Windows (format auto-relatif) : lecture des ACE,
//! résolution des SID, construction d'un SD pour la délégation basée sur les
//! ressources (RBCD).

use super::codec::{guid_to_string, sid_from_string, sid_to_string};
use super::dir::Dir;
use ldap3::Scope;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Ace {
    pub ace_type: u8,
    pub flags: u8,
    pub mask: u32,
    pub object_type: Option<String>,
    pub inherited_object_type: Option<String>,
    pub sid: String,
}

impl Ace {
    pub fn is_allow(&self) -> bool {
        matches!(self.ace_type, 0x00 | 0x05 | 0x09 | 0x0B)
    }
    pub fn is_inherited(&self) -> bool {
        self.flags & 0x10 != 0
    }
}

#[derive(Debug, Clone, Default)]
pub struct SecurityDescriptor {
    pub control: u16,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub dacl: Vec<Ace>,
}

fn u16le(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(o)?, *b.get(o + 1)?]))
}
fn u32le(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes([*b.get(o)?, *b.get(o + 1)?, *b.get(o + 2)?, *b.get(o + 3)?]))
}

fn sid_at(b: &[u8], o: usize) -> Option<String> {
    let count = *b.get(o + 1)? as usize;
    sid_to_string(b.get(o..o + 8 + count * 4)?)
}

fn parse_acl(b: &[u8], off: usize) -> Option<Vec<Ace>> {
    let count = u16le(b, off + 4)? as usize;
    let mut p = off + 8;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let ace_type = *b.get(p)?;
        let flags = *b.get(p + 1)?;
        let size = u16le(b, p + 2)? as usize;
        if size < 8 {
            return None;
        }
        let mask = u32le(b, p + 4)?;
        let mut q = p + 8;
        let mut object_type = None;
        let mut inherited_object_type = None;
        if matches!(ace_type, 0x05 | 0x06 | 0x07 | 0x08 | 0x0B | 0x0C | 0x0F | 0x10) {
            let oflags = u32le(b, q)?;
            q += 4;
            if oflags & 0x1 != 0 {
                object_type = guid_to_string(b.get(q..q + 16)?);
                q += 16;
            }
            if oflags & 0x2 != 0 {
                inherited_object_type = guid_to_string(b.get(q..q + 16)?);
                q += 16;
            }
        }
        let sid = sid_at(b, q).unwrap_or_default();
        out.push(Ace { ace_type, flags, mask, object_type, inherited_object_type, sid });
        p += size;
    }
    Some(out)
}

pub fn parse_sd(b: &[u8]) -> Option<SecurityDescriptor> {
    if b.len() < 20 {
        return None;
    }
    let control = u16le(b, 2)?;
    let o_owner = u32le(b, 4)? as usize;
    let o_group = u32le(b, 8)? as usize;
    let o_dacl = u32le(b, 16)? as usize;
    Some(SecurityDescriptor {
        control,
        owner: if o_owner > 0 { sid_at(b, o_owner) } else { None },
        group: if o_group > 0 { sid_at(b, o_group) } else { None },
        dacl: if o_dacl > 0 && control & 0x0004 != 0 { parse_acl(b, o_dacl).unwrap_or_default() } else { vec![] },
    })
}

/// SD « O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;<sid>)... » pour
/// msDS-AllowedToActOnBehalfOfOtherIdentity.
pub fn build_rbcd_sd(sids: &[String]) -> Option<Vec<u8>> {
    let owner = sid_from_string("S-1-5-32-544")?;
    let mut aces = Vec::new();
    for s in sids {
        let sid = sid_from_string(s)?;
        let size = 8 + sid.len();
        let mut ace = vec![0x00, 0x00];
        ace.extend_from_slice(&(size as u16).to_le_bytes());
        ace.extend_from_slice(&0x000F_01FFu32.to_le_bytes());
        ace.extend_from_slice(&sid);
        aces.push(ace);
    }
    let acl_size: usize = 8 + aces.iter().map(|a| a.len()).sum::<usize>();
    let mut acl = vec![0x04, 0x00];
    acl.extend_from_slice(&(acl_size as u16).to_le_bytes());
    acl.extend_from_slice(&(aces.len() as u16).to_le_bytes());
    acl.extend_from_slice(&[0, 0]);
    for a in aces {
        acl.extend(a);
    }
    let mut sd = vec![0x01, 0x00];
    // SE_SELF_RELATIVE | SE_DACL_PRESENT
    sd.extend_from_slice(&(0x8004u16).to_le_bytes());
    let o_owner = 20u32;
    let o_dacl = 20 + owner.len() as u32;
    sd.extend_from_slice(&o_owner.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes()); // groupe
    sd.extend_from_slice(&0u32.to_le_bytes()); // SACL
    sd.extend_from_slice(&o_dacl.to_le_bytes());
    sd.extend(owner);
    sd.extend(acl);
    Some(sd)
}

pub fn well_known_sid(sid: &str) -> Option<&'static str> {
    Some(match sid {
        "S-1-0-0" => "Personne",
        "S-1-1-0" => "Tout le monde",
        "S-1-3-0" => "CREATEUR PROPRIETAIRE",
        "S-1-3-1" => "GROUPE CREATEUR",
        "S-1-5-2" => "RÉSEAU",
        "S-1-5-4" => "INTERACTIF",
        "S-1-5-7" => "ANONYMOUS LOGON",
        "S-1-5-9" => "Contrôleurs de domaine d'entreprise",
        "S-1-5-10" => "SELF",
        "S-1-5-11" => "Utilisateurs authentifiés",
        "S-1-5-18" => "Système local",
        "S-1-5-19" => "SERVICE LOCAL",
        "S-1-5-20" => "SERVICE RÉSEAU",
        "S-1-5-32-544" => "BUILTIN\\Administrateurs",
        "S-1-5-32-545" => "BUILTIN\\Utilisateurs",
        "S-1-5-32-546" => "BUILTIN\\Invités",
        "S-1-5-32-548" => "BUILTIN\\Opérateurs de compte",
        "S-1-5-32-549" => "BUILTIN\\Opérateurs de serveur",
        "S-1-5-32-550" => "BUILTIN\\Opérateurs d'impression",
        "S-1-5-32-551" => "BUILTIN\\Opérateurs de sauvegarde",
        "S-1-5-32-554" => "BUILTIN\\Accès compatible pré-Windows 2000",
        "S-1-5-32-560" => "BUILTIN\\Groupe d'accès d'autorisation Windows",
        "S-1-5-32-561" => "BUILTIN\\Serveurs de licences TS",
        _ => return None,
    })
}

pub fn domain_rid_name(rid: u32) -> Option<&'static str> {
    Some(match rid {
        500 => "Administrateur",
        501 => "Invité",
        502 => "krbtgt",
        512 => "Admins du domaine",
        513 => "Utilisateurs du domaine",
        514 => "Invités du domaine",
        515 => "Ordinateurs du domaine",
        516 => "Contrôleurs de domaine",
        517 => "Éditeurs de certificats",
        518 => "Administrateurs du schéma",
        519 => "Administrateurs de l'entreprise",
        520 => "Propriétaires créateurs de la stratégie de groupe",
        521 => "Contrôleurs de domaine en lecture seule",
        525 => "Utilisateurs protégés",
        526 => "Administrateurs clés",
        527 => "Administrateurs clés Enterprise",
        553 => "Serveurs RAS et IAS",
        _ => return None,
    })
}

/// Résolution d'une liste de SID en noms (annuaire puis SID connus).
pub async fn resolve_sids(dir: &mut Dir, sids: &[String]) -> HashMap<String, (String, Option<String>)> {
    let mut out: HashMap<String, (String, Option<String>)> = HashMap::new();
    let mut to_query = Vec::new();
    for s in sids {
        if out.contains_key(s) {
            continue;
        }
        if let Some(n) = well_known_sid(s) {
            out.insert(s.clone(), (n.to_string(), None));
        } else {
            to_query.push(s.clone());
        }
    }
    for chunk in to_query.chunks(50) {
        let filter: String = chunk
            .iter()
            .filter_map(|s| {
                sid_from_string(s).map(|b| format!("(objectSid={})", super::codec::filter_escape_bytes(&b)))
            })
            .collect();
        if filter.is_empty() {
            continue;
        }
        let base = dir.info.base_dn.clone();
        let bases: Vec<String> = std::iter::once(base)
            .chain(std::iter::once(format!("CN=ForeignSecurityPrincipals,{}", dir.info.base_dn)))
            .collect();
        for b in bases {
            if let Ok(v) =
                dir.search(&b, Scope::Subtree, &format!("(|{filter})"), &["objectSid", "sAMAccountName", "name"]).await
            {
                for e in v {
                    if let Some(sid) = e.bin("objectSid").and_then(sid_to_string) {
                        let name = e.str("sAMAccountName").unwrap_or_else(|| e.display_name());
                        let name = match &dir.info.netbios {
                            Some(nb) if e.has("sAMAccountName") => format!("{nb}\\{name}"),
                            _ => name,
                        };
                        out.insert(sid, (name, Some(e.dn.clone())));
                    }
                }
            }
        }
    }
    for s in sids {
        if !out.contains_key(s) {
            let rid_name = s
                .rsplit('-')
                .next()
                .and_then(|r| r.parse::<u32>().ok())
                .and_then(domain_rid_name)
                .map(|n| n.to_string());
            out.insert(s.clone(), (rid_name.unwrap_or_else(|| s.clone()), None));
        }
    }
    out
}

/// Droits courants sur les objets AD.
pub fn mask_labels(mask: u32) -> Vec<&'static str> {
    const M: &[(u32, &str)] = &[
        (0x000F_01FF, "Contrôle total"),
        (0x0000_0001, "Créer des enfants"),
        (0x0000_0002, "Supprimer des enfants"),
        (0x0000_0004, "Lister le contenu"),
        (0x0000_0008, "Écriture validée"),
        (0x0000_0010, "Lire les propriétés"),
        (0x0000_0020, "Écrire les propriétés"),
        (0x0000_0040, "Supprimer l'arborescence"),
        (0x0000_0080, "Lister l'objet"),
        (0x0000_0100, "Droit étendu"),
        (0x0001_0000, "Supprimer"),
        (0x0002_0000, "Lire les autorisations"),
        (0x0004_0000, "Modifier les autorisations"),
        (0x0008_0000, "Modifier le propriétaire"),
    ];
    if mask & 0x000F_01FF == 0x000F_01FF {
        return vec!["Contrôle total"];
    }
    M.iter().skip(1).filter(|(m, _)| mask & m == *m).map(|(_, l)| *l).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rbcd_roundtrip() {
        let sid = "S-1-5-21-1-2-3-1105".to_string();
        let sd = build_rbcd_sd(std::slice::from_ref(&sid)).unwrap();
        let p = parse_sd(&sd).unwrap();
        assert_eq!(p.owner.as_deref(), Some("S-1-5-32-544"));
        assert_eq!(p.dacl.len(), 1);
        assert_eq!(p.dacl[0].sid, sid);
        assert_eq!(p.dacl[0].mask, 0x000F01FF);
    }
}
