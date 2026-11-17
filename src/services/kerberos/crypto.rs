//! Dérivation des clés Kerberos à partir d'un mot de passe (RFC 3961 / 3962) :
//! AES256-CTS-HMAC-SHA1-96, AES128-CTS-HMAC-SHA1-96 et RC4-HMAC (MD4).

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use md4::{Digest as _, Md4};
use sha1::Sha1;

pub const ETYPE_AES256: i32 = 18;
pub const ETYPE_AES128: i32 = 17;
pub const ETYPE_RC4: i32 = 23;

pub fn etype_name(e: i32) -> &'static str {
    match e {
        ETYPE_AES256 => "aes256-cts-hmac-sha1-96",
        ETYPE_AES128 => "aes128-cts-hmac-sha1-96",
        ETYPE_RC4 => "arcfour-hmac (RC4)",
        _ => "inconnu",
    }
}

fn gcd(a: usize, b: usize) -> usize {
    if b == 0 { a } else { gcd(b, a % b) }
}

fn rotate_right(b: &[u8], nbits: usize) -> Vec<u8> {
    let total = b.len() * 8;
    let n = nbits % total;
    let mut out = vec![0u8; b.len()];
    for i in 0..total {
        let src = (i + total - n) % total;
        let bit = (b[src / 8] >> (7 - (src % 8))) & 1;
        out[i / 8] |= bit << (7 - (i % 8));
    }
    out
}

/// n-fold (RFC 3961 §5.1) : `out_len` en octets.
pub fn nfold(input: &[u8], out_len: usize) -> Vec<u8> {
    let in_len = input.len();
    let lcm = in_len * out_len / gcd(in_len, out_len);
    let mut buf = Vec::with_capacity(lcm);
    for i in 0..(lcm / in_len) {
        buf.extend(rotate_right(input, 13 * i));
    }
    let mut result = vec![0u8; out_len];
    for chunk in buf.chunks(out_len) {
        let mut carry = 0u32;
        for j in (0..out_len).rev() {
            let s = result[j] as u32 + chunk[j] as u32 + carry;
            result[j] = (s & 0xff) as u8;
            carry = s >> 8;
        }
        while carry != 0 {
            for j in (0..out_len).rev() {
                let s = result[j] as u32 + carry;
                result[j] = (s & 0xff) as u8;
                carry = s >> 8;
                if carry == 0 {
                    break;
                }
            }
        }
    }
    result
}

fn aes_encrypt_block(key: &[u8], block: &[u8; 16]) -> [u8; 16] {
    let mut b = aes::Block::clone_from_slice(block);
    match key.len() {
        16 => Aes128::new_from_slice(key).unwrap().encrypt_block(&mut b),
        32 => Aes256::new_from_slice(key).unwrap().encrypt_block(&mut b),
        _ => unreachable!("clé AES invalide"),
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&b);
    out
}

/// DK(clé, constante) pour AES (RFC 3961 §5.1, RFC 3962).
fn derive_key(key: &[u8], constant: &[u8]) -> Vec<u8> {
    let mut block = [0u8; 16];
    let folded = if constant.len() == 16 { constant.to_vec() } else { nfold(constant, 16) };
    block.copy_from_slice(&folded);
    let mut out = Vec::with_capacity(key.len());
    while out.len() < key.len() {
        block = aes_encrypt_block(key, &block);
        out.extend_from_slice(&block);
    }
    out.truncate(key.len());
    out
}

/// string-to-key AES (RFC 3962) ; `iterations` vaut 4096 par défaut.
pub fn aes_string_to_key(password: &str, salt: &str, key_len: usize, iterations: u32) -> Vec<u8> {
    let mut tkey = vec![0u8; key_len];
    pbkdf2::pbkdf2_hmac::<Sha1>(password.as_bytes(), salt.as_bytes(), iterations, &mut tkey);
    derive_key(&tkey, b"kerberos")
}

/// Clé RC4-HMAC : MD4 du mot de passe en UTF-16LE (= empreinte NT).
pub fn rc4_key(password: &str) -> Vec<u8> {
    let utf16: Vec<u8> = password.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let mut h = Md4::new();
    h.update(&utf16);
    h.finalize().to_vec()
}

pub fn string_to_key(etype: i32, password: &str, salt: &str) -> Option<Vec<u8>> {
    match etype {
        ETYPE_AES256 => Some(aes_string_to_key(password, salt, 32, 4096)),
        ETYPE_AES128 => Some(aes_string_to_key(password, salt, 16, 4096)),
        ETYPE_RC4 => Some(rc4_key(password)),
        _ => None,
    }
}

/// Sel Active Directory : ROYAUME + nom de compte (utilisateurs), ou
/// ROYAUME + "host" + nom en minuscules + "." + domaine en minuscules (ordinateurs).
pub fn ad_salt(realm: &str, sam: &str, is_computer: bool) -> String {
    let realm_u = realm.to_uppercase();
    if is_computer {
        let name = sam.trim_end_matches('$').to_lowercase();
        format!("{realm_u}host{name}.{}", realm.to_lowercase())
    } else {
        format!("{realm_u}{sam}")
    }
}

/// Sel par défaut MIT : ROYAUME + composantes du principal concaténées.
pub fn mit_salt(realm: &str, principal: &str) -> String {
    let name = principal.split('@').next().unwrap_or(principal);
    format!("{realm}{}", name.split('/').collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nfold_vectors() {
        // RFC 3961 annexe A.1
        assert_eq!(hex::encode(nfold(b"012345", 8)), "be072631276b1955");
        assert_eq!(hex::encode(nfold(b"password", 7)), "78a07b6caf85fa");
        assert_eq!(hex::encode(nfold(b"Rough Consensus, and Running Code", 8)), "bb6ed30870b7f0e0");
        assert_eq!(hex::encode(nfold(b"password", 21)), "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e");
        assert_eq!(hex::encode(nfold(b"kerberos", 8)), "6b65726265726f73");
        assert_eq!(hex::encode(nfold(b"kerberos", 16)), "6b65726265726f737b9b5b2b93132b93");
        assert_eq!(hex::encode(nfold(b"Q", 21)), "518a54a215a8452a518a54a215a8452a518a54a215");
    }

    #[test]
    fn aes_vectors() {
        // RFC 3962 annexe B
        let salt = "ATHENA.MIT.EDUraeburn";
        assert_eq!(hex::encode(aes_string_to_key("password", salt, 16, 1)), "42263c6e89f4fc28b8df68ee09799f15");
        assert_eq!(
            hex::encode(aes_string_to_key("password", salt, 32, 1)),
            "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161"
        );
        assert_eq!(hex::encode(aes_string_to_key("password", salt, 16, 2)), "c651bf29e2300ac27fa469d693bdda13");
        assert_eq!(hex::encode(aes_string_to_key("password", salt, 16, 1200)), "4c01cd46d632d01e6dbe230a01ed642a");
    }

    #[test]
    fn rc4_vector() {
        // Empreinte NT bien connue de « password »
        assert_eq!(hex::encode(rc4_key("password")), "8846f7eaee8fb117ad06bdd830b7586c");
    }

    #[test]
    fn salts() {
        assert_eq!(ad_salt("corp.example", "svc_web", false), "CORP.EXAMPLEsvc_web");
        assert_eq!(ad_salt("CORP.EXAMPLE", "WEB01$", true), "CORP.EXAMPLEhostweb01.corp.example");
        assert_eq!(mit_salt("LAB.EXAMPLE", "HTTP/www.lab.example@LAB.EXAMPLE"), "LAB.EXAMPLEHTTPwww.lab.example");
    }
}
