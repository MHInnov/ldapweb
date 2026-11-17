//! Écriture de fichiers keytab (format MIT 0x0502, compatible ktpass / ktutil).

pub struct KeytabEntry {
    pub principal: String,
    pub realm: String,
    pub kvno: u32,
    pub etype: i32,
    pub key: Vec<u8>,
}

fn counted(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s);
}

pub fn write(entries: &[KeytabEntry]) -> Vec<u8> {
    let mut out = vec![0x05, 0x02];
    let ts = chrono::Utc::now().timestamp() as u32;
    for e in entries {
        let name = e.principal.split('@').next().unwrap_or(&e.principal);
        let comps: Vec<&str> = name.split('/').collect();
        let mut body = Vec::new();
        body.extend_from_slice(&(comps.len() as u16).to_be_bytes());
        counted(&mut body, e.realm.as_bytes());
        for c in &comps {
            counted(&mut body, c.as_bytes());
        }
        body.extend_from_slice(&1u32.to_be_bytes()); // KRB5_NT_PRINCIPAL
        body.extend_from_slice(&ts.to_be_bytes());
        body.push((e.kvno & 0xff) as u8);
        body.extend_from_slice(&(e.etype as u16).to_be_bytes());
        counted(&mut body, &e.key);
        body.extend_from_slice(&e.kvno.to_be_bytes());
        out.extend_from_slice(&(body.len() as i32).to_be_bytes());
        out.extend(body);
    }
    out
}

/// Lecture minimale (tests) : (principal, kvno, etype, clé).
#[cfg(test)]
pub fn read(data: &[u8]) -> Vec<(String, u32, i32, Vec<u8>)> {
    let mut out = Vec::new();
    let mut p = 2;
    let u16at = |d: &[u8], o: usize| u16::from_be_bytes([d[o], d[o + 1]]) as usize;
    while p + 4 <= data.len() {
        let size = i32::from_be_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]) as usize;
        p += 4;
        let e = &data[p..p + size];
        let n = u16at(e, 0);
        let mut q = 2;
        let rl = u16at(e, q);
        let realm = String::from_utf8_lossy(&e[q + 2..q + 2 + rl]).to_string();
        q += 2 + rl;
        let mut comps = Vec::new();
        for _ in 0..n {
            let l = u16at(e, q);
            comps.push(String::from_utf8_lossy(&e[q + 2..q + 2 + l]).to_string());
            q += 2 + l;
        }
        q += 8;
        let vno8 = e[q] as u32;
        q += 1;
        let et = u16at(e, q) as i32;
        let kl = u16at(e, q + 2);
        let key = e[q + 4..q + 4 + kl].to_vec();
        q += 4 + kl;
        let kvno = if q + 4 <= e.len() { u32::from_be_bytes([e[q], e[q + 1], e[q + 2], e[q + 3]]) } else { vno8 };
        out.push((format!("{}@{realm}", comps.join("/")), kvno, et, key));
        p += size;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let data = write(&[KeytabEntry {
            principal: "HTTP/web.corp.example".into(),
            realm: "CORP.EXAMPLE".into(),
            kvno: 3,
            etype: 18,
            key: vec![7u8; 32],
        }]);
        let r = read(&data);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].0, "HTTP/web.corp.example@CORP.EXAMPLE");
        assert_eq!(r[0].1, 3);
        assert_eq!(r[0].2, 18);
    }
}
