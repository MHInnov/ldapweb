//! Lecture du schéma (subschemaSubentry, RFC 4512) : types d'attributs, classes
//! d'objets et règles de contenu AD. Sert à l'éditeur d'attributs générique.

use super::dir::Dir;
use crate::error::AppResult;
use ldap3::Scope;
use std::collections::{BTreeSet, HashMap};

#[derive(Debug, Clone, Default)]
pub struct AttrType {
    pub oid: String,
    pub names: Vec<String>,
    pub desc: String,
    pub syntax: String,
    pub single: bool,
    pub no_user_mod: bool,
    pub operational: bool,
    pub sup: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClassKind {
    #[default]
    Structural,
    Auxiliary,
    Abstract,
}

#[derive(Debug, Clone, Default)]
pub struct ObjClass {
    pub oid: String,
    pub names: Vec<String>,
    pub sups: Vec<String>,
    pub kind: ClassKind,
    pub must: Vec<String>,
    pub may: Vec<String>,
    pub aux: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Schema {
    pub attrs: HashMap<String, AttrType>,
    pub classes: HashMap<String, ObjClass>,
}

// ---------------------------------------------------------------- analyseur

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Open,
    Close,
    Dollar,
    Word(String),
    Quoted(String),
}

fn tokenize(s: &str) -> Vec<Tok> {
    let mut out = Vec::new();
    let mut chars = s.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            '(' => {
                out.push(Tok::Open);
                chars.next();
            }
            ')' => {
                out.push(Tok::Close);
                chars.next();
            }
            '$' => {
                out.push(Tok::Dollar);
                chars.next();
            }
            '\'' => {
                chars.next();
                let mut v = String::new();
                for ch in chars.by_ref() {
                    if ch == '\'' {
                        break;
                    }
                    v.push(ch);
                }
                out.push(Tok::Quoted(v));
            }
            c if c.is_whitespace() => {
                chars.next();
            }
            _ => {
                let mut v = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch.is_whitespace() || ch == '(' || ch == ')' || ch == '$' || ch == '\'' {
                        break;
                    }
                    v.push(ch);
                    chars.next();
                }
                out.push(Tok::Word(v));
            }
        }
    }
    out
}

/// Lit une valeur simple ou une liste « ( a $ b ) ».
fn take_list(toks: &[Tok], i: &mut usize) -> Vec<String> {
    let mut out = Vec::new();
    match toks.get(*i) {
        Some(Tok::Open) => {
            *i += 1;
            while let Some(t) = toks.get(*i) {
                *i += 1;
                match t {
                    Tok::Close => break,
                    Tok::Word(w) | Tok::Quoted(w) => out.push(w.clone()),
                    _ => {}
                }
            }
        }
        Some(Tok::Word(w)) | Some(Tok::Quoted(w)) => {
            out.push(w.clone());
            *i += 1;
        }
        _ => {}
    }
    out
}

type Fields = Vec<(String, Vec<String>)>;

/// Découpe une description en (oid, liste de (mot-clé, valeurs)).
fn parse_desc(s: &str) -> Option<(String, Fields)> {
    let toks = tokenize(s);
    let mut i = 0;
    if toks.first() != Some(&Tok::Open) {
        return None;
    }
    i += 1;
    let oid = match toks.get(i)? {
        Tok::Word(w) | Tok::Quoted(w) => w.clone(),
        _ => return None,
    };
    i += 1;
    let mut fields = Vec::new();
    while i < toks.len() {
        match &toks[i] {
            Tok::Close => break,
            Tok::Word(k) => {
                let key = k.to_ascii_uppercase();
                i += 1;
                let flag = matches!(
                    key.as_str(),
                    "SINGLE-VALUE"
                        | "NO-USER-MODIFICATION"
                        | "OBSOLETE"
                        | "COLLECTIVE"
                        | "STRUCTURAL"
                        | "AUXILIARY"
                        | "ABSTRACT"
                );
                let vals = if flag { vec![] } else { take_list(&toks, &mut i) };
                fields.push((key, vals));
            }
            _ => i += 1,
        }
    }
    Some((oid, fields))
}

pub fn parse_attr_type(s: &str) -> Option<AttrType> {
    let (oid, fields) = parse_desc(s)?;
    let mut a = AttrType { oid, ..Default::default() };
    for (k, v) in fields {
        match k.as_str() {
            "NAME" => a.names = v,
            "DESC" => a.desc = v.join(" "),
            "SYNTAX" => a.syntax = v.first().map(|x| x.split('{').next().unwrap_or(x).to_string()).unwrap_or_default(),
            "SINGLE-VALUE" => a.single = true,
            "NO-USER-MODIFICATION" => a.no_user_mod = true,
            "SUP" => a.sup = v.first().cloned(),
            "USAGE" => a.operational = v.first().map(|u| u != "userApplications").unwrap_or(false),
            _ => {}
        }
    }
    Some(a)
}

pub fn parse_obj_class(s: &str) -> Option<ObjClass> {
    let (oid, fields) = parse_desc(s)?;
    let mut c = ObjClass { oid, ..Default::default() };
    for (k, v) in fields {
        match k.as_str() {
            "NAME" => c.names = v,
            "SUP" => c.sups = v,
            "MUST" => c.must = v,
            "MAY" => c.may = v,
            "AUX" => c.aux = v,
            "AUXILIARY" => c.kind = ClassKind::Auxiliary,
            "ABSTRACT" => c.kind = ClassKind::Abstract,
            "STRUCTURAL" => c.kind = ClassKind::Structural,
            _ => {}
        }
    }
    Some(c)
}

const BINARY_SYNTAXES: &[&str] = &[
    "1.3.6.1.4.1.1466.115.121.1.40", // Octet String
    "1.3.6.1.4.1.1466.115.121.1.5",  // Binary
    "1.3.6.1.4.1.1466.115.121.1.8",  // Certificate
    "1.3.6.1.4.1.1466.115.121.1.9",  // Certificate List
    "1.3.6.1.4.1.1466.115.121.1.10", // Certificate Pair
    "1.3.6.1.4.1.1466.115.121.1.28", // JPEG
    "1.3.6.1.4.1.1466.115.121.1.49", // Supported Algorithm
    "1.2.840.113556.1.4.907",        // NT Security Descriptor
    "1.2.840.113556.1.4.903",        // DN-Binary
];

impl Schema {
    pub async fn load(dir: &mut Dir) -> AppResult<Schema> {
        let mut schema = Schema::default();
        let sub = match dir.info.subschema.clone() {
            Some(s) => s,
            None => return Ok(schema),
        };
        let v = dir
            .search(&sub, Scope::Base, "(objectClass=*)", &["attributeTypes", "objectClasses", "dITContentRules"])
            .await?;
        let Some(e) = v.into_iter().next() else { return Ok(schema) };
        for s in e.strs("attributeTypes") {
            if let Some(a) = parse_attr_type(&s) {
                for n in &a.names {
                    schema.attrs.insert(n.to_ascii_lowercase(), a.clone());
                }
            }
        }
        for s in e.strs("objectClasses") {
            if let Some(c) = parse_obj_class(&s) {
                for n in &c.names {
                    schema.classes.insert(n.to_ascii_lowercase(), c.clone());
                }
            }
        }
        // Règles de contenu AD : classes auxiliaires et attributs supplémentaires.
        for s in e.strs("dITContentRules") {
            if let Some(rule) = parse_obj_class(&s) {
                for n in &rule.names {
                    if let Some(c) = schema.classes.get_mut(&n.to_ascii_lowercase()) {
                        c.aux.extend(rule.aux.iter().cloned());
                        c.may.extend(rule.may.iter().cloned());
                        c.must.extend(rule.must.iter().cloned());
                    }
                }
            }
        }
        // Héritage des syntaxes via SUP.
        let snapshot: Vec<(String, Option<String>)> =
            schema.attrs.iter().filter(|(_, a)| a.syntax.is_empty()).map(|(k, a)| (k.clone(), a.sup.clone())).collect();
        for (k, sup) in snapshot {
            let mut cur = sup;
            let mut depth = 0;
            while let Some(s) = cur {
                depth += 1;
                if depth > 10 {
                    break;
                }
                match schema.attrs.get(&s.to_ascii_lowercase()) {
                    Some(p) if !p.syntax.is_empty() => {
                        let syn = p.syntax.clone();
                        if let Some(a) = schema.attrs.get_mut(&k) {
                            a.syntax = syn;
                        }
                        break;
                    }
                    Some(p) => cur = p.sup.clone(),
                    None => break,
                }
            }
        }
        Ok(schema)
    }

    pub fn attr(&self, name: &str) -> Option<&AttrType> {
        self.attrs.get(&name.to_ascii_lowercase())
    }

    pub fn is_single(&self, name: &str) -> bool {
        self.attr(name).map(|a| a.single).unwrap_or(false)
    }

    pub fn is_binary(&self, name: &str) -> bool {
        if super::codec::is_binary_attr(name) {
            return true;
        }
        self.attr(name).map(|a| BINARY_SYNTAXES.contains(&a.syntax.as_str())).unwrap_or(false)
    }

    pub fn is_readonly(&self, name: &str) -> bool {
        self.attr(name).map(|a| a.no_user_mod).unwrap_or(false)
    }

    pub fn canonical_name(&self, name: &str) -> String {
        self.attr(name)
            .and_then(|a| a.names.iter().find(|n| n.eq_ignore_ascii_case(name)).cloned())
            .unwrap_or_else(|| name.to_string())
    }

    /// Attributs obligatoires et facultatifs pour un ensemble de classes
    /// (héritage SUP et classes auxiliaires inclus).
    pub fn allowed(&self, classes: &[String]) -> (BTreeSet<String>, BTreeSet<String>) {
        let mut must = BTreeSet::new();
        let mut may = BTreeSet::new();
        let mut seen = std::collections::HashSet::new();
        let mut stack: Vec<String> = classes.to_vec();
        while let Some(c) = stack.pop() {
            let key = c.to_ascii_lowercase();
            if !seen.insert(key.clone()) {
                continue;
            }
            if let Some(cls) = self.classes.get(&key) {
                must.extend(cls.must.iter().map(|a| self.canonical_name(a)));
                may.extend(cls.may.iter().map(|a| self.canonical_name(a)));
                stack.extend(cls.sups.iter().cloned());
                stack.extend(cls.aux.iter().cloned());
            }
        }
        for m in &must {
            may.remove(m);
        }
        (must, may)
    }

    pub fn syntax_label(&self, name: &str) -> &'static str {
        let syn = self.attr(name).map(|a| a.syntax.as_str()).unwrap_or("");
        match syn {
            "1.3.6.1.4.1.1466.115.121.1.12" => "DN",
            "1.3.6.1.4.1.1466.115.121.1.15" | "1.3.6.1.4.1.1466.115.121.1.26" | "1.3.6.1.4.1.1466.115.121.1.44" => {
                "Chaîne"
            }
            "1.3.6.1.4.1.1466.115.121.1.27" | "1.2.840.113556.1.4.906" => "Entier",
            "1.3.6.1.4.1.1466.115.121.1.7" => "Booléen",
            "1.3.6.1.4.1.1466.115.121.1.24" | "1.3.6.1.4.1.1466.115.121.1.53" => "Date",
            "1.3.6.1.4.1.1466.115.121.1.38" => "OID",
            "1.3.6.1.4.1.1466.115.121.1.50" => "Téléphone",
            "1.3.6.1.4.1.1466.115.121.1.36" => "Numérique",
            "1.3.6.1.4.1.1466.115.121.1.40" | "1.3.6.1.4.1.1466.115.121.1.5" => "Binaire",
            "1.2.840.113556.1.4.907" => "Descripteur de sécurité",
            "1.3.6.1.4.1.1466.115.121.1.8" => "Certificat",
            "" => "",
            _ => "Autre",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_openldap_attr() {
        let a = parse_attr_type(
            "( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'RFC4519: common name(s)' SUP name EQUALITY caseIgnoreMatch )",
        )
        .unwrap();
        assert_eq!(a.names, vec!["cn", "commonName"]);
        assert_eq!(a.sup.as_deref(), Some("name"));
        assert!(!a.single);
    }

    #[test]
    fn parse_ad_attr() {
        let a = parse_attr_type(
            "( 1.2.840.113556.1.4.221 NAME 'sAMAccountName' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' SINGLE-VALUE )",
        )
        .unwrap();
        assert_eq!(a.syntax, "1.3.6.1.4.1.1466.115.121.1.15");
        assert!(a.single);
    }

    #[test]
    fn parse_class() {
        let c = parse_obj_class(
            "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber ) )",
        )
        .unwrap();
        assert_eq!(c.must, vec!["sn", "cn"]);
        assert_eq!(c.may.len(), 2);
        assert_eq!(c.kind, ClassKind::Structural);
    }
}
