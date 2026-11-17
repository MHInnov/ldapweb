//! Tableau de bord : informations du domaine, rôles FSMO, statistiques et
//! contrôles de santé / sécurité.

use crate::error::AppResult;
use crate::ldap::codec::{filetime_to_dt, fmt_dt, uac};
use crate::ldap::flavor::functional_level_label;
use crate::ldap::{Dir, dn};
use crate::web::auth::{Auth, Ctx};
use crate::web::html::render;
use askama::Template;
use axum::response::Response;
use chrono::Utc;
use ldap3::Scope;

#[derive(Template)]
#[template(path = "dashboard.html")]
struct Page {
    ctx: Ctx,
    domain: String,
    vendor: String,
    base_dn: String,
    server: Vec<(String, String)>,
    fsmo: Vec<(String, String)>,
    dcs: Vec<(String, String)>,
    session: Vec<(String, String)>,
}

fn server_of_ntds(v: &str) -> String {
    // CN=NTDS Settings,CN=DC1,CN=Servers,... → DC1
    let p = dn::parent(v);
    let n = dn::rdn_value(&p);
    if n.is_empty() { v.to_string() } else { n }
}

pub async fn page(a: Auth) -> AppResult<Response> {
    let info = a.s.info.clone();
    let mut dir = a.dir().await?;
    let mut server = vec![
        ("Type".to_string(), info.flavor.label().to_string()),
        ("Version".to_string(), info.vendor.clone()),
        ("URL".to_string(), info.url.clone()),
        ("Chiffrement".to_string(), if info.tls { "TLS".into() } else { "aucun (non chiffré)".into() }),
    ];
    if let Some(h) = &info.dns_host_name {
        server.push(("Nom DNS du serveur".into(), h.clone()));
    }
    if info.flavor.is_ad() {
        server.push(("Domaine DNS".into(), info.domain_dns.clone()));
        if let Some(n) = &info.netbios {
            server.push(("Nom NetBIOS".into(), n.clone()));
        }
        server.push(("Royaume Kerberos".into(), info.realm.clone()));
        if let Some(l) = info.domain_level {
            server.push(("Niveau fonctionnel du domaine".into(), functional_level_label(l).into()));
        }
        if let Some(l) = info.forest_level {
            server.push(("Niveau fonctionnel de la forêt".into(), functional_level_label(l).into()));
        }
        if let Some(l) = info.dc_level {
            server.push(("Niveau fonctionnel du DC".into(), functional_level_label(l).into()));
        }
        if let Some(r) = &info.root_domain_nc {
            server.push(("Domaine racine de la forêt".into(), dn::dc_to_domain(r)));
        }
        if let Some(s) = &info.server_dn {
            server.push(("Site".into(), dn::rdn_value(&dn::parent(&dn::parent(&dn::parent(s))))));
        }
        if let Some(sid) = &info.domain_sid {
            server.push(("SID du domaine".into(), sid.clone()));
        }
        server.push(("Corbeille AD".into(), if info.recycle_bin { "activée".into() } else { "désactivée".into() }));
    } else {
        server.push(("Contextes de nommage".into(), info.naming_contexts.join(", ")));
        server.push((
            "Password Modify (RFC 3062)".into(),
            if info.supports_passmod() { "oui".into() } else { "non".into() },
        ));
    }

    let mut fsmo = Vec::new();
    let mut dcs = Vec::new();
    if info.flavor.is_ad() {
        let base = info.base_dn.clone();
        let mut roles: Vec<(&str, String)> = vec![
            ("Émulateur PDC", base.clone()),
            ("Maître RID", format!("CN=RID Manager$,CN=System,{base}")),
            ("Maître d'infrastructure", format!("CN=Infrastructure,{base}")),
        ];
        if let Some(c) = &info.config_nc {
            roles.push(("Maître d'attribution des noms", format!("CN=Partitions,{c}")));
        }
        if let Some(s) = &info.schema_nc {
            roles.push(("Contrôleur de schéma", s.clone()));
        }
        for (label, target) in roles {
            if let Ok(Some(e)) = dir.read(&target, &["fSMORoleOwner"]).await {
                if let Some(o) = e.str("fSMORoleOwner") {
                    fsmo.push((label.to_string(), server_of_ntds(&o)));
                }
            }
        }
        let f = "(&(objectCategory=computer)(|(userAccountControl:1.2.840.113556.1.4.803:=8192)(userAccountControl:1.2.840.113556.1.4.803:=67108864)))";
        if let Ok(v) = dir
            .search(
                &base,
                Scope::Subtree,
                f,
                &["dNSHostName", "cn", "operatingSystem", "operatingSystemVersion", "userAccountControl"],
            )
            .await
        {
            for e in v {
                let ro = e.int("userAccountControl").unwrap_or(0) & uac::PARTIAL_SECRETS_ACCOUNT != 0;
                let name = e.str("dNSHostName").unwrap_or_else(|| e.s("cn"));
                let os = format!(
                    "{} {}{}",
                    e.s("operatingSystem"),
                    e.s("operatingSystemVersion"),
                    if ro { " (RODC)" } else { "" }
                );
                dcs.push((name, os.trim().to_string()));
            }
        }
    }
    if !info.sasl_mechs.is_empty() {
        server.push(("Mécanismes SASL".into(), info.sasl_mechs.join(", ")));
    }
    let session = vec![
        ("Connecté en tant que".to_string(), a.s.display.clone()),
        ("Identifiant".to_string(), a.s.login.clone()),
        ("DN".to_string(), a.s.user_dn.clone()),
        ("Adresse IP".to_string(), a.ip.clone()),
        ("Sessions actives (console)".to_string(), a.st.sessions.count().to_string()),
    ];
    let domain = if info.flavor.is_ad() { info.domain_dns.clone() } else { a.s.profile.name.clone() };
    render(&Page {
        ctx: a.ctx("dashboard"),
        domain,
        vendor: info.vendor.clone(),
        base_dn: info.base_dn.clone(),
        server,
        fsmo,
        dcs,
        session,
    })
}

struct Stat {
    label: String,
    value: String,
    link: String,
}

#[derive(Template)]
#[template(path = "dashboard_stats.html")]
struct StatsTpl {
    stats: Vec<Stat>,
}

async fn count(dir: &Dir, filter: &str) -> String {
    let mut d = dir.clone();
    let base = d.base().to_string();
    match d.count(&base, filter, 200_000).await {
        Ok((n, false)) => n.to_string(),
        Ok((n, true)) => format!("{n}+"),
        Err(_) => "—".into(),
    }
}

pub async fn stats(a: Auth) -> AppResult<Response> {
    let dir = a.dir().await?;
    let ad = dir.is_ad();
    let defs: Vec<(&str, String, &str)> = if ad {
        vec![
            ("Utilisateurs", "(&(objectCategory=person)(objectClass=user))".into(), "users"),
            (
                "Désactivés",
                "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))".into(),
                "disabled",
            ),
            ("Verrouillés", "(&(objectCategory=person)(objectClass=user)(lockoutTime>=1))".into(), "locked"),
            ("Groupes", "(objectClass=group)".into(), "groups"),
            ("Ordinateurs", "(objectCategory=computer)".into(), "computers"),
            ("Unités d'organisation", "(objectClass=organizationalUnit)".into(), "ous"),
            ("Contacts", "(objectClass=contact)".into(), "contacts"),
        ]
    } else {
        vec![
            (
                "Utilisateurs",
                "(|(objectClass=inetOrgPerson)(objectClass=posixAccount)(objectClass=account))".into(),
                "users",
            ),
            ("Désactivés", "(|(nsAccountLock=TRUE)(pwdAccountLockedTime=000001010000Z))".into(), "disabled"),
            ("Verrouillés", "(pwdAccountLockedTime=*)".into(), "locked"),
            (
                "Groupes",
                "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))".into(),
                "groups",
            ),
            ("Unités d'organisation", "(objectClass=organizationalUnit)".into(), "ous"),
        ]
    };
    let futs = defs.iter().map(|(_, f, _)| count(&dir, f));
    let values = futures::future::join_all(futs).await;
    let stats = defs
        .into_iter()
        .zip(values)
        .map(|((l, _, p), v)| Stat { label: l.into(), value: v, link: format!("/search?preset={p}") })
        .collect();
    render(&StatsTpl { stats })
}

struct Check {
    level: &'static str,
    title: String,
    hint: String,
    result: String,
    link: String,
}

#[derive(Template)]
#[template(path = "dashboard_health.html")]
struct HealthTpl {
    checks: Vec<Check>,
}

fn chk(level: &'static str, title: &str, hint: &str, result: String, link: &str) -> Check {
    Check { level, title: title.into(), hint: hint.into(), result, link: link.into() }
}

pub async fn health(a: Auth) -> AppResult<Response> {
    let mut dir = a.dir().await?;
    let info = a.s.info.clone();
    let mut checks = Vec::new();

    // Certificat du serveur LDAP (connexion de la session)
    match dir.ldap.get_peer_certificate().await {
        Ok(Some(der)) => match crate::services::pki::CertInfo::parse(&der) {
            Some(c) => {
                let days = c.days_left();
                let level = if days < 15 {
                    "danger"
                } else if days < 45 {
                    "warn"
                } else {
                    "ok"
                };
                checks.push(chk(
                    level,
                    "Certificat LDAPS du serveur",
                    "Expiration du certificat présenté par le contrôleur / serveur LDAP.",
                    format!("{} — expire le {} ({} j)", c.subject, fmt_dt(c.not_after), days),
                    "/pki",
                ));
            }
            None => checks.push(chk("warn", "Certificat LDAPS du serveur", "", "illisible".into(), "/pki")),
        },
        _ => checks.push(chk(
            if info.tls { "info" } else { "danger" },
            "Chiffrement de la connexion LDAP",
            "Les mots de passe et données de l'annuaire transitent sur cette connexion.",
            if info.tls {
                "TLS actif".into()
            } else {
                "connexion NON chiffrée : utilisez ldaps:// ou StartTLS".into()
            },
            "",
        )),
    }

    if info.flavor.is_ad() {
        let base = info.base_dn.clone();
        // krbtgt
        if let Ok(Some(e)) = dir.read(&format!("CN=krbtgt,CN=Users,{base}"), &["pwdLastSet"]).await {
            if let Some(dt) = e.int("pwdLastSet").and_then(filetime_to_dt) {
                let days = Utc::now().signed_duration_since(dt).num_days();
                checks.push(chk(
                    if days > 365 {
                        "danger"
                    } else if days > 180 {
                        "warn"
                    } else {
                        "ok"
                    },
                    "Âge du mot de passe krbtgt",
                    "Recommandé : renouvellement au moins tous les 180 jours (deux fois, à 10 h d'intervalle).",
                    format!("{days} jours (dernier changement le {})", fmt_dt(dt)),
                    "/kerberos",
                ));
            }
        }
        let n = |s: String| s.trim_end_matches('+').parse::<usize>().unwrap_or(0);
        let c = count(
            &dir,
            "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
        )
        .await;
        checks.push(chk(
            if n(c.clone()) > 0 { "danger" } else { "ok" },
            "Comptes sans pré-authentification Kerberos",
            "Exposés à l'attaque « AS-REP roasting ».",
            format!("{c} compte(s)"),
            "/search?preset=no_preauth",
        ));
        let c = count(
            &dir,
            "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))",
        )
        .await;
        checks.push(chk(
            if n(c.clone()) > 0 { "warn" } else { "ok" },
            "Comptes utilisateurs avec SPN",
            "Exposés au « Kerberoasting » : préférez des comptes de service gérés (gMSA) ou des mots de passe longs.",
            format!("{c} compte(s)"),
            "/search?preset=kerberoastable",
        ));
        let c = count(&dir, "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))").await;
        checks.push(chk(
            if n(c.clone()) > 0 { "danger" } else { "ok" },
            "Délégation Kerberos non contrainte (hors DC)",
            "Un compte de ce type peut usurper tout utilisateur qui s'y connecte.",
            format!("{c} compte(s)"),
            "/search?preset=unconstrained",
        ));
        let c =
            count(&dir, "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))")
                .await;
        checks.push(chk(
            if n(c.clone()) > 0 { "warn" } else { "ok" },
            "Comptes « mot de passe non requis »",
            "Indicateur PASSWD_NOTREQD : un mot de passe vide peut être accepté.",
            format!("{c} compte(s)"),
            "/search?preset=passwd_notreqd",
        ));
        let c = count(&dir, "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))").await;
        checks.push(chk(
            if n(c.clone()) > 0 { "warn" } else { "ok" },
            "Mots de passe n'expirant jamais (comptes actifs)",
            "",
            format!("{c} compte(s)"),
            "/search?preset=never_expires",
        ));
        let limit = crate::ldap::codec::dt_to_filetime(Utc::now() - chrono::Duration::days(90));
        let c = count(&dir, &format!("(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp<={limit}))")).await;
        checks.push(chk(
            if n(c.clone()) > 0 { "warn" } else { "ok" },
            "Utilisateurs actifs inutilisés depuis 90 jours",
            "Basé sur lastLogonTimestamp (précision d'environ 14 jours).",
            format!("{c} compte(s)"),
            "/search?preset=inactive_users",
        ));
        let c = count(&dir, &format!("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp<={limit}))")).await;
        checks.push(chk(
            if n(c.clone()) > 0 { "warn" } else { "ok" },
            "Ordinateurs inactifs depuis 90 jours",
            "",
            format!("{c} ordinateur(s)"),
            "/search?preset=inactive_computers",
        ));
        if let Ok(Some(e)) = dir.read(&base, &["ms-DS-MachineAccountQuota"]).await {
            let q = e.int("ms-DS-MachineAccountQuota").unwrap_or(10);
            checks.push(chk(
                if q > 0 { "warn" } else { "ok" },
                "Quota de jonction de machines (ms-DS-MachineAccountQuota)",
                "Nombre d'ordinateurs que tout utilisateur authentifié peut joindre au domaine.",
                q.to_string(),
                "",
            ));
        }
        let admins = format!("CN=Domain Admins,CN=Users,{base}");
        let f = format!("(memberOf:1.2.840.113556.1.4.1941:={})", crate::ldap::codec::filter_escape(&admins));
        let c = count(&dir, &format!("(&(objectCategory=person)(objectClass=user){f})")).await;
        checks.push(chk(
            if n(c.clone()) > 5 { "warn" } else { "info" },
            "Membres effectifs de « Domain Admins »",
            "Limitez le nombre de comptes à privilèges.",
            format!("{c} compte(s)"),
            "/search?preset=domain_admins",
        ));
        checks.push(chk(
            if info.recycle_bin { "ok" } else { "warn" },
            "Corbeille Active Directory",
            "Permet la restauration complète des objets supprimés.",
            if info.recycle_bin {
                "activée".into()
            } else {
                "désactivée (restauration limitée aux objets tombstone)".into()
            },
            "/recycle",
        ));
        let schema_laps = a.st.schema(&mut dir).await.ok();
        let laps = schema_laps
            .map(|s| s.attr("msLAPS-Password").is_some() || s.attr("ms-Mcs-AdmPwd").is_some())
            .unwrap_or(false);
        checks.push(chk(
            if laps { "ok" } else { "info" },
            "Schéma LAPS",
            "Rotation automatique des mots de passe administrateur local.",
            if laps { "présent".into() } else { "absent".into() },
            "",
        ));
    } else {
        let base = info.base_dn.clone();
        let c = count(&dir, "(pwdAccountLockedTime=*)").await;
        checks.push(chk(
            "info",
            "Comptes verrouillés (ppolicy)",
            "",
            format!("{c} compte(s)"),
            "/search?preset=locked",
        ));
        let pol =
            dir.search(&base, Scope::Subtree, "(objectClass=pwdPolicy)", &["1.1"]).await.map(|v| v.len()).unwrap_or(0);
        checks.push(chk(
            if pol > 0 { "ok" } else { "warn" },
            "Stratégies de mot de passe (ppolicy)",
            "Objets pwdPolicy présents dans l'annuaire.",
            format!("{pol} stratégie(s)"),
            "/policies",
        ));
    }
    render(&HealthTpl { checks })
}
