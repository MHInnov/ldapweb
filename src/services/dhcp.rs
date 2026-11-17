//! DHCP : client de l'API de commande ISC Kea (kea-ctrl-agent ou socket HTTP
//! des serveurs DHCP). Étendues, réservations, baux, statistiques.

use crate::config::KeaServer;
use crate::error::{AppError, AppResult};
use serde_json::{Value, json};
use std::time::Duration;

pub struct Kea {
    client: reqwest::Client,
    pub server: KeaServer,
}

#[derive(Debug, Clone)]
pub struct Reservation {
    pub hw: String,
    pub ip: String,
    pub hostname: String,
    pub client_id: String,
}

#[derive(Debug, Clone)]
pub struct Subnet {
    pub id: i64,
    pub subnet: String,
    pub pools: Vec<String>,
    pub reservations: Vec<Reservation>,
    pub options: Vec<(String, String)>,
    pub shared_network: String,
    pub valid_lifetime: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct Lease {
    pub ip: String,
    pub hw: String,
    pub hostname: String,
    pub expire: i64,
    pub state: i64,
}

impl Kea {
    pub fn new(s: &KeaServer) -> AppResult<Kea> {
        let tls = crate::ldap::conn::client_tls_config(s.ca_file.as_deref(), s.tls_insecure)
            .map_err(|e| AppError::internal(format!("TLS DHCP : {e}")))?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .connect_timeout(Duration::from_secs(5))
            .tls_backend_preconfigured((*tls).clone())
            .build()
            .map_err(|e| AppError::internal(format!("client HTTP : {e}")))?;
        Ok(Kea { client, server: s.clone() })
    }

    fn v6(&self) -> bool {
        self.server.service == "dhcp6"
    }

    pub fn family(&self) -> &'static str {
        if self.v6() { "Dhcp6" } else { "Dhcp4" }
    }

    /// Exécute une commande et renvoie (code, texte, arguments).
    pub async fn call(&self, cmd: &str, args: Option<Value>) -> AppResult<(i64, String, Value)> {
        let mut body = json!({ "command": cmd });
        if self.server.via_control_agent {
            body["service"] = json!([self.server.service]);
        }
        if let Some(a) = args {
            body["arguments"] = a;
        }
        let mut req = self.client.post(&self.server.url).json(&body);
        if let Some(u) = &self.server.username {
            req = req.basic_auth(u, self.server.password.as_deref());
        }
        let resp = req
            .send()
            .await
            .map_err(|e| AppError::unavailable(format!("serveur DHCP {} injoignable : {e}", self.server.name)))?;
        let status = resp.status();
        let v: Value = resp
            .json()
            .await
            .map_err(|e| AppError::unavailable(format!("réponse DHCP illisible (HTTP {status}) : {e}")))?;
        let r = if v.is_array() { v[0].clone() } else { v };
        let code = r["result"].as_i64().unwrap_or(1);
        let text = r["text"].as_str().unwrap_or("").to_string();
        Ok((code, text, r["arguments"].clone()))
    }

    /// Commande devant réussir (code 0 ; 3 = « vide » accepté).
    pub async fn ok(&self, cmd: &str, args: Option<Value>) -> AppResult<Value> {
        let (code, text, a) = self.call(cmd, args).await?;
        match code {
            0 | 3 => Ok(a),
            2 => Err(AppError::bad_request(format!(
                "commande « {cmd} » non prise en charge (bibliothèque de hooks manquante ?) : {text}"
            ))),
            _ => Err(AppError::bad_request(format!("Kea : {text}"))),
        }
    }

    pub async fn config(&self) -> AppResult<Value> {
        let a = self.ok("config-get", None).await?;
        let mut cfg =
            a.get(self.family()).cloned().ok_or_else(|| AppError::internal("configuration Kea inattendue"))?;
        if let Some(o) = cfg.as_object_mut() {
            o.remove("hash");
        }
        Ok(cfg)
    }

    pub async fn set_config(&self, cfg: Value) -> AppResult<()> {
        let args = json!({ self.family(): cfg });
        self.ok("config-test", Some(args.clone())).await?;
        self.ok("config-set", Some(args)).await?;
        if let Err(e) = self.ok("config-write", Some(json!({}))).await {
            return Err(AppError::bad_request(format!(
                "configuration appliquée mais non enregistrée sur disque (config-write) : {}",
                e.message
            )));
        }
        Ok(())
    }

    pub fn subnet_key(&self) -> &'static str {
        if self.v6() { "subnet6" } else { "subnet4" }
    }

    pub fn subnets(&self, cfg: &Value) -> Vec<Subnet> {
        let key = self.subnet_key();
        let mut out = Vec::new();
        let parse = |s: &Value, shared: &str| -> Subnet {
            let pools = s["pools"]
                .as_array()
                .map(|p| p.iter().filter_map(|x| x["pool"].as_str().map(String::from)).collect())
                .unwrap_or_default();
            let reservations = s["reservations"]
                .as_array()
                .map(|r| {
                    r.iter()
                        .map(|x| Reservation {
                            hw: x["hw-address"].as_str().or(x["duid"].as_str()).unwrap_or("").to_string(),
                            ip: x["ip-address"]
                                .as_str()
                                .map(String::from)
                                .or_else(|| {
                                    x["ip-addresses"]
                                        .as_array()
                                        .and_then(|a| a.first())
                                        .and_then(|v| v.as_str())
                                        .map(String::from)
                                })
                                .unwrap_or_default(),
                            hostname: x["hostname"].as_str().unwrap_or("").to_string(),
                            client_id: x["client-id"].as_str().unwrap_or("").to_string(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            let options = s["option-data"]
                .as_array()
                .map(|o| {
                    o.iter()
                        .map(|x| {
                            let n = x["name"]
                                .as_str()
                                .map(String::from)
                                .unwrap_or_else(|| format!("code {}", x["code"].as_i64().unwrap_or(0)));
                            (n, x["data"].as_str().unwrap_or("").to_string())
                        })
                        .collect()
                })
                .unwrap_or_default();
            Subnet {
                id: s["id"].as_i64().unwrap_or(0),
                subnet: s["subnet"].as_str().unwrap_or("").to_string(),
                pools,
                reservations,
                options,
                shared_network: shared.to_string(),
                valid_lifetime: s["valid-lifetime"].as_i64(),
            }
        };
        if let Some(a) = cfg[key].as_array() {
            out.extend(a.iter().map(|s| parse(s, "")));
        }
        if let Some(sn) = cfg["shared-networks"].as_array() {
            for n in sn {
                let name = n["name"].as_str().unwrap_or("");
                if let Some(a) = n[key].as_array() {
                    out.extend(a.iter().map(|s| parse(s, name)));
                }
            }
        }
        out.sort_by_key(|s| s.id);
        out
    }

    /// Accès mutable à un sous-réseau dans la configuration.
    pub fn subnet_mut<'a>(&self, cfg: &'a mut Value, id: i64) -> Option<&'a mut Value> {
        let key = self.subnet_key();
        let mut path: Option<(Option<usize>, usize)> = None;
        if let Some(a) = cfg[key].as_array() {
            if let Some(i) = a.iter().position(|s| s["id"].as_i64() == Some(id)) {
                path = Some((None, i));
            }
        }
        if path.is_none() {
            if let Some(sn) = cfg["shared-networks"].as_array() {
                for (ni, n) in sn.iter().enumerate() {
                    if let Some(i) = n[key].as_array().and_then(|a| a.iter().position(|s| s["id"].as_i64() == Some(id)))
                    {
                        path = Some((Some(ni), i));
                    }
                }
            }
        }
        match path? {
            (None, i) => cfg[key].get_mut(i),
            (Some(ni), i) => cfg["shared-networks"][ni][key].get_mut(i),
        }
    }

    pub async fn leases(&self, subnet_id: i64) -> AppResult<Result<Vec<Lease>, String>> {
        let cmd = if self.v6() { "lease6-get-all" } else { "lease4-get-all" };
        let (code, text, a) = self.call(cmd, Some(json!({ "subnets": [subnet_id] }))).await?;
        match code {
            0 | 3 => Ok(Ok(a["leases"]
                .as_array()
                .map(|l| {
                    l.iter()
                        .map(|x| Lease {
                            ip: x["ip-address"].as_str().unwrap_or("").to_string(),
                            hw: x["hw-address"].as_str().or(x["duid"].as_str()).unwrap_or("").to_string(),
                            hostname: x["hostname"].as_str().unwrap_or("").to_string(),
                            expire: x["cltt"].as_i64().unwrap_or(0) + x["valid-lft"].as_i64().unwrap_or(0),
                            state: x["state"].as_i64().unwrap_or(0),
                        })
                        .collect()
                })
                .unwrap_or_default())),
            2 => Ok(Err("la consultation des baux nécessite la bibliothèque de hooks lease_cmds".into())),
            _ => Ok(Err(text)),
        }
    }

    pub async fn delete_lease(&self, ip: &str) -> AppResult<()> {
        let cmd = if self.v6() { "lease6-del" } else { "lease4-del" };
        self.ok(cmd, Some(json!({ "ip-address": ip }))).await.map(|_| ())
    }

    /// Statistiques par sous-réseau : (attribuées, total).
    pub async fn usage(&self) -> std::collections::HashMap<i64, (i64, i64)> {
        let mut out = std::collections::HashMap::new();
        let Ok(a) = self.ok("statistic-get-all", Some(json!({}))).await else { return out };
        let (assigned, total) =
            if self.v6() { ("assigned-nas", "total-nas") } else { ("assigned-addresses", "total-addresses") };
        if let Some(o) = a.as_object() {
            for (k, v) in o {
                // « subnet[1].assigned-addresses » : [[valeur, horodatage], ...]
                let Some(rest) = k.strip_prefix("subnet[") else { continue };
                let Some((id, stat)) = rest.split_once("].") else { continue };
                let Ok(id) = id.parse::<i64>() else { continue };
                let val = v[0][0].as_i64().or_else(|| v[0][0].as_f64().map(|f| f as i64)).unwrap_or(0);
                let e = out.entry(id).or_insert((0, 0));
                if stat == assigned {
                    e.0 = val;
                } else if stat == total {
                    e.1 = val;
                }
            }
        }
        out
    }
}

pub fn valid_mac(s: &str) -> bool {
    let parts: Vec<&str> = s.split([':', '-']).collect();
    parts.len() == 6 && parts.iter().all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

pub fn norm_mac(s: &str) -> String {
    s.to_lowercase().replace('-', ":")
}
