//! Connexion aux serveurs LDAP : configuration TLS (rustls, magasin de certificats
//! du système Windows/Linux + AC optionnelle), basculement entre URLs, bind simple.

use crate::config::DirectoryProfile;
use crate::error::{AppError, AppResult};
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Vérificateur acceptant tout certificat (option `tls_insecure`, tests uniquement).
#[derive(Debug)]
pub struct NoVerify(pub Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Magasin de racines : certificats du système + fichier d'AC optionnel.
pub fn root_store(ca_file: Option<&Path>) -> anyhow::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for c in native.certs {
        let _ = roots.add(c);
    }
    if let Some(p) = ca_file {
        let pem = std::fs::read(p).map_err(|e| anyhow::anyhow!("lecture de l'AC {} : {e}", p.display()))?;
        let mut n = 0;
        for c in CertificateDer::pem_slice_iter(&pem) {
            roots.add(c.map_err(|e| anyhow::anyhow!("AC {} invalide : {e:?}", p.display()))?)?;
            n += 1;
        }
        if n == 0 {
            // Peut-être un certificat DER
            roots.add(CertificateDer::from(pem))?;
        }
    }
    Ok(roots)
}

pub fn client_tls_config(ca_file: Option<&Path>, insecure: bool) -> anyhow::Result<Arc<ClientConfig>> {
    let prov = provider();
    let roots = root_store(ca_file)?;
    let mut cfg = ClientConfig::builder_with_provider(prov.clone())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    if insecure {
        cfg.dangerous().set_certificate_verifier(Arc::new(NoVerify(prov)));
    }
    Ok(Arc::new(cfg))
}

pub fn profile_tls(profile: &DirectoryProfile) -> anyhow::Result<Arc<ClientConfig>> {
    client_tls_config(profile.ca_file.as_deref(), profile.tls_insecure)
}

/// Ouvre une connexion en essayant chaque URL du profil.
pub async fn connect(profile: &DirectoryProfile, tls: &Arc<ClientConfig>) -> AppResult<(Ldap, String)> {
    let mut errors = Vec::new();
    for url in &profile.urls {
        let mut settings = LdapConnSettings::new()
            .set_conn_timeout(Duration::from_secs(profile.timeout_secs.clamp(2, 30)))
            .set_config(tls.clone());
        if profile.starttls && url.starts_with("ldap://") {
            settings = settings.set_starttls(true);
        }
        if profile.tls_insecure {
            settings = settings.set_no_tls_verify(true);
        }
        // Connexion TCP ouverte ici pour activer TCP_NODELAY : sans cela, l'algorithme de
        // Nagle et l'acquittement retardé ajoutent environ 40 ms à chaque opération LDAP.
        if !url.starts_with("ldapi://") {
            match tcp_nodelay(url, Duration::from_secs(profile.timeout_secs.clamp(2, 30))).await {
                Ok(stream) => settings = settings.set_std_stream(ldap3::StdStream::Tcp(stream)),
                Err(e) => {
                    tracing::warn!("échec de connexion à {url} : {e}");
                    errors.push(format!("{url} : {e}"));
                    continue;
                }
            }
        }
        match LdapConnAsync::with_settings(settings, url).await {
            Ok((conn, ldap)) => {
                let u = url.clone();
                tokio::spawn(async move {
                    if let Err(e) = conn.drive().await {
                        tracing::debug!("connexion LDAP {u} terminée : {e}");
                    }
                });
                return Ok((ldap, url.clone()));
            }
            Err(e) => {
                tracing::warn!("échec de connexion à {url} : {e}");
                errors.push(format!("{url} : {e}"));
            }
        }
    }
    Err(AppError::unavailable(format!("aucun serveur LDAP joignable — {}", errors.join(" ; "))))
}

async fn tcp_nodelay(url: &str, timeout: Duration) -> std::io::Result<std::net::TcpStream> {
    let (host, port) = super::flavor::url_host(url);
    let addr = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
    let tcp = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "délai de connexion dépassé"))??;
    tcp.set_nodelay(true)?;
    tcp.into_std()
}

pub async fn simple_bind(ldap: &mut Ldap, dn: &str, pw: &str, timeout: Duration) -> AppResult<()> {
    if pw.is_empty() {
        // Un mot de passe vide produirait un bind anonyme « réussi » (RFC 4513 §5.1.2).
        return Err(AppError::new(axum::http::StatusCode::UNAUTHORIZED, "mot de passe requis"));
    }
    ldap.with_timeout(timeout).simple_bind(dn, pw).await?.success()?;
    Ok(())
}

/// Récupère la chaîne de certificats présentée par un serveur TLS (LDAPS),
/// et indique si elle est approuvée par la configuration du profil.
pub async fn probe_tls_chain(
    host: &str,
    port: u16,
    trusted: &Arc<ClientConfig>,
) -> anyhow::Result<(Vec<Vec<u8>>, Result<(), String>)> {
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;
    let addr = format!("{host}:{port}");
    let sname = ServerName::try_from(host.to_string())?;

    // 1. Récupération sans vérification
    let prov = provider();
    let mut cfg = ClientConfig::builder_with_provider(prov.clone())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    cfg.dangerous().set_certificate_verifier(Arc::new(NoVerify(prov)));
    let tcp = tokio::time::timeout(Duration::from_secs(8), TcpStream::connect(&addr)).await??;
    let tls =
        tokio::time::timeout(Duration::from_secs(8), TlsConnector::from(Arc::new(cfg)).connect(sname.clone(), tcp))
            .await??;
    let chain: Vec<Vec<u8>> = tls
        .get_ref()
        .1
        .peer_certificates()
        .map(|c| c.iter().map(|x| x.as_ref().to_vec()).collect())
        .unwrap_or_default();
    drop(tls);

    // 2. Vérification avec la configuration réelle
    let verdict = async {
        let tcp = tokio::time::timeout(Duration::from_secs(8), TcpStream::connect(&addr))
            .await
            .map_err(|_| "délai dépassé".to_string())?
            .map_err(|e| e.to_string())?;
        tokio::time::timeout(Duration::from_secs(8), TlsConnector::from(trusted.clone()).connect(sname, tcp))
            .await
            .map_err(|_| "délai dépassé".to_string())?
            .map_err(|e| e.to_string())?;
        Ok::<(), String>(())
    }
    .await;
    Ok((chain, verdict))
}
