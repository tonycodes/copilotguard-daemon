use anyhow::Result;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::Client;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::api::{truncate_body, InterceptRequestPayload, InterceptResponsePayload};
use crate::api_client::{create_api_client, ApiClient};
use crate::ca;
use crate::config;

/// Custom DNS resolver that returns real IPs for intercepted domains
/// This bypasses the local hosts file which redirects them to 127.0.0.1
struct BypassResolver {
    /// Map of domain -> real IP addresses (looked up once at startup)
    overrides: HashMap<String, Vec<IpAddr>>,
}

impl BypassResolver {
    fn new() -> Self {
        let mut overrides = HashMap::new();

        // Real IP addresses for GitHub Copilot domains
        // These are GitHub's CDN IPs - they may change but are generally stable
        // copilot-proxy.githubusercontent.com resolves to GitHub's CDN
        overrides.insert(
            "copilot-proxy.githubusercontent.com".to_string(),
            vec![
                IpAddr::V4(Ipv4Addr::new(140, 82, 112, 21)),
                IpAddr::V4(Ipv4Addr::new(140, 82, 113, 21)),
                IpAddr::V4(Ipv4Addr::new(140, 82, 114, 21)),
            ],
        );

        overrides.insert(
            "api.githubcopilot.com".to_string(),
            vec![
                IpAddr::V4(Ipv4Addr::new(140, 82, 112, 21)),
                IpAddr::V4(Ipv4Addr::new(140, 82, 113, 21)),
            ],
        );

        // Individual Copilot domain
        overrides.insert(
            "api.individual.githubcopilot.com".to_string(),
            vec![
                IpAddr::V4(Ipv4Addr::new(140, 82, 112, 21)),
                IpAddr::V4(Ipv4Addr::new(140, 82, 113, 21)),
            ],
        );

        // Business Copilot domain
        overrides.insert(
            "api.business.githubcopilot.com".to_string(),
            vec![
                IpAddr::V4(Ipv4Addr::new(140, 82, 112, 21)),
                IpAddr::V4(Ipv4Addr::new(140, 82, 113, 21)),
            ],
        );

        // Enterprise Copilot domain
        overrides.insert(
            "api.enterprise.githubcopilot.com".to_string(),
            vec![
                IpAddr::V4(Ipv4Addr::new(140, 82, 112, 21)),
                IpAddr::V4(Ipv4Addr::new(140, 82, 113, 21)),
            ],
        );

        Self { overrides }
    }
}

impl Resolve for BypassResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let domain = name.as_str().to_string();
        let overrides = self.overrides.clone();

        Box::pin(async move {
            if let Some(ips) = overrides.get(&domain) {
                let addrs: Vec<SocketAddr> = ips
                    .iter()
                    .map(|ip| SocketAddr::new(*ip, 0))
                    .collect();
                info!("Resolved {} to {:?} (bypassing hosts file)", domain, addrs);
                return Ok(Box::new(addrs.into_iter()) as Addrs);
            }

            // For other domains, let the system resolve normally
            // This shouldn't happen for our intercepted traffic
            Err(Box::new(io::Error::new(
                io::ErrorKind::NotFound,
                format!("No override for domain: {}", domain),
            )) as Box<dyn std::error::Error + Send + Sync>)
        })
    }
}

/// SNI-based certificate resolver that generates certificates on-demand
#[derive(Debug)]
struct SniCertResolver {
    /// Cache of generated certificates by domain
    cache: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    /// Domains we're allowed to intercept
    allowed_domains: Vec<String>,
}

impl SniCertResolver {
    fn new(allowed_domains: Vec<String>) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            allowed_domains,
        }
    }

    fn get_or_create_cert(&self, domain: &str) -> Option<Arc<CertifiedKey>> {
        // Check cache first
        {
            let cache = self.cache.read().ok()?;
            if let Some(key) = cache.get(domain) {
                return Some(key.clone());
            }
        }

        // Generate new certificate
        info!("Generating certificate for domain: {}", domain);
        let (cert_pem, key_pem) = match ca::generate_domain_cert(domain) {
            Ok((c, k)) => (c, k),
            Err(e) => {
                error!("Failed to generate certificate for {}: {}", domain, e);
                return None;
            }
        };

        // Parse certificate chain
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cert_pem.as_bytes())
                .filter_map(|r| r.ok())
                .collect();

        if certs.is_empty() {
            error!("No certificates parsed for {}", domain);
            return None;
        }

        // Parse private key
        let key = match rustls_pemfile::private_key(&mut key_pem.as_bytes()) {
            Ok(Some(k)) => k,
            Ok(None) => {
                error!("No private key found for {}", domain);
                return None;
            }
            Err(e) => {
                error!("Failed to parse private key for {}: {}", domain, e);
                return None;
            }
        };

        // Create signing key
        let signing_key = match rustls::crypto::aws_lc_rs::sign::any_supported_type(&key) {
            Ok(k) => k,
            Err(e) => {
                error!("Failed to create signing key for {}: {:?}", domain, e);
                return None;
            }
        };

        let certified_key = Arc::new(CertifiedKey::new(certs, signing_key));

        // Store in cache
        {
            if let Ok(mut cache) = self.cache.write() {
                cache.insert(domain.to_string(), certified_key.clone());
            }
        }

        Some(certified_key)
    }
}

impl ResolvesServerCert for SniCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        info!("TLS connection for SNI: {}", sni);

        // Check if this domain is in our allowed list
        let domain = sni.to_string();
        if !self.allowed_domains.iter().any(|d| d == &domain) {
            warn!("Domain {} not in allowed list, rejecting", domain);
            return None;
        }

        self.get_or_create_cert(&domain)
    }
}

/// Shared state for the proxy
struct ProxyState {
    /// HTTP client for forwarding requests to upstream
    client: Client,
    /// API client for guardrail checks and logging
    api_client: Arc<ApiClient>,
}

/// Run the proxy server
pub async fn run() -> Result<()> {
    let config = config::load()?;
    let addr = SocketAddr::from(([127, 0, 0, 1], config.proxy_port));

    info!("Starting CopilotGuard proxy on {}", addr);

    // Create API client for guardrail checks
    let api_client = create_api_client(&config)?;

    if api_client.has_api_key() {
        info!("API key configured - guardrails and logging enabled");
        info!("Fail mode: {}", config.api_fail_mode);
        info!("Guardrail timeout: {}ms", config.guardrail_timeout_ms);
    } else {
        info!("No API key configured - running in passthrough mode");
    }

    // Create HTTP client for forwarding requests
    // Uses custom DNS resolver to bypass local hosts file
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .dns_resolver(Arc::new(BypassResolver::new()))
        .build()?;

    let state = Arc::new(ProxyState { client, api_client });

    // Load TLS config with SNI-based certificate selection
    let tls_config = create_tls_config(config.intercept_domains.clone())?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = TcpListener::bind(addr).await?;
    info!("Proxy listening on https://{}", addr);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = tls_acceptor.clone();
        let state = state.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let io = TokioIo::new(tls_stream);

                    if let Err(err) = http1::Builder::new()
                        .serve_connection(
                            io,
                            service_fn(move |req| {
                                let state = state.clone();
                                async move { handle_request(req, peer_addr, state).await }
                            }),
                        )
                        .await
                    {
                        error!("Error serving connection: {:?}", err);
                    }
                }
                Err(err) => {
                    error!("TLS handshake failed: {:?}", err);
                }
            }
        });
    }
}

/// Create TLS configuration for the proxy with SNI-based certificate selection
fn create_tls_config(allowed_domains: Vec<String>) -> Result<rustls::ServerConfig> {
    let cert_resolver = Arc::new(SniCertResolver::new(allowed_domains));

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);

    Ok(config)
}

/// Handle an incoming HTTP request by forwarding it to the real destination
async fn handle_request(
    req: Request<hyper::body::Incoming>,
    peer_addr: SocketAddr,
    state: Arc<ProxyState>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    match forward_request(req, peer_addr, state).await {
        Ok(response) => Ok(response),
        Err(err) => {
            error!("Proxy error: {:?}", err);
            Ok(Response::builder()
                .status(502)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(format!(
                    r#"{{"error": "Proxy error: {}"}}"#,
                    err
                ))))
                .unwrap())
        }
    }
}

/// Forward the request to the real destination
async fn forward_request(
    req: Request<hyper::body::Incoming>,
    _peer_addr: SocketAddr,
    state: Arc<ProxyState>,
) -> Result<Response<Full<Bytes>>> {
    // Generate unique request ID for correlation
    let request_id = Uuid::new_v4().to_string();
    let start_time = Instant::now();

    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    // Get the target host from the Host header
    let host = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("copilot-proxy.githubusercontent.com");

    // Build the target URL
    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let target_url = format!("https://{}{}", host, path);

    info!("[{}] {} {} -> {}", request_id, method, uri, target_url);

    // Read the request body
    let body_bytes = req.collect().await?.to_bytes();

    // Log request details for debugging (truncate large bodies)
    if !body_bytes.is_empty() {
        let body_preview = if body_bytes.len() > 200 {
            format!(
                "{}... ({} bytes)",
                String::from_utf8_lossy(&body_bytes[..200]),
                body_bytes.len()
            )
        } else {
            String::from_utf8_lossy(&body_bytes).to_string()
        };
        debug!("[{}] Request body: {}", request_id, body_preview);
    }

    // === GUARDRAIL CHECK ===
    // Build request headers map (sanitized - no auth tokens sent to API)
    let mut headers_map = HashMap::new();
    for (name, value) in headers.iter() {
        let name_str = name.as_str().to_lowercase();
        // Skip sensitive headers
        if name_str != "authorization" && name_str != "x-github-token" {
            if let Ok(v) = value.to_str() {
                headers_map.insert(name_str, v.to_string());
            }
        }
    }

    let check_payload = InterceptRequestPayload {
        request_id: request_id.clone(),
        method: method.to_string(),
        host: host.to_string(),
        path: path.to_string(),
        headers: headers_map,
        body: truncate_body(&body_bytes),
    };

    // Check guardrails before forwarding
    let (blocked, reason) = state.api_client.check_request(check_payload).await;

    if blocked {
        let reason_msg = reason.unwrap_or_else(|| "Request blocked by policy".to_string());
        warn!("[{}] BLOCKED: {}", request_id, reason_msg);

        return Ok(Response::builder()
            .status(403)
            .header("Content-Type", "application/json")
            .header("X-CopilotGuard-Request-Id", &request_id)
            .body(Full::new(Bytes::from(format!(
                r#"{{"error": "blocked", "reason": "{}", "request_id": "{}"}}"#,
                reason_msg, request_id
            ))))
            .unwrap());
    }

    // === FORWARD REQUEST ===
    // Build the forwarding request
    let mut forward_req = state.client.request(method.clone(), &target_url);

    // Copy headers (except Host which reqwest sets automatically)
    for (name, value) in headers.iter() {
        let name_str = name.as_str().to_lowercase();
        // Skip hop-by-hop headers and Host
        if name_str != "host"
            && name_str != "connection"
            && name_str != "keep-alive"
            && name_str != "transfer-encoding"
        {
            if let Ok(v) = value.to_str() {
                forward_req = forward_req.header(name.as_str(), v);
            }
        }
    }

    // Add body if present
    if !body_bytes.is_empty() {
        forward_req = forward_req.body(body_bytes.to_vec());
    }

    // Send the request
    let response = forward_req.send().await?;

    let status = response.status();
    let resp_headers = response.headers().clone();

    // Read response body
    let resp_body = response.bytes().await?;

    // Calculate latency
    let latency_ms = start_time.elapsed().as_millis() as u64;

    // Log response
    info!(
        "[{}] Response: {} ({} bytes, {}ms)",
        request_id,
        status,
        resp_body.len(),
        latency_ms
    );

    // === LOG RESPONSE ASYNC ===
    // Fire-and-forget - doesn't block response delivery
    let log_payload = InterceptResponsePayload {
        request_id: request_id.clone(),
        status_code: status.as_u16(),
        latency_ms,
        body: truncate_body(&resp_body),
    };
    state.api_client.log_response(log_payload);

    // Build response to return to client
    let mut builder = Response::builder().status(status.as_u16());

    // Add our request ID header
    builder = builder.header("X-CopilotGuard-Request-Id", &request_id);

    // Copy response headers
    for (name, value) in resp_headers.iter() {
        let name_str = name.as_str().to_lowercase();
        // Skip hop-by-hop headers
        if name_str != "connection"
            && name_str != "keep-alive"
            && name_str != "transfer-encoding"
        {
            builder = builder.header(name.as_str(), value.as_bytes());
        }
    }

    Ok(builder.body(Full::new(resp_body)).unwrap())
}
