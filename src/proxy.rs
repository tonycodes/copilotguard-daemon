use anyhow::Result;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

use crate::ca;
use crate::config;

/// Run the proxy server
pub async fn run() -> Result<()> {
    let config = config::load()?;
    let addr = SocketAddr::from(([127, 0, 0, 1], config.proxy_port));

    info!("Starting CopilotGuard proxy on {}", addr);

    // Load TLS config
    let tls_config = create_tls_config()?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = TcpListener::bind(addr).await?;
    info!("Proxy listening on https://{}", addr);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let io = TokioIo::new(tls_stream);

                    if let Err(err) = http1::Builder::new()
                        .serve_connection(io, service_fn(move |req| handle_request(req, peer_addr)))
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

/// Create TLS configuration for the proxy
fn create_tls_config() -> Result<rustls::ServerConfig> {
    // For now, generate a certificate for the first domain
    // TODO: Implement SNI-based certificate selection
    let (cert_pem, key_pem) = ca::generate_domain_cert("copilot-proxy.githubusercontent.com")?;

    // Parse certificate
    let cert = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()?;

    // Parse private key
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())?
        .ok_or_else(|| anyhow::anyhow!("No private key found"))?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert, key)?;

    Ok(config)
}

/// Handle an incoming HTTP request
async fn handle_request(
    req: Request<hyper::body::Incoming>,
    peer_addr: SocketAddr,
) -> Result<Response<http_body_util::Full<hyper::body::Bytes>>, Infallible> {
    use http_body_util::Full;
    use hyper::body::Bytes;

    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    info!(
        "[{}] {} {} {:?}",
        peer_addr,
        method,
        uri,
        headers.get("host")
    );

    // TODO: Implement actual proxying
    // 1. Analyze request for policy violations
    // 2. Forward to real destination
    // 3. Analyze response
    // 4. Return response to client

    // For now, return a placeholder response
    let response = Response::builder()
        .status(502)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(
            r#"{"error": "CopilotGuard proxy not fully implemented yet"}"#,
        )))
        .unwrap();

    Ok(response)
}
