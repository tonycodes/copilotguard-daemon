use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose,
};
use std::fs;
use std::path::PathBuf;
use tracing::info;

use crate::config::config_dir;

const CA_CERT_FILENAME: &str = "ca.crt";
const CA_KEY_FILENAME: &str = "ca.key";

/// Get the CA certificate path
pub fn ca_cert_path() -> Result<PathBuf> {
    Ok(config_dir()?.join(CA_CERT_FILENAME))
}

/// Get the CA private key path
pub fn ca_key_path() -> Result<PathBuf> {
    Ok(config_dir()?.join(CA_KEY_FILENAME))
}

/// Check if CA certificate exists
pub fn ca_exists() -> Result<bool> {
    let cert_path = ca_cert_path()?;
    let key_path = ca_key_path()?;
    Ok(cert_path.exists() && key_path.exists())
}

/// Ensure CA certificate exists, generate if not
pub fn ensure_ca_exists() -> Result<()> {
    if !ca_exists()? {
        info!("CA certificate not found, generating...");
        generate_ca()?;
    } else {
        info!("CA certificate already exists");
    }
    Ok(())
}

/// Generate a new CA certificate
pub fn generate_ca() -> Result<()> {
    info!("Generating new CA certificate...");

    // Generate key pair
    let key_pair = KeyPair::generate()?;

    // Set up certificate parameters
    let mut params = CertificateParams::default();

    // Distinguished name
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "CopilotGuard Local CA");
    dn.push(DnType::OrganizationName, "CopilotGuard");
    dn.push(DnType::CountryName, "GB");
    params.distinguished_name = dn;

    // CA settings
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    // Valid for 10 years
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = params.not_before + time::Duration::days(3650);

    // Generate certificate
    let cert = params.self_signed(&key_pair)?;

    // Save certificate
    let cert_path = ca_cert_path()?;
    let cert_pem = cert.pem();
    fs::write(&cert_path, &cert_pem).context("Failed to write CA certificate")?;
    info!("CA certificate saved to: {}", cert_path.display());

    // Save private key with restricted permissions
    let key_path = ca_key_path()?;
    let key_pem = key_pair.serialize_pem();

    // Set restrictive permissions before writing (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);
        let mut file = options.open(&key_path)?;
        use std::io::Write;
        file.write_all(key_pem.as_bytes())?;
    }

    #[cfg(not(unix))]
    {
        fs::write(&key_path, &key_pem)?;
    }

    info!("CA private key saved to: {}", key_path.display());

    Ok(())
}

/// Trust the CA certificate in the system keychain
pub fn trust_ca() -> Result<()> {
    let cert_path = ca_cert_path()?;

    if !cert_path.exists() {
        anyhow::bail!("CA certificate not found. Run 'copilotguard generate-ca' first.");
    }

    #[cfg(target_os = "macos")]
    {
        trust_ca_macos(&cert_path)?;
    }

    #[cfg(target_os = "linux")]
    {
        trust_ca_linux(&cert_path)?;
    }

    #[cfg(target_os = "windows")]
    {
        trust_ca_windows(&cert_path)?;
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn trust_ca_macos(cert_path: &PathBuf) -> Result<()> {
    use std::process::Command;

    info!("Adding CA to macOS System Keychain...");

    // Add to system keychain with trust settings
    let output = Command::new("sudo")
        .args([
            "security",
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
            "/Library/Keychains/System.keychain",
            cert_path.to_str().unwrap(),
        ])
        .output()
        .context("Failed to run security command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to trust CA certificate: {}", stderr);
    }

    info!("CA certificate trusted in macOS System Keychain");
    Ok(())
}

#[cfg(target_os = "linux")]
fn trust_ca_linux(cert_path: &PathBuf) -> Result<()> {
    use std::process::Command;

    info!("Adding CA to Linux trust store...");

    // Copy to system CA directory
    let dest = PathBuf::from("/usr/local/share/ca-certificates/copilotguard.crt");

    let output = Command::new("sudo")
        .args(["cp", cert_path.to_str().unwrap(), dest.to_str().unwrap()])
        .output()
        .context("Failed to copy CA certificate")?;

    if !output.status.success() {
        anyhow::bail!("Failed to copy CA certificate");
    }

    // Update CA certificates
    let output = Command::new("sudo")
        .args(["update-ca-certificates"])
        .output()
        .context("Failed to run update-ca-certificates")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to update CA certificates: {}", stderr);
    }

    info!("CA certificate trusted in Linux trust store");
    Ok(())
}

#[cfg(target_os = "windows")]
fn trust_ca_windows(cert_path: &PathBuf) -> Result<()> {
    use std::process::Command;

    info!("Adding CA to Windows certificate store...");

    let output = Command::new("certutil")
        .args(["-addstore", "-user", "Root", cert_path.to_str().unwrap()])
        .output()
        .context("Failed to run certutil")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to trust CA certificate: {}", stderr);
    }

    info!("CA certificate trusted in Windows certificate store");
    Ok(())
}

/// Generate a certificate for a specific domain, signed by the CA
/// Returns (cert_chain_pem, key_pem) where cert_chain includes both domain cert and CA cert
pub fn generate_domain_cert(domain: &str) -> Result<(String, String)> {
    // Load CA certificate and key
    let ca_cert_pem = fs::read_to_string(ca_cert_path()?)?;
    let ca_key_pem = fs::read_to_string(ca_key_path()?)?;
    let ca_key_pair = KeyPair::from_pem(&ca_key_pem)?;

    // Re-create CA params to get a signable CA cert
    let mut ca_params = CertificateParams::default();
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "CopilotGuard Local CA");
    ca_dn.push(DnType::OrganizationName, "CopilotGuard");
    ca_dn.push(DnType::CountryName, "GB");
    ca_params.distinguished_name = ca_dn;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    // Note: We need to use the same validity as the original CA
    ca_params.not_before = time::OffsetDateTime::now_utc();
    ca_params.not_after = ca_params.not_before + time::Duration::days(3650);

    let ca_cert = ca_params.self_signed(&ca_key_pair)?;

    // Generate domain certificate
    let domain_key_pair = KeyPair::generate()?;

    let mut params = CertificateParams::new(vec![domain.to_string()])?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, domain);
    params.distinguished_name = dn;

    // Valid for 1 year
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = params.not_before + time::Duration::days(365);

    let domain_cert = params.signed_by(&domain_key_pair, &ca_cert, &ca_key_pair)?;

    // Return full certificate chain: domain cert + CA cert
    let cert_chain = format!("{}{}", domain_cert.pem(), ca_cert_pem);

    Ok((cert_chain, domain_key_pair.serialize_pem()))
}
