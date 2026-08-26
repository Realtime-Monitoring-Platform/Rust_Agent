use std::env;
use std::fs;
use std::path::PathBuf;

use local_ip_address::local_ip;
use mac_address::get_mac_address;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509NameBuilder, X509Req};
use reqwest::Client;
use sysinfo::System;

use crate::config::DEVICE_SERVICE_BASE_URL;
use crate::models::{DeviceIdentity, DeviceSystemInfo, ProvisionRequest, ProvisionResponse};
use crate::paths::AgentPaths;

// ============================================================
// GET PROVISIONING TOKEN
// ============================================================
pub fn get_token() -> Result<String, String> {
    let args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        return Err(format!("Usage: {} --token <provisioning-token>", args[0]));
    }
    let mut index = 1;
    while index < args.len() {
        if args[index] == "--token" {
            if index + 1 >= args.len() {
                return Err("Missing value for --token".to_string());
            }
            return Ok(args[index + 1].clone());
        }
        index += 1;
    }
    Err("Usage: --token <provisioning-token>".to_string())
}

// ============================================================
// COLLECT DEVICE SYSTEM INFO
// ============================================================
//
// Gathers hostname, primary IP address, MAC address, OS/kernel
// info, CPU count, and total memory. This is sent once, along
// with the CSR, during the first-run provisioning request.
pub fn collect_device_info() -> DeviceSystemInfo {
    let hostname = System::host_name().unwrap_or_else(|| "unknown".to_string());
    let ip_address = local_ip()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let mac_address = get_mac_address()
        .ok()
        .flatten()
        .map(|m| m.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let os_name = System::name().unwrap_or_else(|| "unknown".to_string());
    let os_version = System::os_version().unwrap_or_else(|| "unknown".to_string());
    let kernel_version = System::kernel_version().unwrap_or_else(|| "unknown".to_string());
    let mut sys = System::new_all();
    sys.refresh_all();
    DeviceSystemInfo {
        hostname,
        ip_address,
        mac_address,
        os_name,
        os_version,
        kernel_version,
        cpu_count: sys.cpus().len(),
        total_memory_kb: sys.total_memory(),
    }
}

// ============================================================
// CREATE DEVICE KEY
// ============================================================
pub fn generate_private_key() -> Result<PKey<openssl::pkey::Private>, Box<dyn std::error::Error>> {
    let rsa = Rsa::generate(2048)?;
    let private_key = PKey::from_rsa(rsa)?;
    Ok(private_key)
}

// ============================================================
// CREATE CSR
// ============================================================
pub fn generate_csr(
    private_key: &PKey<openssl::pkey::Private>,
    device_name: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("CN", device_name)?;
    let name = name_builder.build();
    let mut request = X509Req::builder()?;
    request.set_subject_name(&name)?;
    request.set_pubkey(private_key)?;
    request.sign(private_key, MessageDigest::sha256())?;
    let csr = request.build();
    Ok(csr.to_pem()?)
}

// ============================================================
// SAVE PRIVATE KEY
// ============================================================
pub fn save_private_key(
    path: &PathBuf,
    private_key: &PKey<openssl::pkey::Private>,
) -> Result<(), Box<dyn std::error::Error>> {
    let pem = private_key.private_key_to_pem_pkcs8()?;
    fs::write(path, pem)?;
    Ok(())
}

// ============================================================
// SAVE IDENTITY
// ============================================================
pub fn save_identity(
    path: &PathBuf,
    identity: &DeviceIdentity,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(identity)?;
    fs::write(path, json)?;
    Ok(())
}

// ============================================================
// PROVISION DEVICE
// ============================================================
pub async fn provision_device(
    paths: &AgentPaths,
    token: &str,
) -> Result<DeviceIdentity, Box<dyn std::error::Error>> {
    println!("========================================");
    println!("Starting device provisioning");
    println!("========================================");
    fs::create_dir_all(&paths.agent_directory)?;
    fs::create_dir_all(&paths.pki_directory)?;

    println!("Generating device private key...");
    let private_key = generate_private_key()?;
    save_private_key(&paths.device_key, &private_key)?;
    println!("Private key saved to {:?}", paths.device_key);

    println!("Generating CSR...");
    let csr = generate_csr(&private_key, "monitoring-device")?;
    fs::write(&paths.device_csr, &csr)?;
    println!("CSR saved to {:?}", paths.device_csr);

    let csr_string = String::from_utf8(csr)?;

    println!("Collecting device system info...");
    let device_info = collect_device_info();
    println!("Hostname: {}", device_info.hostname);
    println!("IP address: {}", device_info.ip_address);
    println!("MAC address: {}", device_info.mac_address);
    println!("OS: {} {}", device_info.os_name, device_info.os_version);
    println!("Kernel: {}", device_info.kernel_version);
    println!("CPU count: {}", device_info.cpu_count);
    println!("Total memory (KB): {}", device_info.total_memory_kb);

    let request = ProvisionRequest {
        csr: csr_string,
        device_info,
    };

    println!(
        "Sending provisioning request to {}",
        DEVICE_SERVICE_BASE_URL
    );
    let client = Client::new();
    let response = client
        .post(DEVICE_SERVICE_BASE_URL)
        .header("Authorization", format!("Bearer {}", token))
        .json(&request)
        .send()
        .await?;
    println!("Provisioning HTTP status: {}", response.status());

    if !response.status().is_success() {
        let body = response.text().await?;
        return Err(format!("Provisioning failed: {}", body).into());
    }

    let provision_response: ProvisionResponse = response.json().await?;
    println!("Provisioning successful.");
    println!("Device ID: {}", provision_response.device_id);
    println!("Tenant ID: {}", provision_response.tenant_id);

    fs::write(
        &paths.ca_certificate,
        provision_response.ca_certificate.as_bytes(),
    )?;
    fs::write(
        &paths.device_certificate,
        provision_response.client_certificate.as_bytes(),
    )?;

    let identity = DeviceIdentity {
        device_id: provision_response.device_id,
        tenant_id: provision_response.tenant_id,
    };
    save_identity(&paths.identity, &identity)?;

    println!("CA certificate saved to {:?}", paths.ca_certificate);
    println!(
        "Device certificate saved to {:?}",
        paths.device_certificate
    );
    println!("Identity saved to {:?}", paths.identity);

    Ok(identity)
}

// ============================================================
// LOAD EXISTING IDENTITY
// ============================================================
pub fn load_identity(paths: &AgentPaths) -> Result<DeviceIdentity, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(&paths.identity)?;
    let identity: DeviceIdentity = serde_json::from_str(&content)?;
    Ok(identity)
}

// ============================================================
// CHECK PROVISIONING
// ============================================================
pub fn device_is_provisioned(paths: &AgentPaths) -> bool {
    paths.identity.exists()
        && paths.ca_certificate.exists()
        && paths.device_certificate.exists()
        && paths.device_key.exists()
}

// ============================================================
// LOAD CERTIFICATE
// ============================================================
pub fn load_certificate(path: &PathBuf) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let data = fs::read(path)?;
    Ok(data)
}
