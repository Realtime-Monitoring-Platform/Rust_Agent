use std::env;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use local_ip_address::local_ip;
use mac_address::get_mac_address;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509NameBuilder, X509Req};
use reqwest::Client;
use rumqttc::{
    AsyncClient,
    Event,
    MqttOptions,
    Packet,
    QoS,
    Transport,
};
use serde::{Deserialize, Serialize};
use sysinfo::System;
use tokio::sync::mpsc;
// ============================================================
// CONFIGURATION
// ============================================================
const DEVICE_SERVICE_BASE_URL: &str =
    "http://192.168.1.205:9005/api/v1/devices/provision";
const MQTT_HOST: &str =
    "192.168.1.122";
const MQTT_PORT: u16 =
    8883;
const MQTT_KEEP_ALIVE_SECONDS: u64 =
    30;
const METRICS_INTERVAL_SECONDS: u64 =
    5;
// ------------------------------------------------------------
// COMMAND OUTPUT
// ------------------------------------------------------------
const MAX_OUTPUT_BYTES: usize =
    200_000;
// ------------------------------------------------------------
// LOGGING
// ------------------------------------------------------------
const MAX_LOG_BYTES: usize =
    4_000;
const LOG_BATCH_SIZE: usize =
    100;
const LOG_FLUSH_INTERVAL_SECONDS: u64 =
    1;
const LOG_CHANNEL_SIZE: usize =
    10_000;
// ============================================================
// DEVICE SYSTEM INFO
// ============================================================
#[derive(Debug, Serialize, Clone)]
struct DeviceSystemInfo {
    hostname: String,
    #[serde(rename = "ipAddress")]
    ip_address: String,
    #[serde(rename = "macAddress")]
    mac_address: String,
    #[serde(rename = "osName")]
    os_name: String,
    #[serde(rename = "osVersion")]
    os_version: String,
    #[serde(rename = "kernelVersion")]
    kernel_version: String,
    #[serde(rename = "cpuCount")]
    cpu_count: usize,
    #[serde(rename = "totalMemoryKb")]
    total_memory_kb: u64,
}
// ============================================================
// PROVISIONING REQUEST
// ============================================================
#[derive(Serialize)]
struct ProvisionRequest {
    csr: String,
    #[serde(rename = "deviceInfo")]
    device_info: DeviceSystemInfo,
}
// ============================================================
// PROVISIONING RESPONSE
// ============================================================
#[derive(Deserialize, Debug)]
struct ProvisionResponse {
    #[serde(rename = "caCertificate")]
    ca_certificate: String,
    #[serde(rename = "clientCertificate")]
    client_certificate: String,
    #[serde(rename = "deviceId")]
    device_id: String,
    #[serde(rename = "tenantId")]
    tenant_id: String,
}
// ============================================================
// DEVICE IDENTITY
// ============================================================
#[derive(Serialize, Deserialize, Debug, Clone)]
struct DeviceIdentity {
    device_id: String,
    tenant_id: String,
}
// ============================================================
// MQTT COMMAND
// ============================================================
#[derive(Debug, Deserialize)]
struct DeviceCommandMessage {
    #[serde(rename = "commandId")]
    command_id: String,
    #[serde(rename = "deviceId")]
    device_id: String,
    command: String,
}
// ============================================================
// MQTT COMMAND RESULT
// ============================================================
#[derive(Debug, Serialize)]
struct CommandResultMessage {
    #[serde(rename = "commandId")]
    command_id: String,
    #[serde(rename = "deviceId")]
    device_id: String,
    status: String,
    stdout: String,
    #[serde(rename = "exitCode")]
    exit_code: i32,
}
// ============================================================
// METRICS
// ============================================================
#[derive(Debug, Serialize)]
struct DeviceMetrics {
    device_id: String,
    tenant_id: String,
    cpu: f32,
    ram: f32,
}
// ============================================================
// LOG ENTRY
// ============================================================
#[derive(Debug, Clone, Serialize)]
struct DeviceLogMessage {
    device_id: String,
    tenant_id: String,
    level: String,
    service: String,
    source: String,
    message: String,
    #[serde(rename = "timestamp")]
    timestamp_millis: u128,
}
// ============================================================
// LOG BATCH
// ============================================================
#[derive(Debug, Serialize)]
struct DeviceLogBatch {
    device_id: String,
    tenant_id: String,
    logs: Vec<DeviceLogMessage>,
}
// ============================================================
// JOURNAL JSON ENTRY
// ============================================================
#[derive(Debug, Deserialize)]
struct JournalEntry {
    #[serde(rename = "__REALTIME_TIMESTAMP")]
    realtime_timestamp: Option<String>,
    #[serde(rename = "PRIORITY")]
    priority: Option<String>,
    #[serde(rename = "MESSAGE")]
    message: Option<String>,
    #[serde(rename = "_SYSTEMD_UNIT")]
    systemd_unit: Option<String>,
    #[serde(rename = "_COMM")]
    command: Option<String>,
    #[serde(rename = "_EXE")]
    executable: Option<String>,
}
// ============================================================
// CURRENT TIME
// ============================================================
fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}
// ============================================================
// DEVICE PATHS
// ============================================================
struct AgentPaths {
    agent_directory: PathBuf,
    pki_directory: PathBuf,
    ca_certificate: PathBuf,
    device_certificate: PathBuf,
    device_key: PathBuf,
    device_csr: PathBuf,
    identity: PathBuf,
}
// ============================================================
// BUILD PATHS
// ============================================================
fn build_paths() -> Result<AgentPaths, Box<dyn std::error::Error>> {
    let home = env::var("HOME")
        .map_err(|_| "HOME environment variable is not available")?;
    let agent_directory =
        PathBuf::from(home)
            .join(".monitoring-agent");
    let pki_directory =
        agent_directory.join("pki");
    Ok(AgentPaths {
        ca_certificate:
            pki_directory.join("ca.crt"),
        device_certificate:
            pki_directory.join("device.crt"),
        device_key:
            pki_directory.join("device.key"),
        device_csr:
            pki_directory.join("device.csr"),
        identity:
            agent_directory.join("identity.json"),
        agent_directory,
        pki_directory,
    })
}
// ============================================================
// GET PROVISIONING TOKEN
// ============================================================
fn get_token() -> Result<String, String> {
    let args: Vec<String> =
        env::args().collect();
    if args.len() == 1 {
        return Err(
            format!(
                "Usage: {} --token <provisioning-token>",
                args[0]
            )
        );
    }
    let mut index = 1;
    while index < args.len() {
        if args[index] == "--token" {
            if index + 1 >= args.len() {
                return Err(
                    "Missing value for --token".to_string()
                );
            }
            return Ok(
                args[index + 1].clone()
            );
        }
        index += 1;
    }
    Err(
        "Usage: --token <provisioning-token>".to_string()
    )
}
// ============================================================
// COLLECT DEVICE SYSTEM INFO
// ============================================================
//
// Gathers hostname, primary IP address, MAC address, OS/kernel
// info, CPU count, and total memory. This is sent once, along
// with the CSR, during the first-run provisioning request.
fn collect_device_info() -> DeviceSystemInfo {
    let hostname =
        System::host_name()
            .unwrap_or_else(|| "unknown".to_string());

    let ip_address =
        local_ip()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|_| "unknown".to_string());

    let mac_address =
        get_mac_address()
            .ok()
            .flatten()
            .map(|m| m.to_string())
            .unwrap_or_else(|| "unknown".to_string());

    let os_name =
        System::name()
            .unwrap_or_else(|| "unknown".to_string());
    let os_version =
        System::os_version()
            .unwrap_or_else(|| "unknown".to_string());
    let kernel_version =
        System::kernel_version()
            .unwrap_or_else(|| "unknown".to_string());

    let mut sys =
        System::new_all();
    sys.refresh_all();

    DeviceSystemInfo {
        hostname,
        ip_address,
        mac_address,
        os_name,
        os_version,
        kernel_version,
        cpu_count:
            sys.cpus().len(),
        total_memory_kb:
            sys.total_memory(),
    }
}
// ============================================================
// CREATE DEVICE KEY
// ============================================================
fn generate_private_key()
    -> Result<
        PKey<openssl::pkey::Private>,
        Box<dyn std::error::Error>
    >
{
    let rsa =
        Rsa::generate(2048)?;
    let private_key =
        PKey::from_rsa(rsa)?;
    Ok(private_key)
}
// ============================================================
// CREATE CSR
// ============================================================
fn generate_csr(
    private_key: &PKey<openssl::pkey::Private>,
    device_name: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut name_builder =
        X509NameBuilder::new()?;
    name_builder.append_entry_by_text(
        "CN",
        device_name,
    )?;
    let name =
        name_builder.build();
    let mut request =
        X509Req::builder()?;
    request.set_subject_name(
        &name
    )?;
    request.set_pubkey(
        private_key
    )?;
    request.sign(
        private_key,
        MessageDigest::sha256(),
    )?;
    let csr =
        request.build();
    Ok(
        csr.to_pem()?
    )
}
// ============================================================
// SAVE PRIVATE KEY
// ============================================================
fn save_private_key(
    path: &PathBuf,
    private_key: &PKey<openssl::pkey::Private>,
) -> Result<(), Box<dyn std::error::Error>> {
    let pem =
        private_key.private_key_to_pem_pkcs8()?;
    fs::write(
        path,
        pem,
    )?;
    Ok(())
}
// ============================================================
// SAVE IDENTITY
// ============================================================
fn save_identity(
    path: &PathBuf,
    identity: &DeviceIdentity,
) -> Result<(), Box<dyn std::error::Error>> {
    let json =
        serde_json::to_string_pretty(
            identity
        )?;
    fs::write(
        path,
        json,
    )?;
    Ok(())
}
// ============================================================
// PROVISION DEVICE
// ============================================================
async fn provision_device(
    paths: &AgentPaths,
    token: &str,
) -> Result<DeviceIdentity, Box<dyn std::error::Error>> {
    println!("========================================");
    println!("Starting device provisioning");
    println!("========================================");
    fs::create_dir_all(
        &paths.agent_directory
    )?;
    fs::create_dir_all(
        &paths.pki_directory
    )?;
    println!(
        "Generating device private key..."
    );
    let private_key =
        generate_private_key()?;
    save_private_key(
        &paths.device_key,
        &private_key,
    )?;
    println!(
        "Private key saved to {:?}",
        paths.device_key
    );
    println!(
        "Generating CSR..."
    );
    let csr =
        generate_csr(
            &private_key,
            "monitoring-device",
        )?;
    fs::write(
        &paths.device_csr,
        &csr,
    )?;
    println!(
        "CSR saved to {:?}",
        paths.device_csr
    );
    let csr_string =
        String::from_utf8(csr)?;
    println!(
        "Collecting device system info..."
    );
    let device_info =
        collect_device_info();
    println!(
        "Hostname: {}",
        device_info.hostname
    );
    println!(
        "IP address: {}",
        device_info.ip_address
    );
    println!(
        "MAC address: {}",
        device_info.mac_address
    );
    println!(
        "OS: {} {}",
        device_info.os_name,
        device_info.os_version
    );
    println!(
        "Kernel: {}",
        device_info.kernel_version
    );
    println!(
        "CPU count: {}",
        device_info.cpu_count
    );
    println!(
        "Total memory (KB): {}",
        device_info.total_memory_kb
    );
    let request =
        ProvisionRequest {
            csr: csr_string,
            device_info,
        };
    println!(
        "Sending provisioning request to {}",
        DEVICE_SERVICE_BASE_URL
    );
    let client =
        Client::new();
    let response =
        client
            .post(
                DEVICE_SERVICE_BASE_URL
            )
            .header(
                "Authorization",
                format!("Bearer {}", token),
            )
            .json(&request)
            .send()
            .await?;
    println!(
        "Provisioning HTTP status: {}",
        response.status()
    );
    if !response.status().is_success() {
        let body =
            response.text().await?;
        return Err(
            format!(
                "Provisioning failed: {}",
                body
            ).into()
        );
    }
    let provision_response:
        ProvisionResponse =
            response.json().await?;
    println!(
        "Provisioning successful."
    );
    println!(
        "Device ID: {}",
        provision_response.device_id
    );
    println!(
        "Tenant ID: {}",
        provision_response.tenant_id
    );
    fs::write(
        &paths.ca_certificate,
        provision_response
            .ca_certificate
            .as_bytes(),
    )?;
    fs::write(
        &paths.device_certificate,
        provision_response
            .client_certificate
            .as_bytes(),
    )?;
    let identity =
        DeviceIdentity {
            device_id:
                provision_response.device_id,
            tenant_id:
                provision_response.tenant_id,
        };
    save_identity(
        &paths.identity,
        &identity,
    )?;
    println!(
        "CA certificate saved to {:?}",
        paths.ca_certificate
    );
    println!(
        "Device certificate saved to {:?}",
        paths.device_certificate
    );
    println!(
        "Identity saved to {:?}",
        paths.identity
    );
    Ok(identity)
}
// ============================================================
// LOAD EXISTING IDENTITY
// ============================================================
fn load_identity(
    paths: &AgentPaths,
) -> Result<
    DeviceIdentity,
    Box<dyn std::error::Error>
> {
    let content =
        fs::read_to_string(
            &paths.identity
        )?;
    let identity:
        DeviceIdentity =
            serde_json::from_str(
                &content
            )?;
    Ok(identity)
}
// ============================================================
// CHECK PROVISIONING
// ============================================================
fn device_is_provisioned(
    paths: &AgentPaths,
) -> bool {
    paths.identity.exists()
        && paths.ca_certificate.exists()
        && paths.device_certificate.exists()
        && paths.device_key.exists()
}
// ============================================================
// LOAD CERTIFICATE
// ============================================================
fn load_certificate(
    path: &PathBuf,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let data =
        fs::read(path)?;
    Ok(data)
}
// ============================================================
// CREATE MQTT CLIENT
// ============================================================
fn create_mqtt_client(
    identity: &DeviceIdentity,
    paths: &AgentPaths,
) -> Result<
    (AsyncClient, rumqttc::EventLoop),
    Box<dyn std::error::Error>
> {
    println!("========================================");
    println!("Creating MQTT client...");
    println!("========================================");
    let client_id =
        format!(
            "monitoring-agent-{}",
            identity.device_id
        );
    println!(
        "MQTT Client ID: {}",
        client_id
    );
    println!(
        "Connecting to MQTT broker {}:{}",
        MQTT_HOST,
        MQTT_PORT
    );
    let mut mqtt_options =
        MqttOptions::new(
            client_id,
            MQTT_HOST,
            MQTT_PORT,
        );
    mqtt_options.set_keep_alive(
        Duration::from_secs(
            MQTT_KEEP_ALIVE_SECONDS
        )
    );
    let ca =
        load_certificate(
            &paths.ca_certificate
        )?;
    let client_cert =
        load_certificate(
            &paths.device_certificate
        )?;
    let private_key =
        load_certificate(
            &paths.device_key
        )?;
    let transport =
        Transport::tls(
            ca,
            Some((
                client_cert,
                private_key,
            )),
            None,
        );
    mqtt_options.set_transport(
        transport
    );
    let (client, event_loop) =
        AsyncClient::new(
            mqtt_options,
            100,
        );
    Ok((
        client,
        event_loop,
    ))
}
// ============================================================
// MQTT TOPICS
// ============================================================
fn command_topic(
    identity: &DeviceIdentity,
) -> String {
    format!(
        "tenants/{}/devices/{}/commands",
        identity.tenant_id,
        identity.device_id
    )
}
fn metrics_topic(
    identity: &DeviceIdentity,
) -> String {
    format!(
        "tenants/{}/devices/{}/metrics",
        identity.tenant_id,
        identity.device_id
    )
}
fn command_result_topic(
    identity: &DeviceIdentity,
) -> String {
    format!(
        "tenants/{}/devices/{}/command-results",
        identity.tenant_id,
        identity.device_id
    )
}
fn logs_topic(
    identity: &DeviceIdentity,
) -> String {
    format!(
        "tenants/{}/devices/{}/logs",
        identity.tenant_id,
        identity.device_id
    )
}
// ============================================================
// NORMALIZE LOG LEVEL
// ============================================================
fn normalize_log_level(
    priority: Option<&str>,
) -> String {
    match priority {
        Some("0") => "FATAL".to_string(),
        Some("1") => "FATAL".to_string(),
        Some("2") => "ERROR".to_string(),
        Some("3") => "ERROR".to_string(),
        Some("4") => "WARN".to_string(),
        Some("5") => "NOTICE".to_string(),
        Some("6") => "INFO".to_string(),
        Some("7") => "DEBUG".to_string(),
        _ => "UNKNOWN".to_string(),
    }
}
// ============================================================
// CREATE LOG ENTRY FROM JOURNAL ENTRY
// ============================================================
fn journal_to_device_log(
    entry: JournalEntry,
    identity: &DeviceIdentity,
) -> Option<DeviceLogMessage> {
    let message =
        entry.message?;
    if message.trim().is_empty() {
        return None;
    }
    let mut message =
        message;
    if message.len() > MAX_LOG_BYTES {
        let mut cut =
            MAX_LOG_BYTES;
        while !message.is_char_boundary(cut) {
            cut -= 1;
        }
        message.truncate(cut);
        message.push_str(
            " [truncated]"
        );
    }
    let service =
        entry
            .systemd_unit
            .or(entry.command)
            .or(entry.executable)
            .unwrap_or_else(
                || "unknown".to_string()
            );
    let timestamp =
        entry
            .realtime_timestamp
            .and_then(
                |value| value.parse::<u128>().ok()
            )
            .map(|micros| micros / 1000)
            .unwrap_or_else(now_millis);
    Some(
        DeviceLogMessage {
            device_id:
                identity.device_id.clone(),
            tenant_id:
                identity.tenant_id.clone(),
            level:
                normalize_log_level(
                    entry.priority.as_deref()
                ),
            service,
            source:
                "systemd".to_string(),
            message,
            timestamp_millis:
                timestamp,
        }
    )
}
// ============================================================
// JOURNAL COLLECTOR
// ============================================================
//
// This uses journalctl instead of a journal cursor.
//
// IMPORTANT:
// There is intentionally NO persistent journal.cursor.
//
// After restart, journalctl -f -n 0 starts from new entries.
// Existing historical entries are not replayed.
fn start_journal_collector(
    identity: DeviceIdentity,
    log_sender: mpsc::Sender<DeviceLogMessage>,
) {
    std::thread::spawn(
        move || {
            println!(
                "Starting Linux systemd journal collector..."
            );
            let mut child =
                match Command::new("journalctl")
                    .args([
                        "-f",
                        "-n",
                        "0",
                        "-o",
                        "json",
                    ])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                {
                    Ok(child) => child,
                    Err(error) => {
                        eprintln!(
                            "Failed to start journalctl: {}",
                            error
                        );
                        return;
                    }
                };
            let stdout =
                match child.stdout.take() {
                    Some(stdout) => stdout,
                    None => {
                        eprintln!(
                            "Failed to access journalctl stdout"
                        );
                        return;
                    }
                };
            let reader =
                BufReader::new(stdout);
            for line_result in reader.lines() {
                let line =
                    match line_result {
                        Ok(line) => line,
                        Err(error) => {
                            eprintln!(
                                "Failed to read journal entry: {}",
                                error
                            );
                            continue;
                        }
                    };
                if line.trim().is_empty() {
                    continue;
                }
                let journal_entry:
                    JournalEntry =
                    match serde_json::from_str(
                        &line
                    ) {
                        Ok(entry) => entry,
                        Err(error) => {
                            eprintln!(
                                "Failed to parse journal JSON: {}",
                                error
                            );
                            continue;
                        }
                    };
                let log =
                    match journal_to_device_log(
                        journal_entry,
                        &identity,
                    ) {
                        Some(log) => log,
                        None => continue,
                    };
                match log_sender.try_send(log) {
                    Ok(_) => {}
                    Err(
                        mpsc::error::TrySendError::Full(_)
                    ) => {
                        eprintln!(
                            "WARNING: log channel is full; dropping log"
                        );
                    }
                    Err(
                        mpsc::error::TrySendError::Closed(_)
                    ) => {
                        eprintln!(
                            "Log channel closed; stopping journal collector"
                        );
                        break;
                    }
                }
            }
            let _ =
                child.kill();
            println!(
                "Systemd journal collector stopped."
            );
        }
    );
}
// ============================================================
// LOG BATCHER
// ============================================================
async fn run_log_batcher(
    mqtt_client: AsyncClient,
    identity: DeviceIdentity,
    mut log_receiver: mpsc::Receiver<DeviceLogMessage>,
) {
    println!(
        "Log batcher started."
    );
    let mut buffer:
        Vec<DeviceLogMessage> =
        Vec::with_capacity(
            LOG_BATCH_SIZE
        );
    let mut flush_interval =
        tokio::time::interval(
            Duration::from_secs(
                LOG_FLUSH_INTERVAL_SECONDS
            )
        );
    loop {
        tokio::select! {
            // ------------------------------------------------
            // RECEIVE LOG
            // ------------------------------------------------
            log =
                log_receiver.recv() => {
                match log {
                    Some(log) => {
                        buffer.push(log);
                        if buffer.len()
                            >= LOG_BATCH_SIZE
                        {
                            publish_log_batch(
                                &mqtt_client,
                                &identity,
                                &mut buffer,
                            )
                            .await;
                        }
                    }
                    None => {
                        println!(
                            "Log channel closed."
                        );
                        if !buffer.is_empty() {
                            publish_log_batch(
                                &mqtt_client,
                                &identity,
                                &mut buffer,
                            )
                            .await;
                        }
                        break;
                    }
                }
            }
            // ------------------------------------------------
            // FLUSH EVERY SECOND
            // ------------------------------------------------
            _ =
                flush_interval.tick() => {
                if !buffer.is_empty() {
                    publish_log_batch(
                        &mqtt_client,
                        &identity,
                        &mut buffer,
                    )
                    .await;
                }
            }
        }
    }
}
// ============================================================
// PUBLISH LOG BATCH
// ============================================================
async fn publish_log_batch(
    mqtt_client: &AsyncClient,
    identity: &DeviceIdentity,
    buffer: &mut Vec<DeviceLogMessage>,
) {
    if buffer.is_empty() {
        return;
    }
    let logs =
        std::mem::take(buffer);
    let batch =
        DeviceLogBatch {
            device_id:
                identity.device_id.clone(),
            tenant_id:
                identity.tenant_id.clone(),
            logs,
        };
    let json =
        match serde_json::to_string(
            &batch
        ) {
            Ok(json) => json,
            Err(error) => {
                eprintln!(
                    "Failed to serialize log batch: {}",
                    error
                );
                return;
            }
        };
    let topic =
        logs_topic(identity);
    println!(
        "Publishing {} logs to {}",
        batch.logs.len(),
        topic
    );
    if let Err(error) =
        mqtt_client
            .publish(
                topic,
                QoS::AtLeastOnce,
                false,
                json.as_bytes(),
            )
            .await
    {
        eprintln!(
            "Failed to publish log batch: {}",
            error
        );
    }
}
// ============================================================
// AGENT INTERNAL LOG
// ============================================================
async fn publish_log(
    mqtt_client: &AsyncClient,
    identity: &DeviceIdentity,
    level: &str,
    message: impl Into<String>,
) {
    let mut message =
        message.into();
    if message.len() > MAX_LOG_BYTES {
        let mut cut =
            MAX_LOG_BYTES;
        while !message.is_char_boundary(cut) {
            cut -= 1;
        }
        message.truncate(cut);
        message.push_str(
            " [truncated]"
        );
    }
    println!(
        "[{}] {} | device={} | {}",
        level,
        now_millis(),
        identity.device_id,
        message
    );
    let log =
        DeviceLogMessage {
            device_id:
                identity.device_id.clone(),
            tenant_id:
                identity.tenant_id.clone(),
            level:
                level.to_string(),
            service:
                "monitoring-agent".to_string(),
            source:
                "agent".to_string(),
            message,
            timestamp_millis:
                now_millis(),
        };
    let topic =
        logs_topic(identity);
    let json =
        match serde_json::to_string(&log) {
            Ok(json) => json,
            Err(error) => {
                eprintln!(
                    "Failed to serialize agent log: {}",
                    error
                );
                return;
            }
        };
    if let Err(error) =
        mqtt_client
            .publish(
                topic,
                QoS::AtLeastOnce,
                false,
                json.as_bytes(),
            )
            .await
    {
        eprintln!(
            "Failed to publish agent log: {}",
            error
        );
    }
}
// ============================================================
// TRUNCATE OUTPUT
// ============================================================
fn truncate_output(
    output: String,
) -> String {
    if output.len()
        <= MAX_OUTPUT_BYTES
    {
        return output;
    }
    let mut cut =
        MAX_OUTPUT_BYTES;
    while !output.is_char_boundary(cut) {
        cut -= 1;
    }
    format!(
        "{}\n\n[... output truncated: {} of {} bytes shown ...]",
        &output[..cut],
        cut,
        output.len()
    )
}
// ============================================================
// EXECUTE COMMAND
// ============================================================
fn execute_command(
    command: &str,
    current_dir: &mut PathBuf,
) -> (String, i32) {
    println!("========================================");
    println!("EXECUTING COMMAND");
    println!("Command: {}", command);
    println!("Current dir: {:?}", current_dir);
    println!("========================================");
    let trimmed =
        command.trim();
    if trimmed == "cd"
        || trimmed.starts_with("cd ")
    {
        let target =
            if trimmed == "cd" {
                match env::var("HOME") {
                    Ok(home) =>
                        PathBuf::from(home),
                    Err(_) => {
                        return (
                            "cd: HOME not set"
                                .to_string(),
                            1,
                        );
                    }
                }
            } else {
                let path_str =
                    trimmed[3..].trim();
                let candidate =
                    if path_str.starts_with('/') {
                        PathBuf::from(
                            path_str
                        )
                    } else {
                        current_dir.join(
                            path_str
                        )
                    };
                match candidate.canonicalize() {
                    Ok(p) => p,
                    Err(e) => {
                        return (
                            format!(
                                "cd: {}: {}",
                                path_str,
                                e
                            ),
                            1,
                        );
                    }
                }
            };
        if !target.is_dir() {
            return (
                format!(
                    "cd: {}: Not a directory",
                    target.display()
                ),
                1,
            );
        }
        *current_dir =
            target;
        println!(
            "Changed directory to {:?}",
            current_dir
        );
        return (
            String::new(),
            0,
        );
    }
    match Command::new("sh")
        .arg("-c")
        .arg(command)
        .current_dir(&*current_dir)
        .output()
    {
        Ok(output) => {
            let stdout =
                String::from_utf8_lossy(
                    &output.stdout
                )
                .to_string();
            let stderr =
                String::from_utf8_lossy(
                    &output.stderr
                )
                .to_string();
            let exit_code =
                output
                    .status
                    .code()
                    .unwrap_or(-1);
            let result =
                if !stdout.is_empty() {
                    stdout
                } else {
                    stderr
                };
            println!(
                "Exit code: {}",
                exit_code
            );
            println!(
                "Command output: {}",
                result
            );
            (
                truncate_output(result),
                exit_code,
            )
        }
        Err(error) => {
            println!(
                "Failed to execute command: {}",
                error
            );
            (
                error.to_string(),
                -1,
            )
        }
    }
}
// ============================================================
// PROCESS MQTT COMMAND
// ============================================================
async fn process_command(
    mqtt_client: &AsyncClient,
    identity: &DeviceIdentity,
    payload: &[u8],
    current_dir: &mut PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("========================================");
    println!("MQTT COMMAND RECEIVED");
    println!("========================================");
    let payload_string =
        String::from_utf8_lossy(
            payload
        );
    println!(
        "Payload: {}",
        payload_string
    );
    let command:
        DeviceCommandMessage =
        serde_json::from_slice(
            payload
        )?;
    println!(
        "Command ID: {}",
        command.command_id
    );
    println!(
        "Device ID: {}",
        command.device_id
    );
    println!(
        "Command: {}",
        command.command
    );
    publish_log(
        mqtt_client,
        identity,
        "INFO",
        format!(
            "Received command '{}' (commandId={})",
            command.command,
            command.command_id
        ),
    )
    .await;
    if command.device_id
        != identity.device_id
    {
        println!(
            "WARNING: Command device ID does not match this device."
        );
        publish_log(
            mqtt_client,
            identity,
            "WARN",
            format!(
                "Rejected command {}: deviceId mismatch",
                command.command_id
            ),
        )
        .await;
        return Ok(());
    }
    let (
        output,
        exit_code,
    ) =
        execute_command(
            &command.command,
            current_dir,
        );
    let status =
        if exit_code == 0 {
            "SUCCESS"
        } else {
            "FAILED"
        };
    publish_log(
        mqtt_client,
        identity,
        if exit_code == 0 {
            "INFO"
        } else {
            "ERROR"
        },
        format!(
            "Command '{}' (commandId={}) finished with exit code {}",
            command.command,
            command.command_id,
            exit_code
        ),
    )
    .await;
    let result =
        CommandResultMessage {
            command_id:
                command.command_id,
            device_id:
                command.device_id,
            status:
                status.to_string(),
            stdout:
                output,
            exit_code,
        };
    let result_json =
        serde_json::to_string(
            &result
        )?;
    let topic =
        command_result_topic(
            identity
        );
    println!(
        "Publishing command result..."
    );
    println!(
        "Result topic: {}",
        topic
    );
    mqtt_client
        .publish(
            topic,
            QoS::AtLeastOnce,
            false,
            result_json.as_bytes(),
        )
        .await?;
    println!(
        "Command result published successfully."
    );
    Ok(())
}
// ============================================================
// COLLECT METRICS
// ============================================================
fn collect_metrics(
    system: &mut System,
    identity: &DeviceIdentity,
) -> DeviceMetrics {
    system.refresh_cpu_usage();
    system.refresh_memory();
    let cpu =
        system.global_cpu_usage();
    let total_memory =
        system.total_memory();
    let used_memory =
        system.used_memory();
    let ram =
        if total_memory > 0 {
            (
                used_memory as f32
                /
                total_memory as f32
            )
            * 100.0
        } else {
            0.0
        };
    DeviceMetrics {
        device_id:
            identity.device_id.clone(),
        tenant_id:
            identity.tenant_id.clone(),
        cpu,
        ram,
    }
}
// ============================================================
// PUBLISH METRICS
// ============================================================
async fn publish_metrics(
    mqtt_client: &AsyncClient,
    identity: &DeviceIdentity,
    system: &mut System,
) -> Result<(), Box<dyn std::error::Error>> {
    let metrics =
        collect_metrics(
            system,
            identity,
        );
    let json =
        serde_json::to_string(
            &metrics
        )?;
    let topic =
        metrics_topic(
            identity
        );
    println!(
        "Sending metrics: {}",
        json
    );
    mqtt_client
        .publish(
            topic,
            QoS::AtLeastOnce,
            false,
            json.as_bytes(),
        )
        .await?;
    println!(
        "Metrics published successfully."
    );
    Ok(())
}
// ============================================================
// MAIN
// ============================================================
#[tokio::main]
async fn main()
    -> Result<(), Box<dyn std::error::Error>>
{
    // --------------------------------------------------------
    // RUSTLS CRYPTO PROVIDER
    // --------------------------------------------------------
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect(
            "Failed to install Rustls crypto provider"
        );
    // --------------------------------------------------------
    // START
    // --------------------------------------------------------
    println!(
        "========================================"
    );
    println!(
        "Monitoring Agent Starting"
    );
    println!(
        "========================================"
    );
    // --------------------------------------------------------
    // BUILD PATHS
    // --------------------------------------------------------
    let paths =
        build_paths()?;
    // --------------------------------------------------------
    // TOKEN
    // --------------------------------------------------------
    let token =
        match get_token() {
            Ok(token) =>
                token,
            Err(error) => {
                eprintln!(
                    "{}",
                    error
                );
                return Ok(());
            }
        };
    // --------------------------------------------------------
    // PROVISION OR LOAD IDENTITY
    // --------------------------------------------------------
    let identity;
    if device_is_provisioned(
        &paths
    ) {
        println!(
            "Existing device identity found."
        );
        identity =
            load_identity(
                &paths
            )?;
    } else {
        println!(
            "No device identity found."
        );
        identity =
            provision_device(
                &paths,
                &token,
            )
            .await?;
    }
    // --------------------------------------------------------
    // PRINT IDENTITY
    // --------------------------------------------------------
    println!(
        "========================================"
    );
    println!(
        "DEVICE ID: {}",
        identity.device_id
    );
    println!(
        "TENANT ID: {}",
        identity.tenant_id
    );
    println!(
        "========================================"
    );
    // --------------------------------------------------------
    // CREATE MQTT CLIENT
    // --------------------------------------------------------
    let (
        mqtt_client,
        mut event_loop,
    ) =
        create_mqtt_client(
            &identity,
            &paths,
        )?;
    // --------------------------------------------------------
    // COMMAND TOPIC
    // --------------------------------------------------------
    let command_topic =
        command_topic(
            &identity
        );
    println!(
        "Subscribing to command topic:"
    );
    println!(
        "{}",
        command_topic
    );
    mqtt_client
        .subscribe(
            command_topic.clone(),
            QoS::AtLeastOnce,
        )
        .await?;
    println!(
        "Subscribe request sent."
    );
    // --------------------------------------------------------
    // LOG CHANNEL
    // --------------------------------------------------------
    let (
        log_sender,
        log_receiver
    ) =
        mpsc::channel::<DeviceLogMessage>(
            LOG_CHANNEL_SIZE
        );
    // --------------------------------------------------------
    // START JOURNAL COLLECTOR
    // --------------------------------------------------------
    start_journal_collector(
        identity.clone(),
        log_sender,
    );
    // --------------------------------------------------------
    // START LOG BATCHER
    // --------------------------------------------------------
    tokio::spawn(
        run_log_batcher(
            mqtt_client.clone(),
            identity.clone(),
            log_receiver,
        )
    );
    // --------------------------------------------------------
    // AGENT START LOG
    // --------------------------------------------------------
    publish_log(
        &mqtt_client,
        &identity,
        "INFO",
        "Monitoring agent started and log collector initialized",
    )
    .await;
    // --------------------------------------------------------
    // PERSISTENT WORKING DIRECTORY
    // --------------------------------------------------------
    let mut current_dir =
        env::current_dir()
            .unwrap_or_else(
                |_| PathBuf::from("/")
            );
    println!(
        "Initial working directory: {:?}",
        current_dir
    );
    // --------------------------------------------------------
    // SYSTEM METRICS
    // --------------------------------------------------------
    let mut system =
        System::new_all();
    system.refresh_all();
    // --------------------------------------------------------
    // METRICS TIMER
    // --------------------------------------------------------
    let mut metrics_interval =
        tokio::time::interval(
            Duration::from_secs(
                METRICS_INTERVAL_SECONDS
            )
        );
    // --------------------------------------------------------
    // MQTT EVENT LOOP
    // --------------------------------------------------------
    loop {
        tokio::select! {
            // =================================================
            // MQTT
            // =================================================
            event =
                event_loop.poll() => {
                match event {
                    Ok(
                        Event::Incoming(
                            Packet::Publish(publish)
                        )
                    ) => {
                        println!(
                            "MQTT incoming publish received."
                        );
                        println!(
                            "Topic: {}",
                            publish.topic
                        );
                        if publish.topic
                            == command_topic
                        {
                            if let Err(error) =
                                process_command(
                                    &mqtt_client,
                                    &identity,
                                    &publish.payload,
                                    &mut current_dir,
                                )
                                .await
                            {
                                eprintln!(
                                    "Failed to process command: {}",
                                    error
                                );
                                publish_log(
                                    &mqtt_client,
                                    &identity,
                                    "ERROR",
                                    format!(
                                        "Failed to process command: {}",
                                        error
                                    ),
                                )
                                .await;
                            }
                        }
                    }
                    // =================================================
                    // MQTT CONNECT / RECONNECT
                    // =================================================
                    Ok(
                        Event::Incoming(
                            Packet::ConnAck(connack)
                        )
                    ) => {
                        println!(
                            "MQTT event: Incoming(ConnAck({:?}))",
                            connack
                        );
                        println!(
                            "Re-subscribing to command topic after (re)connect..."
                        );
                        if let Err(error) =
                            mqtt_client
                                .subscribe(
                                    command_topic.clone(),
                                    QoS::AtLeastOnce,
                                )
                                .await
                        {
                            eprintln!(
                                "Failed to re-subscribe after reconnect: {}",
                                error
                            );
                        } else {
                            publish_log(
                                &mqtt_client,
                                &identity,
                                "INFO",
                                "Reconnected to broker and re-subscribed to command topic",
                            )
                            .await;
                        }
                    }
                    Ok(
                        Event::Incoming(packet)
                    ) => {
                        println!(
                            "MQTT event: Incoming({:?})",
                            packet
                        );
                    }
                    Ok(
                        Event::Outgoing(packet)
                    ) => {
                        println!(
                            "MQTT event: Outgoing({:?})",
                            packet
                        );
                    }
                    Err(error) => {
                        eprintln!(
                            "MQTT event loop error: {}",
                            error
                        );
                        tokio::time::sleep(
                            Duration::from_secs(5)
                        )
                        .await;
                    }
                }
            }
            // =================================================
            // METRICS
            // =================================================
            _ =
                metrics_interval.tick() => {
                if let Err(error) =
                    publish_metrics(
                        &mqtt_client,
                        &identity,
                        &mut system,
                    )
                    .await
                {
                    eprintln!(
                        "Failed to publish metrics: {}",
                        error
                    );
                    publish_log(
                        &mqtt_client,
                        &identity,
                        "ERROR",
                        format!(
                            "Failed to publish metrics: {}",
                            error
                        ),
                    )
                    .await;
                }
            }
        }
    }
}
