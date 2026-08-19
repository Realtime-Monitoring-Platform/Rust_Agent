
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509NameBuilder, X509Req};

use reqwest::Client;

use rumqttc::{
    Client as MqttClient,
    MqttOptions,
    QoS,
    Transport,
};

use serde::{Deserialize, Serialize};

use sysinfo::System;


// ============================================================
// APPLICATION CONFIGURATION
// ============================================================
//
// These values are the same for every device.
// The customer does NOT need to create a config file.
//
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


// ============================================================
// PROVISIONING REQUEST
// ============================================================

#[derive(Serialize)]
struct ProvisionRequest {
    csr: String,
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
//
// This file is automatically created by the agent.
//
// The customer does NOT manually create it.
//
// ============================================================

#[derive(Serialize, Deserialize, Debug)]
struct DeviceIdentity {

    device_id: String,

    tenant_id: String,
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

fn build_paths()
    -> Result<AgentPaths, Box<dyn std::error::Error>>
{
    let home = env::var("HOME")
        .map_err(|_| {
            "HOME environment variable is not available"
        })?;

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

fn get_token()
    -> Result<String, String>
{
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

    let mut token: Option<String> = None;

    let mut index = 1;

    while index < args.len() {

        match args[index].as_str() {

            "--token" => {

                if index + 1 >= args.len() {

                    return Err(
                        "Missing value for --token"
                            .to_string()
                    );
                }

                if token.is_some() {

                    return Err(
                        "The --token argument was provided more than once"
                            .to_string()
                    );
                }

                let value =
                    args[index + 1]
                        .trim()
                        .to_string();

                if value.is_empty() {

                    return Err(
                        "Token cannot be empty"
                            .to_string()
                    );
                }

                token = Some(value);

                index += 2;
            }

            "--help" | "-h" => {

                return Err(
                    format!(
                        "Usage: {} --token <provisioning-token>",
                        args[0]
                    )
                );
            }

            unknown => {

                return Err(
                    format!(
                        "Unknown argument: {}",
                        unknown
                    )
                );
            }
        }
    }

    token.ok_or_else(|| {

        format!(
            "Missing required argument: --token\n\
             Usage: {} --token <provisioning-token>",
            args[0]
        )

    })
}


// ============================================================
// CREATE DIRECTORIES
// ============================================================

fn create_directories(
    paths: &AgentPaths,
)
    -> Result<(), Box<dyn std::error::Error>>
{
    fs::create_dir_all(
        &paths.agent_directory
    )?;

    fs::create_dir_all(
        &paths.pki_directory
    )?;

    // Linux:
    //
    // ~/.monitoring-agent       -> 700
    // ~/.monitoring-agent/pki   -> 700
    //
    // This protects the private key.

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(
            &paths.agent_directory,
            fs::Permissions::from_mode(0o700),
        )?;

        fs::set_permissions(
            &paths.pki_directory,
            fs::Permissions::from_mode(0o700),
        )?;
    }

    Ok(())
}


// ============================================================
// CHECK IF DEVICE IS ALREADY PROVISIONED
// ============================================================

fn is_provisioned(
    paths: &AgentPaths,
) -> bool
{
    paths.device_key.exists()
        &&
    paths.device_certificate.exists()
        &&
    paths.ca_certificate.exists()
        &&
    paths.identity.exists()
}


// ============================================================
// GENERATE PRIVATE KEY
// ============================================================

fn generate_private_key()
    -> Result<PKey<Private>, Box<dyn std::error::Error>>
{
    println!(
        "Generating device private key..."
    );

    let rsa =
        Rsa::generate(2048)?;

    let private_key =
        PKey::from_rsa(rsa)?;

    println!(
        "Device private key generated."
    );

    Ok(private_key)
}


// ============================================================
// GENERATE CSR
// ============================================================

fn generate_csr(
    private_key: &PKey<Private>,
)
    -> Result<String, Box<dyn std::error::Error>>
{
    println!(
        "Generating CSR..."
    );

    let mut name_builder =
        X509NameBuilder::new()?;

    name_builder.append_entry_by_text(
        "C",
        "TN",
    )?;

    name_builder.append_entry_by_text(
        "O",
        "Realtime Monitoring",
    )?;

    // The Device Service assigns the real device ID.
    //
    // The CSR only needs to prove possession of the
    // generated private key.
    //
    name_builder.append_entry_by_text(
        "CN",
        "monitoring-agent",
    )?;

    let subject =
        name_builder.build();

    let mut request_builder =
        X509Req::builder()?;

    request_builder.set_subject_name(
        &subject
    )?;

    request_builder.set_pubkey(
        private_key
    )?;

    request_builder.sign(
        private_key,
        MessageDigest::sha256(),
    )?;

    let request =
        request_builder.build();

    let csr =
        String::from_utf8(
            request.to_pem()?
        )?;

    println!(
        "CSR generated successfully."
    );

    Ok(csr)
}


// ============================================================
// SAVE PRIVATE KEY
// ============================================================

fn save_private_key(
    paths: &AgentPaths,
    private_key: &PKey<Private>,
)
    -> Result<(), Box<dyn std::error::Error>>
{
    let key_pem =
        private_key.private_key_to_pem_pkcs8()?;

    fs::write(
        &paths.device_key,
        &key_pem
    )?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(
            &paths.device_key,
            fs::Permissions::from_mode(0o600),
        )?;
    }

    println!(
        "Private key saved: {}",
        paths.device_key.display()
    );

    Ok(())
}

#[derive(Serialize)]
struct Metrics {
    device_id: String,
    tenant_id: String,
    cpu: f32,
    ram: f32,
}
// ============================================================
// SAVE CSR
// ============================================================

fn save_csr(
    paths: &AgentPaths,
    csr: &str,
)
    -> Result<(), Box<dyn std::error::Error>>
{
    fs::write(
        &paths.device_csr,
        csr.as_bytes()
    )?;

    println!(
        "CSR saved: {}",
        paths.device_csr.display()
    );

    Ok(())
}


// ============================================================
// SAVE CERTIFICATE
// ============================================================

fn save_certificate(
    path: &Path,
    certificate: &str,
)
    -> Result<(), Box<dyn std::error::Error>>
{
    if certificate.trim().is_empty() {

        return Err(
            format!(
                "Certificate is empty: {}",
                path.display()
            )
            .into()
        );
    }

    fs::write(
        path,
        certificate.as_bytes()
    )?;

    println!(
        "Certificate saved: {}",
        path.display()
    );

    Ok(())
}


// ============================================================
// SAVE DEVICE IDENTITY
// ============================================================

fn save_identity(
    paths: &AgentPaths,
    identity: &DeviceIdentity,
)
    -> Result<(), Box<dyn std::error::Error>>
{
    let json =
        serde_json::to_string_pretty(
            identity
        )?;

    fs::write(
        &paths.identity,
        json.as_bytes()
    )?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(
            &paths.identity,
            fs::Permissions::from_mode(0o600),
        )?;
    }

    println!(
        "Device identity saved: {}",
        paths.identity.display()
    );

    Ok(())
}


// ============================================================
// LOAD DEVICE IDENTITY
// ============================================================

fn load_identity(
    paths: &AgentPaths,
)
    -> Result<DeviceIdentity, Box<dyn std::error::Error>>
{
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
// PROVISION DEVICE
// ============================================================

async fn provision_device(
    token: &str,
    csr: &str,
)
    -> Result<
        ProvisionResponse,
        Box<dyn std::error::Error>
    >
{
    let client =
        Client::new();

    let url =
        format!(
            "{}/{}",
            DEVICE_SERVICE_BASE_URL,
            token
        );

    println!(
        "========================================"
    );

    println!(
        "DEVICE PROVISIONING"
    );

    println!(
        "========================================"
    );

    println!(
        "Provisioning URL: {}",
        url
    );

    let request =
        ProvisionRequest {
            csr: csr.to_string(),
        };

    let response =
        client
            .post(&url)
            .json(&request)
            .send()
            .await?;

    println!(
        "HTTP status: {}",
        response.status()
    );

    if !response.status().is_success() {

        let body =
            response.text().await?;

        return Err(
            format!(
                "Provisioning failed: {}",
                body
            )
            .into()
        );
    }

    let result:
        ProvisionResponse =
        response.json().await?;

    println!(
        "Device provisioned successfully."
    );

    println!(
        "Device ID: {}",
        result.device_id
    );

    println!(
        "Tenant ID: {}",
        result.tenant_id
    );

    Ok(result)
}


// ============================================================
// LOAD MQTT CERTIFICATES
// ============================================================

fn load_certificates(
    paths: &AgentPaths,
)
    -> Result<
        (
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
        ),
        Box<dyn std::error::Error>
    >
{
    let ca =
        fs::read(
            &paths.ca_certificate
        )?;

    let client_certificate =
        fs::read(
            &paths.device_certificate
        )?;

    let client_key =
        fs::read(
            &paths.device_key
        )?;

    Ok((
        ca,
        client_certificate,
        client_key,
    ))
}


// ============================================================
// START MQTT
// ============================================================

fn start_mqtt(
    paths: &AgentPaths,
    device_id: &str,
)
    -> MqttClient
{
    let (
        ca,
        client_certificate,
        client_key,
    ) =
        match load_certificates(paths) {

            Ok(certificates) =>
                certificates,

            Err(error) => {

                eprintln!(
                    "Failed to load MQTT certificates: {}",
                    error
                );

                std::process::exit(1);
            }
        };


    let mut mqtt_options =
        MqttOptions::new(
            device_id,
            MQTT_HOST,
            MQTT_PORT,
        );


    mqtt_options.set_keep_alive(
        Duration::from_secs(
            MQTT_KEEP_ALIVE_SECONDS
        )
    );


    // ========================================================
    // mTLS
    // ========================================================

    mqtt_options.set_transport(
        Transport::tls(
            ca,
            Some((
                client_certificate,
                client_key,
            )),
            None,
        )
    );


    println!(
        "MQTT broker: {}:{}",
        MQTT_HOST,
        MQTT_PORT
    );

    println!(
        "MQTT mTLS configured."
    );


    let (
        mqtt_client,
        mut connection
    ) =
        MqttClient::new(
            mqtt_options,
            10,
        );


    thread::spawn(
        move || {

            for notification
                in connection.iter()
            {
                match notification {

                    Ok(event) => {

                        println!(
                            "MQTT: {:?}",
                            event
                        );
                    }

                    Err(error) => {

                        eprintln!(
                            "MQTT error: {:?}",
                            error
                        );

                        break;
                    }
                }
            }
        }
    );


    mqtt_client
}


// ============================================================
// MAIN
// ============================================================

#[tokio::main]
async fn main()
{
    println!(
        "========================================"
    );

    println!(
        "Realtime Monitoring Agent"
    );

    println!(
        "========================================"
    );


    // ========================================================
    // PATHS
    // ========================================================

    let paths =
        match build_paths()
        {

            Ok(paths) =>
                paths,

            Err(error) => {

                eprintln!(
                    "Failed to determine agent paths: {}",
                    error
                );

                return;
            }
        };


    println!(
        "Agent directory: {}",
        paths.agent_directory.display()
    );


    // ========================================================
    // DIRECTORIES
    // ========================================================

    if let Err(error) =
        create_directories(&paths)
    {

        eprintln!(
            "Failed to create agent directories: {}",
            error
        );

        return;
    }


    // ========================================================
    // TOKEN
    // ========================================================
    //
    // We still accept the token on every invocation.
    //
    // On first run it is used for provisioning.
    //
    // On later runs it is not needed because the device
    // already has its identity and certificates.
    //
    // ========================================================

    let token =
        match get_token()
        {

            Ok(token) =>
                token,

            Err(error) => {

                eprintln!(
                    "{}",
                    error
                );

                return;
            }
        };


    println!(
        "Provisioning token received."
    );


    // ========================================================
    // DEVICE IDENTITY
    // ========================================================

    let identity;


    // ========================================================
    // FIRST RUN
    // ========================================================

    if !is_provisioned(&paths)
    {
        println!(
            "========================================"
        );

        println!(
            "FIRST RUN"
        );

        println!(
            "Device is not provisioned."
        );

        println!(
            "Starting automatic PKI provisioning..."
        );

        println!(
            "========================================"
        );


        // ====================================================
        // PRIVATE KEY
        // ====================================================

        let private_key =
            match generate_private_key()
            {

                Ok(key) => key,

                Err(error) => {

                    eprintln!(
                        "Failed to generate private key: {}",
                        error
                    );

                    return;
                }
            };


        // ====================================================
        // CSR
        // ====================================================

        let csr =
            match generate_csr(
                &private_key,
            )
            {

                Ok(csr) => csr,

                Err(error) => {

                    eprintln!(
                        "Failed to generate CSR: {}",
                        error
                    );

                    return;
                }
            };


        // ====================================================
        // SAVE PRIVATE KEY
        // ====================================================

        if let Err(error) =
            save_private_key(
                &paths,
                &private_key,
            )
        {

            eprintln!(
                "Failed to save private key: {}",
                error
            );

            return;
        }


        // ====================================================
        // SAVE CSR
        // ====================================================

        if let Err(error) =
            save_csr(
                &paths,
                &csr,
            )
        {

            eprintln!(
                "Failed to save CSR: {}",
                error
            );

            return;
        }


        // ====================================================
        // PROVISION
        // ====================================================

        let registration =
            match provision_device(
                &token,
                &csr,
            )
            .await
            {

                Ok(result) =>
                    result,

                Err(error) => {

                    eprintln!(
                        "Device provisioning failed: {}",
                        error
                    );

                    return;
                }
            };


        // ====================================================
        // SAVE CA
        // ====================================================

        if let Err(error) =
            save_certificate(
                &paths.ca_certificate,
                &registration.ca_certificate,
            )
        {

            eprintln!(
                "Failed to save CA certificate: {}",
                error
            );

            return;
        }


        // ====================================================
        // SAVE DEVICE CERTIFICATE
        // ====================================================

        if let Err(error) =
            save_certificate(
                &paths.device_certificate,
                &registration.client_certificate,
            )
        {

            eprintln!(
                "Failed to save device certificate: {}",
                error
            );

            return;
        }


        // ====================================================
        // SAVE DEVICE IDENTITY
        // ====================================================

        identity =
            DeviceIdentity {

                device_id:
                    registration.device_id,

                tenant_id:
                    registration.tenant_id,
            };


        if let Err(error) =
            save_identity(
                &paths,
                &identity,
            )
        {

            eprintln!(
                "Failed to save device identity: {}",
                error
            );

            return;
        }


        // ====================================================
        // DELETE CSR
        // ====================================================

        if let Err(error) =
            fs::remove_file(
                &paths.device_csr
            )
        {

            eprintln!(
                "Warning: failed to remove CSR: {}",
                error
            );
        }


        println!(
            "========================================"
        );

        println!(
            "DEVICE PKI PROVISIONED"
        );

        println!(
            "========================================"
        );

        println!(
            "CA: {}",
            paths.ca_certificate.display()
        );

        println!(
            "Device certificate: {}",
            paths.device_certificate.display()
        );

        println!(
            "Private key: {}",
            paths.device_key.display()
        );

        println!(
            "Device ID: {}",
            identity.device_id
        );

        println!(
            "Tenant ID: {}",
            identity.tenant_id
        );

        println!(
            "========================================"
        );
    }


    // ========================================================
    // EXISTING DEVICE
    // ========================================================

    else
    {
        println!(
            "========================================"
        );

        println!(
            "EXISTING DEVICE"
        );

        println!(
            "PKI already exists."
        );

        println!(
            "Skipping provisioning."
        );

        println!(
            "========================================"
        );


        identity =
            match load_identity(&paths)
            {

                Ok(identity) =>
                    identity,

                Err(error) => {

                    eprintln!(
                        "Failed to load device identity: {}",
                        error
                    );

                    return;
                }
            };


        println!(
            "Device ID: {}",
            identity.device_id
        );

        println!(
            "Tenant ID: {}",
            identity.tenant_id
        );
    }


    // ========================================================
    // DEVICE INFORMATION
    // ========================================================

    let device_id =
        identity.device_id;

    let tenant_id =
        identity.tenant_id;


    // ========================================================
    // MQTT
    // ========================================================

    let mqtt_client =
        start_mqtt(
            &paths,
            &device_id,
        );


    // ========================================================
    // MQTT TOPIC
    // ========================================================

    let topic =
        format!(
            "tenants/{}/devices/{}/metrics",
            tenant_id,
            device_id
        );


    println!(
        "MQTT topic: {}",
        topic
    );


    // ========================================================
    // SYSTEM
    // ========================================================

    let mut system =
        System::new_all();


    // ========================================================
    // METRICS LOOP
    // ========================================================

    loop {

        system.refresh_all();


        let total_memory =
            system.total_memory();

        let used_memory =
            system.used_memory();


        let ram_percentage =
            if total_memory > 0 {

                (
                    used_memory as f32
                    /
                    total_memory as f32
                ) * 100.0

            } else {

                0.0
            };


        let metrics =
            Metrics {

                device_id:
                    device_id.clone(),

                tenant_id:
                    tenant_id.clone(),

                cpu:
                    system.global_cpu_usage(),

                ram:
                    ram_percentage,
            };


        let json =
            match serde_json::to_string(
                &metrics
            )
            {

                Ok(json) =>
                    json,

                Err(error) => {

                    eprintln!(
                        "Failed to serialize metrics: {}",
                        error
                    );

                    thread::sleep(
                        Duration::from_secs(
                            METRICS_INTERVAL_SECONDS
                        )
                    );

                    continue;
                }
            };


        println!(
            "Sending metrics: {}",
            json
        );


        match mqtt_client.publish(
            &topic,
            QoS::AtLeastOnce,
            false,
            json,
        )
        {

            Ok(_) => {

                println!(
                    "Metrics published successfully."
                );
            }

            Err(error) => {

                eprintln!(
                    "Failed to publish metrics: {}",
                    error
                );
            }
        }


        thread::sleep(
            Duration::from_secs(
                METRICS_INTERVAL_SECONDS
            )
        );
    }
}

