use std::env;
use std::fs;
use std::path::Path;
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
// PATHS
// ============================================================

const AGENT_DIRECTORY: &str =
    "/etc/monitoring/agent";

const PKI_DIRECTORY: &str =
    "/etc/monitoring/agent/pki";

const CA_CERT_PATH: &str =
    "/etc/monitoring/agent/pki/ca.crt";

const CLIENT_CERT_PATH: &str =
    "/etc/monitoring/agent/pki/device.crt";

const CLIENT_KEY_PATH: &str =
    "/etc/monitoring/agent/pki/device.key";

const CSR_PATH: &str =
    "/etc/monitoring/agent/pki/device.csr";

const CONFIG_PATH: &str =
    "/etc/monitoring/agent/config.toml";


// ============================================================
// DEVICE SERVICE
// ============================================================

const DEVICE_SERVICE_BASE_URL: &str =
    "http://192.168.1.39:9005/api/v1/devices/provision";


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
// CONFIGURATION
// ============================================================

#[derive(Debug, Deserialize)]
struct Config {

    mqtt_host: String,

    mqtt_port: u16,

    metrics_interval_seconds: u64,
}


// ============================================================
// METRICS
// ============================================================

#[derive(Serialize)]
struct Metrics {

    device_id: String,

    tenant_id: String,

    cpu: f32,

    ram: f32,
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

fn create_directories()
    -> Result<(), Box<dyn std::error::Error>>
{
    fs::create_dir_all(AGENT_DIRECTORY)?;
    fs::create_dir_all(PKI_DIRECTORY)?;

    Ok(())
}


// ============================================================
// GENERATE PRIVATE KEY
// ============================================================

fn generate_private_key()
    -> Result<PKey<Private>, Box<dyn std::error::Error>>
{

    println!("Generating device private key...");

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
    device_id: &str,
)
    -> Result<String, Box<dyn std::error::Error>>
{

    println!("Generating CSR...");

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

    name_builder.append_entry_by_text(
        "CN",
        device_id,
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
    private_key: &PKey<Private>,
)
    -> Result<(), Box<dyn std::error::Error>>
{

    let key_pem =
        private_key.private_key_to_pem_pkcs8()?;

    fs::write(
        CLIENT_KEY_PATH,
        &key_pem
    )?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(
            CLIENT_KEY_PATH,
            fs::Permissions::from_mode(0o600),
        )?;
    }

    println!(
        "Private key saved: {}",
        CLIENT_KEY_PATH
    );

    Ok(())
}


// ============================================================
// SAVE CSR
// ============================================================

fn save_csr(
    csr: &str,
)
    -> Result<(), Box<dyn std::error::Error>>
{

    fs::write(
        CSR_PATH,
        csr.as_bytes()
    )?;

    println!(
        "CSR saved: {}",
        CSR_PATH
    );

    Ok(())
}


// ============================================================
// SAVE CERTIFICATE
// ============================================================

fn save_certificate(
    path: &str,
    certificate: &str,
)
    -> Result<(), Box<dyn std::error::Error>>
{

    if certificate.trim().is_empty() {

        return Err(
            format!(
                "Certificate is empty: {}",
                path
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
        path
    );

    Ok(())
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

    // IMPORTANT:
    //
    // Spring endpoint:
    //
    // POST /provision/{token}
    //
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
// LOAD CONFIGURATION
// ============================================================

fn load_config()
    -> Result<
        Config,
        Box<dyn std::error::Error>
    >
{

    let content =
        fs::read_to_string(
            CONFIG_PATH
        )?;

    let config:
        Config =
        toml::from_str(
            &content
        )?;

    println!(
        "MQTT broker: {}:{}",
        config.mqtt_host,
        config.mqtt_port
    );

    Ok(config)
}


// ============================================================
// LOAD MQTT CERTIFICATES
// ============================================================

fn load_certificates()
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
            CA_CERT_PATH
        )?;

    let client_certificate =
        fs::read(
            CLIENT_CERT_PATH
        )?;

    let client_key =
        fs::read(
            CLIENT_KEY_PATH
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
    config: &Config,
    device_id: &str,
    tenant_id: &str,
)
    -> MqttClient
{

    let (
        ca,
        client_certificate,
        client_key,
    ) =
        match load_certificates() {

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
            &config.mqtt_host,
            config.mqtt_port,
        );


    mqtt_options.set_keep_alive(
        Duration::from_secs(30)
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


    println!(
        "MQTT topic: tenants/{}/devices/{}/metrics",
        tenant_id,
        device_id
    );


    mqtt_client
}


// ============================================================
// MAIN
// ============================================================

#[tokio::main]
async fn main() {

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
    // TOKEN
    // ========================================================

    let token =
        match get_token() {

            Ok(token) => token,

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
    // DIRECTORIES
    // ========================================================

    if let Err(error) =
        create_directories()
    {

        eprintln!(
            "Failed to create agent directories: {}",
            error
        );

        return;
    }


    // ========================================================
    // PRIVATE KEY
    // ========================================================

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


    // ========================================================
    // CSR
    //
    // We don't know the real device ID yet.
    //
    // Device Service will identify the device from
    // the provisioning token.
    //
    // ========================================================

    let csr =
        match generate_csr(
            &private_key,
            "monitoring-agent",
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


    if let Err(error) =
        save_private_key(
            &private_key
        )
    {

        eprintln!(
            "Failed to save private key: {}",
            error
        );

        return;
    }


    if let Err(error) =
        save_csr(
            &csr
        )
    {

        eprintln!(
            "Failed to save CSR: {}",
            error
        );

        return;
    }


    // ========================================================
    // PROVISION
    // ========================================================

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


    // ========================================================
    // SAVE CA
    // ========================================================

    if let Err(error) =
        save_certificate(
            CA_CERT_PATH,
            &registration.ca_certificate,
        )
    {

        eprintln!(
            "Failed to save CA certificate: {}",
            error
        );

        return;
    }


    // ========================================================
    // SAVE DEVICE CERTIFICATE
    // ========================================================

    if let Err(error) =
        save_certificate(
            CLIENT_CERT_PATH,
            &registration.client_certificate,
        )
    {

        eprintln!(
            "Failed to save device certificate: {}",
            error
        );

        return;
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
        CA_CERT_PATH
    );

    println!(
        "Device certificate: {}",
        CLIENT_CERT_PATH
    );

    println!(
        "Private key: {}",
        CLIENT_KEY_PATH
    );

    println!(
        "========================================"
    );


    // ========================================================
    // DEVICE INFORMATION
    // ========================================================

    let device_id =
        registration.device_id;

    let tenant_id =
        registration.tenant_id;


    // ========================================================
    // CONFIG
    // ========================================================

    let config =
        match load_config()
        {

            Ok(config) =>
                config,

            Err(error) => {

                eprintln!(
                    "Failed to load configuration: {}",
                    error
                );

                return;
            }
        };


    // ========================================================
    // MQTT
    // ========================================================

    let mqtt_client =
        start_mqtt(
            &config,
            &device_id,
            &tenant_id,
        );


    // ========================================================
    // SYSTEM
    // ========================================================

    let mut system =
        System::new_all();


    // ========================================================
    // MQTT TOPIC
    // ========================================================

    let topic =
        format!(
            "tenants/{}/devices/{}/metrics",
            tenant_id,
            device_id
        );


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
                            config.metrics_interval_seconds
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
                config.metrics_interval_seconds
            )
        );
    }
}
