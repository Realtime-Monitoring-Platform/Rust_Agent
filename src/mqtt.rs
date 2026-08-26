use std::time::Duration;

use rumqttc::{AsyncClient, MqttOptions, Transport};

use crate::config::{MQTT_HOST, MQTT_KEEP_ALIVE_SECONDS, MQTT_PORT};
use crate::models::DeviceIdentity;
use crate::paths::AgentPaths;
use crate::provisioning::load_certificate;

// ============================================================
// CREATE MQTT CLIENT
// ============================================================
pub fn create_mqtt_client(
    identity: &DeviceIdentity,
    paths: &AgentPaths,
) -> Result<(AsyncClient, rumqttc::EventLoop), Box<dyn std::error::Error>> {
    println!("========================================");
    println!("Creating MQTT client...");
    println!("========================================");
    let client_id = format!("monitoring-agent-{}", identity.device_id);
    println!("MQTT Client ID: {}", client_id);
    println!("Connecting to MQTT broker {}:{}", MQTT_HOST, MQTT_PORT);

    let mut mqtt_options = MqttOptions::new(client_id, MQTT_HOST, MQTT_PORT);
    mqtt_options.set_keep_alive(Duration::from_secs(MQTT_KEEP_ALIVE_SECONDS));

    let ca = load_certificate(&paths.ca_certificate)?;
    let client_cert = load_certificate(&paths.device_certificate)?;
    let private_key = load_certificate(&paths.device_key)?;

    let transport = Transport::tls(ca, Some((client_cert, private_key)), None);
    mqtt_options.set_transport(transport);

    let (client, event_loop) = AsyncClient::new(mqtt_options, 100);
    Ok((client, event_loop))
}

// ============================================================
// MQTT TOPICS
// ============================================================
pub fn command_topic(identity: &DeviceIdentity) -> String {
    format!(
        "tenants/{}/devices/{}/commands",
        identity.tenant_id, identity.device_id
    )
}

pub fn metrics_topic(identity: &DeviceIdentity) -> String {
    format!(
        "tenants/{}/devices/{}/metrics",
        identity.tenant_id, identity.device_id
    )
}

pub fn command_result_topic(identity: &DeviceIdentity) -> String {
    format!(
        "tenants/{}/devices/{}/command-results",
        identity.tenant_id, identity.device_id
    )
}

pub fn logs_topic(identity: &DeviceIdentity) -> String {
    format!(
        "tenants/{}/devices/{}/logs",
        identity.tenant_id, identity.device_id
    )
}
