use rumqttc::{AsyncClient, QoS};
use sysinfo::System;

use crate::models::{DeviceIdentity, DeviceMetrics};
use crate::mqtt::metrics_topic;

// ============================================================
// COLLECT METRICS
// ============================================================
fn collect_metrics(system: &mut System, identity: &DeviceIdentity) -> DeviceMetrics {
    system.refresh_cpu_usage();
    system.refresh_memory();
    let cpu = system.global_cpu_usage();
    let total_memory = system.total_memory();
    let used_memory = system.used_memory();
    let ram = if total_memory > 0 {
        (used_memory as f32 / total_memory as f32) * 100.0
    } else {
        0.0
    };
    DeviceMetrics {
        device_id: identity.device_id.clone(),
        tenant_id: identity.tenant_id.clone(),
        cpu,
        ram,
    }
}

// ============================================================
// PUBLISH METRICS
// ============================================================
pub async fn publish_metrics(
    mqtt_client: &AsyncClient,
    identity: &DeviceIdentity,
    system: &mut System,
) -> Result<(), Box<dyn std::error::Error>> {
    let metrics = collect_metrics(system, identity);
    let json = serde_json::to_string(&metrics)?;
    let topic = metrics_topic(identity);
    println!("Sending metrics: {}", json);
    mqtt_client
        .publish(topic, QoS::AtLeastOnce, false, json.as_bytes())
        .await?;
    println!("Metrics published successfully.");
    Ok(())
}
