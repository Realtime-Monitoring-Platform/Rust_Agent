use serde::{Deserialize, Serialize};

// ============================================================
// DEVICE SYSTEM INFO
// ============================================================
#[derive(Debug, Serialize, Clone)]
pub struct DeviceSystemInfo {
    pub hostname: String,
    #[serde(rename = "ipAddress")]
    pub ip_address: String,
    #[serde(rename = "macAddress")]
    pub mac_address: String,
    #[serde(rename = "osName")]
    pub os_name: String,
    #[serde(rename = "osVersion")]
    pub os_version: String,
    #[serde(rename = "kernelVersion")]
    pub kernel_version: String,
    #[serde(rename = "cpuCount")]
    pub cpu_count: usize,
    #[serde(rename = "totalMemoryKb")]
    pub total_memory_kb: u64,
}

// ============================================================
// PROVISIONING REQUEST
// ============================================================
#[derive(Serialize)]
pub struct ProvisionRequest {
    pub csr: String,
    #[serde(rename = "deviceInfo")]
    pub device_info: DeviceSystemInfo,
}

// ============================================================
// PROVISIONING RESPONSE
// ============================================================
#[derive(Deserialize, Debug)]
pub struct ProvisionResponse {
    #[serde(rename = "caCertificate")]
    pub ca_certificate: String,
    #[serde(rename = "clientCertificate")]
    pub client_certificate: String,
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
}

// ============================================================
// DEVICE IDENTITY
// ============================================================
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeviceIdentity {
    pub device_id: String,
    pub tenant_id: String,
}

// ============================================================
// MQTT COMMAND
// ============================================================
#[derive(Debug, Deserialize)]
pub struct DeviceCommandMessage {
    #[serde(rename = "commandId")]
    pub command_id: String,
    #[serde(rename = "deviceId")]
    pub device_id: String,
    pub command: String,
}

// ============================================================
// MQTT COMMAND RESULT
// ============================================================
#[derive(Debug, Serialize)]
pub struct CommandResultMessage {
    #[serde(rename = "commandId")]
    pub command_id: String,
    #[serde(rename = "deviceId")]
    pub device_id: String,
    pub status: String,
    pub stdout: String,
    #[serde(rename = "exitCode")]
    pub exit_code: i32,
}

// ============================================================
// METRICS
// ============================================================
#[derive(Debug, Serialize)]
pub struct DeviceMetrics {
    pub device_id: String,
    pub tenant_id: String,
    pub cpu: f32,
    pub ram: f32,
}

// ============================================================
// LOG ENTRY
// ============================================================
#[derive(Debug, Clone, Serialize)]
pub struct DeviceLogMessage {
    pub device_id: String,
    pub tenant_id: String,
    pub level: String,
    pub service: String,
    pub source: String,
    pub message: String,
    #[serde(rename = "timestamp")]
    pub timestamp_millis: u128,
}

// ============================================================
// LOG BATCH
// ============================================================
#[derive(Debug, Serialize)]
pub struct DeviceLogBatch {
    pub device_id: String,
    pub tenant_id: String,
    pub logs: Vec<DeviceLogMessage>,
}

// ============================================================
// JOURNAL JSON ENTRY
// ============================================================
#[derive(Debug, Deserialize)]
pub struct JournalEntry {
    #[serde(rename = "__REALTIME_TIMESTAMP")]
    pub realtime_timestamp: Option<String>,
    #[serde(rename = "PRIORITY")]
    pub priority: Option<String>,
    #[serde(rename = "MESSAGE")]
    pub message: Option<String>,
    #[serde(rename = "_SYSTEMD_UNIT")]
    pub systemd_unit: Option<String>,
    #[serde(rename = "_COMM")]
    pub command: Option<String>,
    #[serde(rename = "_EXE")]
    pub executable: Option<String>,
}
