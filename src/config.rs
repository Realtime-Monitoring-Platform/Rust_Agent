// ============================================================
// CONFIGURATION
// ============================================================

pub const DEVICE_SERVICE_BASE_URL: &str = "http://192.168.1.205:9005/api/v1/devices/provision";
pub const MQTT_HOST: &str = "192.168.1.122";
pub const MQTT_PORT: u16 = 8883;
pub const MQTT_KEEP_ALIVE_SECONDS: u64 = 30;
pub const METRICS_INTERVAL_SECONDS: u64 = 5;

// ------------------------------------------------------------
// COMMAND OUTPUT
// ------------------------------------------------------------
pub const MAX_OUTPUT_BYTES: usize = 200_000;

// ------------------------------------------------------------
// LOGGING
// ------------------------------------------------------------
pub const MAX_LOG_BYTES: usize = 4_000;
pub const LOG_BATCH_SIZE: usize = 100;
pub const LOG_FLUSH_INTERVAL_SECONDS: u64 = 1;
pub const LOG_CHANNEL_SIZE: usize = 10_000;
