use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::Duration;

use rumqttc::{AsyncClient, QoS};
use tokio::sync::mpsc;

use crate::config::{LOG_BATCH_SIZE, LOG_FLUSH_INTERVAL_SECONDS, MAX_LOG_BYTES};
use crate::models::{DeviceIdentity, DeviceLogBatch, DeviceLogMessage, JournalEntry};
use crate::mqtt::logs_topic;
use crate::util::now_millis;

// ============================================================
// NORMALIZE LOG LEVEL
// ============================================================
fn normalize_log_level(priority: Option<&str>) -> String {
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
    let message = entry.message?;
    if message.trim().is_empty() {
        return None;
    }
    let mut message = message;
    if message.len() > MAX_LOG_BYTES {
        let mut cut = MAX_LOG_BYTES;
        while !message.is_char_boundary(cut) {
            cut -= 1;
        }
        message.truncate(cut);
        message.push_str(" [truncated]");
    }
    let service = entry
        .systemd_unit
        .or(entry.command)
        .or(entry.executable)
        .unwrap_or_else(|| "unknown".to_string());
    let timestamp = entry
        .realtime_timestamp
        .and_then(|value| value.parse::<u128>().ok())
        .map(|micros| micros / 1000)
        .unwrap_or_else(now_millis);
    Some(DeviceLogMessage {
        device_id: identity.device_id.clone(),
        tenant_id: identity.tenant_id.clone(),
        level: normalize_log_level(entry.priority.as_deref()),
        service,
        source: "systemd".to_string(),
        message,
        timestamp_millis: timestamp,
    })
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
pub fn start_journal_collector(identity: DeviceIdentity, log_sender: mpsc::Sender<DeviceLogMessage>) {
    std::thread::spawn(move || {
        println!("Starting Linux systemd journal collector...");
        let mut child = match Command::new("journalctl")
            .args(["-f", "-n", "0", "-o", "json"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(error) => {
                eprintln!("Failed to start journalctl: {}", error);
                return;
            }
        };
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                eprintln!("Failed to access journalctl stdout");
                return;
            }
        };
        let reader = BufReader::new(stdout);
        for line_result in reader.lines() {
            let line = match line_result {
                Ok(line) => line,
                Err(error) => {
                    eprintln!("Failed to read journal entry: {}", error);
                    continue;
                }
            };
            if line.trim().is_empty() {
                continue;
            }
            let journal_entry: JournalEntry = match serde_json::from_str(&line) {
                Ok(entry) => entry,
                Err(error) => {
                    eprintln!("Failed to parse journal JSON: {}", error);
                    continue;
                }
            };
            let log = match journal_to_device_log(journal_entry, &identity) {
                Some(log) => log,
                None => continue,
            };
            match log_sender.try_send(log) {
                Ok(_) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    eprintln!("WARNING: log channel is full; dropping log");
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    eprintln!("Log channel closed; stopping journal collector");
                    break;
                }
            }
        }
        let _ = child.kill();
        println!("Systemd journal collector stopped.");
    });
}

// ============================================================
// LOG BATCHER
// ============================================================
pub async fn run_log_batcher(
    mqtt_client: AsyncClient,
    identity: DeviceIdentity,
    mut log_receiver: mpsc::Receiver<DeviceLogMessage>,
) {
    println!("Log batcher started.");
    let mut buffer: Vec<DeviceLogMessage> = Vec::with_capacity(LOG_BATCH_SIZE);
    let mut flush_interval = tokio::time::interval(Duration::from_secs(LOG_FLUSH_INTERVAL_SECONDS));
    loop {
        tokio::select! {
            // ------------------------------------------------
            // RECEIVE LOG
            // ------------------------------------------------
            log = log_receiver.recv() => {
                match log {
                    Some(log) => {
                        buffer.push(log);
                        if buffer.len() >= LOG_BATCH_SIZE {
                            publish_log_batch(&mqtt_client, &identity, &mut buffer).await;
                        }
                    }
                    None => {
                        println!("Log channel closed.");
                        if !buffer.is_empty() {
                            publish_log_batch(&mqtt_client, &identity, &mut buffer).await;
                        }
                        break;
                    }
                }
            }
            // ------------------------------------------------
            // FLUSH EVERY SECOND
            // ------------------------------------------------
            _ = flush_interval.tick() => {
                if !buffer.is_empty() {
                    publish_log_batch(&mqtt_client, &identity, &mut buffer).await;
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
    let logs = std::mem::take(buffer);
    let batch = DeviceLogBatch {
        device_id: identity.device_id.clone(),
        tenant_id: identity.tenant_id.clone(),
        logs,
    };
    let json = match serde_json::to_string(&batch) {
        Ok(json) => json,
        Err(error) => {
            eprintln!("Failed to serialize log batch: {}", error);
            return;
        }
    };
    let topic = logs_topic(identity);
    println!("Publishing {} logs to {}", batch.logs.len(), topic);
    if let Err(error) = mqtt_client
        .publish(topic, QoS::AtLeastOnce, false, json.as_bytes())
        .await
    {
        eprintln!("Failed to publish log batch: {}", error);
    }
}

// ============================================================
// AGENT INTERNAL LOG
// ============================================================
pub async fn publish_log(
    mqtt_client: &AsyncClient,
    identity: &DeviceIdentity,
    level: &str,
    message: impl Into<String>,
) {
    let mut message = message.into();
    if message.len() > MAX_LOG_BYTES {
        let mut cut = MAX_LOG_BYTES;
        while !message.is_char_boundary(cut) {
            cut -= 1;
        }
        message.truncate(cut);
        message.push_str(" [truncated]");
    }
    println!(
        "[{}] {} | device={} | {}",
        level,
        now_millis(),
        identity.device_id,
        message
    );
    let log = DeviceLogMessage {
        device_id: identity.device_id.clone(),
        tenant_id: identity.tenant_id.clone(),
        level: level.to_string(),
        service: "monitoring-agent".to_string(),
        source: "agent".to_string(),
        message,
        timestamp_millis: now_millis(),
    };
    let topic = logs_topic(identity);
    let json = match serde_json::to_string(&log) {
        Ok(json) => json,
        Err(error) => {
            eprintln!("Failed to serialize agent log: {}", error);
            return;
        }
    };
    if let Err(error) = mqtt_client
        .publish(topic, QoS::AtLeastOnce, false, json.as_bytes())
        .await
    {
        eprintln!("Failed to publish agent log: {}", error);
    }
}
