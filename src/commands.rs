use std::env;
use std::path::PathBuf;
use std::process::Command;

use rumqttc::{AsyncClient, QoS};

use crate::config::MAX_OUTPUT_BYTES;
use crate::logging::publish_log;
use crate::models::{CommandResultMessage, DeviceCommandMessage, DeviceIdentity};
use crate::mqtt::command_result_topic;

// ============================================================
// TRUNCATE OUTPUT
// ============================================================
fn truncate_output(output: String) -> String {
    if output.len() <= MAX_OUTPUT_BYTES {
        return output;
    }
    let mut cut = MAX_OUTPUT_BYTES;
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
fn execute_command(command: &str, current_dir: &mut PathBuf) -> (String, i32) {
    println!("========================================");
    println!("EXECUTING COMMAND");
    println!("Command: {}", command);
    println!("Current dir: {:?}", current_dir);
    println!("========================================");
    let trimmed = command.trim();
    if trimmed == "cd" || trimmed.starts_with("cd ") {
        let target = if trimmed == "cd" {
            match env::var("HOME") {
                Ok(home) => PathBuf::from(home),
                Err(_) => {
                    return ("cd: HOME not set".to_string(), 1);
                }
            }
        } else {
            let path_str = trimmed[3..].trim();
            let candidate = if path_str.starts_with('/') {
                PathBuf::from(path_str)
            } else {
                current_dir.join(path_str)
            };
            match candidate.canonicalize() {
                Ok(p) => p,
                Err(e) => {
                    return (format!("cd: {}: {}", path_str, e), 1);
                }
            }
        };
        if !target.is_dir() {
            return (format!("cd: {}: Not a directory", target.display()), 1);
        }
        *current_dir = target;
        println!("Changed directory to {:?}", current_dir);
        return (String::new(), 0);
    }
    match Command::new("sh")
        .arg("-c")
        .arg(command)
        .current_dir(&*current_dir)
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let exit_code = output.status.code().unwrap_or(-1);
            let result = if !stdout.is_empty() { stdout } else { stderr };
            println!("Exit code: {}", exit_code);
            println!("Command output: {}", result);
            (truncate_output(result), exit_code)
        }
        Err(error) => {
            println!("Failed to execute command: {}", error);
            (error.to_string(), -1)
        }
    }
}

// ============================================================
// PROCESS MQTT COMMAND
// ============================================================
pub async fn process_command(
    mqtt_client: &AsyncClient,
    identity: &DeviceIdentity,
    payload: &[u8],
    current_dir: &mut PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("========================================");
    println!("MQTT COMMAND RECEIVED");
    println!("========================================");
    let payload_string = String::from_utf8_lossy(payload);
    println!("Payload: {}", payload_string);

    let command: DeviceCommandMessage = serde_json::from_slice(payload)?;
    println!("Command ID: {}", command.command_id);
    println!("Device ID: {}", command.device_id);
    println!("Command: {}", command.command);

    publish_log(
        mqtt_client,
        identity,
        "INFO",
        format!(
            "Received command '{}' (commandId={})",
            command.command, command.command_id
        ),
    )
    .await;

    if command.device_id != identity.device_id {
        println!("WARNING: Command device ID does not match this device.");
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

    let (output, exit_code) = execute_command(&command.command, current_dir);
    let status = if exit_code == 0 { "SUCCESS" } else { "FAILED" };

    publish_log(
        mqtt_client,
        identity,
        if exit_code == 0 { "INFO" } else { "ERROR" },
        format!(
            "Command '{}' (commandId={}) finished with exit code {}",
            command.command, command.command_id, exit_code
        ),
    )
    .await;

    let result = CommandResultMessage {
        command_id: command.command_id,
        device_id: command.device_id,
        status: status.to_string(),
        stdout: output,
        exit_code,
    };
    let result_json = serde_json::to_string(&result)?;
    let topic = command_result_topic(identity);

    println!("Publishing command result...");
    println!("Result topic: {}", topic);
    mqtt_client
        .publish(topic, QoS::AtLeastOnce, false, result_json.as_bytes())
        .await?;
    println!("Command result published successfully.");

    Ok(())
}
