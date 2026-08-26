mod commands;
mod config;
mod logging;
mod metrics;
mod models;
mod mqtt;
mod paths;
mod provisioning;
mod util;

use std::env;
use std::path::PathBuf;
use std::time::Duration;

use rumqttc::{Event, Packet, QoS};
use sysinfo::System;
use tokio::sync::mpsc;

use commands::process_command;
use config::{LOG_CHANNEL_SIZE, METRICS_INTERVAL_SECONDS};
use logging::{publish_log, run_log_batcher, start_journal_collector};
use metrics::publish_metrics;
use mqtt::{command_topic, create_mqtt_client};
use paths::build_paths;
use provisioning::{device_is_provisioned, get_token, load_identity, provision_device};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --------------------------------------------------------
    // RUSTLS CRYPTO PROVIDER
    // --------------------------------------------------------
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install Rustls crypto provider");

    // --------------------------------------------------------
    // START
    // --------------------------------------------------------
    println!("========================================");
    println!("Monitoring Agent Starting");
    println!("========================================");

    // --------------------------------------------------------
    // BUILD PATHS
    // --------------------------------------------------------
    let paths = build_paths()?;

    // --------------------------------------------------------
    // TOKEN
    // --------------------------------------------------------
    let token = match get_token() {
        Ok(token) => token,
        Err(error) => {
            eprintln!("{}", error);
            return Ok(());
        }
    };

    // --------------------------------------------------------
    // PROVISION OR LOAD IDENTITY
    // --------------------------------------------------------
    let identity;
    if device_is_provisioned(&paths) {
        println!("Existing device identity found.");
        identity = load_identity(&paths)?;
    } else {
        println!("No device identity found.");
        identity = provision_device(&paths, &token).await?;
    }

    // --------------------------------------------------------
    // PRINT IDENTITY
    // --------------------------------------------------------
    println!("========================================");
    println!("DEVICE ID: {}", identity.device_id);
    println!("TENANT ID: {}", identity.tenant_id);
    println!("========================================");

    // --------------------------------------------------------
    // CREATE MQTT CLIENT
    // --------------------------------------------------------
    let (mqtt_client, mut event_loop) = create_mqtt_client(&identity, &paths)?;

    // --------------------------------------------------------
    // COMMAND TOPIC
    // --------------------------------------------------------
    let command_topic = command_topic(&identity);
    println!("Subscribing to command topic:");
    println!("{}", command_topic);
    mqtt_client
        .subscribe(command_topic.clone(), QoS::AtLeastOnce)
        .await?;
    println!("Subscribe request sent.");

    // --------------------------------------------------------
    // LOG CHANNEL
    // --------------------------------------------------------
    let (log_sender, log_receiver) = mpsc::channel(LOG_CHANNEL_SIZE);

    // --------------------------------------------------------
    // START JOURNAL COLLECTOR
    // --------------------------------------------------------
    start_journal_collector(identity.clone(), log_sender);

    // --------------------------------------------------------
    // START LOG BATCHER
    // --------------------------------------------------------
    tokio::spawn(run_log_batcher(
        mqtt_client.clone(),
        identity.clone(),
        log_receiver,
    ));

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
    let mut current_dir = env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    println!("Initial working directory: {:?}", current_dir);

    // --------------------------------------------------------
    // SYSTEM METRICS
    // --------------------------------------------------------
    let mut system = System::new_all();
    system.refresh_all();

    // --------------------------------------------------------
    // METRICS TIMER
    // --------------------------------------------------------
    let mut metrics_interval =
        tokio::time::interval(Duration::from_secs(METRICS_INTERVAL_SECONDS));

    // --------------------------------------------------------
    // MQTT EVENT LOOP
    // --------------------------------------------------------
    loop {
        tokio::select! {
            // =================================================
            // MQTT
            // =================================================
            event = event_loop.poll() => {
                match event {
                    Ok(Event::Incoming(Packet::Publish(publish))) => {
                        println!("MQTT incoming publish received.");
                        println!("Topic: {}", publish.topic);
                        if publish.topic == command_topic {
                            if let Err(error) = process_command(
                                &mqtt_client,
                                &identity,
                                &publish.payload,
                                &mut current_dir,
                            )
                            .await
                            {
                                eprintln!("Failed to process command: {}", error);
                                publish_log(
                                    &mqtt_client,
                                    &identity,
                                    "ERROR",
                                    format!("Failed to process command: {}", error),
                                )
                                .await;
                            }
                        }
                    }
                    // =================================================
                    // MQTT CONNECT / RECONNECT
                    // =================================================
                    Ok(Event::Incoming(Packet::ConnAck(connack))) => {
                        println!("MQTT event: Incoming(ConnAck({:?}))", connack);
                        println!("Re-subscribing to command topic after (re)connect...");
                        if let Err(error) = mqtt_client
                            .subscribe(command_topic.clone(), QoS::AtLeastOnce)
                            .await
                        {
                            eprintln!("Failed to re-subscribe after reconnect: {}", error);
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
                    Ok(Event::Incoming(packet)) => {
                        println!("MQTT event: Incoming({:?})", packet);
                    }
                    Ok(Event::Outgoing(packet)) => {
                        println!("MQTT event: Outgoing({:?})", packet);
                    }
                    Err(error) => {
                        eprintln!("MQTT event loop error: {}", error);
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
            // =================================================
            // METRICS
            // =================================================
            _ = metrics_interval.tick() => {
                if let Err(error) = publish_metrics(&mqtt_client, &identity, &mut system).await {
                    eprintln!("Failed to publish metrics: {}", error);
                    publish_log(
                        &mqtt_client,
                        &identity,
                        "ERROR",
                        format!("Failed to publish metrics: {}", error),
                    )
                    .await;
                }
            }
        }
    }
}
