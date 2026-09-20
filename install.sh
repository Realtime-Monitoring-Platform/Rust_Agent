#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_URL="${MONITORING_AGENT_REPOSITORY:-https://github.com/Realtime-Monitoring-Platform/Rust_Agent.git}"
INSTALL_DIR="/opt/monitoring-agent"
BINARY_PATH="/usr/local/bin/monitoring-agent"
CONFIG_DIR="/etc/monitoring-agent"
CONFIG_FILE="${CONFIG_DIR}/agent.env"
SERVICE_NAME="monitoring-agent.service"
PROVISIONING_TOKEN=""
DEVICE_SERVICE_URL="${MONITORING_DEVICE_SERVICE_URL:-http://192.168.1.205:9005/api/v1/devices/provision}"
MQTT_HOST_VALUE="${MONITORING_MQTT_HOST:-192.168.1.122}"
MQTT_PORT_VALUE="${MONITORING_MQTT_PORT:-8883}"

usage() {
    cat <<'EOF'
Usage: install.sh --token TOKEN [options]

Options:
  --token TOKEN       Provisioning token for a new device.
  --device-url URL    Device provisioning endpoint.
  --mqtt-host HOST    MQTT broker host.
  --mqtt-port PORT    MQTT broker TLS port.
  --help              Show this help.
EOF
}
    
while [[ $# -gt 0 ]]; do
    case "$1" in
        --token) 
            [[ $# -ge 2 ]] || { echo "Missing value for --token" >&2; exit 2; }
            PROVISIONING_TOKEN="$2"
            shift 2
            ;;
        --device-url)
            # condition  || command
            [[ $# -ge 2 ]] || { echo "Missing value for --device-url" >&2; exit 2; }
            DEVICE_SERVICE_URL="$2"
            shift 2
            ;;
        --mqtt-host)
            [[ $# -ge 2 ]] || { echo "Missing value for --mqtt-host" >&2; exit 2; }
            MQTT_HOST_VALUE="$2"
            shift 2
            ;;
        --mqtt-port)
            [[ $# -ge 2 ]] || { echo "Missing value for --mqtt-port" >&2; exit 2; }
            MQTT_PORT_VALUE="$2"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Run this installer as root, for example: curl ... | sudo bash -s -- --token TOKEN" >&2
    exit 1
fi


command -v cargo >/dev/null 2>&1 || {
    echo "Rust/Cargo is required . install it " >&2
    exit 1
}


command -v systemctl >/dev/null 2>&1 || {
    echo "systemd is required for the service installation" >&2
    exit 1
}




build_dir="$(mktemp -d)"
trap 'rm -rf "$build_dir"' EXIT

echo "Downloading monitoring agent source..."
git clone --depth 1 "$REPOSITORY_URL" "$build_dir/source" >/dev/null
echo "Building monitoring agent..."
cargo build --release --manifest-path "$build_dir/source/Cargo.toml"




install -d -m 0755 "$INSTALL_DIR" "$CONFIG_DIR"
install -m 0755 "$build_dir/source/target/release/rust-agent" "$BINARY_PATH"



cat > "$CONFIG_FILE" <<EOF
MONITORING_DEVICE_SERVICE_URL=$DEVICE_SERVICE_URL
MONITORING_MQTT_HOST=$MQTT_HOST_VALUE
MONITORING_MQTT_PORT=$MQTT_PORT_VALUE
EOF


chmod 0600 "$CONFIG_FILE"

if [[ ! -f /root/.monitoring-agent/identity.json ]]; then
    [[ -n "$PROVISIONING_TOKEN" ]] || {
        echo "A provisioning token is required for a new device (--token TOKEN)." >&2
        exit 1
    }
    echo "Provisioning device (the token is not saved)..."
    "$BINARY_PATH" --token "$PROVISIONING_TOKEN"
fi


cat > "/etc/systemd/system/$SERVICE_NAME" <<EOF
[Unit]
Description=Realtime Monitoring Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile=$CONFIG_FILE
ExecStart=$BINARY_PATH
Restart=on-failure
RestartSec=5
WorkingDirectory=/root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"
systemctl --no-pager --full status "$SERVICE_NAME" || true
echo "Monitoring agent installed and enabled as $SERVICE_NAME."