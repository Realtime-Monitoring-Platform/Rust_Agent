use std::env;
use std::path::PathBuf;

// ============================================================
// DEVICE PATHS
// ============================================================
pub struct AgentPaths {
    pub agent_directory: PathBuf,
    pub pki_directory: PathBuf,
    pub ca_certificate: PathBuf,
    pub device_certificate: PathBuf,
    pub device_key: PathBuf,
    pub device_csr: PathBuf,
    pub identity: PathBuf,
}

// ============================================================
// BUILD PATHS
// ============================================================
pub fn build_paths() -> Result<AgentPaths, Box<dyn std::error::Error>> {
    let home = env::var("HOME").map_err(|_| "HOME environment variable is not available")?;
    let agent_directory = PathBuf::from(home).join(".monitoring-agent");
    let pki_directory = agent_directory.join("pki");
    Ok(AgentPaths {
        ca_certificate: pki_directory.join("ca.crt"),
        device_certificate: pki_directory.join("device.crt"),
        device_key: pki_directory.join("device.key"),
        device_csr: pki_directory.join("device.csr"),
        identity: agent_directory.join("identity.json"),
        agent_directory,
        pki_directory,
    })
}
