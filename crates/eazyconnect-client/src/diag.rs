use std::path::Path;
use std::time::Duration;

use eazyconnect_core::{
    discover_masters, load_client_config, DiscoveredMaster, DEFAULT_DISCOVERY_PORT,
};
use eazyconnect_hw::{collect_hardware_report, SystemHardwareReport};
use serde::{Deserialize, Serialize};

use crate::http::MasterHttpClient;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticReport {
    pub master_url: Option<String>,
    pub client_id: Option<String>,
    pub has_sealed_token: bool,
    pub tls_verify: bool,
    pub master_health_ok: Option<bool>,
    pub master_health_error: Option<String>,
    pub discovered_masters: Vec<DiscoveredMaster>,
    pub hardware: SystemHardwareReport,
}

pub async fn run_diagnostics(
    config_path: Option<&Path>,
    master_override: Option<&str>,
    discovery_timeout: Duration,
    client_for_probe: Option<&MasterHttpClient>,
) -> Result<DiagnosticReport, String> {
    let cfg = load_client_config(config_path)?;
    let master_url = master_override
        .map(ToString::to_string)
        .or_else(|| cfg.master.clone());

    let hardware = tokio::task::spawn_blocking(collect_hardware_report)
        .await
        .map_err(|e| format!("hardware probe join error: {e}"))?;

    let target = std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::BROADCAST),
        DEFAULT_DISCOVERY_PORT,
    );
    let discovered_masters = discover_masters(target, discovery_timeout)
        .await
        .unwrap_or_default();

    let (master_health_ok, master_health_error) = match client_for_probe {
        Some(client) => match client.health().await {
            Ok(_) => (Some(true), None),
            Err(e) => (Some(false), Some(e)),
        },
        None => (None, None),
    };

    Ok(DiagnosticReport {
        master_url,
        client_id: cfg.client_id,
        has_sealed_token: cfg.sealed_token_hex.is_some(),
        tls_verify: cfg.verify,
        master_health_ok,
        master_health_error,
        discovered_masters,
        hardware,
    })
}
