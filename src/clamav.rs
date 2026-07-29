use anyhow::{Context, Result};
use std::process::Command;
use std::sync::LazyLock;

#[derive(Debug, Clone)]
pub struct ClamAvInfo {
    pub signature_version: String,
    pub signature_count: String,
    pub build_info: String,
    pub is_clamscan_available: bool,
    pub is_freshclam_available: bool,
    pub is_clamd_available: bool,
}

static CLAMAV_INFO: LazyLock<ClamAvInfo> = LazyLock::new(|| detect_clamav().unwrap_or_else(|_| ClamAvInfo {
    signature_version: "Unknown".into(),
    signature_count: "Unknown".into(),
    build_info: String::new(),
    is_clamscan_available: false,
    is_freshclam_available: false,
    is_clamd_available: false,
}));

pub fn get_info() -> &'static ClamAvInfo {
    &CLAMAV_INFO
}

fn detect_clamav() -> Result<ClamAvInfo> {
    let clamscan_version = get_command_output("clamscan", &["--version"])
        .unwrap_or_else(|_| "Not found".into());

    let is_clamscan_available = which_command("clamscan");
    let is_freshclam_available = which_command("freshclam");
    let is_clamd_available = which_command("clamd");

    // Parse signature info from clamscan version output
    let (signature_version, signature_count, build_info) =
        parse_clamscan_version(&clamscan_version);

    Ok(ClamAvInfo {
        signature_version,
        signature_count,
        build_info,
        is_clamscan_available,
        is_freshclam_available,
        is_clamd_available,
    })
}

fn get_command_output(cmd: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .context(format!("Failed to execute {}", cmd))?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn which_command(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn parse_clamscan_version(output: &str) -> (String, String, String) {
    let mut sig_version = "Unknown".to_string();
    let mut sig_count = "Unknown".to_string();
    let mut build_info = String::new();

    for line in output.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.contains("clamav") && line_lower.contains("/") {
            // e.g., "ClamAV 1.0.7/27320/Wed Jan  8 08:28:22 2025"
            let parts: Vec<&str> = line.splitn(3, '/').collect();
            if parts.len() >= 2 {
                sig_count = parts[1].trim().to_string();
            }
            if parts.len() >= 3 {
                sig_version = parts[2].trim().to_string();
            }
            if !parts.is_empty() {
                build_info = parts[0].trim().to_string();
            }
        }
    }

    // If the version line format is the compact one-line format
    if sig_version == "Unknown" {
        let parts: Vec<&str> = output.splitn(3, '/').collect();
        if parts.len() >= 2 {
            sig_count = parts[1].trim().to_string();
        }
        if parts.len() >= 3 {
            sig_version = parts[2].trim().to_string();
        }
        if !parts.is_empty() && build_info.is_empty() {
            build_info = parts[0].trim().to_string();
        }
    }

    (sig_version, sig_count, build_info)
}

/// Check if ClamAV daemon is running
pub fn is_clamd_running() -> bool {
    Command::new("pgrep")
        .arg("clamd")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
