use anyhow::{Context, Result};
use std::process::Command;
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub struct ClamAvInfo {
    pub signature_version: String,
    pub signature_count: String,
    pub build_info: String,
    pub is_clamscan_available: bool,
    pub is_freshclam_available: bool,
    pub is_clamd_available: bool,
}

static CLAMAV_INFO: Mutex<Option<ClamAvInfo>> = Mutex::new(None);

/// Return the cached ClamAV information, detecting it on first call.
pub fn get_info() -> ClamAvInfo {
    if let Ok(guard) = CLAMAV_INFO.lock() {
        if let Some(info) = guard.as_ref() {
            return info.clone();
        }
    }
    refresh_info()
}

/// Re-detect the ClamAV information (e.g. after the virus database was
/// downloaded) and update the cache.
pub fn refresh_info() -> ClamAvInfo {
    let info = detect_clamav().unwrap_or_else(|_| ClamAvInfo {
        signature_version: "Unknown".into(),
        signature_count: "Unknown".into(),
        build_info: String::new(),
        is_clamscan_available: false,
        is_freshclam_available: false,
        is_clamd_available: false,
    });
    if let Ok(mut guard) = CLAMAV_INFO.lock() {
        *guard = Some(info.clone());
    }
    info
}

fn detect_clamav() -> Result<ClamAvInfo> {
    // Inside a snap, clamscan must be pointed at the bundled signature
    // database so `--version` reports the actual signature version/count
    // instead of an empty (host) database.
    let mut version_args: Vec<String> = vec!["--version".into()];
    if let Some(db_dir) = crate::utils::snap_database_dir() {
        version_args.push("--database".into());
        version_args.push(db_dir.to_string_lossy().to_string());
    }

    let clamscan_version = get_command_output(
        "clamscan",
        &version_args.iter().map(String::as_str).collect::<Vec<_>>(),
    )
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

pub(crate) fn which_command(cmd: &str) -> bool {
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

/// The freshclam.conf used by the snap's bundled freshclam. It is written to
/// the snap's writable data directory because the compiled-in default
/// (`/etc/clamav/freshclam.conf`) is not present inside the snap.
pub fn snap_freshclam_config_path() -> Option<std::path::PathBuf> {
    crate::utils::snap_database_dir().and_then(|db| db.parent().map(|p| p.join("freshclam.conf")))
}

/// Write a freshclam.conf suitable for the snap's bundled ClamAV and return
/// its path. Called before running freshclam inside a snap.
pub fn write_snap_freshclam_config() -> Result<std::path::PathBuf> {
    let db_dir = crate::utils::snap_database_dir()
        .context("SNAP_USER_DATA is not set; not running inside a snap")?;
    let certs_dir = crate::utils::snap_cvdcerts_dir()
        .context("SNAP is not set; not running inside a snap")?;

    std::fs::create_dir_all(&db_dir)
        .with_context(|| format!("Failed to create database directory {}", db_dir.display()))?;

    let config_path = snap_freshclam_config_path()
        .context("SNAP_USER_DATA is not set; not running inside a snap")?;

    let config = format!(
        "DatabaseDirectory {}\n\
         DatabaseMirror database.clamav.net\n\
         cvdcertsdir {}\n\
         TestDatabases no\n\
         LogTime true\n\
         ConnectTimeout 30\n\
         ReceiveTimeout 30\n\
         MaxAttempts 5\n",
        db_dir.display(),
        certs_dir.display(),
    );
    std::fs::write(&config_path, config)
        .with_context(|| format!("Failed to write {}", config_path.display()))?;

    Ok(config_path)
}

/// Whether the snap's signature database already contains a usable database
/// file (`.cvd`/`.cld`). Used to decide whether a download is needed.
pub fn snap_database_available() -> bool {
    let db_dir = match crate::utils::snap_database_dir() {
        Some(d) => d,
        None => return false,
    };

    std::fs::read_dir(&db_dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .any(|e| {
                    e.path()
                        .extension()
                        .map(|ext| ext == "cvd" || ext == "cld")
                        .unwrap_or(false)
                })
        })
        .unwrap_or(false)
}

/// Make sure the virus database is available before scanning. Inside a snap
/// the database lives in the snap's writable data directory; if it is missing
/// (or empty), freshclam is run once to download it. Returns true when a
/// download was actually performed.
pub fn ensure_database() -> Result<bool> {
    if !crate::utils::is_running_in_snap() {
        return Ok(false);
    }

    if snap_database_available() {
        return Ok(false);
    }

    let db_dir = crate::utils::snap_database_dir().unwrap();
    let config_path = write_snap_freshclam_config()?;
    // Note: pass --datadir is intentionally NOT used. In freshclam 1.5.3,
    // combining --config-file with --datadir makes it fall back to the
    // compiled-in /var/lib/clamav and ignore the config. The config's
    // DatabaseDirectory alone is sufficient.
    let output = Command::new("freshclam")
        .arg("--config-file")
        .arg(&config_path)
        .output()
        .context("Failed to launch freshclam")?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        anyhow::bail!(
            "Could not download the virus database: {}",
            stderr.trim().lines().last().unwrap_or("unknown error")
        );
    }

    log::info!("Downloaded ClamAV virus database to {}", db_dir.display());
    log::debug!("{}", stdout.trim());
    Ok(true)
}

/// Check if ClamAV daemon is running
pub fn is_clamd_running() -> bool {
    Command::new("pgrep")
        .arg("clamd")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
