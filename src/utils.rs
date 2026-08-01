/// Format a file size in human-readable format
pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format elapsed time in a human-readable way
pub fn format_duration(seconds: f64) -> String {
    if seconds < 1.0 {
        format!("{:.0} ms", seconds * 1000.0)
    } else if seconds < 60.0 {
        format!("{:.1} s", seconds)
    } else {
        let mins = (seconds / 60.0) as u64;
        let secs = (seconds % 60.0) as u64;
        format!("{}m {}s", mins, secs)
    }
}

/// Truncate a path for display
pub fn truncate_path(path: &str, max_len: usize) -> String {
    if path.len() <= max_len {
        path.to_string()
    } else {
        let start = path.len() - max_len + 3;
        format!("...{}", &path[start..])
    }
}

/// Get the display name for a scan type
pub fn scan_type_display(scan_type: &crate::scanner::ScanType) -> &'static str {
    match scan_type {
        crate::scanner::ScanType::File => "File Scan",
        crate::scanner::ScanType::Directory => "Directory Scan",
        crate::scanner::ScanType::Home => "Home Directory Scan",
        crate::scanner::ScanType::FullSystem => "Full System Scan",
        crate::scanner::ScanType::Custom => "Custom Scan",
    }
}

/// Detect whether the process is running inside a snap (strict confinement).
pub fn is_running_in_snap() -> bool {
    std::env::var_os("SNAP").is_some()
}

/// The real home directory of the invoking user. Inside a snap, `$HOME` is
/// redirected to the snap's private data directory, but the actual user home
/// (used by "Scan Home") is the one listed in /etc/passwd for the current UID.
pub fn real_home_dir() -> std::path::PathBuf {
    if is_running_in_snap() {
        if let Some(uid) = current_uid() {
            if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
                for line in passwd.lines() {
                    let fields: Vec<&str> = line.split(':').collect();
                    if fields.len() >= 6 && fields[2].parse::<u32>().ok() == Some(uid) {
                        return std::path::PathBuf::from(fields[5]);
                    }
                }
            }
        }
    }
    dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("/home"))
}

/// Read the real UID of the process from /proc/self/status (Linux). The
/// "Uid:" line lists real, effective, saved-set and filesystem UIDs.
fn current_uid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

/// When running inside a snap, the bundled ClamAV keeps its signature database
/// under `$SNAP_USER_DATA/clamav`. This directory is owned by the invoking
/// user and therefore writable, unlike `$SNAP_DATA` which is owned by root.
pub fn snap_database_dir() -> Option<std::path::PathBuf> {
    let snap_user_data = std::env::var_os("SNAP_USER_DATA")?;
    Some(std::path::Path::new(&snap_user_data).join("clamav"))
}

/// When running inside a snap, point libclamav at the code-signature
/// certificate bundled with the snap. The compiled-in default
/// (`/etc/clamav/certs`) refers to the host directory, which strict
/// confinement blocks.
pub fn snap_cvdcerts_dir() -> Option<std::path::PathBuf> {
    let snap = std::env::var_os("SNAP")?;
    Some(std::path::Path::new(&snap).join("etc/clamav/certs"))
}

/// Detect whether the host OS is Ubuntu (or an Ubuntu derivative) by reading
/// /etc/os-release. On Ubuntu, ClamAV updates its virus definitions
/// automatically through the freshclam service, so manual signature updates
/// are unnecessary and are therefore disabled.
pub fn is_host_ubuntu() -> bool {
    let content = match std::fs::read_to_string("/etc/os-release") {
        Ok(c) => c,
        Err(_) => return false,
    };

    content.lines().any(|line| {
        let line = line.trim();
        if let Some(id) = line.strip_prefix("ID=") {
            return id.trim() == "ubuntu";
        }
        if let Some(like) = line.strip_prefix("ID_LIKE=") {
            return like.split_whitespace().any(|id| id == "ubuntu");
        }
        false
    })
}
