/// Play a short bird-tweet sound to notify the user that a scan has finished.
/// The WAV is bundled in the app resources; it is extracted to the user's
/// cache directory and played with whatever audio player is available.
/// Does nothing (with a logged warning) if no player can be found.
pub fn play_chirp() {
    let data = match gio::resources_lookup_data(
        "/com/gatochalupa/clamtk-rs/sounds/chirp.wav",
        gio::ResourceLookupFlags::NONE,
    ) {
        Ok(bytes) => bytes,
        Err(e) => {
            log::warn!("chirp.wav resource not found: {}", e);
            return;
        }
    };

    let cache_dir = dirs::cache_dir().unwrap_or_else(std::env::temp_dir);
    let sound_dir = cache_dir.join("clamtk-rs");
    if let Err(e) = std::fs::create_dir_all(&sound_dir) {
        log::warn!(
            "could not create sound directory {}: {}",
            sound_dir.display(),
            e
        );
        return;
    }
    let wav_path = sound_dir.join("chirp.wav");
    if let Err(e) = std::fs::write(&wav_path, data.as_ref()) {
        log::warn!("could not write {}: {}", wav_path.display(), e);
        return;
    }
    log::debug!("chirp.wav extracted to {}", wav_path.display());

    // Try the available players in order of preference, both by name and by
    // their usual absolute paths, without relying on the `which` binary.
    let mut candidates: Vec<(&str, Vec<&str>)> = vec![
        ("paplay", vec![]),
        ("aplay", vec![]),
        ("canberra-gtk-play", vec!["-f"]),
    ];
    candidates.push(("/usr/bin/paplay", vec![]));
    candidates.push(("/usr/bin/aplay", vec![]));
    candidates.push(("/usr/bin/canberra-gtk-play", vec!["-f"]));
    candidates.push(("/bin/aplay", vec![]));

    for (player, args) in candidates {
        let mut cmd = std::process::Command::new(player);
        cmd.args(&args).arg(&wav_path);
        match cmd.spawn() {
            Ok(_) => return,
            Err(e) => log::warn!("failed to start {}: {}", player, e),
        }
    }

    log::warn!("no audio player available to play {}", wav_path.display());
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chirp_wav_is_bundled_and_playable() {
        gio::resources_register_include!("clamtk_rs.gresource");
        let data = gio::resources_lookup_data(
            "/com/gatochalupa/clamtk-rs/sounds/chirp.wav",
            gio::ResourceLookupFlags::NONE,
        );
        assert!(data.is_ok(), "resource lookup failed: {:?}", data.err());
        assert!(data.unwrap().len() > 100, "chirp.wav is too small");
    }

    #[test]
    fn play_chirp_starts_a_player() {
        gio::resources_register_include!("clamtk_rs.gresource");
        // Must not panic regardless of whether an audio player is available.
        play_chirp();
    }
}
