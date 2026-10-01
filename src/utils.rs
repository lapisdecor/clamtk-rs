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

/// The snap's revision-independent writable data directory,
/// `$SNAP_USER_COMMON` (`~/snap/<name>/common`).
///
/// Everything the app must survive a `snap refresh` belongs here rather than in
/// `$SNAP_USER_DATA`: the latter embeds the revision, and snapd's AppArmor
/// profile grants write access only to the *current* revision directory
/// (`owner @{HOME}/snap/@{SNAP_INSTANCE_NAME}/@{SNAP_REVISION}/** wl`) while all
/// other revisions are read-only (`.../** mrkix`). Storing a path built from
/// `$SNAP_USER_DATA` therefore dangles after a refresh.
pub fn snap_common_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("SNAP_USER_COMMON")
        .map(std::path::PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        // Older/unusual environments may not export SNAP_USER_COMMON; the
        // revision directory still works for a single-revision install.
        .or_else(|| std::env::var_os("SNAP_USER_DATA").map(std::path::PathBuf::from))
}

/// True when `path` sits under a `~/snap/<name>/<revision>/...` directory and is
/// not under `common` — i.e. it is a revision-scoped path that snapd copied
/// forward from a previous revision and that can no longer be written to.
///
/// This is the shape of the `quarantine_dir` that older versions persisted,
/// which is what made startup fail with `Permission denied (os error 13)`
/// after a refresh. Anything else (a user-chosen location) is left alone.
pub fn is_stale_snap_path(path: &std::path::Path, common: &std::path::Path) -> bool {
    if path.starts_with(common) {
        return false;
    }
    let mut components = path.components();
    while let Some(component) = components.next() {
        if component.as_os_str() != "snap" {
            continue;
        }
        // ~/snap/<instance>/<revision>/... — the instance name is anything, the
        // revision is a number.
        let _instance = components.next();
        return components.next().is_some_and(|revision| {
            revision
                .as_os_str()
                .to_str()
                .is_some_and(|r| !r.is_empty() && r.chars().all(|ch| ch.is_ascii_digit()))
        });
    }
    false
}

/// Move one legacy revision-scoped file into its `$SNAP_USER_COMMON`
/// equivalent, unless the destination already exists. Best effort: a failure
/// only means the file is re-created at its new location.
fn adopt_legacy_file(legacy: &std::path::Path, target: &std::path::Path) {
    if !legacy.exists() || target.exists() {
        return;
    }
    if let Some(parent) = target.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            log::warn!("could not create {}: {}", parent.display(), e);
            return;
        }
    }
    match std::fs::rename(legacy, target) {
        Ok(()) => log::info!("migrated {} -> {}", legacy.display(), target.display()),
        Err(e) => {
            log::warn!("could not migrate {}: {}", legacy.display(), e);
            // Cross-device or otherwise unrenameable: fall back to a copy.
            match std::fs::copy(legacy, target) {
                Ok(_) => {
                    log::info!("copied {} -> {}", legacy.display(), target.display());
                    let _ = std::fs::remove_file(legacy);
                }
                Err(e) => log::warn!("could not copy {}: {}", legacy.display(), e),
            }
        }
    }
}

/// Move one legacy revision-scoped directory into its `$SNAP_USER_COMMON`
/// equivalent, unless the destination already exists. Best effort: on failure
/// the destination is simply re-created and the data re-downloaded.
fn adopt_legacy_dir(legacy: &std::path::Path, target: &std::path::Path) {
    if !legacy.is_dir() || target.exists() {
        return;
    }
    if let Some(parent) = target.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            log::warn!("could not create {}: {}", parent.display(), e);
            return;
        }
    }
    // Rename is cheap (same filesystem) even for the ~100 MB signature set.
    if let Err(e) = std::fs::rename(legacy, target) {
        log::warn!("could not migrate {}: {}", legacy.display(), e);
        return;
    }
    log::info!("migrated {} -> {}", legacy.display(), target.display());
}

/// Point the XDG base directories at `$SNAP_USER_COMMON` when running as a snap.
///
/// Without this, `dirs::config_dir()`/`data_dir()`/`cache_dir()` resolve against
/// `$HOME`, which snapd sets to the revision directory, so settings, history and
/// cached data would be tied to a single revision. Must be called before the
/// first `dirs::*` use.
pub fn init_persistent_dirs() {
    if !is_running_in_snap() {
        return;
    }
    let Some(common) = snap_common_dir() else {
        return;
    };

    // Carry the per-revision data forward once, so settings, scan history and
    // the downloaded virus signatures survive the move to the common directory.
    if let Some(user_data) = std::env::var_os("SNAP_USER_DATA") {
        let legacy = std::path::PathBuf::from(user_data);
        for (sub, file) in [(".config", "config.json"), (".local/share", "history.json")] {
            adopt_legacy_file(
                &legacy.join(sub).join("clamtk-rs").join(file),
                &common.join(sub).join("clamtk-rs").join(file),
            );
        }
        adopt_legacy_dir(&legacy.join("clamav"), &common.join("clamav"));
        // The generated config is rewritten on every run, so it needs no move.
        let _ = std::fs::remove_file(legacy.join("freshclam.conf"));
    }

    for (var, sub) in [
        ("XDG_CONFIG_HOME", ".config"),
        ("XDG_DATA_HOME", ".local/share"),
        ("XDG_CACHE_HOME", ".cache"),
    ] {
        let current = std::env::var_os(var);
        let already_revision_independent = current
            .as_deref()
            .is_some_and(|v| std::path::Path::new(v).starts_with(&common));
        if !already_revision_independent {
            std::env::set_var(var, common.join(sub));
        }
    }
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
/// under `$SNAP_USER_COMMON/clamav`. This directory is owned by the invoking
/// user and therefore writable, unlike `$SNAP_DATA` which is owned by root, and
/// unlike `$SNAP_USER_DATA` it survives a refresh instead of forcing a
/// re-download of the ~100 MB signature sets on every snap update.
pub fn snap_database_dir() -> Option<std::path::PathBuf> {
    Some(snap_common_dir()?.join("clamav"))
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
pub(crate) mod testutil {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, MutexGuard};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Serialises tests that change the process environment, which is global.
    pub(crate) fn env_lock() -> MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A fresh, empty scratch directory unique to the calling test.
    pub(crate) fn temp_dir(name: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("clamtk_rs_{}_{}_{}", name, std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("could not create scratch directory");
        dir
    }

    /// Remove a scratch directory, restoring write permission first.
    pub(crate) fn cleanup(dir: &Path) {
        make_writable(dir);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Restore write permission recursively, so a test can clean up after
    /// itself even if it made a directory read-only.
    pub(crate) fn make_writable(dir: &Path) {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    make_writable(&entry.path());
                }
            }
        }
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revision_scoped_paths_are_stale() {
        let common = std::path::Path::new("/home/u/snap/clamtk-rs/common");
        assert!(is_stale_snap_path(
            std::path::Path::new("/home/u/snap/clamtk-rs/39/quarantine"),
            common
        ));
        assert!(is_stale_snap_path(
            std::path::Path::new("/home/u/snap/clamtk-rs/39"),
            common
        ));
        assert!(is_stale_snap_path(
            std::path::Path::new("/home/u/snap/clamtk-rs/1007/clamav"),
            common
        ));
    }

    #[test]
    fn common_and_user_chosen_paths_are_not_stale() {
        let common = std::path::Path::new("/home/u/snap/clamtk-rs/common");
        assert!(!is_stale_snap_path(
            std::path::Path::new("/home/u/snap/clamtk-rs/common/quarantine"),
            common
        ));
        assert!(!is_stale_snap_path(
            std::path::Path::new("/srv/clamtk-quarantine"),
            common
        ));
        assert!(!is_stale_snap_path(
            std::path::Path::new("/home/u/.local/share/clamtk-rs/quarantine"),
            common
        ));
        // A directory that merely starts with "snap" is unrelated.
        assert!(!is_stale_snap_path(
            std::path::Path::new("/home/u/snapshots/clamtk/quarantine"),
            common
        ));
        // Another snap's common directory is not ours to rewrite.
        assert!(!is_stale_snap_path(
            std::path::Path::new("/home/u/snap/other-snap/common/quarantine"),
            common
        ));
    }

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
