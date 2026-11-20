use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
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
    if let Some(certs_dir) = crate::utils::snap_cvdcerts_dir() {
        version_args.push("--cvdcertsdir".into());
        version_args.push(certs_dir.to_string_lossy().to_string());
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
        .context("SNAP_USER_COMMON is not set; not running inside a snap")?;
    let certs_dir =
        crate::utils::snap_cvdcerts_dir().context("SNAP is not set; not running inside a snap")?;

    std::fs::create_dir_all(&db_dir)
        .with_context(|| format!("Failed to create database directory {}", db_dir.display()))?;

    let config_path = snap_freshclam_config_path()
        .context("SNAP_USER_COMMON is not set; not running inside a snap")?;

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

/// The database file for `stem` ("main" or "daily"), preferring `.cvd` over
/// `.cld`, but only if it actually contains data. A zero-length file left by an
/// interrupted download is not usable.
fn database_file(db_dir: &Path, stem: &str) -> Option<PathBuf> {
    ["cvd", "cld"].iter().find_map(|ext| {
        let path = db_dir.join(format!("{}.{}", stem, ext));
        let usable = std::fs::metadata(&path)
            .map(|meta| meta.is_file() && meta.len() > 0)
            .unwrap_or(false);
        usable.then_some(path)
    })
}

/// Whether `db` has the detached `<name>-<version>.<ext>.sign` file next to it.
///
/// Without one ClamAV falls back to the legacy MD5/RSA signature embedded in
/// the CVD header, which still works, so there is nothing for us to verify.
fn has_sign_file(db_dir: &Path, db: &Path) -> bool {
    let (Some(stem), Some(ext)) = (
        db.file_stem().and_then(|s| s.to_str()),
        db.extension().and_then(|e| e.to_str()),
    ) else {
        return false;
    };
    let prefix = format!("{}-", stem);
    let suffix = format!(".{}.sign", ext);

    std::fs::read_dir(db_dir)
        .map(|entries| {
            entries.filter_map(|e| e.ok()).any(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with(&prefix) && name.ends_with(&suffix)
            })
        })
        .unwrap_or(false)
}

/// Whether the snap's signature database already contains usable `main` and
/// `daily` files (`.cvd`/`.cld`). Used to decide whether a download is needed.
pub fn snap_database_available() -> bool {
    let Some(db_dir) = crate::utils::snap_database_dir() else {
        return false;
    };

    database_file(&db_dir, "main").is_some() && database_file(&db_dir, "daily").is_some()
}

/// Identifies the current database files by name, size and modification time,
/// so a successful verification is not repeated until the database changes.
/// The detached signatures are included too: a stale `.sign` next to an
/// otherwise unchanged CVD is what makes clamscan reject the database.
fn database_fingerprint(db_dir: &Path) -> Option<String> {
    let mut parts = Vec::new();
    for entry in std::fs::read_dir(db_dir).ok()?.filter_map(|e| e.ok()) {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let relevant = name.ends_with(".cvd")
            || name.ends_with(".cld")
            || name.ends_with(".cud")
            || name.ends_with(".sign");
        if !relevant {
            continue;
        }

        let meta = entry.metadata().ok()?;
        let nanos = meta
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_nanos();
        parts.push(format!("{}:{}:{}", name, meta.len(), nanos));
    }

    parts.sort();
    (!parts.is_empty()).then(|| parts.join("\n"))
}

/// Stamp recording which database the last successful verification covered.
/// It lives outside the database directory so freshclam never mistakes it for
/// a signature file.
fn verification_stamp_path(db_dir: &Path) -> Option<PathBuf> {
    db_dir.parent().map(|p| p.join(".clamtk-db-verified"))
}

fn database_verification_cached(db_dir: &Path, fingerprint: &str) -> bool {
    verification_stamp_path(db_dir)
        .and_then(|path| std::fs::read_to_string(path).ok())
        .is_some_and(|stamp| stamp.trim() == fingerprint)
}

fn mark_database_verified(db_dir: &Path, fingerprint: &str) {
    if let Some(stamp) = verification_stamp_path(db_dir) {
        if let Err(e) = std::fs::write(&stamp, fingerprint) {
            log::warn!("could not write {}: {}", stamp.display(), e);
        }
    }
}

/// Outcome of checking a database's digital signature.
#[derive(Debug, PartialEq, Eq)]
enum DatabaseVerdict {
    /// The signed files verified, or there was nothing to verify.
    Ok,
    /// No usable verifier is available here (missing sigtool/certs).
    CannotVerify(String),
    /// The certificate is outside its validity window: the clock is wrong.
    Clock(String),
    /// The files or their signatures are damaged.
    Invalid(String),
}

/// Pick the most useful line out of sigtool's output.
fn verification_detail(output: &str) -> String {
    let mut first = "";
    for line in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if first.is_empty() {
            first = line;
        }
        let lower = line.to_lowercase();
        if lower.contains("not yet valid")
            || lower.contains("has expired")
            || lower.contains("failed to verify")
            || lower.contains("signature")
            || lower.contains("error:")
        {
            return line.to_string();
        }
    }
    first.to_string()
}

fn classify_verification_failure(output: &str) -> DatabaseVerdict {
    let lower = output.to_lowercase();
    let detail = verification_detail(output);

    if lower.contains("not yet valid")
        || lower.contains("has expired")
        || lower.contains("certificate expired")
    {
        // Re-downloading cannot help: the signing certificate is valid, the
        // device clock is not.
        DatabaseVerdict::Clock(detail)
    } else if lower.contains("no such file")
        || lower.contains("cannot open shared object")
        || lower.contains("command not found")
    {
        DatabaseVerdict::CannotVerify(detail)
    } else {
        DatabaseVerdict::Invalid(detail)
    }
}

/// Verify one database file with the bundled `sigtool`, which reports the real
/// reason instead of clamscan's generic "Can't verify database integrity".
fn verify_database_file(db: &Path) -> DatabaseVerdict {
    let Some(certs) = crate::utils::snap_cvdcerts_dir() else {
        return DatabaseVerdict::CannotVerify(
            "the snap certificate directory is unavailable".into(),
        );
    };

    let output = match Command::new("sigtool")
        .arg("--verify")
        .arg(db)
        .arg("--cvdcertsdir")
        .arg(&certs)
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            return DatabaseVerdict::CannotVerify(format!("could not run sigtool: {}", e));
        }
    };

    if output.status.success() {
        return DatabaseVerdict::Ok;
    }

    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    classify_verification_failure(&text)
}

/// Verify every `.cvd`/`.cld`/`.cud` file that has a detached signature.
/// ClamAV loads all of them from the database directory, so a damaged extra
/// file breaks the scan just as surely as a damaged `main.cvd`.
fn verify_database(db_dir: &Path) -> DatabaseVerdict {
    let Ok(entries) = std::fs::read_dir(db_dir) else {
        return DatabaseVerdict::Ok;
    };

    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|path| {
            path.extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext == "cvd" || ext == "cld" || ext == "cud")
        })
        .collect();
    files.sort();

    let mut verdict = DatabaseVerdict::Ok;

    for db in files {
        if !has_sign_file(db_dir, &db) {
            continue;
        }

        match verify_database_file(&db) {
            DatabaseVerdict::Ok => {}
            DatabaseVerdict::Clock(detail) => return DatabaseVerdict::Clock(detail),
            DatabaseVerdict::Invalid(detail) => verdict = DatabaseVerdict::Invalid(detail),
            DatabaseVerdict::CannotVerify(detail) => {
                if verdict == DatabaseVerdict::Ok {
                    verdict = DatabaseVerdict::CannotVerify(detail);
                }
            }
        }
    }

    verdict
}

/// Remove the downloaded database files and the verification stamp so
/// `ensure_database()` fetches a clean copy. Only files this app owns are
/// touched.
fn reset_snap_database() -> Result<()> {
    let db_dir = crate::utils::snap_database_dir()
        .context("SNAP_USER_COMMON is not set; not running inside a snap")?;

    if let Ok(entries) = std::fs::read_dir(&db_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let is_database = name.ends_with(".cvd")
                || name.ends_with(".cld")
                || name.ends_with(".cud")
                || name.ends_with(".sign")
                || name == "freshclam.dat";
            if !is_database || !entry.file_type().is_ok_and(|t| t.is_file()) {
                continue;
            }

            let path = entry.path();
            std::fs::remove_file(&path)
                .with_context(|| format!("Failed to remove {}", path.display()))?;
        }
    }

    if let Some(stamp) = verification_stamp_path(&db_dir) {
        let _ = std::fs::remove_file(stamp);
    }

    Ok(())
}

/// Make sure the snap's database is present and passes ClamAV's signature
/// check before a scan starts.
///
/// A database left behind by a killed download (or a stale detached signature)
/// makes clamscan abort with "Can't verify database integrity" before it scans
/// a single file. Rather than surfacing that, verify the database with the
/// bundled `sigtool` and re-download it when it is damaged. The check runs only
/// when the database files change; the result is cached in a stamp file.
pub fn prepare_snap_database<F: FnMut(&str)>(mut on_status: F) -> Result<()> {
    if !crate::utils::is_running_in_snap() {
        return Ok(());
    }

    let db_dir = crate::utils::snap_database_dir()
        .context("SNAP_USER_COMMON is not set; not running inside a snap")?;

    if !snap_database_available() {
        on_status("Downloading virus definitions...");
        ensure_database()?;
    }

    if !snap_database_available() {
        anyhow::bail!(
            "the virus database is still missing or incomplete. Check your network connection and try again"
        );
    }

    let fingerprint =
        database_fingerprint(&db_dir).context("could not read the downloaded virus database")?;
    if database_verification_cached(&db_dir, &fingerprint) {
        return Ok(());
    }

    on_status("Verifying virus database...");
    match verify_database(&db_dir) {
        DatabaseVerdict::Ok => {
            mark_database_verified(&db_dir, &fingerprint);
            Ok(())
        }
        DatabaseVerdict::CannotVerify(detail) => {
            // Let clamscan decide: it may still load the database through the
            // legacy signature embedded in the file.
            log::warn!("could not verify the virus database: {}", detail);
            Ok(())
        }
        DatabaseVerdict::Clock(detail) => anyhow::bail!(
            "the virus database certificate is not valid at the current system time ({}). Check that the date and time are correct and try again",
            detail
        ),
        DatabaseVerdict::Invalid(detail) => {
            log::warn!(
                "virus database failed verification ({}); downloading a clean copy",
                detail
            );

            on_status("Repairing virus database...");
            reset_snap_database()?;
            on_status("Downloading virus definitions...");
            ensure_database()?;

            if !snap_database_available() {
                anyhow::bail!(
                    "the virus database could not be repaired automatically ({}). Check your network connection and try again",
                    detail
                );
            }

            let fingerprint = database_fingerprint(&db_dir)
                .context("could not read the downloaded virus database")?;
            match verify_database(&db_dir) {
                DatabaseVerdict::Ok => {
                    mark_database_verified(&db_dir, &fingerprint);
                    Ok(())
                }
                DatabaseVerdict::CannotVerify(detail) => {
                    log::warn!("could not verify the repaired virus database: {}", detail);
                    Ok(())
                }
                DatabaseVerdict::Clock(detail) => anyhow::bail!(
                    "the virus database certificate is not valid at the current system time ({}). Check that the date and time are correct and try again",
                    detail
                ),
                DatabaseVerdict::Invalid(detail) => anyhow::bail!(
                    "the virus database is damaged and could not be repaired automatically ({}). Try again later",
                    detail
                ),
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::testutil;

    #[test]
    fn database_requires_non_empty_main_and_daily() {
        let _guard = testutil::env_lock();
        let common = testutil::temp_dir("clamav_database_available");
        testutil::set_snap_env(&common);
        let db_dir = common.join("clamav");
        std::fs::create_dir_all(&db_dir).unwrap();

        // Only bytecode: not enough to scan.
        std::fs::write(db_dir.join("bytecode.cvd"), b"x").unwrap();
        assert!(!snap_database_available());

        // main alone is still not enough.
        std::fs::write(db_dir.join("main.cvd"), b"x").unwrap();
        assert!(!snap_database_available());

        // A zero-length file is what an interrupted download leaves behind.
        std::fs::write(db_dir.join("daily.cvd"), b"").unwrap();
        assert!(!snap_database_available());

        std::fs::write(db_dir.join("daily.cvd"), b"x").unwrap();
        assert!(snap_database_available());

        testutil::cleanup(&common);
        // Do not leave the fake snap environment behind for later tests.
        std::env::remove_var("SNAP");
        std::env::remove_var("SNAP_NAME");
        std::env::remove_var("SNAP_USER_COMMON");
    }

    #[test]
    fn clock_and_corruption_failures_are_distinguished() {
        assert!(matches!(
            classify_verification_failure(
                "Error verifying signature: ... certificate is not yet valid\n\
                 ERROR: verify: Failed to verify file"
            ),
            DatabaseVerdict::Clock(_)
        ));
        assert!(matches!(
            classify_verification_failure(
                "LibClamAV Error: cli_cvdload: Can't verify CVD file main.cvd: MD5 hash does not match"
            ),
            DatabaseVerdict::Invalid(_)
        ));
        assert!(matches!(
            classify_verification_failure(
                "verify: Failed to create verifier: ... no such file or directory"
            ),
            DatabaseVerdict::CannotVerify(_)
        ));
    }

    #[test]
    fn detached_signature_is_recognised() {
        let db_dir = testutil::temp_dir("clamav_sign_file");
        let cvd = db_dir.join("main.cvd");
        std::fs::write(&cvd, b"x").unwrap();
        assert!(!has_sign_file(&db_dir, &cvd));

        std::fs::write(db_dir.join("main-63.cvd.sign"), b"x").unwrap();
        assert!(has_sign_file(&db_dir, &cvd));

        testutil::cleanup(&db_dir);
    }
}
