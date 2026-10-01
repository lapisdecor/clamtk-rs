use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: PathBuf,
    pub threat_name: String,
    pub quarantine_path: PathBuf,
    pub quarantined_at: chrono::DateTime<chrono::Local>,
    pub file_hash: String,
    pub file_size: u64,
    pub restored: bool,
}

pub fn quarantine_dir() -> PathBuf {
    crate::config::AppConfig::load()
        .map(|c| c.quarantine_dir)
        .unwrap_or_else(|_| default_quarantine_dir())
}

fn default_quarantine_dir() -> PathBuf {
    if crate::utils::is_running_in_snap() {
        crate::utils::snap_common_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("quarantine")
    } else {
        dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("clamtk-rs")
            .join("quarantine")
    }
}

/// Move an existing quarantine directory from `from` to `to`, rewriting the
/// stored locations so restore/delete/purge keep working.
///
/// Older versions stored `$SNAP_USER_DATA/quarantine`, so after a refresh the
/// files are still in the previous revision's directory (or, if snapd already
/// pruned it, gone) while the app now looks in `$SNAP_USER_COMMON/quarantine`.
/// Best effort and never fatal: anything that cannot be recovered is left where
/// it is for the user to inspect.
pub fn migrate_quarantine_dir(from: &Path, to: &Path) {
    if from == to || !from.join("metadata.json").exists() {
        return;
    }
    if to.join("metadata.json").exists() {
        return;
    }

    let moved = match fs::rename(from, to) {
        Ok(()) => true,
        Err(e) => {
            log::warn!("could not move {}: {}", from.display(), e);
            // Rename can fail across filesystems; copy the files instead.
            match copy_dir_all(from, to) {
                Ok(()) => {
                    let _ = fs::remove_dir_all(from);
                    true
                }
                Err(e) => {
                    log::warn!("could not copy {}: {}", from.display(), e);
                    false
                }
            }
        }
    };
    if !moved {
        return;
    }
    log::info!(
        "quarantine migrated from {} to {}",
        from.display(),
        to.display()
    );

    // Entries hold absolute paths into the old directory; repoint them. Reading
    // and writing through explicit paths keeps this independent of the
    // configuration, which the caller may be in the middle of repairing.
    let metadata = to.join("metadata.json");
    let entries = match read_entries(&metadata) {
        Ok(entries) => entries,
        Err(e) => {
            log::warn!("could not re-read quarantine metadata: {}", e);
            return;
        }
    };
    let updated: Vec<QuarantineEntry> = entries
        .into_iter()
        .map(|mut entry| {
            if entry.quarantine_path.starts_with(from) {
                let name = entry
                    .quarantine_path
                    .file_name()
                    .map(PathBuf::from)
                    .unwrap_or_default();
                entry.quarantine_path = to.join(name);
            }
            entry
        })
        .collect();
    if let Err(e) = write_entries(&metadata, &updated) {
        log::warn!("could not update quarantine metadata: {}", e);
    }
}

/// Adopt a quarantine directory left in `$SNAP_USER_DATA` by a previous revision
/// of this snap, for the case where the configuration itself was not stale.
///
/// `effective_dir` is the directory the app is about to use. Anything left in
/// the revision directory is only adopted when that is the default location,
/// since moving files to a directory the app is not configured to read would
/// simply hide them.
pub fn adopt_legacy_quarantine(effective_dir: &Path) {
    if effective_dir != default_quarantine_dir() {
        return;
    }
    let Some(user_data) = std::env::var_os("SNAP_USER_DATA") else {
        return;
    };
    migrate_quarantine_dir(&PathBuf::from(user_data).join("quarantine"), effective_dir);
}

fn copy_dir_all(from: &Path, to: &Path) -> Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let dest = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_all(&entry.path(), &dest)?;
        } else {
            fs::copy(entry.path(), &dest)?;
        }
    }
    Ok(())
}

pub fn metadata_file() -> PathBuf {
    quarantine_dir().join("metadata.json")
}

pub fn load_entries() -> Result<Vec<QuarantineEntry>> {
    read_entries(&metadata_file())
}

pub fn save_entries(entries: &[QuarantineEntry]) -> Result<()> {
    let path = metadata_file();
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    write_entries(&path, entries)
}

fn read_entries(path: &Path) -> Result<Vec<QuarantineEntry>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = fs::read_to_string(path)?;
    let entries: Vec<QuarantineEntry> = serde_json::from_str(&data)?;
    Ok(entries)
}

fn write_entries(path: &Path, entries: &[QuarantineEntry]) -> Result<()> {
    let data = serde_json::to_string_pretty(entries)?;
    fs::write(path, data)?;
    Ok(())
}

pub fn can_quarantine(file_path: &Path) -> Result<()> {
    fs::metadata(file_path).context("Cannot read the infected file (permission denied)")?;

    let parent = file_path.parent().unwrap_or(Path::new("/"));

    let test_name = format!(".clamtk-rs-test-{}", std::process::id());
    let test_path = parent.join(&test_name);
    fs::write(&test_path, b"")
        .with_context(|| format!("Cannot write to directory {}", parent.display()))?;
    fs::remove_file(&test_path)
        .with_context(|| format!("Cannot delete from directory {}", parent.display()))?;

    Ok(())
}

pub fn quarantine_command(file_path: &Path) -> String {
    let dest = quarantine_dir();
    format!("sudo mv '{}' '{}/'", file_path.display(), dest.display(),)
}

fn is_path_accessible_in_snap(file_path: &Path) -> bool {
    let path_str = file_path.to_string_lossy();

    if path_str.starts_with("/media/")
        || path_str.starts_with("/mnt/")
        || path_str.starts_with("/run/media/")
    {
        return true;
    }

    let real_home = crate::utils::real_home_dir();
    if let Some(home_str) = real_home.to_str() {
        if path_str.starts_with(home_str) {
            if let Ok(rel) = file_path.strip_prefix(home_str) {
                for component in rel.components() {
                    let name = component.as_os_str().to_string_lossy();
                    if name.starts_with('.') {
                        return false;
                    }
                }
                return true;
            }
        }
    }

    false
}

pub fn quarantine_file(file_path: &Path, threat_name: &str) -> Result<QuarantineEntry> {
    if !file_path.exists() {
        anyhow::bail!("File does not exist: {}", file_path.display());
    }

    if crate::utils::is_running_in_snap() && !is_path_accessible_in_snap(file_path) {
        let cmd = quarantine_command(file_path);
        anyhow::bail!(
            "Cannot quarantine system files from within the snap sandbox. \
             Run this command in a terminal:\n\n{}",
            cmd,
        );
    }

    can_quarantine(file_path)?;

    let file_name = file_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let mut hasher = Sha256::new();
    let file_data = fs::read(file_path)?;
    hasher.update(&file_data);
    let hash = format!("{:x}", hasher.finalize());

    let file_size = file_data.len() as u64;

    // Create quarantine filename with timestamp
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let quarantine_name = format!("{}_{}.quar", timestamp, file_name);
    let quarantine_path = quarantine_dir().join(&quarantine_name);

    // Copy the file to quarantine
    fs::create_dir_all(quarantine_dir())?;
    fs::copy(file_path, &quarantine_path).context("Failed to copy file to quarantine")?;

    // Remove the original file
    fs::remove_file(file_path).context("Failed to remove original infected file")?;

    // Create a zero-byte file in the original location to mark it as quarantined
    // (similar to ClamTK behavior)
    let marker_path = format!("{}.quarantined", file_path.display());
    let _ = fs::write(
        &marker_path,
        format!(
            "Quarantined by clamtk-rs\nThreat: {}\nQuarantine ID: {}\n",
            threat_name,
            &hash[..8]
        ),
    );

    let entry = QuarantineEntry {
        id: hash[..8].to_string(),
        original_path: file_path.to_path_buf(),
        threat_name: threat_name.to_string(),
        quarantine_path,
        quarantined_at: chrono::Local::now(),
        file_hash: hash,
        file_size,
        restored: false,
    };

    // Save metadata
    let mut entries = load_entries().unwrap_or_default();
    entries.push(entry.clone());
    save_entries(&entries)?;

    Ok(entry)
}

pub fn restore_file(entry_id: &str) -> Result<PathBuf> {
    let mut entries = load_entries()?;
    let entry_idx = entries
        .iter()
        .position(|e| e.id == entry_id)
        .context("Quarantine entry not found")?;

    let entry = &entries[entry_idx];

    if !entry.quarantine_path.exists() {
        anyhow::bail!(
            "Quarantined file not found: {}",
            entry.quarantine_path.display()
        );
    }

    // Copy back from quarantine
    let original_dir = entry.original_path.parent().unwrap_or(Path::new("/tmp"));
    fs::create_dir_all(original_dir)?;

    // If original location still has a file, restore with a suffix
    let restore_path = if entry.original_path.exists() {
        let mut p = entry.original_path.clone();
        p.set_extension(format!(
            "restored.{}",
            chrono::Local::now().format("%Y%m%d%H%M%S")
        ));
        p
    } else {
        entry.original_path.clone()
    };

    fs::copy(&entry.quarantine_path, &restore_path)
        .context("Failed to restore file from quarantine")?;

    // Remove the quarantine copy
    let _ = fs::remove_file(&entry.quarantine_path);

    // Remove the marker file
    let marker_path = format!("{}.quarantined", entry.original_path.display());
    let _ = fs::remove_file(&marker_path);

    // Update entry
    entries[entry_idx].restored = true;
    save_entries(&entries)?;

    Ok(restore_path)
}

pub fn delete_quarantined(entry_id: &str) -> Result<()> {
    let mut entries = load_entries()?;
    let entry_idx = entries
        .iter()
        .position(|e| e.id == entry_id)
        .context("Quarantine entry not found")?;

    let entry = &entries[entry_idx];

    // Delete the quarantined file
    if entry.quarantine_path.exists() {
        fs::remove_file(&entry.quarantine_path)?;
    }

    // Remove the marker file
    let marker_path = format!("{}.quarantined", entry.original_path.display());
    let _ = fs::remove_file(&marker_path);

    entries.remove(entry_idx);
    save_entries(&entries)?;

    Ok(())
}

pub fn purge_all() -> Result<usize> {
    let entries = load_entries()?;
    let count = entries.len();

    for entry in &entries {
        if entry.quarantine_path.exists() {
            let _ = fs::remove_file(&entry.quarantine_path);
        }
        let marker_path = format!("{}.quarantined", entry.original_path.display());
        let _ = fs::remove_file(&marker_path);
    }

    save_entries(&[])?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::testutil;

    fn entry(id: &str, quarantine_path: &Path) -> QuarantineEntry {
        QuarantineEntry {
            id: id.into(),
            original_path: PathBuf::from("/home/u/Documents/report.pdf"),
            threat_name: "Eicar-Test-Signature".into(),
            quarantine_path: quarantine_path.to_path_buf(),
            quarantined_at: chrono::Local::now(),
            file_hash: "abc123".into(),
            file_size: 68,
            restored: false,
        }
    }

    fn write_metadata(dir: &Path, entries: &[QuarantineEntry]) {
        fs::create_dir_all(dir).unwrap();
        fs::write(
            dir.join("metadata.json"),
            serde_json::to_string_pretty(entries).unwrap(),
        )
        .unwrap();
    }

    /// Files quarantined by a previous snap revision must move to the current
    /// location, with their recorded paths repointed so restore/delete/purge
    /// still find them.
    #[test]
    fn migration_moves_files_and_repoints_entries() {
        let root = testutil::temp_dir("quarantine_migrate");
        let old_dir = root.join("snap/clamtk-rs/39/quarantine");
        let new_dir = root.join("common/quarantine");

        let name = "eicar.pdf.quarantined";
        write_metadata(&old_dir, &[entry("abc123", &old_dir.join(name))]);
        fs::write(old_dir.join(name), b"infected").unwrap();

        migrate_quarantine_dir(&old_dir, &new_dir);

        assert!(
            new_dir.join("metadata.json").is_file(),
            "metadata not moved"
        );
        assert_eq!(
            fs::read(new_dir.join(name)).unwrap(),
            b"infected",
            "quarantined file not moved"
        );
        assert!(!old_dir.exists(), "old directory should be gone");

        let entries = read_entries(&new_dir.join("metadata.json")).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "abc123");
        assert_eq!(entries[0].quarantine_path, new_dir.join(name));
        assert!(
            entries[0].quarantine_path.exists(),
            "repointed path does not resolve"
        );

        testutil::cleanup(&root);
    }

    /// Metadata without any matching file must not be resurrected as an empty
    /// quarantine directory.
    #[test]
    fn migration_is_a_no_op_without_metadata() {
        let root = testutil::temp_dir("quarantine_empty");
        let old_dir = root.join("snap/clamtk-rs/39/quarantine");
        let new_dir = root.join("common/quarantine");
        fs::create_dir_all(&old_dir).unwrap();

        migrate_quarantine_dir(&old_dir, &new_dir);

        assert!(!new_dir.exists());
        assert!(old_dir.is_dir(), "source must be left alone");

        testutil::cleanup(&root);
    }

    /// An already-migrated quarantine must never be overwritten by the contents
    /// of an older revision.
    #[test]
    fn migration_never_overwrites_existing_quarantine() {
        let root = testutil::temp_dir("quarantine_keep");
        let old_dir = root.join("snap/clamtk-rs/39/quarantine");
        let new_dir = root.join("common/quarantine");

        write_metadata(&old_dir, &[entry("old", &old_dir.join("old.bin"))]);
        write_metadata(&new_dir, &[entry("new", &new_dir.join("new.bin"))]);

        migrate_quarantine_dir(&old_dir, &new_dir);

        let entries = read_entries(&new_dir.join("metadata.json")).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "new");
        assert!(old_dir.is_dir(), "source must be left alone");

        testutil::cleanup(&root);
    }
}
