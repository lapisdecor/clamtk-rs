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
        .unwrap_or_else(|_| {
            dirs::data_dir()
                .unwrap_or_else(|| PathBuf::from("/tmp"))
                .join("clamtk-rs")
                .join("quarantine")
        })
}

pub fn metadata_file() -> PathBuf {
    quarantine_dir().join("metadata.json")
}

pub fn load_entries() -> Result<Vec<QuarantineEntry>> {
    let path = metadata_file();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = fs::read_to_string(&path)?;
    let entries: Vec<QuarantineEntry> = serde_json::from_str(&data)?;
    Ok(entries)
}

pub fn save_entries(entries: &[QuarantineEntry]) -> Result<()> {
    let dir = quarantine_dir();
    fs::create_dir_all(&dir)?;
    let data = serde_json::to_string_pretty(entries)?;
    fs::write(metadata_file(), data)?;
    Ok(())
}

pub fn quarantine_file(file_path: &Path, threat_name: &str) -> Result<QuarantineEntry> {
    if !file_path.exists() {
        anyhow::bail!("File does not exist: {}", file_path.display());
    }

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
    fs::copy(file_path, &quarantine_path)
        .context("Failed to copy file to quarantine")?;

    // Remove the original file
    fs::remove_file(file_path)
        .context("Failed to remove original infected file")?;

    // Create a zero-byte file in the original location to mark it as quarantined
    // (similar to ClamTK behavior)
    let marker_path = format!("{}.quarantined", file_path.display());
    let _ = fs::write(&marker_path, format!("Quarantined by clamtk-rs\nThreat: {}\nQuarantine ID: {}\n", threat_name, &hash[..8]));

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
        anyhow::bail!("Quarantined file not found: {}", entry.quarantine_path.display());
    }

    // Copy back from quarantine
    let original_dir = entry
        .original_path
        .parent()
        .unwrap_or(Path::new("/tmp"));
    fs::create_dir_all(original_dir)?;

    // If original location still has a file, restore with a suffix
    let restore_path = if entry.original_path.exists() {
        let mut p = entry.original_path.clone();
        p.set_extension(format!("restored.{}", chrono::Local::now().format("%Y%m%d%H%M%S")));
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
