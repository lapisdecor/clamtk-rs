use anyhow::Result;
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::fs;

use crate::scanner::ScanType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub id: u64,
    pub scan_type: ScanType,
    pub target: String,
    pub timestamp: DateTime<Local>,
    pub files_scanned: u64,
    pub threats_found: u64,
    pub time_elapsed: f64,
    pub infected_files: Vec<String>,
}

pub fn load_entries() -> Result<Vec<HistoryEntry>> {
    let path = crate::config::AppConfig::history_file();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = fs::read_to_string(&path)?;
    let entries: Vec<HistoryEntry> = serde_json::from_str(&data)?;
    Ok(entries)
}

pub fn save_entries(entries: &[HistoryEntry]) -> Result<()> {
    let path = crate::config::AppConfig::history_file();
    let dir = path.parent().unwrap();
    fs::create_dir_all(dir)?;
    let data = serde_json::to_string_pretty(entries)?;
    fs::write(path, data)?;
    Ok(())
}

pub fn add_entry(entry: &HistoryEntry) -> Result<()> {
    let mut entries = load_entries().unwrap_or_default();

    // Keep only the most recent entries based on config limit
    let limit = crate::config::AppConfig::load()
        .map(|c| c.history_limit)
        .unwrap_or(100);

    entries.push(entry.clone());

    if entries.len() > limit {
        entries = entries.split_off(entries.len() - limit);
    }

    // Sort by timestamp descending
    entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    save_entries(&entries)
}

pub fn clear_history() -> Result<()> {
    save_entries(&[])
}
