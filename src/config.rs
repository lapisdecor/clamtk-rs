use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default = "default_true")]
    pub play_sound_on_complete: bool,
    pub scan_archives: bool,
    pub scan_elf: bool,
    pub scan_pdf: bool,
    pub scan_mail: bool,
    pub scan_ole2: bool,
    pub detect_pua: bool,
    pub heuristic_scan: bool,
    pub scan_follow_symlinks: bool,
    pub exclude_paths: Vec<String>,
    pub max_file_size_mb: u64,
    pub max_scan_time_sec: u64,
    pub quarantine_dir: PathBuf,
    pub history_limit: usize,
}

impl Default for AppConfig {
    fn default() -> Self {
        let quarantine_dir = if crate::utils::is_running_in_snap() {
            std::env::var_os("SNAP_USER_DATA")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/tmp"))
                .join("quarantine")
        } else {
            dirs::data_dir()
                .unwrap_or_else(|| PathBuf::from("/tmp"))
                .join("clamtk-rs")
                .join("quarantine")
        };

        Self {
            play_sound_on_complete: true,
            scan_archives: true,
            scan_elf: true,
            scan_pdf: true,
            scan_mail: true,
            scan_ole2: true,
            detect_pua: false,
            heuristic_scan: true,
            scan_follow_symlinks: false,
            exclude_paths: vec![
                "/proc".into(),
                "/sys".into(),
                "/dev".into(),
            ],
            max_file_size_mb: 25,
            max_scan_time_sec: 600,
            quarantine_dir,
            history_limit: 100,
        }
    }
}

impl AppConfig {
    pub fn config_dir() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("clamtk-rs")
    }

    pub fn config_file() -> PathBuf {
        Self::config_dir().join("config.json")
    }

    pub fn data_dir() -> PathBuf {
        dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("clamtk-rs")
    }

    pub fn history_file() -> PathBuf {
        Self::data_dir().join("history.json")
    }

    pub fn load() -> Result<Self> {
        let path = Self::config_file();
        if !path.exists() {
            let config = Self::default();
            config.save()?;
            return Ok(config);
        }
        let data = fs::read_to_string(&path)?;
        let config: AppConfig = serde_json::from_str(&data)?;
        Ok(config)
    }

    pub fn save(&self) -> Result<()> {
        let dir = Self::config_dir();
        fs::create_dir_all(&dir)?;
        let data = serde_json::to_string_pretty(self)?;
        fs::write(Self::config_file(), data)?;
        Ok(())
    }

    /// Build clamscan arguments from the current config
    pub fn to_clamscan_args(&self) -> Vec<String> {
        let mut args = Vec::new();

        if self.scan_archives {
            args.push("--archive-verbose".into());
        } else {
            args.push("--no-archive".into());
        }

        if self.scan_elf {
            args.push("--scan-elf=yes".into());
        }

        if self.scan_pdf {
            args.push("--scan-pdf=yes".into());
        } else {
            args.push("--scan-pdf=no".into());
        }

        if self.scan_mail {
            args.push("--scan-mail=yes".into());
        } else {
            args.push("--scan-mail=no".into());
        }

        if self.scan_ole2 {
            args.push("--scan-ole2=yes".into());
        } else {
            args.push("--scan-ole2=no".into());
        }

        if self.detect_pua {
            args.push("--detect-pua=yes".into());
        }

        if self.heuristic_scan {
            args.push("--heuristic-scan-precedence=yes".into());
        }

        if !self.scan_follow_symlinks {
            args.push("--follow-file-symlinks=0".into());
        }

        args.push(format!("--max-filesize={}M", self.max_file_size_mb));
        args.push(format!("--max-scantime={}", self.max_scan_time_sec * 1000));

        args.push("--recursive".into());

        for path in &self.exclude_paths {
            args.push("--exclude-dir".into());
            args.push(path.clone());
        }

        args.push("--infected".into());
        args.push("--bell".into());

        args
    }
}

pub fn ensure_dirs() -> Result<()> {
    let config_dir = AppConfig::config_dir();
    fs::create_dir_all(&config_dir)?;

    let data_dir = AppConfig::data_dir();
    fs::create_dir_all(&data_dir)?;

    let quarantine_dir = AppConfig::load()
        .map(|c| c.quarantine_dir)
        .unwrap_or_default();
    fs::create_dir_all(&quarantine_dir)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_play_sound() {
        let mut c = AppConfig::default();
        c.play_sound_on_complete = false;
        let json = serde_json::to_string(&c).unwrap();
        println!("serialized: {}", json);
        assert!(json.contains("\"play_sound_on_complete\":false"));
        let back: AppConfig = serde_json::from_str(&json).unwrap();
        assert!(!back.play_sound_on_complete);
    }

    #[test]
    fn old_config_defaults_to_true() {
        // A config written before this option existed (all other fields
        // present, play_sound_on_complete missing) must default to true.
        let old = r#"{
            "scan_archives": true,
            "scan_elf": true,
            "scan_pdf": true,
            "scan_mail": true,
            "scan_ole2": true,
            "detect_pua": false,
            "heuristic_scan": true,
            "scan_follow_symlinks": false,
            "exclude_paths": ["/proc", "/sys", "/dev"],
            "max_file_size_mb": 25,
            "max_scan_time_sec": 600,
            "quarantine_dir": "/tmp/q",
            "history_limit": 100
        }"#;
        let c: AppConfig = serde_json::from_str(old).unwrap();
        assert!(c.play_sound_on_complete);
    }
}
