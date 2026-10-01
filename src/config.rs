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
            // `$SNAP_USER_COMMON`, never `$SNAP_USER_DATA`: the latter embeds
            // the revision, and snapd makes non-current revisions read-only.
            crate::utils::snap_common_dir()
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
            exclude_paths: vec!["/proc".into(), "/sys".into(), "/dev".into()],
            max_file_size_mb: 25,
            max_scan_time_sec: 600,
            quarantine_dir,
            history_limit: 100,
        }
    }
}

impl AppConfig {
    pub fn config_dir() -> PathBuf {
        crate::utils::config_root().join("clamtk-rs")
    }

    pub fn config_file() -> PathBuf {
        Self::config_dir().join("config.json")
    }

    pub fn data_dir() -> PathBuf {
        crate::utils::data_root().join("clamtk-rs")
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
        let mut config: AppConfig = serde_json::from_str(&data)?;
        if config.repair_revision_scoped_paths() {
            if let Err(e) = config.save() {
                log::warn!("could not save repaired config: {}", e);
            }
        }
        Ok(config)
    }

    /// Replace a stored path that snapd copied forward from a previous revision.
    ///
    /// Older versions persisted `$SNAP_USER_DATA/quarantine`, i.e.
    /// `~/snap/<name>/<revision>/quarantine`. On refresh snapd copies
    /// `$SNAP_USER_DATA` forward, so the stale path survives in the new
    /// revision while the directory it points at is deleted and read-only per
    /// AppArmor — which made startup abort with `Permission denied
    /// (os error 13)`. Only such revision-scoped paths are rewritten; a
    /// location the user picked themselves is left untouched.
    fn repair_revision_scoped_paths(&mut self) -> bool {
        if !crate::utils::is_running_in_snap() {
            return false;
        }
        let Some(common) = crate::utils::snap_common_dir() else {
            return false;
        };
        let stale = crate::utils::is_stale_snap_path(&self.quarantine_dir, &common);
        if stale {
            let new_dir = common.join("quarantine");
            log::warn!(
                "quarantine directory {} belongs to a previous snap revision; moving to {}",
                self.quarantine_dir.display(),
                new_dir.display()
            );
            // Carry any quarantined files across before the old location is
            // forgotten, so restore/delete/purge keep working.
            crate::quarantine::migrate_quarantine_dir(&self.quarantine_dir, &new_dir);
            self.quarantine_dir = new_dir;
        }
        stale
    }

    pub fn save(&self) -> Result<()> {
        let dir = Self::config_dir();
        fs::create_dir_all(&dir)?;
        let data = serde_json::to_string_pretty(self)?;
        let path = Self::config_file();
        // Write through a temporary file so an interrupted write cannot leave a
        // truncated config that would discard the user's settings.
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, data)?;
        match fs::rename(&tmp, &path) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                Err(e.into())
            }
        }
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

/// Create the directories the app writes to.
///
/// Failures are collected instead of propagated: a directory the user cannot
/// write to must not stop the app from starting, it only makes the feature that
/// needs it unavailable. The returned messages are shown to the user at
/// startup. The quarantine directory is created last because resolving it loads
/// the config, which itself writes to the config directory.
pub fn ensure_dirs() -> Vec<String> {
    let mut warnings = Vec::new();

    for (label, dir) in [
        ("Settings directory", AppConfig::config_dir()),
        ("Data directory", AppConfig::data_dir()),
    ] {
        if let Err(e) = fs::create_dir_all(&dir) {
            log::error!("could not create {} {}: {}", label, dir.display(), e);
            warnings.push(format!(
                "Could not create the {} {}: {}.",
                label,
                dir.display(),
                e
            ));
        }
    }

    let quarantine_dir = match AppConfig::load() {
        Ok(config) => config.quarantine_dir,
        Err(e) => {
            log::error!("could not load configuration: {}", e);
            warnings.push(format!("Could not load the configuration: {}.", e));
            AppConfig::default().quarantine_dir
        }
    };
    if let Err(e) = fs::create_dir_all(&quarantine_dir) {
        log::error!(
            "could not create quarantine directory {}: {}",
            quarantine_dir.display(),
            e
        );
        warnings.push(format!(
            "The quarantine directory {} cannot be written to: {}. \
             Please choose a different folder in Settings → Quarantine.",
            quarantine_dir.display(),
            e
        ));
    }

    crate::quarantine::adopt_legacy_quarantine(&quarantine_dir);

    warnings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::testutil;

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

    /// The regression behind `Error: Permission denied (os error 13)`: a config
    /// carrying a `~/snap/<name>/<old revision>/quarantine` path left behind by
    /// snapd when it copied `$SNAP_USER_DATA` forward on refresh. That
    /// directory is read-only for the new revision, so `ensure_dirs` used to
    /// fail and abort startup.
    #[test]
    fn stale_revision_quarantine_dir_is_repaired() {
        let _guard = testutil::env_lock();
        let root = testutil::temp_dir("cfg_stale");
        let common = root.join("common");
        testutil::set_snap_env(&common);

        let config = AppConfig {
            quarantine_dir: root.join("snap/clamtk-rs/39/quarantine"),
            ..Default::default()
        };
        let path = AppConfig::config_file();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        // Must not fail even though the recorded directory cannot be created.
        let warnings = ensure_dirs();
        assert!(
            warnings.is_empty(),
            "startup reported problems: {:?}",
            warnings
        );

        let expected = common.join("quarantine");
        assert!(expected.is_dir(), "quarantine dir was not created");
        assert!(AppConfig::config_file().is_file(), "config was not written");

        // The repair must be persisted, not just applied in memory.
        let stored: AppConfig =
            serde_json::from_str(&fs::read_to_string(AppConfig::config_file()).unwrap()).unwrap();
        assert_eq!(stored.quarantine_dir, expected);

        testutil::cleanup(&root);
    }

    /// A quarantine directory the user chose themselves must survive a refresh.
    #[test]
    fn custom_quarantine_dir_is_preserved() {
        let _guard = testutil::env_lock();
        let root = testutil::temp_dir("cfg_custom");
        let common = root.join("common");
        testutil::set_snap_env(&common);

        let custom = root.join("my-quarantine");
        let config = AppConfig {
            quarantine_dir: custom.clone(),
            ..Default::default()
        };
        let path = AppConfig::config_file();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        assert!(ensure_dirs().is_empty());
        assert!(custom.is_dir());
        assert!(!common.join("quarantine").exists());

        testutil::cleanup(&root);
    }

    /// Leftovers in the revision directory must not be moved into the common
    /// directory when the user keeps a custom quarantine location: the app
    /// reads the custom directory, so anything moved elsewhere would silently
    /// disappear from the quarantine list.
    #[test]
    fn legacy_quarantine_is_not_adopted_for_custom_dir() {
        let _guard = testutil::env_lock();
        let root = testutil::temp_dir("cfg_custom_adopt");
        let common = root.join("common");
        let new_rev = root.join("snap/clamtk-rs/44");
        testutil::set_snap_env(&common);
        std::env::set_var("SNAP_USER_DATA", &new_rev);

        let custom = root.join("my-quarantine");
        let config = AppConfig {
            quarantine_dir: custom.clone(),
            ..Default::default()
        };
        let path = AppConfig::config_file();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        // Files the older build left behind in the revision directory.
        let legacy = new_rev.join("quarantine");
        fs::create_dir_all(&legacy).unwrap();
        fs::write(legacy.join("metadata.json"), "[]").unwrap();
        fs::write(legacy.join("eicar.pdf"), "infected").unwrap();

        assert!(ensure_dirs().is_empty());

        assert!(
            legacy.join("eicar.pdf").is_file(),
            "legacy files must not be moved away from a custom configuration"
        );
        assert!(!common.join("quarantine").exists());
        assert!(custom.is_dir());

        testutil::cleanup(&root);
    }

    /// An unwritable directory must be reported to the user, never fatal.
    #[test]
    fn unwritable_quarantine_dir_warns_instead_of_failing() {
        use std::os::unix::fs::PermissionsExt;
        let _guard = testutil::env_lock();
        let root = testutil::temp_dir("cfg_nowrite");
        let common = root.join("common");
        testutil::set_snap_env(&common);

        let read_only = root.join("read-only");
        fs::create_dir_all(&read_only).unwrap();
        fs::set_permissions(&read_only, fs::Permissions::from_mode(0o500)).unwrap();
        // Root ignores the permission bits, so check whether the restriction
        // actually applies before asserting on it.
        let restricted = fs::create_dir(read_only.join("probe")).is_err();
        let _ = fs::remove_dir(read_only.join("probe"));

        let config = AppConfig {
            quarantine_dir: read_only.join("quarantine"),
            ..Default::default()
        };
        let path = AppConfig::config_file();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        let warnings = ensure_dirs();
        if restricted {
            assert!(
                warnings.iter().any(|w| w.contains("quarantine")),
                "expected a quarantine warning, got {:?}",
                warnings
            );
        } else {
            assert!(warnings.is_empty(), "unexpected warnings: {:?}", warnings);
        }

        testutil::cleanup(&root);
    }

    #[test]
    fn snap_defaults_keep_state_in_common_dir() {
        let _guard = testutil::env_lock();
        let root = testutil::temp_dir("cfg_default");
        testutil::set_snap_env(&root.join("common"));

        let config = AppConfig::default();
        assert_eq!(config.quarantine_dir, root.join("common/quarantine"));
        // Defaults must never embed a revision number.
        assert!(!crate::utils::is_stale_snap_path(
            &config.quarantine_dir,
            &root.join("common")
        ));

        testutil::cleanup(&root);
    }

    /// Reproduces a full `snap refresh` on a machine that already used an older
    /// build: snapd hands the new revision a copy of the old `$SNAP_USER_DATA`
    /// and deletes the revision it came from. Everything the user cares about
    /// must end up in `$SNAP_USER_COMMON`, and startup must succeed.
    #[test]
    fn refresh_migrates_all_state_to_common_dir() {
        let _guard = testutil::env_lock();
        let root = testutil::temp_dir("refresh");
        let old_rev = root.join("snap/clamtk-rs/39");
        let new_rev = root.join("snap/clamtk-rs/43");
        let common = root.join("snap/clamtk-rs/common");

        // State snapd copied forward into the new revision.
        let config_dir = new_rev.join(".config/clamtk-rs");
        fs::create_dir_all(&config_dir).unwrap();
        let config = AppConfig {
            quarantine_dir: old_rev.join("quarantine"),
            max_file_size_mb: 42,
            ..Default::default()
        };
        fs::write(
            config_dir.join("config.json"),
            serde_json::to_string_pretty(&config).unwrap(),
        )
        .unwrap();

        let data_dir = new_rev.join(".local/share/clamtk-rs");
        fs::create_dir_all(&data_dir).unwrap();
        fs::write(data_dir.join("history.json"), "[]").unwrap();

        let db = new_rev.join("clamav");
        fs::create_dir_all(&db).unwrap();
        fs::write(db.join("daily.cvd"), "signatures").unwrap();
        fs::write(new_rev.join("freshclam.conf"), "stale").unwrap();

        let quarantined = old_rev.join("quarantine");
        fs::create_dir_all(&quarantined).unwrap();
        fs::write(quarantined.join("eicar.pdf"), "infected").unwrap();

        std::env::set_var("SNAP", root.join("snap/clamtk-rs/43"));
        std::env::set_var("SNAP_NAME", "clamtk-rs");
        std::env::set_var("SNAP_USER_DATA", &new_rev);
        std::env::set_var("SNAP_USER_COMMON", &common);
        // As the GNOME platform launcher sets them, so we can prove we leave
        // them alone.
        std::env::set_var("XDG_CONFIG_HOME", new_rev.join(".config"));
        std::env::set_var("XDG_DATA_HOME", new_rev.join(".local/share"));

        crate::utils::adopt_legacy_revision_data();

        // Settings, history and signatures are now revision-independent.
        assert_eq!(
            AppConfig::config_file(),
            common.join("config/clamtk-rs/config.json")
        );
        assert!(common.join("data/clamtk-rs/history.json").is_file());
        assert_eq!(
            std::fs::read_to_string(common.join("clamav/daily.cvd")).unwrap(),
            "signatures",
            "signatures should move, not be re-downloaded"
        );
        assert_eq!(
            crate::utils::snap_database_dir().unwrap(),
            common.join("clamav")
        );
        // The GNOME platform owns the XDG directories: it keeps its
        // fontconfig, ibus and theme data there, so they must not be
        // redirected into the common directory.
        assert_eq!(
            std::env::var("XDG_CONFIG_HOME").unwrap(),
            new_rev.join(".config").to_str().unwrap()
        );
        assert_eq!(
            std::env::var("XDG_DATA_HOME").unwrap(),
            new_rev.join(".local/share").to_str().unwrap()
        );
        assert!(
            !common.join(".config").exists(),
            "the app must not take over the platform's XDG config directory"
        );

        // Startup succeeds and repairs the dangling quarantine path.
        let warnings = ensure_dirs();
        assert!(warnings.is_empty(), "unexpected warnings: {:?}", warnings);
        assert!(common.join("quarantine").is_dir());

        let stored: AppConfig =
            serde_json::from_str(&fs::read_to_string(AppConfig::config_file()).unwrap()).unwrap();
        assert_eq!(stored.quarantine_dir, common.join("quarantine"));
        assert_eq!(
            stored.max_file_size_mb, 42,
            "the user's settings must be preserved"
        );

        testutil::cleanup(&root);
    }
}
