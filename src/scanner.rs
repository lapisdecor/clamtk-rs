use chrono::Local;
use crossbeam_channel::Receiver;
use serde::{Deserialize, Serialize};
use std::io::BufRead;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::config::AppConfig;
use crate::history;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub path: String,
    pub status: FileStatus,
    pub threat: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FileStatus {
    Clean,
    Infected,
    Error,
    Skipped,
}

#[derive(Debug, Clone)]
pub enum ScanMessage {
    Started {
        target: String,
        scan_type: ScanType,
    },
    Progress {
        current_file: String,
        files_scanned: u64,
        known_threats: u64,
    },
    FileResult(ScanResult),
    Completed {
        files_scanned: u64,
        time_elapsed: f64,
        results: Vec<ScanResult>,
    },
    Error(String),
    Cancelled,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ScanType {
    File,
    Directory,
    Home,
    FullSystem,
    Custom,
}

pub struct Scanner {
    process: Arc<Mutex<Option<Child>>>,
    cancel_flag: Arc<Mutex<bool>>,
}

impl Scanner {
    pub fn new() -> Self {
        Self {
            process: Arc::new(Mutex::new(None)),
            cancel_flag: Arc::new(Mutex::new(false)),
        }
    }

    pub fn cancel(&self) {
        if let Ok(mut flag) = self.cancel_flag.lock() {
            *flag = true;
        }
        if let Ok(mut proc) = self.process.lock() {
            if let Some(ref mut child) = *proc {
                let _ = child.kill();
            }
        }
    }

    pub fn start_scan(
        &self,
        target: PathBuf,
        scan_type: ScanType,
        config: AppConfig,
    ) -> Receiver<ScanMessage> {
        let (tx, rx) = crossbeam_channel::bounded(256);

        let process_arc = self.process.clone();
        let cancel_flag = self.cancel_flag.clone();

        // Reset cancel flag
        if let Ok(mut flag) = cancel_flag.lock() {
            *flag = false;
        }

        thread::spawn(move || {
            let start_time = std::time::Instant::now();
            let target_str = target.to_string_lossy().to_string();

            let _ = tx.send(ScanMessage::Started {
                target: target_str.clone(),
                scan_type,
            });

            let mut args = config.to_clamscan_args();

            // Inside a snap the bundled freshclam writes the signature database
            // to the snap's writable data directory, so clamscan must be told
            // where to find it. Download it first if it is not there yet.
            if crate::utils::is_running_in_snap() {
                let needs_download = !crate::clamav::snap_database_available();
                if needs_download {
                    let _ = tx.send(ScanMessage::Progress {
                        current_file: "Downloading virus definitions (first run)...".into(),
                        files_scanned: 0,
                        known_threats: 0,
                    });
                }
                if let Err(e) = crate::clamav::ensure_database() {
                    let _ = tx.send(ScanMessage::Error(format!(
                        "Could not prepare the virus database: {}",
                        e
                    )));
                    return;
                }

                if let Some(db_dir) = crate::utils::snap_database_dir() {
                    args.push("--database".into());
                    args.push(db_dir.to_string_lossy().to_string());
                }

                // The compiled-in certificate path refers to the host's
                // /etc/clamav/certs, which strict confinement blocks.
                if let Some(certs_dir) = crate::utils::snap_cvdcerts_dir() {
                    args.push("--cvdcertsdir".into());
                    args.push(certs_dir.to_string_lossy().to_string());
                }
            }

            args.push(target_str.clone());

            let mut cmd = Command::new("clamscan");
            cmd.args(&args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());

            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx.send(ScanMessage::Error(format!(
                        "Failed to start clamscan: {}. Is ClamAV installed?",
                        e
                    )));
                    return;
                }
            };

            let stdout = child.stdout.take().expect("stdout should be piped");

            // Store child so cancel() can kill it
            if let Ok(mut proc_guard) = process_arc.lock() {
                *proc_guard = Some(child);
            }

            // Read stdout incrementally
            let reader = std::io::BufReader::new(stdout);
            let mut files_scanned = 0u64;
            let known_threats = 0u64;
            let mut results = Vec::new();
            let mut all_lines = Vec::new();

            for line_result in reader.lines() {
                // Check if cancelled
                if cancel_flag.lock().map(|f| *f).unwrap_or(false) {
                    if let Ok(mut proc_guard) = process_arc.lock() {
                        if let Some(ref mut c) = *proc_guard {
                            let _ = c.kill();
                        }
                    }
                    let _ = tx.send(ScanMessage::Cancelled);
                    return;
                }

                let line = match line_result {
                    Ok(l) => l,
                    Err(_) => break,
                };

                all_lines.push(line.clone());

                if line.trim().is_empty()
                    || line.starts_with("-----")
                    || line.starts_with("Scan started")
                {
                    continue;
                }

                // Parse per-file results in real time
                if line.contains("FOUND") {
                    if let Some(pos) = line.rfind(": ") {
                        let path = line[..pos].to_string();
                        let rest = &line[pos + 2..];
                        let threat = rest.replace("FOUND", "").trim().to_string();
                        files_scanned += 1;
                        let result = ScanResult {
                            path: path.clone(),
                            status: FileStatus::Infected,
                            threat: Some(threat.clone()),
                        };
                        results.push(result.clone());
                        let _ = tx.send(ScanMessage::FileResult(result));
                        let _ = tx.send(ScanMessage::Progress {
                            current_file: path,
                            files_scanned,
                            known_threats,
                        });
                        continue;
                    }
                } else if line.contains("OK") {
                    if let Some(pos) = line.rfind(": ") {
                        let path = line[..pos].to_string();
                        files_scanned += 1;
                        let result = ScanResult {
                            path: path.clone(),
                            status: FileStatus::Clean,
                            threat: None,
                        };
                        results.push(result.clone());
                        let _ = tx.send(ScanMessage::FileResult(result));
                        let _ = tx.send(ScanMessage::Progress {
                            current_file: path,
                            files_scanned,
                            known_threats,
                        });
                        continue;
                    }
                } else if line.contains("ERROR") {
                    if let Some(pos) = line.rfind(": ") {
                        let path = line[..pos].to_string();
                        files_scanned += 1;
                        let result = ScanResult {
                            path: path.clone(),
                            status: FileStatus::Error,
                            threat: None,
                        };
                        results.push(result.clone());
                        let _ = tx.send(ScanMessage::FileResult(result));
                        let _ = tx.send(ScanMessage::Progress {
                            current_file: path,
                            files_scanned,
                            known_threats,
                        });
                        continue;
                    }
                }

                // Count summary lines for progress too
                let lower = line.trim().to_lowercase();
                if lower.starts_with("scanned directories:")
                    || lower.starts_with("scanned files:")
                {
                    files_scanned += lower.split(':').nth(1)
                        .and_then(|v| v.trim().parse::<u64>().ok())
                        .unwrap_or(0);
                }
            }

            // Wait for process to finish
            let exit_status = if let Ok(mut proc_guard) = process_arc.lock() {
                proc_guard.take()
            } else {
                None
            };

            let output_status = match exit_status {
                Some(mut c) => c.wait(),
                None => return,
            };

            // Clear process handle
            if let Ok(mut proc_guard) = process_arc.lock() {
                *proc_guard = None;
            }

            let elapsed = start_time.elapsed().as_secs_f64();

            let cancelled = cancel_flag.lock().map(|f| *f).unwrap_or(false);
            if cancelled {
                let _ = tx.send(ScanMessage::Cancelled);
                return;
            }

            // Check exit code
            match output_status {
                Ok(status) => {
                    let exit_code = status.code().unwrap_or(-1);
                    if exit_code == 2 {
                        let _ = tx.send(ScanMessage::Error(
                            "clamscan failed (exit code 2)".into(),
                        ));
                        return;
                    }
                }
                Err(e) => {
                    let _ = tx.send(ScanMessage::Error(format!(
                        "Scan failed: {}",
                        e
                    )));
                    return;
                }
            }

            // Parse summary from collected lines
            let full_output = all_lines.join("\n");
            let summary = parse_clamscan_summary(&full_output);
            if summary.files_scanned > 0 {
                files_scanned = summary.files_scanned;
            }

            let infected_results: Vec<ScanResult> = results
                .iter()
                .filter(|r| r.status == FileStatus::Infected)
                .cloned()
                .collect();

            let _ = tx.send(ScanMessage::Completed {
                files_scanned,
                time_elapsed: elapsed,
                results: infected_results.clone(),
            });

            // Save to history
            let history_entry = history::HistoryEntry {
                id: chrono::Utc::now().timestamp_millis() as u64,
                scan_type,
                target: target_str.clone(),
                timestamp: Local::now(),
                files_scanned,
                threats_found: infected_results.len() as u64,
                time_elapsed: elapsed,
                infected_files: infected_results
                    .iter()
                    .map(|r| r.path.clone())
                    .collect(),
            };

            if let Err(e) = history::add_entry(&history_entry) {
                log::error!("Failed to save history: {}", e);
            }
        });

        rx
    }
}

#[derive(Debug)]
struct ScanSummary {
    files_scanned: u64,
}

fn parse_clamscan_output(output: &str) -> Vec<ScanResult> {
    let mut results = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("-----") || line.starts_with("Scan started") {
            continue;
        }

        if line.contains("FOUND") {
            if let Some(pos) = line.rfind(": ") {
                let path = line[..pos].to_string();
                let rest = &line[pos + 2..];
                let threat = rest.replace("FOUND", "").trim().to_string();
                results.push(ScanResult {
                    path,
                    status: FileStatus::Infected,
                    threat: Some(threat),
                });
            }
        } else if line.contains("OK") {
            if let Some(pos) = line.rfind(": ") {
                let path = line[..pos].to_string();
                results.push(ScanResult {
                    path,
                    status: FileStatus::Clean,
                    threat: None,
                });
            }
        } else if line.contains("ERROR") {
            if let Some(pos) = line.rfind(": ") {
                let path = line[..pos].to_string();
                results.push(ScanResult {
                    path,
                    status: FileStatus::Error,
                    threat: None,
                });
            }
        }
    }

    results
}

fn parse_clamscan_summary(output: &str) -> ScanSummary {
    let mut files_scanned = 0u64;

    for line in output.lines() {
        let line = line.trim().to_lowercase();
        if line.starts_with("engine version:") {
            // skip
        }
        if line.starts_with("scanned directories:") || line.starts_with("scanned files:") {
            if let Some(v) = line.split(':').nth(1) {
                files_scanned += v.trim().parse().unwrap_or(0);
            }
        }
        if line.starts_with("infected files:") {
            // We could also track this separately
        }
    }

    if files_scanned == 0 {
        let parsed = parse_clamscan_output(output);
        files_scanned = parsed.len() as u64;
    }

    ScanSummary {
        files_scanned,
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}
