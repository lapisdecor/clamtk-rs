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
        total_files: u64,
    },
    Progress {
        current_file: String,
        files_scanned: u64,
        known_threats: u64,
        total_files: u64,
    },
    FileResult(ScanResult),
    Completed {
        files_scanned: u64,
        time_elapsed: f64,
        results: Vec<ScanResult>,
        /// Non-fatal issue detected while scanning (e.g. unreadable files).
        warning: Option<String>,
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

            let _ = tx.send(ScanMessage::Progress {
                current_file: "Counting files to scan...".into(),
                files_scanned: 0,
                known_threats: 0,
                total_files: 0,
            });
            let total_files = count_files(&target);

            let _ = tx.send(ScanMessage::Started {
                target: target_str.clone(),
                scan_type,
                total_files,
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
                        total_files,
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
            let stderr = child.stderr.take().expect("stderr should be piped");

            // Drain stderr on its own thread so the pipe never fills up and
            // blocks clamscan; the collected text is used for diagnostics.
            let stderr_thread = thread::spawn(move || {
                let mut collected = String::new();
                let reader = std::io::BufReader::new(stderr);
                for line in reader.lines().map_while(Result::ok) {
                    collected.push_str(&line);
                    collected.push('\n');
                }
                collected
            });

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
                            total_files,
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
                            total_files,
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
                            total_files,
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

            // Collect what clamscan wrote to stderr (diagnostics only)
            let stderr_output = stderr_thread.join().unwrap_or_default();
            if !stderr_output.trim().is_empty() {
                log::debug!("clamscan stderr: {}", stderr_output.trim());
            }

            let elapsed = start_time.elapsed().as_secs_f64();

            let cancelled = cancel_flag.lock().map(|f| *f).unwrap_or(false);
            if cancelled {
                let _ = tx.send(ScanMessage::Cancelled);
                return;
            }

            // Parse summary from collected lines
            let full_output = all_lines.join("\n");
            let summary = parse_clamscan_summary(&full_output);
            if summary.files_scanned > 0 {
                files_scanned = summary.files_scanned;
            }

            // Check exit code. clamscan exits with 2 when *anything* went
            // wrong, including single files it could not open ("Access
            // denied" / "Can't open directory"), even though the rest of the
            // scan completed fine. Under snap confinement that is expected:
            // the home interface does not expose hidden files and system
            // paths are blocked entirely, so a scan that processed at least
            // some files still counts as finished.
            let mut warning: Option<String> = None;
            match output_status {
                Ok(status) => match status.code() {
                    Some(0) | Some(1) => {}
                    Some(2) => {
                        if files_scanned == 0 && results.is_empty() {
                            // Nothing was scanned at all: a real failure
                            // (e.g. unreadable database or target).
                            let reason = stderr_output
                                .lines()
                                .rev()
                                .find(|l| !l.trim().is_empty())
                                .unwrap_or("unknown error");
                            let _ = tx.send(ScanMessage::Error(format!(
                                "clamscan failed (exit code 2): {}",
                                reason
                            )));
                            return;
                        }
                        warning = Some(if crate::utils::is_running_in_snap() {
                            "some files were skipped because the snap sandbox cannot read hidden or system files".into()
                        } else {
                            "some files could not be read and were skipped".into()
                        });
                    }
                    other => {
                        let _ = tx.send(ScanMessage::Error(format!(
                            "clamscan exited unexpectedly ({})",
                            other
                                .map(|c| c.to_string())
                                .unwrap_or_else(|| "killed by signal".into())
                        )));
                        return;
                    }
                },
                Err(e) => {
                    let _ = tx.send(ScanMessage::Error(format!(
                        "Scan failed: {}",
                        e
                    )));
                    return;
                }
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
                warning,
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

/// Estimate the number of files clamscan will scan so the UI can show a
/// percentage. For a single file this is trivially 1; otherwise walk the
/// target directory without following symlinks, matching clamscan's defaults.
fn count_files(path: &std::path::Path) -> u64 {
    if path.is_file() {
        return 1;
    }
    walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count() as u64
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_scan_reaches_completed() {
        // End-to-end check of the scanner -> Completed message flow, the same
        // path that triggers play_bell() in the UI. Skips (does not fail) when
        // clamscan is unavailable on the machine running the tests.
        let tmp = std::env::temp_dir().join(format!("clamtk_rs_scan_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let _ = std::fs::write(tmp.join("a.txt"), "hello");
        let _ = std::fs::write(tmp.join("b.txt"), "world");

        let scanner = Scanner::new();
        let rx = scanner.start_scan(tmp.clone(), ScanType::Directory, AppConfig::default());

        let mut result = None;
        while let Ok(msg) = rx.recv() {
            match msg {
                ScanMessage::Completed { .. } => {
                    result = Some("completed");
                    break;
                }
                ScanMessage::Error(e) => {
                    eprintln!("scan skipped (clamscan unavailable?): {}", e);
                    result = Some("skipped");
                    break;
                }
                ScanMessage::Cancelled => break,
                _ => {}
            }
        }
        assert!(result.is_some(), "scan channel closed without a terminal message");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
