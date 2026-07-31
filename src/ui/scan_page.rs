use gtk4::prelude::*;
use gtk4::{
    Box, Button, FileChooserDialog, FileChooserAction,
    Label, Orientation, ProgressBar, PolicyType,
    ScrolledWindow, Align, ResponseType, ApplicationWindow,
};

use std::path::PathBuf;
use std::rc::Rc;
use std::cell::RefCell;

use crate::config::AppConfig;
use crate::scanner::{ScanMessage, ScanType, Scanner};

pub struct ScanPage {
    container: Box,
    start_scan_fn: Rc<RefCell<Option<std::boxed::Box<dyn Fn(PathBuf, ScanType)>>>>,
}

impl ScanPage {
    pub fn new(window: &ApplicationWindow) -> Self {
        let container = Box::new(Orientation::Vertical, 16);
        container.set_margin_start(24);
        container.set_margin_end(24);
        container.set_margin_top(24);
        container.set_margin_bottom(24);

        let scanner = Rc::new(RefCell::new(Scanner::new()));
        let config = Rc::new(RefCell::new(
            AppConfig::load().unwrap_or_default()
        ));

        // Title
        let title = Label::builder()
            .label("<big><b>Scan</b></big>")
            .use_markup(true)
            .halign(Align::Start)
            .build();
        container.append(&title);

        // Scan type buttons
        let scan_btn_box = Box::new(Orientation::Horizontal, 8);

        let file_btn = Button::builder()
            .label("📄 Scan a File")
            .css_classes(["big-button"])
            .tooltip_text("Select a single file to scan")
            .build();

        let dir_btn = Button::builder()
            .label("📁 Scan a Directory")
            .css_classes(["big-button"])
            .tooltip_text("Select a directory to scan")
            .build();

        let home_btn = Button::builder()
            .label("🏠 Scan Home")
            .css_classes(["big-button", "suggested-action"])
            .tooltip_text("Scan your home directory")
            .build();

        let full_btn = Button::builder()
            .label("💻 Full System Scan")
            .css_classes(["big-button", "destructive-action"])
            .tooltip_text("Scan the entire filesystem (may take a long time)")
            .build();

        let cancel_btn = Button::builder()
            .label("⏹ Cancel Scan")
            .css_classes(["big-button"])
            .sensitive(false)
            .build();

        scan_btn_box.append(&file_btn);
        scan_btn_box.append(&dir_btn);
        scan_btn_box.append(&home_btn);
        scan_btn_box.append(&full_btn);
        scan_btn_box.append(&cancel_btn);

        container.append(&scan_btn_box);

        // Progress section
        let progress_box = Box::new(Orientation::Vertical, 8);

        let progress_bar = ProgressBar::builder()
            .show_text(true)
            .fraction(0.0)
            .build();

        let current_file_label = Label::builder()
            .label("Ready to scan")
            .halign(Align::Start)
            .ellipsize(gtk4::pango::EllipsizeMode::End)
            .max_width_chars(80)
            .build();

        let status_label = Label::builder()
            .label("")
            .halign(Align::Start)
            .build();

        progress_box.append(&progress_bar);
        progress_box.append(&current_file_label);
        progress_box.append(&status_label);

        container.append(&progress_box);

        // Results section
        let results_title = Label::builder()
            .label("<b>Scan Results</b>")
            .use_markup(true)
            .halign(Align::Start)
            .build();
        container.append(&results_title);

        let results_scroll = ScrolledWindow::builder()
            .vexpand(true)
            .min_content_height(200)
            .hscrollbar_policy(PolicyType::Automatic)
            .vscrollbar_policy(PolicyType::Automatic)
            .build();

        let results_box = Box::new(Orientation::Vertical, 4);
        results_scroll.set_child(Some(&results_box));

        container.append(&results_scroll);

        // Wire up buttons
        let start_scan_fn: Rc<RefCell<Option<std::boxed::Box<dyn Fn(PathBuf, ScanType)>>>> = Rc::new(RefCell::new(None));

        let scanner_rc = scanner.clone();
        let config_rc = config.clone();
        let progress_bar_clone = progress_bar.clone();
        let status_label_clone = status_label.clone();
        let current_file_label_clone = current_file_label.clone();
        let results_box_clone = results_box.clone();
        let cancel_btn_clone = cancel_btn.clone();
        let scan_btn_box_clone = scan_btn_box.clone();

        let start_scan = move |target: PathBuf, scan_type: ScanType| {
            let sc = scanner_rc.clone();
            let config = config_rc.clone();
            let pb = progress_bar_clone.clone();
            let sl = status_label_clone.clone();
            let cfl = current_file_label_clone.clone();
            let rb = results_box_clone.clone();
            let cb = cancel_btn_clone.clone();
            let sbb = scan_btn_box_clone.clone();

            // Clear previous results
            while let Some(child) = rb.first_child() {
                rb.remove(&child);
            }

            pb.set_fraction(0.0);
            pb.set_text(Some("Starting scan..."));
            sl.set_label("");
            cfl.set_label("Initializing...");

            // Disable scan buttons, enable cancel
            let mut child = sbb.first_child();
            while let Some(c) = child {
                if let Some(btn) = c.downcast_ref::<Button>() {
                    if btn.label().unwrap_or_default().as_str() != "⏹ Cancel Scan" {
                        btn.set_sensitive(false);
                    }
                }
                child = c.next_sibling();
            }
            cb.set_sensitive(true);

            let rx = sc.borrow().start_scan(target, scan_type, config.borrow().clone());

            // Process messages from the scanner
            glib::spawn_future_local(async move {
                loop {
                    // Use glib idle to check for messages
                    let _msg = glib::timeout_future(std::time::Duration::from_millis(100)).await;

                    match rx.try_recv() {
                        Ok(ScanMessage::Started { target, scan_type }) => {
                            let type_str = match scan_type {
                                ScanType::File => "File",
                                ScanType::Directory => "Directory",
                                ScanType::Home => "Home Directory",
                                ScanType::FullSystem => "Full System",
                                ScanType::Custom => "Custom",
                            };
                            pb.set_text(Some(&format!("Scanning: {} ({})", target, type_str)));
                            cfl.set_label(&format!("Scanning: {}", target));
                        }
                        Ok(ScanMessage::Progress { current_file, files_scanned, known_threats }) => {
                            cfl.set_label(&crate::utils::truncate_path(&current_file, 80));
                            pb.pulse();
                            if known_threats > 0 {
                                pb.set_text(Some(&format!("Files scanned: {}  —  Threats found: {}", files_scanned, known_threats)));
                            } else {
                                pb.set_text(Some(&format!("Files scanned: {}", files_scanned)));
                            }
                        }
                        Ok(ScanMessage::FileResult(result)) => {
                            let row = Box::new(Orientation::Horizontal, 8);
                            row.set_margin_start(8);
                            row.set_margin_end(8);
                            row.set_margin_top(4);
                            row.set_margin_bottom(4);

                            let icon = match result.status {
                                crate::scanner::FileStatus::Infected => "⚠️",
                                crate::scanner::FileStatus::Clean => "✅",
                                _ => "❓",
                            };
                            let icon_label = Label::builder()
                                .label(icon)
                                .build();
                            let path_label = Label::builder()
                                .label(&crate::utils::truncate_path(&result.path, 60))
                                .halign(Align::Start)
                                .hexpand(true)
                                .build();
                            row.append(&icon_label);
                            row.append(&path_label);

                            if result.status == crate::scanner::FileStatus::Infected {
                                let threat = result.threat.unwrap_or_default();
                                let threat_label = Label::builder()
                                    .label(&threat)
                                    .css_classes(["status-bad"])
                                    .halign(Align::End)
                                    .build();
                                row.append(&threat_label);

                                let q_btn = Button::builder()
                                    .label("Quarantine")
                                    .css_classes(["small-button"])
                                    .build();
                                let path_for_q = result.path.clone();
                                let threat_for_q = threat.clone();
                                let sl_for_q = sl.clone();
                                q_btn.connect_clicked(move |_| {
                                    match crate::quarantine::quarantine_file(
                                        std::path::Path::new(&path_for_q),
                                        &threat_for_q,
                                    ) {
                                        Ok(_) => {
                                    sl_for_q.set_label(&format!("Quarantined: {}", path_for_q));
                                        }
                                        Err(e) => {
                                    sl_for_q.set_label(&format!("Quarantine failed: {}", e));
                                        }
                                    }
                                });
                                row.append(&q_btn);
                            }

                            rb.append(&row);
                        }
                        Ok(ScanMessage::Completed {
                            files_scanned,
                            time_elapsed,
                            results,
                        }) => {
                            pb.set_fraction(1.0);
                            let infected_count = results.len();
                            pb.set_text(Some("Scan complete"));

                            if infected_count == 0 {
                                sl.set_label(&format!(
                                    "✅ Scan complete — No threats found. {} files scanned in {}.",
                                    files_scanned,
                                    crate::utils::format_duration(time_elapsed)
                                ));
                                sl.remove_css_class("status-bad");
                                sl.add_css_class("status-good");
                            } else {
                                sl.set_label(&format!(
                                    "⚠️ Scan complete — {} threat(s) found! {} files scanned in {}.",
                                    infected_count,
                                    files_scanned,
                                    crate::utils::format_duration(time_elapsed)
                                ));
                                sl.remove_css_class("status-good");
                                sl.add_css_class("status-bad");
                            }

                            // Re-enable buttons
                            cb.set_sensitive(false);
                            let mut child = sbb.first_child();
                            while let Some(c) = child {
                                if let Some(btn) = c.downcast_ref::<Button>() {
                                    if btn.label().unwrap_or_default().as_str() != "⏹ Cancel Scan" {
                                        btn.set_sensitive(true);
                                    }
                                }
                                child = c.next_sibling();
                            }
                            return;
                        }
                        Ok(ScanMessage::Error(msg)) => {
                            pb.set_fraction(0.0);
                            pb.set_text(Some("Error"));
                            sl.set_label(&format!("❌ {}", msg));
                            sl.add_css_class("status-bad");

                            cb.set_sensitive(false);
                            let mut child = sbb.first_child();
                            while let Some(c) = child {
                                if let Some(btn) = c.downcast_ref::<Button>() {
                                    if btn.label().unwrap_or_default().as_str() != "⏹ Cancel Scan" {
                                        btn.set_sensitive(true);
                                    }
                                }
                                child = c.next_sibling();
                            }
                            return;
                        }
                        Ok(ScanMessage::Cancelled) => {
                            pb.set_text(Some("Scan cancelled"));
                            sl.set_label("Scan was cancelled.");

                            cb.set_sensitive(false);
                            let mut child = sbb.first_child();
                            while let Some(c) = child {
                                if let Some(btn) = c.downcast_ref::<Button>() {
                                    if btn.label().unwrap_or_default().as_str() != "⏹ Cancel Scan" {
                                        btn.set_sensitive(true);
                                    }
                                }
                                child = c.next_sibling();
                            }
                            return;
                        }
                        Err(crossbeam_channel::TryRecvError::Empty) => {
                            // Pulse periodically so the bar shows activity
                            // even when clamscan output is sparse
                            pb.pulse();
                        }
                        Err(crossbeam_channel::TryRecvError::Disconnected) => {
                            // Channel closed
                            return;
                        }
                    }
                }
            });
        };

        *start_scan_fn.borrow_mut() = Some(std::boxed::Box::new(start_scan));

        // File scan button
        let start_scan_fn1 = start_scan_fn.clone();
        let win = window.clone();
        file_btn.connect_clicked(move |_| {
            let dialog = FileChooserDialog::builder()
                .title("Select a File to Scan")
                .action(FileChooserAction::Open)
                .transient_for(&win)
                .build();

            dialog.add_button("Cancel", ResponseType::Cancel);
            dialog.add_button("Scan", ResponseType::Accept);

            let sf = start_scan_fn1.clone();
            dialog.connect_response(move |dlg, resp| {
                if resp == ResponseType::Accept {
                    if let Some(file) = dlg.file() {
                        if let Some(path) = file.path() {
                            if let Some(f) = sf.borrow().as_ref() {
                                f(path, ScanType::File);
                            }
                        }
                    }
                }
                dlg.close();
            });

            dialog.show();
        });

        // Directory scan button
        let start_scan_fn2 = start_scan_fn.clone();
        let win2 = window.clone();
        dir_btn.connect_clicked(move |_| {
            let dialog = FileChooserDialog::builder()
                .title("Select a Directory to Scan")
                .action(FileChooserAction::SelectFolder)
                .transient_for(&win2)
                .build();

            dialog.add_button("Cancel", ResponseType::Cancel);
            dialog.add_button("Scan", ResponseType::Accept);

            let sf = start_scan_fn2.clone();
            dialog.connect_response(move |dlg, resp| {
                if resp == ResponseType::Accept {
                    if let Some(file) = dlg.file() {
                        if let Some(path) = file.path() {
                            if let Some(f) = sf.borrow().as_ref() {
                                f(path, ScanType::Directory);
                            }
                        }
                    }
                }
                dlg.close();
            });

            dialog.show();
        });

        // Home scan button
        let start_scan_fn3 = start_scan_fn.clone();
        home_btn.connect_clicked(move |_| {
            if let Some(f) = start_scan_fn3.borrow().as_ref() {
                let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/home"));
                f(home, ScanType::Home);
            }
        });

        // Full system scan button
        let start_scan_fn4 = start_scan_fn.clone();
        full_btn.connect_clicked(move |_| {
            if let Some(f) = start_scan_fn4.borrow().as_ref() {
                f(PathBuf::from("/"), ScanType::FullSystem);
            }
        });

        // Cancel button
        let cancel_scanner = scanner.clone();
        cancel_btn.connect_clicked(move |_| {
            cancel_scanner.borrow().cancel();
        });

        ScanPage {
            container,
            start_scan_fn,
        }
    }

    pub fn container(&self) -> &Box {
        &self.container
    }

    pub fn scan_home(&self) {
        if let Some(f) = self.start_scan_fn.borrow().as_ref() {
            let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/home"));
            f(home, ScanType::Home);
        }
    }
}
