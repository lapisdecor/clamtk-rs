use gtk4::prelude::*;
use gtk4::{
    Box, Button, Label, Orientation, ProgressBar, Align,
};
use std::process::Command;
use std::sync::mpsc;

pub struct UpdatePage {
    container: Box,
}

impl UpdatePage {
    pub fn new() -> Self {
        let container = Box::new(Orientation::Vertical, 16);
        container.set_margin_start(24);
        container.set_margin_end(24);
        container.set_margin_top(24);
        container.set_margin_bottom(24);

        // Title
        let title = Label::builder()
            .label("<big><b>Update Signatures</b></big>")
            .use_markup(true)
            .halign(Align::Start)
            .build();
        container.append(&title);

        // Info section
        let info = crate::clamav::get_info();

        let info_box = Box::new(Orientation::Vertical, 8);

        let current_version = Label::builder()
            .label(&format!("Current signature date: {}", info.signature_version))
            .halign(Align::Start)
            .build();

        let signature_count = Label::builder()
            .label(&format!("Known signatures: {}", info.signature_count))
            .halign(Align::Start)
            .build();

        let freshclam_status = if info.is_freshclam_available {
            Label::builder()
                .label("Freshclam: ● Available")
                .css_classes(["status-good"])
                .halign(Align::Start)
                .build()
        } else {
            Label::builder()
                .label("Freshclam: ● Not Found")
                .css_classes(["status-bad"])
                .halign(Align::Start)
                .build()
        };

        info_box.append(&current_version);
        info_box.append(&signature_count);
        info_box.append(&freshclam_status);

        container.append(&info_box);

        // Update button
        let update_btn = Button::builder()
            .label("🔄 Update Virus Signatures")
            .css_classes(["big-button", "suggested-action"])
            .sensitive(info.is_freshclam_available)
            .build();

        container.append(&update_btn);

        // Progress area
        let progress_box = Box::new(Orientation::Vertical, 8);

        let progress_bar = ProgressBar::builder()
            .show_text(true)
            .build();

        let status_label = Label::builder()
            .label("")
            .halign(Align::Start)
            .wrap(true)
            .build();

        let output_label = Label::builder()
            .label("")
            .halign(Align::Start)
            .wrap(true)
            .css_classes(["dim-label"])
            .build();

        progress_box.append(&progress_bar);
        progress_box.append(&status_label);
        progress_box.append(&output_label);

        container.append(&progress_box);

        // Spacer
        let spacer = Box::new(Orientation::Vertical, 0);
        spacer.set_vexpand(true);
        container.append(&spacer);

        // Note about sudo
        let note = Label::builder()
            .label("<i>Note: Updating signatures typically requires root privileges.\n\
                    The update will attempt to run with pkexec if needed.</i>")
            .use_markup(true)
            .halign(Align::Start)
            .css_classes(["dim-label"])
            .build();
        container.append(&note);

        // Wire up update button
        let update_btn_clone = update_btn.clone();
        let progress_bar_clone = progress_bar.clone();
        let status_label_clone = status_label.clone();
        let output_label_clone = output_label.clone();

        update_btn.connect_clicked(move |_| {
            update_btn_clone.set_sensitive(false);
            progress_bar_clone.set_fraction(0.0);
            progress_bar_clone.set_text(Some("Updating..."));
            status_label_clone.set_label("Starting signature update...");
            output_label_clone.set_label("");

            let (tx, rx) = mpsc::channel();

            // Run freshclam in a thread
            std::thread::spawn(move || {
                let result = run_freshclam();
                let _ = tx.send(result);
            });

            let pb = progress_bar_clone.clone();
            let sl = status_label_clone.clone();
            let ol = output_label_clone.clone();
            let btn = update_btn_clone.clone();

            glib::spawn_future_local(async move {
                loop {
                    let _ = glib::timeout_future(std::time::Duration::from_millis(100)).await;
                    match rx.try_recv() {
                        Ok(Ok(output)) => {
                            pb.set_fraction(1.0);
                            pb.set_text(Some("Update complete"));

                            if output.contains("Database updated") || output.contains("main.cvd") {
                                sl.set_label("✅ Signatures updated successfully!");
                                sl.add_css_class("status-good");
                            } else if output.contains("already up-to-date") {
                                sl.set_label("ℹ️ Signatures are already up to date.");
                                sl.add_css_class("status-good");
                            } else {
                                sl.set_label("⚠️ Update completed. Check output for details.");
                                sl.add_css_class("status-warn");
                            }

                            ol.set_label(&output);
                            btn.set_sensitive(true);
                            return;
                        }
                        Ok(Err(e)) => {
                            pb.set_fraction(0.0);
                            pb.set_text(Some("Update failed"));
                            sl.set_label(&format!("❌ Update failed: {}", e));
                            sl.add_css_class("status-bad");
                            ol.set_label(&format!("Error: {}", e));
                            btn.set_sensitive(true);
                            return;
                        }
                        Err(mpsc::TryRecvError::Empty) => {}
                        Err(mpsc::TryRecvError::Disconnected) => return,
                    }
                }
            });
        });

        UpdatePage { container }
    }

    pub fn container(&self) -> &Box {
        &self.container
    }
}

fn run_freshclam() -> anyhow::Result<String> {
    // Try running freshclam directly first, then with pkexec
    let output = Command::new("freshclam")
        .output()
        .or_else(|_| {
            Command::new("pkexec")
                .arg("freshclam")
                .output()
        })
        .map_err(|e| anyhow::anyhow!("Failed to run freshclam: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() && stdout.is_empty() {
        anyhow::bail!("freshclam exited with error: {}", stderr);
    }

    Ok(format!("{}\n{}", stdout, stderr).trim().to_string())
}
