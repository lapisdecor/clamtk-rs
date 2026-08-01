use gtk4::prelude::*;
use gtk4::{
    Box, Button, Label, Orientation, ProgressBar, Align,
};
use std::process::Command;
use std::sync::mpsc;

enum UpdateMessage {
    Status(String),
    Done(anyhow::Result<String>),
}

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

        // On Ubuntu, ClamAV keeps its virus definitions up to date through the
        // freshclam service, so manual updates are disabled and a warning is
        // shown. Inside a snap this does not apply: the snap bundles its own
        // ClamAV, which is confined away from the host's database.
        let is_ubuntu = crate::utils::is_host_ubuntu() && !crate::utils::is_running_in_snap();
        if is_ubuntu {
            let warn_box = Box::new(Orientation::Vertical, 4);
            warn_box.set_margin_top(8);
            warn_box.add_css_class("card");

            let warn_label = Label::builder()
                .label(
                    "⚠️ <b>Manual signature updates are disabled.</b>\n\
                     On Ubuntu, ClamAV updates its virus definitions automatically \
                     via the freshclam service, so no manual update is needed.",
                )
                .use_markup(true)
                .halign(Align::Start)
                .wrap(true)
                .css_classes(["status-warn"])
                .build();
            warn_box.append(&warn_label);
            container.append(&warn_box);
        }

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

        // Update button (disabled on Ubuntu, where freshclam runs automatically)
        let update_btn = Button::builder()
            .label("🔄 Update Virus Signatures")
            .css_classes(["big-button", "suggested-action"])
            .sensitive(info.is_freshclam_available && !is_ubuntu)
            .tooltip_text(if is_ubuntu {
                "Disabled on Ubuntu: ClamAV updates virus definitions automatically."
            } else {
                "Download the latest virus definitions"
            })
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

        // Note about privileges
        let note = if is_ubuntu {
            Label::builder()
                .label("<i>On Ubuntu, ClamAV's freshclam service keeps virus \
                        definitions up to date automatically.</i>")
                .use_markup(true)
                .halign(Align::Start)
                .css_classes(["dim-label"])
                .build()
        } else {
            Label::builder()
                .label("<i>Note: Updating signatures requires root privileges. The freshclam \
                        service will be stopped before the update and started again afterwards.</i>")
                .use_markup(true)
                .halign(Align::Start)
                .css_classes(["dim-label"])
                .build()
        };
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

            // Run the update sequence in a thread
            std::thread::spawn(move || {
                let result = run_freshclam(|status| {
                    let _ = tx.send(UpdateMessage::Status(status.to_string()));
                });
                let _ = tx.send(UpdateMessage::Done(result));
            });

            let pb = progress_bar_clone.clone();
            let sl = status_label_clone.clone();
            let ol = output_label_clone.clone();
            let btn = update_btn_clone.clone();

            glib::spawn_future_local(async move {
                loop {
                    let _ = glib::timeout_future(std::time::Duration::from_millis(100)).await;
                    match rx.try_recv() {
                        Ok(UpdateMessage::Status(status)) => {
                            sl.set_label(&status);
                        }
                        Ok(UpdateMessage::Done(Ok(output))) => {
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
                        Ok(UpdateMessage::Done(Err(e))) => {
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

fn run_freshclam<F: FnMut(&str)>(mut on_status: F) -> anyhow::Result<String> {
    // On Ubuntu, ClamAV updates its virus definitions automatically through the
    // freshclam service. Never run a manual update there.
    if crate::utils::is_host_ubuntu() && !crate::utils::is_running_in_snap() {
        on_status("ClamAV updates virus definitions automatically on Ubuntu.");
        return Ok(
            "Manual signature updates are disabled on Ubuntu: ClamAV updates its \
             virus definitions automatically via the freshclam service."
                .to_string(),
        );
    }

    // When running inside a snap, freshclam is bundled and writes to the snap's
    // writable data directory, so no root privileges are required.
    if crate::utils::is_running_in_snap() {
        return run_freshclam_in_snap(&mut on_status);
    }

    let mut log = Vec::new();

    on_status("Stopping freshclam service...");
    match run_privileged("service clamav-freshclam stop") {
        Ok(out) => log.push(format!("Freshclam service stopped.\n{}", out)),
        Err(e) => log.push(format!("Note: could not stop freshclam service: {}", e)),
    }

    on_status("Updating virus signatures (root password required)...");
    let update_output = match run_privileged("freshclam") {
        Ok(out) => out,
        Err(e) => {
            let _ = run_privileged("service clamav-freshclam start");
            anyhow::bail!("Signature update failed: {}", e);
        }
    };

    on_status("Starting freshclam service...");
    match run_privileged("service clamav-freshclam start") {
        Ok(out) => log.push(format!("Freshclam service started.\n{}", out)),
        Err(e) => log.push(format!("Note: could not restart freshclam service: {}", e)),
    }

    Ok(format!("{}\n{}", update_output, log.join("\n")).trim().to_string())
}

fn run_freshclam_in_snap<F: FnMut(&str)>(on_status: &mut F) -> anyhow::Result<String> {
    let config_path = crate::clamav::write_snap_freshclam_config()?;

    on_status("Updating virus signatures...");
    // Note: --datadir is intentionally NOT passed; see clamav::ensure_database.
    let output = Command::new("freshclam")
        .arg("--config-file")
        .arg(&config_path)
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to launch freshclam: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        anyhow::bail!("{}", stderr.trim());
    }

    Ok(format!("{}\n{}", stdout, stderr).trim().to_string())
}

fn run_privileged(script: &str) -> anyhow::Result<String> {
    let output = Command::new("pkexec")
        .arg("sh")
        .arg("-c")
        .arg(script)
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to launch pkexec: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        anyhow::bail!("{}", stderr.trim());
    }

    Ok(format!("{}\n{}", stdout, stderr).trim().to_string())
}
