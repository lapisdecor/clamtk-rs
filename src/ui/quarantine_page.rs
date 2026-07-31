use gtk4::prelude::*;
use gtk4::{
    Box, Button, Label, Orientation,
    PolicyType, ScrolledWindow, Align, MessageDialog, MessageType,
    ButtonsType, ResponseType, ApplicationWindow,
};

pub struct QuarantinePage {
    container: Box,
}

impl QuarantinePage {
    pub fn new(window: &ApplicationWindow) -> Self {
        let container = Box::new(Orientation::Vertical, 16);
        container.set_margin_start(24);
        container.set_margin_end(24);
        container.set_margin_top(24);
        container.set_margin_bottom(24);

        // Title
        let title = Label::builder()
            .label("<big><b>Quarantine</b></big>")
            .use_markup(true)
            .halign(Align::Start)
            .build();
        container.append(&title);

        // Description
        let desc = Label::builder()
            .label("Quarantined files are isolated to prevent further infection.\n\
                    You can restore or permanently delete them from here.")
            .halign(Align::Start)
            .wrap(true)
            .css_classes(["dim-label"])
            .build();
        container.append(&desc);

        // Action buttons
        let action_box = Box::new(Orientation::Horizontal, 8);

        let refresh_btn = Button::builder()
            .label("🔄 Refresh")
            .build();

        let purge_btn = Button::builder()
            .label("🗑️ Purge All")
            .css_classes(["destructive-action"])
            .build();

        action_box.append(&refresh_btn);
        action_box.append(&purge_btn);

        container.append(&action_box);

        // Quarantine list
        let scroll = ScrolledWindow::builder()
            .vexpand(true)
            .min_content_height(200)
            .hscrollbar_policy(PolicyType::Automatic)
            .vscrollbar_policy(PolicyType::Automatic)
            .build();

        let entries_box = Box::new(Orientation::Vertical, 4);
        scroll.set_child(Some(&entries_box));

        container.append(&scroll);

        // Load initial entries
        refresh_quarantine_list(&entries_box);

        // Wire up refresh button
        let entries_box_clone = entries_box.clone();
        refresh_btn.connect_clicked(move |_| {
            refresh_quarantine_list(&entries_box_clone);
        });

        // Wire up purge button
        let entries_box_clone2 = entries_box.clone();
        let win = window.clone();
        purge_btn.connect_clicked(move |_| {
            // Show confirmation dialog
            let dialog = MessageDialog::builder()
                .text("Purge All Quarantined Files?")
                .secondary_text("This will permanently delete all quarantined files. This cannot be undone.")
                .message_type(MessageType::Warning)
                .buttons(ButtonsType::YesNo)
                .transient_for(&win)
                .build();

            let eb = entries_box_clone2.clone();
            dialog.connect_response(move |dlg, resp| {
                if resp == ResponseType::Yes {
                    match crate::quarantine::purge_all() {
                        Ok(count) => {
                            log::info!("Purged {} quarantined files", count);
                        }
                        Err(e) => {
                            log::error!("Failed to purge: {}", e);
                        }
                    }
                    refresh_quarantine_list(&eb);
                }
                dlg.close();
            });

            dialog.show();
        });

        QuarantinePage {
            container,
        }
    }

    pub fn container(&self) -> &Box {
        &self.container
    }
}

fn refresh_quarantine_list(entries_box: &Box) {
    // Clear existing entries
    while let Some(child) = entries_box.first_child() {
        entries_box.remove(&child);
    }

    let entries = match crate::quarantine::load_entries() {
        Ok(e) => e,
        Err(_) => Vec::new(),
    };

    if entries.is_empty() {
        let empty_label = Label::builder()
            .label("No files in quarantine.")
            .halign(Align::Center)
            .css_classes(["dim-label"])
            .margin_top(40)
            .build();
        entries_box.append(&empty_label);
        return;
    }

    let active_entries: Vec<_> = entries.into_iter().filter(|e| !e.restored).collect();

    for entry in active_entries {
        let row = Box::new(Orientation::Horizontal, 8);
        row.set_margin_start(8);
        row.set_margin_end(8);
        row.set_margin_top(4);
        row.set_margin_bottom(4);

        let icon = Label::builder()
            .label("⚠️")
            .build();

        let info_box = Box::new(Orientation::Vertical, 2);
        info_box.set_hexpand(true);

        let path_label = Label::builder()
            .label(&*entry.original_path.to_string_lossy())
            .halign(Align::Start)
            .ellipsize(gtk4::pango::EllipsizeMode::End)
            .build();

        let threat_label = Label::builder()
            .label(&format!("Threat: {} | Size: {} | Quarantined: {}",
                entry.threat_name,
                crate::utils::format_size(entry.file_size),
                entry.quarantined_at.format("%Y-%m-%d %H:%M")
            ))
            .halign(Align::Start)
            .css_classes(["dim-label"])
            .build();

        info_box.append(&path_label);
        info_box.append(&threat_label);

        let restore_btn = Button::builder()
            .label("Restore")
            .build();

        let delete_btn = Button::builder()
            .label("Delete")
            .css_classes(["destructive-action"])
            .build();

        let entry_id = entry.id.clone();
        let eb = entries_box.clone();
        restore_btn.connect_clicked(move |_| {
            match crate::quarantine::restore_file(&entry_id) {
                Ok(path) => {
                    log::info!("Restored file to: {}", path.display());
                }
                Err(e) => {
                    log::error!("Failed to restore: {}", e);
                }
            }
            refresh_quarantine_list(&eb);
        });

        let entry_id2 = entry.id.clone();
        let eb2 = entries_box.clone();
        delete_btn.connect_clicked(move |_| {
            match crate::quarantine::delete_quarantined(&entry_id2) {
                Ok(_) => {
                    log::info!("Deleted quarantined file");
                }
                Err(e) => {
                    log::error!("Failed to delete: {}", e);
                }
            }
            refresh_quarantine_list(&eb2);
        });

        row.append(&icon);
        row.append(&info_box);
        row.append(&restore_btn);
        row.append(&delete_btn);

        entries_box.append(&row);
        entries_box.append(&gtk4::Separator::new(Orientation::Horizontal));
    }
}
