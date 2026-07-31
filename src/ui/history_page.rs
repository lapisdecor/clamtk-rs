use gtk4::prelude::*;
use gtk4::{
    Box, Button, Label, Orientation, Separator,
    PolicyType, ScrolledWindow, Align, MessageDialog,
    MessageType, ButtonsType, ResponseType, ApplicationWindow,
};

pub struct HistoryPage {
    container: Box,
}

impl HistoryPage {
    pub fn new(window: &ApplicationWindow) -> Self {
        let container = Box::new(Orientation::Vertical, 16);
        container.set_margin_start(24);
        container.set_margin_end(24);
        container.set_margin_top(24);
        container.set_margin_bottom(24);

        // Title
        let title = Label::builder()
            .label("<big><b>Scan History</b></big>")
            .use_markup(true)
            .halign(Align::Start)
            .build();
        container.append(&title);

        // Action buttons
        let action_box = Box::new(Orientation::Horizontal, 8);

        let refresh_btn = Button::builder()
            .label("🔄 Refresh")
            .build();

        let clear_btn = Button::builder()
            .label("🗑️ Clear History")
            .css_classes(["destructive-action"])
            .build();

        action_box.append(&refresh_btn);
        action_box.append(&clear_btn);

        container.append(&action_box);

        // History list
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
        let eb = entries_box.clone();
        refresh_history_list(&eb);

        // Refresh button
        let eb2 = entries_box.clone();
        refresh_btn.connect_clicked(move |_| {
            refresh_history_list(&eb2);
        });

        // Clear button
        let eb3 = entries_box.clone();
        let win = window.clone();
        clear_btn.connect_clicked(move |_| {
            let dialog = MessageDialog::builder()
                .text("Clear Scan History?")
                .secondary_text("This will permanently delete all scan history records.")
                .message_type(MessageType::Warning)
                .buttons(ButtonsType::YesNo)
                .transient_for(&win)
                .build();

            let eb = eb3.clone();
            dialog.connect_response(move |dlg, resp| {
                if resp == ResponseType::Yes {
                    let _ = crate::history::clear_history();
                    refresh_history_list(&eb);
                }
                dlg.close();
            });

            dialog.show();
        });

        HistoryPage { container }
    }

    pub fn container(&self) -> &Box {
        &self.container
    }
}

fn refresh_history_list(entries_box: &Box) {
    while let Some(child) = entries_box.first_child() {
        entries_box.remove(&child);
    }

    let entries = match crate::history::load_entries() {
        Ok(e) => e,
        Err(_) => Vec::new(),
    };

    if entries.is_empty() {
        let empty_label = Label::builder()
            .label("No scan history yet.")
            .halign(Align::Center)
            .css_classes(["dim-label"])
            .margin_top(40)
            .build();
        entries_box.append(&empty_label);
        return;
    }

    for entry in entries {
        let row = Box::new(Orientation::Vertical, 4);
        row.set_margin_start(8);
        row.set_margin_end(8);
        row.set_margin_top(8);
        row.set_margin_bottom(4);

        let header = Box::new(Orientation::Horizontal, 8);

        let scan_type_label = Label::builder()
            .label(&format!("📋 {}", crate::utils::scan_type_display(&entry.scan_type)))
            .halign(Align::Start)
            .build();

        let date_label = Label::builder()
            .label(&entry.timestamp.format("%Y-%m-%d %H:%M:%S").to_string())
            .halign(Align::End)
            .css_classes(["dim-label"])
            .hexpand(true)
            .build();

        header.append(&scan_type_label);
        header.append(&date_label);

        let target_label = Label::builder()
            .label(&format!("Target: {}", crate::utils::truncate_path(&entry.target, 80)))
            .halign(Align::Start)
            .css_classes(["dim-label"])
            .build();

        let result_label = if entry.threats_found == 0 {
            Label::builder()
                .label(&format!("✅ {} files scanned, no threats found ({})",
                    entry.files_scanned,
                    crate::utils::format_duration(entry.time_elapsed)
                ))
                .css_classes(["status-good"])
                .halign(Align::Start)
                .build()
        } else {
            Label::builder()
                .label(&format!("⚠️ {} files scanned, {} threat(s) found ({})",
                    entry.files_scanned,
                    entry.threats_found,
                    crate::utils::format_duration(entry.time_elapsed)
                ))
                .css_classes(["status-bad"])
                .halign(Align::Start)
                .build()
        };

        // Show infected files if any
        let infected_label = if !entry.infected_files.is_empty() {
            let files: Vec<String> = entry.infected_files
                .iter()
                .map(|f| crate::utils::truncate_path(f, 60))
                .collect();
            Label::builder()
                .label(&format!("Infected: {}", files.join(", ")))
                .halign(Align::Start)
                .wrap(true)
                .css_classes(["dim-label"])
                .build()
        } else {
            Label::new(None)
        };

        row.append(&header);
        row.append(&target_label);
        row.append(&result_label);
        if !entry.infected_files.is_empty() {
            row.append(&infected_label);
        }

        let sep = Separator::new(Orientation::Horizontal);

        entries_box.append(&row);
        entries_box.append(&sep);
    }
}
