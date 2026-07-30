use gtk4::prelude::*;
use gtk4::{
    Box, Button, Grid, Label, Orientation,
    Separator, Align,
};

use crate::clamav;

pub struct DashboardPage {
    container: Box,
}

impl DashboardPage {
    pub fn new(
        on_scan_home: Option<std::boxed::Box<dyn Fn() + 'static>>,
        on_update: Option<std::boxed::Box<dyn Fn() + 'static>>,
        on_settings: Option<std::boxed::Box<dyn Fn() + 'static>>,
    ) -> Self {
        let container = Box::new(Orientation::Vertical, 16);
        container.set_margin_start(24);
        container.set_margin_end(24);
        container.set_margin_top(24);
        container.set_margin_bottom(24);

        // Title
        let title = Label::builder()
            .label("<big><b>ClamTK Rust — Dashboard</b></big>")
            .use_markup(true)
            .halign(Align::Start)
            .build();
        container.append(&title);

        let separator = Separator::new(Orientation::Horizontal);
        container.append(&separator);

        // Status grid
        let grid = Grid::builder()
            .column_spacing(20)
            .row_spacing(12)
            .build();

        let info = clamav::get_info();

        // Row 0: Engine Status
        let status_label = Label::builder()
            .label("Engine Status")
            .halign(Align::Start)
            .build();
        let status_value = if info.is_clamscan_available {
            Label::builder()
                .label("● Active")
                .css_classes(["status-good"])
                .halign(Align::Start)
                .build()
        } else {
            Label::builder()
                .label("● Not Found")
                .css_classes(["status-bad"])
                .halign(Align::Start)
                .build()
        };
        grid.attach(&status_label, 0, 0, 1, 1);
        grid.attach(&status_value, 1, 0, 1, 1);

        // Row 1: ClamAV Version
        let version_label = Label::builder()
            .label("ClamAV Version")
            .halign(Align::Start)
            .build();
        let version_value = Label::builder()
            .label(&info.build_info)
            .halign(Align::Start)
            .build();
        grid.attach(&version_label, 0, 1, 1, 1);
        grid.attach(&version_value, 1, 1, 1, 1);

        // Row 2: Signature Count
        let sig_label = Label::builder()
            .label("Signature Count")
            .halign(Align::Start)
            .build();
        let sig_value = Label::builder()
            .label(&info.signature_count)
            .halign(Align::Start)
            .build();
        grid.attach(&sig_label, 0, 2, 1, 1);
        grid.attach(&sig_value, 1, 2, 1, 1);

        // Row 3: Signature Version
        let sig_ver_label = Label::builder()
            .label("Signature Date")
            .halign(Align::Start)
            .build();
        let sig_ver_value = Label::builder()
            .label(&info.signature_version)
            .halign(Align::Start)
            .build();
        grid.attach(&sig_ver_label, 0, 3, 1, 1);
        grid.attach(&sig_ver_value, 1, 3, 1, 1);

        // Row 4: Freshclam
        let fc_label = Label::builder()
            .label("Freshclam")
            .halign(Align::Start)
            .build();
        let fc_value = if info.is_freshclam_available {
            Label::builder()
                .label("● Available")
                .css_classes(["status-good"])
                .halign(Align::Start)
                .build()
        } else {
            Label::builder()
                .label("● Not Found")
                .css_classes(["status-warn"])
                .halign(Align::Start)
                .build()
        };
        grid.attach(&fc_label, 0, 4, 1, 1);
        grid.attach(&fc_value, 1, 4, 1, 1);

        // Row 5: Clamd
        let cd_label = Label::builder()
            .label("ClamD Daemon")
            .halign(Align::Start)
            .build();
        let cd_value = if info.is_clamd_available {
            let running = clamav::is_clamd_running();
            if running {
                Label::builder()
                    .label("● Running")
                    .css_classes(["status-good"])
                    .halign(Align::Start)
                    .build()
            } else {
                Label::builder()
                    .label("● Available (not running)")
                    .css_classes(["status-warn"])
                    .halign(Align::Start)
                    .build()
            }
        } else {
            Label::builder()
                .label("● Not Available")
                .css_classes(["status-bad"])
                .halign(Align::Start)
                .build()
        };
        grid.attach(&cd_label, 0, 5, 1, 1);
        grid.attach(&cd_value, 1, 5, 1, 1);

        // Make the first column wider
        let first_col_label = Label::builder()
            .label("Signature Count  ")
            .visible(false)
            .build();
        grid.attach(&first_col_label, 0, 10, 1, 1);

        container.append(&grid);

        container.append(&Separator::new(Orientation::Horizontal));

        // Quick Actions
        let actions_title = Label::builder()
            .label("<b>Quick Actions</b>")
            .use_markup(true)
            .halign(Align::Start)
            .build();
        container.append(&actions_title);

        let actions_box = Box::new(Orientation::Horizontal, 12);

        let quick_scan_btn = Button::builder()
            .label("Scan Home Directory")
            .css_classes(["big-button", "suggested-action"])
            .build();

        let quick_update_btn = Button::builder()
            .label("Update Signatures")
            .css_classes(["big-button"])
            .build();

        let quick_prefs_btn = Button::builder()
            .label("Settings")
            .css_classes(["big-button"])
            .build();

        actions_box.append(&quick_scan_btn);
        actions_box.append(&quick_update_btn);
        actions_box.append(&quick_prefs_btn);

        if let Some(callback) = on_scan_home {
            quick_scan_btn.connect_clicked(move |_| {
                callback();
            });
        }

        if let Some(callback) = on_update {
            quick_update_btn.connect_clicked(move |_| {
                callback();
            });
        }

        if let Some(callback) = on_settings {
            quick_prefs_btn.connect_clicked(move |_| {
                callback();
            });
        }

        container.append(&actions_box);

        // Spacer
        let spacer = Box::new(Orientation::Vertical, 0);
        spacer.set_vexpand(true);
        container.append(&spacer);

        // Footer info
        let footer = Label::builder()
            .label("<i>ClamTK Rust — A GTK4 frontend for ClamAV</i>")
            .use_markup(true)
            .halign(Align::Center)
            .css_classes(["dim-label"])
            .build();
        container.append(&footer);

        DashboardPage { container }
    }

    pub fn container(&self) -> &Box {
        &self.container
    }
}
