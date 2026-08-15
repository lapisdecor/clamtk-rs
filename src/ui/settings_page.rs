use gtk4::prelude::*;
use gtk4::{
    Box, Button, CheckButton, Grid, Label, Orientation,
    SpinButton, Entry, Separator, Align, MessageDialog,
    MessageType, ButtonsType, ResponseType, ApplicationWindow,
};

use std::rc::Rc;
use std::cell::RefCell;

use crate::config::AppConfig;

pub struct SettingsPage {
    container: Box,
}

impl SettingsPage {
    pub fn new(window: &ApplicationWindow) -> Self {
        let container = Box::new(Orientation::Vertical, 16);
        container.set_margin_start(24);
        container.set_margin_end(24);
        container.set_margin_top(24);
        container.set_margin_bottom(24);

        let config = Rc::new(RefCell::new(
            AppConfig::load().unwrap_or_default()
        ));

        // Title
        let title = Label::builder()
            .label("<big><b>Settings</b></big>")
            .use_markup(true)
            .halign(Align::Start)
            .build();
        container.append(&title);

        let scroll = gtk4::ScrolledWindow::builder()
            .vexpand(true)
            .hscrollbar_policy(gtk4::PolicyType::Never)
            .build();

        let content = Box::new(Orientation::Vertical, 16);
        scroll.set_child(Some(&content));

        // === Notifications ===
        let notif_title = Label::builder()
            .label("<b>Notifications</b>")
            .use_markup(true)
            .halign(Align::Start)
            .build();
        content.append(&notif_title);

        let play_sound = {
            let c = config.borrow();
            CheckButton::builder()
                .label("Play a sound when a scan is finished")
                .active(c.play_sound_on_complete)
                .build()
        };
        content.append(&play_sound);

        // Apply this toggle immediately (no need to press Save), so disabling
        // the sound stops it from playing on the very next scan.
        let config_sound = config.clone();
        play_sound.connect_toggled(move |chk| {
            let mut cfg = config_sound.borrow_mut();
            cfg.play_sound_on_complete = chk.is_active();
            if let Err(e) = cfg.save() {
                log::error!("Failed to save notification setting: {}", e);
            }
        });

        content.append(&Separator::new(Orientation::Horizontal));

        // === Scan Options ===
        let scan_title = Label::builder()
            .label("<b>Scan Options</b>")
            .use_markup(true)
            .halign(Align::Start)
            .build();
        content.append(&scan_title);

        let scan_grid = Grid::builder()
            .column_spacing(12)
            .row_spacing(8)
            .build();

        let scan_archives;
        let scan_elf;
        let scan_pdf;
        let scan_mail;
        let scan_ole2;
        let detect_pua;
        let heuristic;
        let follow_symlinks;
        {
            let c = config.borrow();
            scan_archives = CheckButton::builder()
                .label("Scan archives (zip, tar, etc.)")
                .active(c.scan_archives)
                .build();
            scan_elf = CheckButton::builder()
                .label("Scan ELF executables")
                .active(c.scan_elf)
                .build();
            scan_pdf = CheckButton::builder()
                .label("Scan PDF files")
                .active(c.scan_pdf)
                .build();
            scan_mail = CheckButton::builder()
                .label("Scan mail files")
                .active(c.scan_mail)
                .build();
            scan_ole2 = CheckButton::builder()
                .label("Scan OLE2 files (doc, xls, etc.)")
                .active(c.scan_ole2)
                .build();
            detect_pua = CheckButton::builder()
                .label("Detect Potentially Unwanted Applications (PUA)")
                .active(c.detect_pua)
                .build();
            heuristic = CheckButton::builder()
                .label("Heuristic scan precedence")
                .active(c.heuristic_scan)
                .build();
            follow_symlinks = CheckButton::builder()
                .label("Follow symbolic links")
                .active(c.scan_follow_symlinks)
                .build();
        }

        scan_grid.attach(&scan_archives, 0, 0, 2, 1);
        scan_grid.attach(&scan_elf, 0, 1, 2, 1);
        scan_grid.attach(&scan_pdf, 0, 2, 2, 1);
        scan_grid.attach(&scan_mail, 0, 3, 2, 1);
        scan_grid.attach(&scan_ole2, 0, 4, 2, 1);
        scan_grid.attach(&detect_pua, 0, 5, 2, 1);
        scan_grid.attach(&heuristic, 0, 6, 2, 1);
        scan_grid.attach(&follow_symlinks, 0, 7, 2, 1);

        content.append(&scan_grid);

        content.append(&Separator::new(Orientation::Horizontal));

        // === Limits ===
        let limits_title = Label::builder()
            .label("<b>Limits</b>")
            .use_markup(true)
            .halign(Align::Start)
            .build();
        content.append(&limits_title);

        let limits_grid = Grid::builder()
            .column_spacing(12)
            .row_spacing(8)
            .build();

        let max_file_label = Label::builder()
            .label("Max file size (MB):")
            .halign(Align::Start)
            .build();

        let max_file_spin = SpinButton::with_range(1.0, 1000.0, 1.0);
        {
            let c = config.borrow();
            max_file_spin.set_value(c.max_file_size_mb as f64);
        }

        let max_time_label = Label::builder()
            .label("Max scan time (seconds):")
            .halign(Align::Start)
            .build();

        let max_time_spin = SpinButton::with_range(10.0, 3600.0, 10.0);
        {
            let c = config.borrow();
            max_time_spin.set_value(c.max_scan_time_sec as f64);
        }

        let history_limit_label = Label::builder()
            .label("History limit (entries):")
            .halign(Align::Start)
            .build();

        let history_limit_spin = SpinButton::with_range(10.0, 1000.0, 10.0);
        {
            let c = config.borrow();
            history_limit_spin.set_value(c.history_limit as f64);
        }

        limits_grid.attach(&max_file_label, 0, 0, 1, 1);
        limits_grid.attach(&max_file_spin, 1, 0, 1, 1);
        limits_grid.attach(&max_time_label, 0, 1, 1, 1);
        limits_grid.attach(&max_time_spin, 1, 1, 1, 1);
        limits_grid.attach(&history_limit_label, 0, 2, 1, 1);
        limits_grid.attach(&history_limit_spin, 1, 2, 1, 1);

        content.append(&limits_grid);

        content.append(&Separator::new(Orientation::Horizontal));

        // === Quarantine Directory ===
        let q_title = Label::builder()
            .label("<b>Quarantine Directory</b>")
            .use_markup(true)
            .halign(Align::Start)
            .build();
        content.append(&q_title);

        let q_box = Box::new(Orientation::Horizontal, 8);
        let q_entry = {
            let c = config.borrow();
            Entry::builder()
                .text(&*c.quarantine_dir.to_string_lossy())
                .hexpand(true)
                .build()
        };

        let q_browse = Button::builder()
            .label("Browse...")
            .build();

        q_box.append(&q_entry);
        q_box.append(&q_browse);

        content.append(&q_box);

        content.append(&Separator::new(Orientation::Horizontal));

        // === Exclude Paths ===
        let excl_title = Label::builder()
            .label("<b>Exclude Paths</b>")
            .use_markup(true)
            .halign(Align::Start)
            .build();
        content.append(&excl_title);

        let excl_label = Label::builder()
            .label("One path per line:")
            .halign(Align::Start)
            .build();
        content.append(&excl_label);

        let excl_text = gtk4::TextView::builder()
            .wrap_mode(gtk4::WrapMode::WordChar)
            .height_request(80)
            .build();

        let excl_buffer = excl_text.buffer();
        {
            let c = config.borrow();
            let excl_text_str = c.exclude_paths.join("\n");
            excl_buffer.set_text(&excl_text_str);
        }

        content.append(&excl_text);

        // Spacer
        let spacer = Box::new(Orientation::Vertical, 0);
        spacer.set_vexpand(true);
        content.append(&spacer);

        container.append(&scroll);

        // Save / Reset buttons
        let btn_box = Box::new(Orientation::Horizontal, 8);

        let save_btn = Button::builder()
            .label("💾 Save Settings")
            .css_classes(["suggested-action"])
            .build();

        let reset_btn = Button::builder()
            .label("↩️ Reset to Defaults")
            .build();

        btn_box.append(&save_btn);
        btn_box.append(&reset_btn);
        btn_box.set_halign(Align::End);

        container.append(&btn_box);

        // Wire up save button
        let config_rc = config.clone();
        let play_sound_c = play_sound.clone();
        let scan_archives_c = scan_archives.clone();
        let scan_elf_c = scan_elf.clone();
        let scan_pdf_c = scan_pdf.clone();
        let scan_mail_c = scan_mail.clone();
        let scan_ole2_c = scan_ole2.clone();
        let detect_pua_c = detect_pua.clone();
        let heuristic_c = heuristic.clone();
        let follow_symlinks_c = follow_symlinks.clone();
        let max_file_spin_c = max_file_spin.clone();
        let max_time_spin_c = max_time_spin.clone();
        let history_limit_spin_c = history_limit_spin.clone();
        let q_entry_c = q_entry.clone();
        let excl_buffer_c = excl_buffer.clone();

        save_btn.connect_clicked(move |_| {
            let mut cfg = config_rc.borrow_mut();

            cfg.play_sound_on_complete = play_sound_c.is_active();
            cfg.scan_archives = scan_archives_c.is_active();
            cfg.scan_elf = scan_elf_c.is_active();
            cfg.scan_pdf = scan_pdf_c.is_active();
            cfg.scan_mail = scan_mail_c.is_active();
            cfg.scan_ole2 = scan_ole2_c.is_active();
            cfg.detect_pua = detect_pua_c.is_active();
            cfg.heuristic_scan = heuristic_c.is_active();
            cfg.scan_follow_symlinks = follow_symlinks_c.is_active();
            cfg.max_file_size_mb = max_file_spin_c.value() as u64;
            cfg.max_scan_time_sec = max_time_spin_c.value() as u64;
            cfg.history_limit = history_limit_spin_c.value() as usize;
            cfg.quarantine_dir = std::path::PathBuf::from(q_entry_c.text().as_str());

            // Parse exclude paths
            let (start, end) = excl_buffer_c.bounds();
            let text = excl_buffer_c.text(&start, &end, false);
            cfg.exclude_paths = text
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect();

            match cfg.save() {
                Ok(_) => {
                    log::info!("Settings saved successfully");
                }
                Err(e) => {
                    log::error!("Failed to save settings: {}", e);
                }
            }
        });

        // Wire up browse button for quarantine dir
        let q_entry_browse = q_entry.clone();
        q_browse.connect_clicked(move |_| {
            let dialog = gtk4::FileChooserDialog::builder()
                .title("Select Quarantine Directory")
                .action(gtk4::FileChooserAction::SelectFolder)
                .build();

            dialog.add_button("Cancel", ResponseType::Cancel);
            dialog.add_button("Select", ResponseType::Accept);

            let entry = q_entry_browse.clone();
            dialog.connect_response(move |dlg, resp| {
                if resp == ResponseType::Accept {
                    if let Some(file) = dlg.file() {
                        if let Some(path) = file.path() {
                            entry.set_text(&path.to_string_lossy());
                        }
                    }
                }
                dlg.close();
            });

            dialog.show();
        });

        // Wire up reset button
        let config_rc2 = config.clone();
        let play_sound_r = play_sound.clone();
        let scan_archives_r = scan_archives.clone();
        let scan_elf_r = scan_elf.clone();
        let scan_pdf_r = scan_pdf.clone();
        let scan_mail_r = scan_mail.clone();
        let scan_ole2_r = scan_ole2.clone();
        let detect_pua_r = detect_pua.clone();
        let heuristic_r = heuristic.clone();
        let follow_symlinks_r = follow_symlinks.clone();
        let max_file_spin_r = max_file_spin.clone();
        let max_time_spin_r = max_time_spin.clone();
        let history_limit_spin_r = history_limit_spin.clone();
        let q_entry_r = q_entry.clone();
        let excl_buffer_r = excl_buffer.clone();
        let win = window.clone();

        reset_btn.connect_clicked(move |_| {
            let dialog = MessageDialog::builder()
                .text("Reset Settings to Defaults?")
                .secondary_text("This will reset all settings to their default values.")
                .message_type(MessageType::Question)
                .buttons(ButtonsType::YesNo)
                .transient_for(&win)
                .build();

            let cfg_rc = config_rc2.clone();
            let ps = play_sound_r.clone();
            let sa = scan_archives_r.clone();
            let se = scan_elf_r.clone();
            let sp = scan_pdf_r.clone();
            let sm = scan_mail_r.clone();
            let so = scan_ole2_r.clone();
            let dp = detect_pua_r.clone();
            let he = heuristic_r.clone();
            let fs = follow_symlinks_r.clone();
            let mf = max_file_spin_r.clone();
            let mt = max_time_spin_r.clone();
            let hl = history_limit_spin_r.clone();
            let qe = q_entry_r.clone();
            let eb = excl_buffer_r.clone();

            dialog.connect_response(move |dlg, resp| {
                if resp == ResponseType::Yes {
                    let default = AppConfig::default();
                    *cfg_rc.borrow_mut() = default.clone();

                    ps.set_active(default.play_sound_on_complete);
                    sa.set_active(default.scan_archives);
                    se.set_active(default.scan_elf);
                    sp.set_active(default.scan_pdf);
                    sm.set_active(default.scan_mail);
                    so.set_active(default.scan_ole2);
                    dp.set_active(default.detect_pua);
                    he.set_active(default.heuristic_scan);
                    fs.set_active(default.scan_follow_symlinks);
                    mf.set_value(default.max_file_size_mb as f64);
                    mt.set_value(default.max_scan_time_sec as f64);
                    hl.set_value(default.history_limit as f64);
                    qe.set_text(&default.quarantine_dir.to_string_lossy());

                    let text = default.exclude_paths.join("\n");
                    eb.set_text(&text);

                    let _ = default.save();
                }
                dlg.close();
            });

            dialog.show();
        });

        SettingsPage { container }
    }

    pub fn container(&self) -> &Box {
        &self.container
    }
}
