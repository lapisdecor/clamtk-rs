use gtk4::prelude::*;
use gtk4::{AboutDialog, Window, License};

pub fn show_about_dialog(parent: &Window) {
    let dialog = AboutDialog::builder()
        .transient_for(parent)
        .modal(true)
        .program_name("ClamTK Rust")
        .version("1.0.0")
        .comments("A GTK4 graphical frontend for ClamAV — Rust port of ClamTK")
        .copyright("© 2026 ClamTK Rust Contributors")
        .license_type(License::Gpl30)
        .website("https://github.com/lapisdecor/clamtk-rs")
        .authors(vec![
            "ClamTK Rust Contributors"
        ])
        .artists(vec![
            "ClamAV Team",
            "ClamTK by Dave M",
        ])
        .documenters(vec![
            "ClamAV Documentation",
        ])
        .logo_icon_name("com.clamtk.rs")
        .build();

    dialog.present();
}
