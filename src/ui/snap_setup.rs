use gtk4::prelude::*;
use gtk4::{
    ApplicationWindow, Button, Label,
    MessageDialog, MessageType, ButtonsType, TextView, WrapMode,
};

use std::path::PathBuf;

fn sentinel_file() -> PathBuf {
    std::env::var_os("SNAP_USER_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir())
        .join(".snap-setup-done")
}

pub fn show_if_needed(parent: &ApplicationWindow) {
    if !crate::utils::is_running_in_snap() {
        return;
    }
    if sentinel_file().exists() {
        return;
    }

    show(parent);
}

fn show(parent: &ApplicationWindow) {
    let dialog = MessageDialog::builder()
        .text("ClamTK-rs Snap Setup")
        .secondary_text(
            "To scan external drives and see mount points, run the following \
             commands in a terminal. This only needs to be done once.",
        )
        .message_type(MessageType::Info)
        .buttons(ButtonsType::Close)
        .transient_for(parent)
        .build();

    let content_area = dialog.content_area();

    let cmd1 = "sudo snap connect clamtk-rs:removable-media";
    let cmd2 = "sudo snap connect clamtk-rs:mount-observe";

    let cmd1_label = Label::builder()
        .label("Scan external drives:")
        .halign(gtk4::Align::Start)
        .margin_top(12)
        .build();
    content_area.append(&cmd1_label);

    let cmd1_view = TextView::builder()
        .editable(false)
        .wrap_mode(WrapMode::WordChar)
        .monospace(true)
        .build();
    cmd1_view.buffer().set_text(cmd1);
    content_area.append(&cmd1_view);

    let copy1_btn = Button::builder()
        .label("Copy to Clipboard")
        .margin_top(4)
        .build();
    let cmd1_owned = cmd1.to_string();
    copy1_btn.connect_clicked(move |btn| {
        btn.clipboard().set_text(&cmd1_owned);
    });
    content_area.append(&copy1_btn);

    let cmd2_label = Label::builder()
        .label("See mount points:")
        .halign(gtk4::Align::Start)
        .margin_top(12)
        .build();
    content_area.append(&cmd2_label);

    let cmd2_view = TextView::builder()
        .editable(false)
        .wrap_mode(WrapMode::WordChar)
        .monospace(true)
        .build();
    cmd2_view.buffer().set_text(cmd2);
    content_area.append(&cmd2_view);

    let copy2_btn = Button::builder()
        .label("Copy to Clipboard")
        .margin_top(4)
        .build();
    let cmd2_owned = cmd2.to_string();
    copy2_btn.connect_clicked(move |btn| {
        btn.clipboard().set_text(&cmd2_owned);
    });
    content_area.append(&copy2_btn);

    dialog.connect_response(|dlg, _| {
        let _ = std::fs::write(sentinel_file(), b"");
        dlg.close();
    });

    dialog.show();
}
