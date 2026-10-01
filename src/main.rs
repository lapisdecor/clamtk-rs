mod app;
mod clamav;
mod config;
mod history;
mod quarantine;
mod scanner;
mod ui;
mod utils;

fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Register the compiled gresource (bundled app icon)
    let _ = gio::resources_register_include!("clamtk_rs.gresource");

    // Under a snap, keep settings, history and virus signatures in
    // $SNAP_USER_COMMON so they survive a refresh instead of being redownloaded.
    utils::adopt_legacy_revision_data();

    // Ensure the directories we write to exist. Problems are reported to the
    // user rather than aborting, so a single unwritable directory cannot make
    // the app fail to start.
    let warnings = config::ensure_dirs();

    let app = app::App::new(warnings);
    app.run();

    Ok(())
}
