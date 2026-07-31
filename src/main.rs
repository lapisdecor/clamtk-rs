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

    // Ensure config directories exist
    config::ensure_dirs()?;

    let app = app::App::new();
    app.run();

    Ok(())
}
