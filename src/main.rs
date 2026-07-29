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

    // Ensure config directories exist
    config::ensure_dirs()?;

    let app = app::App::new();
    app.run();

    Ok(())
}
