use glib::ExitCode;
use gtk4::prelude::*;
use gtk4::{Application, ApplicationWindow};

use crate::ui::window::MainWindow;

const APP_ID: &str = "com.gatochalupa.clamtk-rs";

pub struct App {
    gtk_app: Application,
    warnings: Vec<String>,
}

impl App {
    pub fn new(warnings: Vec<String>) -> Self {
        let gtk_app = Application::builder()
            .application_id(APP_ID)
            .flags(gio::ApplicationFlags::HANDLES_OPEN)
            .build();

        let app = App { gtk_app, warnings };
        app.setup_signals();
        app
    }

    fn setup_signals(&self) {
        self.gtk_app.connect_startup(|gtk_app| {
            // Load resources
            gtk_app.set_resource_base_path(Some("/com/gatochalupa/clamtk-rs"));

            // Make the bundled app icon available to the icon theme
            if let Some(display) = gtk4::gdk::Display::default() {
                gtk4::IconTheme::for_display(&display)
                    .add_resource_path("/com/gatochalupa/clamtk-rs/icons");
            }
        });

        let warnings = self.warnings.clone();
        self.gtk_app.connect_activate(move |gtk_app| {
            let main_window = MainWindow::new(gtk_app);
            let win_ref = main_window.window_ref().clone();
            let warnings = warnings.clone();
            let shown = std::cell::Cell::new(false);
            main_window.window_ref().connect_map(move |_| {
                crate::ui::snap_setup::show_if_needed(&win_ref);
                // `connect_map` fires on every show; warn only once.
                if !shown.get() {
                    shown.set(true);
                    crate::ui::window::show_startup_warnings(&win_ref, &warnings);
                }
            });
            main_window.present();
        });

        self.gtk_app.connect_open(|gtk_app, files, _hint| {
            // If files are passed, open scan page with those files
            if let Some(window) = gtk_app.active_window() {
                let paths: Vec<String> = files
                    .iter()
                    .filter_map(|f| f.path())
                    .map(|p| p.to_string_lossy().to_string())
                    .collect();
                if !paths.is_empty() {
                    // We store a reference to our MainWindow data
                    // and trigger a scan
                    if window.downcast_ref::<ApplicationWindow>().is_some() {
                        log::info!("Opening files for scan: {:?}", paths);
                    }
                }
            }
        });
    }

    pub fn run(&self) -> ExitCode {
        self.gtk_app.run()
    }
}
