use gtk4::prelude::*;
use gtk4::{Application, ApplicationWindow};
use glib::ExitCode;

use crate::ui::window::MainWindow;

const APP_ID: &str = "com.clamtk.rs";

pub struct App {
    gtk_app: Application,
}

impl App {
    pub fn new() -> Self {
        let gtk_app = Application::builder()
            .application_id(APP_ID)
            .flags(gio::ApplicationFlags::HANDLES_OPEN)
            .build();

        let app = App { gtk_app };
        app.setup_signals();
        app
    }

    fn setup_signals(&self) {
        self.gtk_app.connect_startup(|gtk_app| {
            // Load resources
            gtk_app.set_resource_base_path(Some("/com/clamtk/rs"));
        });

        self.gtk_app.connect_activate(|gtk_app| {
            let main_window = MainWindow::new(gtk_app);
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
