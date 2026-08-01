use std::rc::Rc;

use gtk4::prelude::*;
use gtk4::{
    Application, ApplicationWindow, Box, Button, HeaderBar, Label, ListBox, ListBoxRow,
    Orientation, Separator, Stack, StackTransitionType,
    PolicyType, ScrolledWindow, Image, CssProvider, STYLE_PROVIDER_PRIORITY_USER,
};

use crate::ui::dashboard::DashboardPage;
use crate::ui::scan_page::ScanPage;
use crate::ui::update_page::UpdatePage;
use crate::ui::quarantine_page::QuarantinePage;
use crate::ui::history_page::HistoryPage;
use crate::ui::settings_page::SettingsPage;
use crate::ui::about::show_about_dialog;

pub struct MainWindow {
    window: ApplicationWindow,
}

impl MainWindow {
    pub fn new(app: &Application) -> Self {
        let window = ApplicationWindow::builder()
            .application(app)
            .title("ClamTK Rust")
            .default_width(950)
            .default_height(650)
            .icon_name("com.clamtk.rs")
            .build();

        // Apply custom CSS
        let css = CssProvider::new();
        css.load_from_data(
            r#"
            .sidebar-row {
                padding: 10px 16px;
                font-size: 14px;
            }
            .sidebar-row:hover {
                background: alpha(@theme_selected_bg_color, 0.1);
            }
            .status-good {
                color: #2ecc71;
                font-weight: bold;
            }
            .status-bad {
                color: #e74c3c;
                font-weight: bold;
            }
            .status-warn {
                color: #f39c12;
                font-weight: bold;
            }
            .card {
                background: @theme_base_color;
                border-radius: 8px;
                padding: 16px;
                margin: 4px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }
            .big-button {
                padding: 12px 24px;
                font-size: 14px;
                font-weight: bold;
            }
            .scan-progress {
                font-size: 12px;
                color: @theme_fg_color;
            }
            "#
        );
        gtk4::style_context_add_provider_for_display(
            &gtk4::prelude::WidgetExt::display(&window),
            &css,
            STYLE_PROVIDER_PRIORITY_USER,
        );

        // Build the main layout: sidebar + content stack
        let main_box = Box::new(Orientation::Horizontal, 0);

        // Stack
        let stack = Stack::builder()
            .transition_type(StackTransitionType::SlideLeftRight)
            .transition_duration(200)
            .build();

        // Create pages
        let scan_page = Rc::new(ScanPage::new(&window));

        let stack_clone = stack.clone();
        let stack_clone2 = stack.clone();
        let stack_clone3 = stack.clone();
        let scan_page_clone = scan_page.clone();
        let dashboard = Rc::new(DashboardPage::new(
            Some(std::boxed::Box::new(move || {
                stack_clone.set_visible_child_name("scan");
                scan_page_clone.scan_home();
            })),
            Some(std::boxed::Box::new(move || {
                stack_clone3.set_visible_child_name("update");
            })),
            Some(std::boxed::Box::new(move || {
                stack_clone2.set_visible_child_name("settings");
            })),
        ));

        let update_page = UpdatePage::new();
        let quarantine_page = QuarantinePage::new(&window);
        let history_page = HistoryPage::new(&window);
        let settings_page = SettingsPage::new(&window);

        // Add pages to stack
        stack.add_titled(dashboard.container(), Some("dashboard"), "Dashboard");
        stack.add_titled(scan_page.container(), Some("scan"), "Scan");
        stack.add_titled(update_page.container(), Some("update"), "Update");
        stack.add_titled(quarantine_page.container(), Some("quarantine"), "Quarantine");
        stack.add_titled(history_page.container(), Some("history"), "History");
        stack.add_titled(settings_page.container(), Some("settings"), "Settings");

        // Build custom sidebar
        let sidebar = build_sidebar();

        // Sidebar selection -> stack transition
        let stack_clone = stack.clone();
        sidebar.connect_row_selected(move |_, row| {
            if let Some(row) = row {
                if let Some(name) = row.widget_name().as_str().strip_prefix("nav-") {
                    stack_clone.set_visible_child_name(name);
                }
            }
        });

        // Sync stack page changes back to sidebar
        let sidebar_clone = sidebar.clone();
        stack.connect_visible_child_name_notify(move |stack| {
            if let Some(name) = stack.visible_child_name() {
                let row_name = format!("nav-{}", name);
                if let Some(row) = sidebar_clone.first_child() {
                    // Walk the children to find the right row
                    let mut child = Some(row);
                    while let Some(c) = child {
                        if c.widget_name() == row_name {
                            if let Some(list_row) = c.downcast_ref::<ListBoxRow>() {
                                sidebar_clone.select_row(Some(list_row));
                            }
                        }
                        child = c.next_sibling();
                    }
                }
            }
        });

        // Refresh the dashboard's ClamAV info whenever it is shown, so it
        // reflects a virus database downloaded after startup (e.g. on the
        // first scan) or a manual signature update.
        let dashboard_refresh = dashboard.clone();
        stack.connect_visible_child_name_notify(move |stack| {
            if stack.visible_child_name().as_deref() == Some("dashboard") {
                dashboard_refresh.refresh();
            }
        });

        // Scroll the sidebar
        let sidebar_scroll = ScrolledWindow::builder()
            .hscrollbar_policy(PolicyType::Never)
            .vscrollbar_policy(PolicyType::Automatic)
            .min_content_width(200)
            .max_content_width(200)
            .child(&sidebar)
            .build();

        // Vertical separator
        let separator = Separator::new(Orientation::Vertical);

        main_box.append(&sidebar_scroll);
        main_box.append(&separator);
        main_box.append(&stack);

        // Header bar
        let header = HeaderBar::builder()
            .title_widget(&Label::new(Some("ClamTK Rust")))
            .build();

        // Add about button to header
        let about_btn = Button::builder()
            .icon_name("help-about-symbolic")
            .tooltip_text("About")
            .build();
        let about_window = window.clone();
        about_btn.connect_clicked(move |_| {
            show_about_dialog(about_window.upcast_ref::<gtk4::Window>());
        });
        header.pack_end(&about_btn);

        window.set_titlebar(Some(&header));
        window.set_child(Some(&main_box));

        // Select first page
        stack.set_visible_child_name("dashboard");

        let mw = MainWindow {
            window,
        };

        mw
    }

    pub fn present(&self) {
        self.window.present();
    }
}

fn build_sidebar() -> ListBox {
    let listbox = ListBox::builder()
        .selection_mode(gtk4::SelectionMode::Single)
        .build();

    let items = [
        ("nav-dashboard", "preferences-system-symbolic", "Dashboard"),
        ("nav-scan", "edit-find-symbolic", "Scan"),
        ("nav-update", "view-refresh-symbolic", "Update"),
        ("nav-quarantine", "dialog-warning-symbolic", "Quarantine"),
        ("nav-history", "document-open-recent-symbolic", "History"),
        ("nav-settings", "emblem-system-symbolic", "Settings"),
    ];

    for (name, icon, label) in items {
        let row = ListBoxRow::builder()
            .selectable(true)
            .activatable(true)
            .build();
        row.set_widget_name(name);

        let hbox = Box::new(Orientation::Horizontal, 10);
        hbox.set_margin_start(12);
        hbox.set_margin_end(12);
        hbox.set_margin_top(8);
        hbox.set_margin_bottom(8);

        let image = Image::from_icon_name(icon);
        image.set_pixel_size(20);

        let label = Label::new(Some(label));
        label.set_halign(gtk4::Align::Start);

        hbox.append(&image);
        hbox.append(&label);
        row.set_child(Some(&hbox));

        listbox.append(&row);
    }

    // Select first row
    if let Some(first) = listbox.row_at_index(0) {
        listbox.select_row(Some(&first));
    }

    listbox
}
