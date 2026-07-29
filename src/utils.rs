/// Format a file size in human-readable format
pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format elapsed time in a human-readable way
pub fn format_duration(seconds: f64) -> String {
    if seconds < 1.0 {
        format!("{:.0} ms", seconds * 1000.0)
    } else if seconds < 60.0 {
        format!("{:.1} s", seconds)
    } else {
        let mins = (seconds / 60.0) as u64;
        let secs = (seconds % 60.0) as u64;
        format!("{}m {}s", mins, secs)
    }
}

/// Truncate a path for display
pub fn truncate_path(path: &str, max_len: usize) -> String {
    if path.len() <= max_len {
        path.to_string()
    } else {
        let start = path.len() - max_len + 3;
        format!("...{}", &path[start..])
    }
}

/// Get the display name for a scan type
pub fn scan_type_display(scan_type: &crate::scanner::ScanType) -> &'static str {
    match scan_type {
        crate::scanner::ScanType::File => "File Scan",
        crate::scanner::ScanType::Directory => "Directory Scan",
        crate::scanner::ScanType::Home => "Home Directory Scan",
        crate::scanner::ScanType::FullSystem => "Full System Scan",
        crate::scanner::ScanType::Custom => "Custom Scan",
    }
}
