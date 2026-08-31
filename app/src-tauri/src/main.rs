//! Digiexam content-filter container app.
//!
//! Deliberately thin: this process exists to install and activate the system extension, drive
//! `NEFilterManager`, and show what the extension is observing. All of that lives in
//! `tauri-plugin-content-filter`.

// Suppress the extra console window on Windows in release. Harmless on macOS, and kept so the
// crate stays buildable cross-platform for frontend work.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_content_filter::init())
        .run(tauri::generate_context!())
        .expect("error while running the Digiexam content filter app");
}
