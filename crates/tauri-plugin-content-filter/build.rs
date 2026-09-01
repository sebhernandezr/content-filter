const COMMANDS: &[&str] = &[
    "activate_extension",
    "enable_filter",
    "disable_filter",
    "remove_filter",
    "filter_status",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS).build();
}
