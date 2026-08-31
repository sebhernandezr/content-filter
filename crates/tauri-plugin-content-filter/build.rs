const COMMANDS: &[&str] = &[
    "activate_extension",
    "enable_filter",
    "disable_filter",
    "remove_filter",
    "filter_status",
    "recent_flows",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS).build();
}
