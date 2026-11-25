//! Office Unbound Desktop GUI (Tauri 2 / WebView2). A client of the per-user background agent (`ou-agent.exe`, installed next
//! to this executable): closing the window only hides it; sync and sessions continue in the agent. "Quit Office Unbound" in
//! the tray stops both. The webview gets status, never tokens.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// The GUI targets Windows (WebView2). On other systems this crate builds a stub, so `cargo test --workspace` needs no GTK,
// WebKitGTK or D-Bus development packages (ADR-0022: macOS/Linux GUIs are Phase 7).
#[cfg(windows)]
mod app;

fn main() {
    #[cfg(windows)]
    app::run();
    #[cfg(not(windows))]
    {
        eprintln!("Office Unbound Desktop's GUI is built for Windows only; the agent (ou-agent) runs everywhere.");
        std::process::exit(2);
    }
}
