//! Office Unbound Desktop GUI (Tauri 2 / WebView2). A client of the per-user background agent (`ou-agent.exe`, installed next
//! to this executable): closing the window only hides it; sync and sessions continue in the agent. "Quit Office Unbound" in
//! the tray stops both. The webview gets status, never tokens.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::time::Duration;

use ou_core::ipc::{Request, Response};
use serde::Serialize;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, WindowEvent};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt};

fn root() -> PathBuf {
    ou_core::accounts::default_root()
}

fn agent_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let name = if cfg!(windows) { "ou-agent.exe" } else { "ou-agent" };
    Some(exe.parent()?.join(name))
}

/// Starts the agent if it is not running. Direct process start with no shell and no arguments from the webview.
async fn ensure_agent() -> Result<(), String> {
    if ou_agent::client::request(&root(), &Request::Status {}).await.is_ok() {
        return Ok(());
    }
    let path = agent_path().ok_or("agent not found")?;
    let mut cmd = std::process::Command::new(&path);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        cmd.creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS);
    }
    cmd.spawn().map_err(|e| format!("could not start {}: {e}", path.display()))?;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if ou_agent::client::request(&root(), &Request::Status {}).await.is_ok() {
            return Ok(());
        }
    }
    Err("the background agent did not start".into())
}

/// The webview's only door to the agent: the typed request set minus `Shutdown` (quitting is a tray action) and minus
/// `AccessToken` (tokens never reach the webview).
#[tauri::command]
async fn agent(req: Request) -> Result<Response, String> {
    if matches!(req, Request::Shutdown {} | Request::AccessToken { .. }) {
        return Err("not allowed from the window".into());
    }
    ensure_agent().await?;
    ou_agent::client::request(&root(), &req).await
}

#[derive(Serialize)]
struct AppInfo {
    version: &'static str,
    data_dir: String,
    log_file: String,
    autostart: bool,
}

#[tauri::command]
fn app_info(app: AppHandle) -> AppInfo {
    let r = root();
    AppInfo {
        version: ou_core::VERSION,
        data_dir: r.display().to_string(),
        log_file: r.join("logs").join("agent.log").display().to_string(),
        autostart: app.autolaunch().is_enabled().unwrap_or(false),
    }
}

#[tauri::command]
fn set_autostart(app: AppHandle, enabled: bool) -> Result<bool, String> {
    let al = app.autolaunch();
    if enabled { al.enable() } else { al.disable() }.map_err(|e| e.to_string())?;
    al.is_enabled().map_err(|e| e.to_string())
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

async fn quit_all(app: AppHandle) {
    let _ = ou_agent::client::request(&root(), &Request::Shutdown {}).await;
    app.exit(0);
}

fn main() {
    let minimized = std::env::args().any(|a| a == "--minimized");
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_main(app)))
        .plugin(tauri_plugin_autostart::init(MacosLauncher::LaunchAgent, Some(vec!["--minimized"])))
        .invoke_handler(tauri::generate_handler![agent, app_info, set_autostart])
        .setup(move |app| {
            let open = MenuItem::with_id(app, "open", "Open Office Unbound", true, None::<&str>)?;
            let files = MenuItem::with_id(app, "files", "Open files in the browser", true, None::<&str>)?;
            let pause = MenuItem::with_id(app, "pause", "Pause background activity", true, None::<&str>)?;
            let resume = MenuItem::with_id(app, "resume", "Resume background activity", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit Office Unbound", true, None::<&str>)?;
            let sep = PredefinedMenuItem::separator(app)?;
            let menu = Menu::with_items(app, &[&open, &files, &pause, &resume, &sep, &quit])?;
            TrayIconBuilder::with_id("main")
                .icon(app.default_window_icon().cloned().expect("bundle icon"))
                .tooltip("Office Unbound")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, e| {
                    let app = app.clone();
                    match e.id.as_ref() {
                        "open" => show_main(&app),
                        "files" => {
                            tauri::async_runtime::spawn(async move {
                                if let Ok(Response::Status { accounts, .. }) = ou_agent::client::request(&root(), &Request::Status {}).await {
                                    if let Some(a) = accounts.into_iter().find(|a| !a.id.is_empty()) {
                                        let _ = ou_agent::client::request(
                                            &root(),
                                            &Request::OpenService { account_id: a.id, service: ou_core::ipc::Service::Files },
                                        )
                                        .await;
                                    }
                                }
                            });
                        }
                        "pause" | "resume" => {
                            let paused = e.id.as_ref() == "pause";
                            tauri::async_runtime::spawn(async move {
                                let _ = ou_agent::client::request(&root(), &Request::SetPaused { paused }).await;
                            });
                        }
                        "quit" => {
                            tauri::async_runtime::spawn(quit_all(app));
                        }
                        _ => {}
                    }
                })
                .on_tray_icon_event(|tray, e| {
                    if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = e {
                        show_main(tray.app_handle());
                    }
                })
                .build(app)?;
            tauri::async_runtime::spawn(async {
                let _ = ensure_agent().await;
            });
            if !minimized {
                show_main(app.handle());
            }
            Ok(())
        })
        .on_window_event(|w, e| {
            // Closing the window keeps the app in the tray; background work lives in the agent anyway.
            if let WindowEvent::CloseRequested { api, .. } = e {
                api.prevent_close();
                let _ = w.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("Office Unbound Desktop failed to start");
}
