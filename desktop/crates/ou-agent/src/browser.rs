//! Opens a URL in the user's default browser. No shell: Windows uses ShellExecuteW with the URL as the only argument (the URL has
//! already passed `urlpolicy`/OIDC validation and is https); Linux dev uses `xdg-open` with an argument vector.

use url::Url;

pub fn open(u: &Url) -> Result<(), String> {
    if u.scheme() != "https" && !cfg!(feature = "test-support") {
        return Err("only https URLs are opened".into());
    }
    #[cfg(feature = "test-support")]
    if let Ok(f) = std::env::var("OU_TEST_BROWSER_FILE") {
        return std::fs::write(f, u.as_str()).map_err(|e| e.to_string());
    }
    platform_open(u)
}

#[cfg(windows)]
fn platform_open(u: &Url) -> Result<(), String> {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let w = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let (verb, file) = (w("open"), w(u.as_str()));
    // SAFETY: NUL-terminated wide strings that outlive the call.
    let r = unsafe { ShellExecuteW(std::ptr::null_mut(), verb.as_ptr(), file.as_ptr(), std::ptr::null(), std::ptr::null(), SW_SHOWNORMAL) };
    if (r as isize) > 32 {
        Ok(())
    } else {
        Err(format!("ShellExecuteW failed ({})", r as isize))
    }
}

#[cfg(not(windows))]
fn platform_open(u: &Url) -> Result<(), String> {
    std::process::Command::new("xdg-open").arg(u.as_str()).spawn().map(|_| ()).map_err(|e| e.to_string())
}
