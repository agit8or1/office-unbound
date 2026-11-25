fn main() {
    // tauri-build generates the Windows resources and context; nothing to do for the non-Windows stub.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        tauri_build::build()
    }
}
