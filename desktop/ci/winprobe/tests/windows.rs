//! Real-NTFS checks of ou-files' Windows code. Compiled and run only on Windows.
#![cfg(windows)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use ou_files::paths::{classify_local, name_problem, scan_local, LocalKind};

fn tmp(tag: &str) -> PathBuf {
    let base = std::env::var_os("RUNNER_TEMP").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    let d = base.join(format!("ou-winprobe-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn mklink_junction(link: &Path, target: &Path) {
    let st = Command::new("cmd").arg("/C").arg("mklink").arg("/J").arg(link).arg(target).status().unwrap();
    assert!(st.success(), "mklink /J failed");
}

#[test]
fn classify_file_dir_junction_symlink() {
    let d = tmp("classify");
    fs::write(d.join("f.txt"), b"x").unwrap();
    fs::create_dir(d.join("dir")).unwrap();
    mklink_junction(&d.join("junction"), &d.join("dir"));
    assert_eq!(classify_local(&d.join("f.txt")).unwrap(), LocalKind::File);
    assert_eq!(classify_local(&d.join("dir")).unwrap(), LocalKind::Dir);
    assert_eq!(classify_local(&d.join("junction")).unwrap(), LocalKind::Junction);
    // Symlinks need SeCreateSymbolicLinkPrivilege (admin or developer mode); the hosted runner is admin.
    match std::os::windows::fs::symlink_dir(d.join("dir"), d.join("symlink-dir")) {
        Ok(()) => assert_eq!(classify_local(&d.join("symlink-dir")).unwrap(), LocalKind::Symlink),
        Err(e) => println!("SKIP symlink_dir: {e}"),
    }
    match std::os::windows::fs::symlink_file(d.join("f.txt"), d.join("symlink-file")) {
        Ok(()) => assert_eq!(classify_local(&d.join("symlink-file")).unwrap(), LocalKind::Symlink),
        Err(e) => println!("SKIP symlink_file: {e}"),
    }
    fs::remove_dir_all(&d).unwrap();
}

#[test]
fn scan_does_not_follow_a_junction_loop() {
    let d = tmp("loop");
    fs::create_dir(d.join("sub")).unwrap();
    fs::write(d.join("sub").join("a.txt"), b"a").unwrap();
    mklink_junction(&d.join("sub").join("loop"), &d); // sub\loop -> root: infinite if followed
    let s = scan_local(&d);
    let rels: Vec<_> = s.entries.iter().map(|e| e.rel.as_str()).collect();
    println!("entries {rels:?} skipped {:?}", s.skipped);
    assert!(s.complete);
    assert_eq!(rels, vec!["sub", "sub/a.txt"]);
    assert!(s.skipped.iter().any(|(r, why)| r == "sub/loop" && why.contains("Junction")));
    // remove the junction first so remove_dir_all cannot wander through it
    fs::remove_dir(d.join("sub").join("loop")).unwrap();
    fs::remove_dir_all(&d).unwrap();
}

/// What NTFS does with a name: created under exactly that name, or rejected/altered.
fn round_trips(dir: &Path, name: &str) -> Result<bool, String> {
    let sub = dir.join(format!("n{}", name.len()));
    let _ = fs::remove_dir_all(&sub);
    fs::create_dir(&sub).map_err(|e| e.to_string())?;
    let created = fs::OpenOptions::new().write(true).create_new(true).open(sub.join(name));
    let listed: Vec<String> = fs::read_dir(&sub).unwrap().filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    let _ = fs::remove_dir_all(&sub);
    Ok(created.is_ok() && listed == vec![name.to_string()])
}

#[test]
fn name_rules_match_ntfs() {
    let d = tmp("names");
    let long = "a".repeat(256);
    let ok_255 = "b".repeat(255);
    let names: Vec<&str> = vec![
        "report.docx", "a b.txt", ".hidden", "Ünïcødé ✓ 日本.txt", "x.CON", "console.txt", "COM10", "LPT10.txt", &ok_255,
        "a.", "a ", "a:b", "a?b", "a*b", "a<b", "a>b", "a|b", "a\"b", "tab\there",
        "CON", "con", "NUL", "nul.txt", "NUL .txt", "PRN", "AUX", "COM1", "COM1.tar.gz", "LPT1", "LPT\u{b9}", "COM\u{b2}", "CONIN$", "CONOUT$",
        "CLOCK$", &long,
    ];
    let mut unsafe_ok = Vec::new(); // rule says fine, NTFS disagrees: data-loss risk
    let mut conservative = Vec::new(); // rule rejects, NTFS would accept: only over-cautious
    for n in &names {
        let rule_ok = name_problem(n).is_none();
        let fs_ok = round_trips(&d, n).unwrap();
        let shown: String = if n.len() > 40 { format!("<{} chars>", n.len()) } else { n.escape_debug().to_string() };
        println!("{:<28} rule_ok={rule_ok:<5} ntfs_round_trip={fs_ok}", shown);
        if rule_ok && !fs_ok {
            unsafe_ok.push(shown);
        } else if !rule_ok && fs_ok {
            conservative.push(shown);
        }
    }
    println!("rule stricter than NTFS (harmless): {conservative:?}");
    let _ = fs::remove_dir_all(&d);
    assert!(unsafe_ok.is_empty(), "name_problem() accepts names NTFS rejects or alters: {unsafe_ok:?}");
}

#[test]
fn used_drive_letters() {
    let used = ou_files::mapped::used_letters();
    println!("used letters: {used:?}");
    assert!(used.contains(&'C'), "C: must be reported as used");
}
