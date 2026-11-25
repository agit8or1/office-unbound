//! Real protocol tests against an OpenCloud deployment (officeunbound8 Files as the test user `doctest`).
//!
//! Enabled only when both variables are set, otherwise every test prints `SKIP` and returns (read the counts!):
//!   OU_FILES_LIVE_URL   e.g. https://cloud.officeunbound.com
//!   OU_FILES_TOKEN_CMD  space-separated command printing an access token (bearer_token_command contract), e.g.
//!                       `python3 blueprints/research/desktop-connector-m0/m0.py token <workdir>`
//! Every item is named `[OU-TEST] …` and removed afterwards, including its trash-bin entry.

use std::path::PathBuf;
use std::sync::Arc;

use ou_files::guard::{preflight, Decision, GuardPolicy, Health, Manifest};
use ou_files::paths::scan_local;
use ou_files::webdav::{hash_file, hex, Client, CachedToken, CommandToken, FilesError, Precondition, Space, StaticToken};
use sha2::{Digest, Sha256};
use url::Url;

fn live() -> Option<(Url, Vec<String>)> {
    let url = std::env::var("OU_FILES_LIVE_URL").ok()?;
    let cmd = std::env::var("OU_FILES_TOKEN_CMD").ok()?;
    Some((Url::parse(&url).ok()?, cmd.split_whitespace().map(str::to_string).collect()))
}

macro_rules! live_or_skip {
    () => {
        match live() {
            Some(v) => v,
            None => {
                eprintln!("SKIP: OU_FILES_LIVE_URL / OU_FILES_TOKEN_CMD not set");
                return;
            }
        }
    };
}

async fn setup(tag: &str) -> (Client, Space, String) {
    let (url, cmd) = live().unwrap();
    let client = Client::new(ou_files::webdav::transfer_client().unwrap(), url, Arc::new(CachedToken::new(CommandToken(cmd)))).unwrap();
    let spaces = client.list_spaces().await.unwrap();
    let personal = spaces.into_iter().find(|s| s.drive_type == "personal").expect("personal space");
    let folder = format!("[OU-TEST] files-{tag}-{}", std::process::id());
    client.mkcol(&personal, &folder).await.unwrap();
    (client, personal, folder)
}

async fn cleanup(client: &Client, space: &Space, folder: &str) {
    match client.delete(space, folder, None).await {
        Ok(()) | Err(FilesError::NotFound) => {}
        Err(e) => panic!("cleanup delete: {e}"),
    }
    let mut purged = 0;
    for t in client.list_trash(space).await.unwrap() {
        if t.original_name == folder || t.original_location.starts_with(&format!("{folder}/")) {
            client.purge_trash_item(space, &t.key).await.unwrap();
            purged += 1;
        }
    }
    assert!(purged >= 1, "trash entry for {folder} not found");
    let left = client.list_trash(space).await.unwrap().into_iter().filter(|t| t.original_name == folder || t.original_name.starts_with(".ou-upload-")).count();
    assert_eq!(left, 0, "trash still holds {folder}");
}

/// Deterministic pseudo-random bytes (SHA-256 counter mode); no RNG dependency, reproducible failures.
fn data(len: usize, seed: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut i = 0u64;
    while out.len() < len {
        out.extend_from_slice(&Sha256::digest(format!("{seed}-{i}").as_bytes()));
        i += 1;
    }
    out.truncate(len);
    out
}

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("ou-files-live-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[tokio::test]
async fn live_list_spaces() {
    let (url, cmd) = live_or_skip!();
    let client = Client::new(ou_files::webdav::transfer_client().unwrap(), url.clone(), Arc::new(CachedToken::new(CommandToken(cmd)))).unwrap();
    let spaces = client.list_spaces().await.unwrap();
    assert!(spaces.iter().any(|s| s.drive_type == "personal"), "personal space listed");
    for s in &spaces {
        assert_eq!(s.webdav_url.host_str(), url.host_str(), "webDavUrl on the cloud origin");
        assert_eq!(client.probe(s).await, Health::Ok, "{} probe", s.drive_type);
    }
    eprintln!("spaces: {:?}", spaces.iter().map(|s| s.drive_type.as_str()).collect::<Vec<_>>());
}

#[tokio::test]
async fn live_bad_token_is_auth_failure_and_guard_skips() {
    let (url, _) = live_or_skip!();
    let (good, space, folder) = setup("auth").await;
    let bad = Client::new(ou_files::webdav::transfer_client().unwrap(), url, Arc::new(StaticToken("not-a-token".into()))).unwrap();
    let health = bad.probe(&space).await;
    assert_eq!(health, Health::AuthFailed);
    let root = tmpdir("auth");
    ou_core::safety::write_marker(&root, "acc").unwrap();
    let m = Manifest { account_id: "acc".into(), ..Default::default() };
    assert!(matches!(preflight(&GuardPolicy::default(), "acc", &root, &health, Some(&m), None, None), Decision::Skip(_)));
    cleanup(&good, &space, &folder).await;
}

#[tokio::test]
async fn live_small_roundtrip_and_no_overwrite() {
    let _ = live_or_skip!();
    let (c, space, folder) = setup("small").await;
    let rel = format!("{folder}/[OU-TEST] small ä #1.bin");
    let body = data(4096, "small");
    let want = hex(&Sha256::digest(&body));
    let up = c.put(&space, &rel, body.clone(), &Precondition::MustNotExist).await.unwrap();
    assert_eq!(up.sha256, want);
    assert!(matches!(c.put(&space, &rel, b"other".to_vec(), &Precondition::MustNotExist).await, Err(FilesError::PreconditionFailed)));
    let dir = tmpdir("small");
    let dest = dir.join("small.bin");
    let down = c.download(&space, &rel, &dest, false).await.unwrap();
    assert_eq!(down.sha256, want, "downloaded content identical");
    assert!(matches!(c.download(&space, &rel, &dest, false).await, Err(FilesError::Exists)), "never overwrite local without asking");
    let e = c.propfind(&space, &rel, 0).await.unwrap().remove(0);
    assert_eq!(e.size, 4096);
    assert_eq!(e.sha1().as_deref(), Some(up.sha1.as_str()), "server SHA1 = local SHA1");
    cleanup(&c, &space, &folder).await;
}

#[tokio::test]
async fn live_large_tus_upload_resume_and_download() {
    let _ = live_or_skip!();
    let (c, space, folder) = setup("large").await;
    let dir = tmpdir("large");
    let src = dir.join("large.bin");
    let len = 25 * 1024 * 1024 + 123; // 3 TUS chunks of 10 MB
    std::fs::write(&src, data(len, "large")).unwrap();
    let (sha1, sha256) = hash_file(&src).await.unwrap();
    let rel = format!("{folder}/[OU-TEST] large.bin");
    let t = c.upload_file(&space, &rel, &src, &Precondition::MustNotExist, 3).await.unwrap();
    assert_eq!((t.bytes, t.sha1.as_str()), (len as u64, sha1.as_str()));
    let dest = dir.join("large.down");
    let d = c.download(&space, &rel, &dest, false).await.unwrap();
    assert_eq!(d.sha256, sha256, "large file intact after TUS upload + download");

    // Interrupted upload: one chunk, then resume from the server's offset.
    let rel2 = format!("{folder}/[OU-TEST] resumed.bin");
    let all = data(15_000_000, "resume");
    let upload = c.tus_create(&space, &rel2, all.len() as u64).await.unwrap();
    let (off, _) = c.tus_patch(&upload, 0, all[..c.chunk_size].to_vec()).await.unwrap();
    assert_eq!(off, c.chunk_size as u64);
    // A stale offset is refused, not appended twice.
    assert!(c.tus_patch(&upload, 0, all[..10].to_vec()).await.is_err());
    let resume = c.tus_offset(&upload).await.unwrap();
    assert_eq!(resume, off, "server reports where to resume");
    let (end, _) = c.tus_patch(&upload, resume, all[resume as usize..].to_vec()).await.unwrap();
    assert_eq!(end, all.len() as u64);
    let dest2 = dir.join("resumed.down");
    let d2 = c.download(&space, &rel2, &dest2, false).await.unwrap();
    assert_eq!(d2.sha256, hex(&Sha256::digest(&all)), "resumed upload intact");
    cleanup(&c, &space, &folder).await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn live_conflict_creates_copy_never_overwrites() {
    let _ = live_or_skip!();
    let (c, space, folder) = setup("conflict").await;
    let rel = format!("{folder}/[OU-TEST] report.txt");
    let v1 = c.put(&space, &rel, b"v1 from computer A".to_vec(), &Precondition::MustNotExist).await.unwrap();
    let e1 = c.propfind(&space, &rel, 0).await.unwrap().remove(0).etag.unwrap();
    // Computer B edits first (knows e1).
    c.put(&space, &rel, b"v2 from computer B".to_vec(), &Precondition::Matches(e1.clone())).await.unwrap();
    // Computer A saves its offline edit, still based on e1: refused.
    let r = c.put(&space, &rel, b"v3 offline edit from A".to_vec(), &Precondition::Matches(e1)).await;
    assert!(matches!(r, Err(FilesError::PreconditionFailed)), "stale ETag must not overwrite");
    // A keeps its data as a conflict copy next to the server version.
    let name = ou_files::guard::conflict_name("[OU-TEST] report.txt", 1_795_601_472, Some("doctest"));
    let copy = format!("{folder}/{name}");
    c.put(&space, &copy, b"v3 offline edit from A".to_vec(), &Precondition::MustNotExist).await.unwrap();
    let dir = tmpdir("conflict");
    c.download(&space, &rel, &dir.join("server"), false).await.unwrap();
    c.download(&space, &copy, &dir.join("copy"), false).await.unwrap();
    assert_eq!(std::fs::read(dir.join("server")).unwrap(), b"v2 from computer B");
    assert_eq!(std::fs::read(dir.join("copy")).unwrap(), b"v3 offline edit from A");
    let _ = v1;
    cleanup(&c, &space, &folder).await;
}

#[tokio::test]
async fn live_mass_delete_guard_holds_and_nothing_is_deleted() {
    let _ = live_or_skip!();
    let (c, space, folder) = setup("guard").await;
    let n = 30;
    for i in 0..n {
        c.put(&space, &format!("{folder}/[OU-TEST] f{i:02}.txt"), format!("file {i}").into_bytes(), &Precondition::MustNotExist).await.unwrap();
    }
    // Local copy as after a good sync.
    let root = tmpdir("guard");
    ou_core::safety::write_marker(&root, "acc").unwrap();
    let remote = c.list_tree(&space, &folder, 10_000).await;
    assert!(remote.complete);
    assert_eq!(remote.entries.len(), n);
    for rel in remote.entries.keys() {
        c.download(&space, &format!("{folder}/{rel}"), &root.join(rel), false).await.unwrap();
    }
    let local = scan_local(&root);
    let manifest = Manifest::from_run("acc", &space.id, &local, &remote);
    assert_eq!(manifest.entries.len(), n);
    let policy = GuardPolicy::default();
    assert_eq!(preflight(&policy, "acc", &root, &Health::Ok, Some(&manifest), Some(&local), Some(&remote)), Decision::Run);

    // 20 of 30 local files vanish (e.g. a tool or ransomware emptied the folder): Hold.
    for i in 0..20 {
        std::fs::remove_file(root.join(format!("[OU-TEST] f{i:02}.txt"))).unwrap();
    }
    let local2 = scan_local(&root);
    let remote2 = c.list_tree(&space, &folder, 10_000).await;
    match preflight(&policy, "acc", &root, &Health::Ok, Some(&manifest), Some(&local2), Some(&remote2)) {
        Decision::Hold { plan, .. } => assert_eq!(plan.local_deletes.len(), 20),
        d => panic!("expected Hold, got {d:?}"),
    }
    // The server still has every file.
    assert_eq!(c.list_tree(&space, &folder, 10_000).await.entries.len(), n);

    // The sync folder disappears entirely (unplugged disk): Skip, never "delete everything".
    std::fs::remove_dir_all(&root).unwrap();
    assert!(matches!(preflight(&policy, "acc", &root, &Health::Ok, Some(&manifest), None, Some(&remote2)), Decision::Skip(_)));
    cleanup(&c, &space, &folder).await;
}
