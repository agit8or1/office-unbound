//! The real OpenCloud sync engine (`opencloudcmd`) driven by `engine::sync_cycle` against a real deployment.
//!
//! Needs OU_FILES_LIVE_URL, OU_FILES_TOKEN_CMD (see live_opencloud.rs) and OU_FILES_ENGINE_EXE (path to opencloudcmd or a wrapper).
//! Prints `SKIP` and passes otherwise. Linux evidence only: proves the driver, the guard and the engine protocol, not Windows.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ou_files::engine::{sync_cycle, CycleOutcome, EngineConfig};
use ou_files::guard::{GuardPolicy, Manifest};
use ou_files::webdav::{CachedToken, Client, CommandToken, FilesError, Precondition, TokenProvider};
use url::Url;

#[tokio::test]
async fn live_engine_cycle_with_guard() {
    let (Ok(url), Ok(cmd), Ok(exe)) = (std::env::var("OU_FILES_LIVE_URL"), std::env::var("OU_FILES_TOKEN_CMD"), std::env::var("OU_FILES_ENGINE_EXE")) else {
        eprintln!("SKIP: OU_FILES_LIVE_URL / OU_FILES_TOKEN_CMD / OU_FILES_ENGINE_EXE not set");
        return;
    };
    let url = Url::parse(&url).unwrap();
    let tokens: Arc<dyn TokenProvider> = Arc::new(CachedToken::new(CommandToken(cmd.split_whitespace().map(str::to_string).collect())));
    let c = Client::new(ou_files::webdav::transfer_client().unwrap(), url.clone(), tokens.clone()).unwrap();
    let space = c.list_spaces().await.unwrap().into_iter().find(|s| s.drive_type == "personal").unwrap();
    let folder = format!("[OU-TEST] engine-{}", std::process::id());
    c.mkcol(&space, &folder).await.unwrap();
    for i in 0..3 {
        c.put(&space, &format!("{folder}/[OU-TEST] doc{i}.txt"), format!("server v1 of doc{i}\n").into_bytes(), &Precondition::MustNotExist).await.unwrap();
    }
    c.mkcol(&space, &format!("{folder}/sub")).await.unwrap();
    c.put(&space, &format!("{folder}/sub/[OU-TEST] nested.txt"), b"nested\n".to_vec(), &Precondition::MustNotExist).await.unwrap();

    let base = std::env::temp_dir().join(format!("ou-files-engine-live-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let local: PathBuf = base.join("Office Unbound");
    std::fs::create_dir_all(&local).unwrap();
    let cfg = EngineConfig {
        exe: exe.into(),
        server: url,
        space_id: space.id.clone(),
        local_dir: local.clone(),
        remote_folder: folder.clone(),
        username: c.username().await.unwrap(),
        state_dir: base.join("state"),
        unsynced_folders: vec![],
        download_limit_kbps: 0,
        max_sync_retries: 3,
        run_timeout: Duration::from_secs(300),
    };
    let policy = GuardPolicy::default();
    let cycle = || sync_cycle(&c, &space, &cfg, "acc-live", &policy);

    // 1. First cycle into an empty folder: downloads everything.
    let r = cycle().await.unwrap();
    assert!(matches!(r, CycleOutcome::Synced { .. }), "first cycle: {r:?}");
    assert_eq!(std::fs::read_to_string(local.join("[OU-TEST] doc1.txt")).unwrap(), "server v1 of doc1\n");
    assert_eq!(std::fs::read_to_string(local.join("sub/[OU-TEST] nested.txt")).unwrap(), "nested\n");
    let m = Manifest::load(&cfg.state_dir).unwrap().unwrap();
    assert_eq!(m.entries.len(), 5, "3 files + sub + nested: {:?}", m.entries.keys().collect::<Vec<_>>());
    // Our marker must not be uploaded.
    assert!(matches!(c.propfind(&space, &format!("{folder}/.ou-sync-root"), 0).await, Err(FilesError::NotFound)));

    // 2. Local edit + new local file are uploaded intact.
    std::fs::write(local.join("[OU-TEST] doc0.txt"), "local edit of doc0\n").unwrap();
    std::fs::write(local.join("[OU-TEST] new local.txt"), "created locally\n").unwrap();
    let r = cycle().await.unwrap();
    assert!(matches!(r, CycleOutcome::Synced { .. }), "upload cycle: {r:?}");
    let dl = base.join("dl");
    std::fs::create_dir_all(&dl).unwrap();
    c.download(&space, &format!("{folder}/[OU-TEST] doc0.txt"), &dl.join("doc0"), false).await.unwrap();
    assert_eq!(std::fs::read_to_string(dl.join("doc0")).unwrap(), "local edit of doc0\n");
    c.download(&space, &format!("{folder}/[OU-TEST] new local.txt"), &dl.join("new"), false).await.unwrap();
    assert_eq!(std::fs::read_to_string(dl.join("new")).unwrap(), "created locally\n");

    // 3. Simultaneous edit on "two computers": server and local both change doc2. Nothing may be lost.
    let e = c.propfind(&space, &format!("{folder}/[OU-TEST] doc2.txt"), 0).await.unwrap().remove(0).etag.unwrap();
    c.put(&space, &format!("{folder}/[OU-TEST] doc2.txt"), b"edit from computer B\n".to_vec(), &Precondition::Matches(e)).await.unwrap();
    std::fs::write(local.join("[OU-TEST] doc2.txt"), "edit from computer A\n").unwrap();
    let r = cycle().await.unwrap();
    assert!(matches!(r, CycleOutcome::Synced { .. }), "conflict cycle: {r:?}");
    let names: Vec<String> = std::fs::read_dir(&local).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    let copy = names.iter().find(|n| n.starts_with("[OU-TEST] doc2") && ou_files::guard::is_conflict_name(n)).expect("conflict copy exists");
    let contents = [std::fs::read_to_string(local.join("[OU-TEST] doc2.txt")).unwrap(), std::fs::read_to_string(local.join(copy)).unwrap()];
    assert!(contents.contains(&"edit from computer A\n".to_string()), "A's edit kept: {contents:?}");
    assert!(contents.contains(&"edit from computer B\n".to_string()), "B's edit kept: {contents:?}");
    eprintln!("conflict copy: {copy}");

    // 4. Most of the local folder vanishes: the guard holds, the engine does not run, the server keeps everything.
    let before = c.list_tree(&space, &folder, 1000).await.entries.len();
    for n in &names {
        let p = local.join(n);
        if p.is_file() && n != ".ou-sync-root" {
            std::fs::remove_file(p).unwrap();
        }
    }
    std::fs::remove_dir_all(local.join("sub")).unwrap();
    let r = cycle().await.unwrap();
    assert!(matches!(r, CycleOutcome::Held { local_deletes, .. } if local_deletes >= 5), "mass delete held: {r:?}");
    assert_eq!(c.list_tree(&space, &folder, 1000).await.entries.len(), before, "nothing deleted on the server");

    // 5. Sync folder gone (unplugged disk): skipped, nothing deleted.
    std::fs::remove_dir_all(&local).unwrap();
    let r = cycle().await.unwrap();
    assert!(matches!(r, CycleOutcome::Skipped(_)), "missing root: {r:?}");
    assert_eq!(c.list_tree(&space, &folder, 1000).await.entries.len(), before);

    // Cleanup: folder + its trash entries.
    c.delete(&space, &folder, None).await.unwrap();
    for t in c.list_trash(&space).await.unwrap() {
        if t.original_name == folder || t.original_location.starts_with(&format!("{folder}/")) {
            c.purge_trash_item(&space, &t.key).await.unwrap();
        }
    }
    assert!(c.list_trash(&space).await.unwrap().iter().all(|t| !t.original_name.contains("[OU-TEST] engine")));
    // No app token of ours is left behind.
    let left: Vec<String> = c.app_token_labels().await.unwrap().into_iter().filter(|l| l.starts_with("Office Unbound Desktop sync")).collect();
    assert!(left.is_empty(), "per-run app tokens deleted: {left:?}");
    std::fs::remove_dir_all(&base).unwrap();
}
