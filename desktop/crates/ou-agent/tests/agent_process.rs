//! Runs the real `ou-agent` binary as a separate process (as the GUI would) against the mock IdP, over its local endpoint.
//! Needs `--features test-support` (the browser hook); skipped otherwise.
#![cfg(feature = "test-support")]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use ou_core::ipc::{Request, Response, Service, SessionState};

struct Proc(Child);
impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn spawn(home: &PathBuf, deployment: &str, browser_file: &PathBuf) -> Proc {
    Proc(
        Command::new(env!("CARGO_BIN_EXE_ou-agent"))
            .env("OU_DESKTOP_HOME", home)
            .env("OU_TEST_DISCOVERY_JSON", deployment)
            .env("OU_TEST_BROWSER_FILE", browser_file)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}

async fn req(home: &PathBuf, r: Request) -> Response {
    ou_agent::client::request(home, &r).await.unwrap()
}

async fn wait_endpoint(home: &PathBuf) {
    for _ in 0..100 {
        if ou_agent::client::request(home, &Request::Status {}).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("agent did not start");
}

#[tokio::test]
async fn agent_lifecycle_against_mock_idp() {
    let idp = ou_core::testing::start().await;
    let base = idp.lock().unwrap().base.clone();
    let home = std::env::temp_dir().join(format!("ou-agent-test-{}", ou_core::accounts::new_account_id()));
    let bf = home.join("browser.url");
    std::fs::create_dir_all(&home).unwrap();
    let deployment = serde_json::json!({
        "domain": "a.example", "name": "Mock Co", "issuer": base, "client_id": "ou-desktop",
        "files_url": format!("{base}/"), "portal_url": format!("{base}/portal/"), "matrix_url": null,
        "chat_web_url": null, "mail_web_url": null, "source": "web_finger", "login_hint": "doc@a.example", "foreign_hosts": []
    })
    .to_string();
    let _agent = spawn(&home, &deployment, &bf);
    wait_endpoint(&home).await;

    // Single instance: a second agent exits at once with 0 and the first keeps serving.
    let st = Command::new(env!("CARGO_BIN_EXE_ou-agent")).env("OU_DESKTOP_HOME", &home).status().unwrap();
    assert!(st.success());

    assert!(matches!(req(&home, Request::Hello { protocol: 1, client: "test".into() }).await, Response::Hello { .. }));
    assert!(matches!(req(&home, Request::Hello { protocol: 99, client: "test".into() }).await, Response::Error { .. }));

    let Response::Discovered { discovery_id, deployment } = req(&home, Request::Discover { input: "doc@a.example".into() }).await else {
        panic!()
    };
    assert_eq!(deployment.name, "Mock Co");
    assert!(matches!(req(&home, Request::SignIn { discovery_id: discovery_id.clone() }).await, Response::SignInStarted));
    assert!(matches!(req(&home, Request::SignIn { discovery_id }).await, Response::Error { .. }), "discovery id is single-use");

    // The "system browser": read the URL the agent opened, follow the IdP redirect to the agent's loopback listener.
    let mut url = String::new();
    for _ in 0..100 {
        if let Ok(u) = std::fs::read_to_string(&bf) {
            url = u;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(url.contains("code_challenge_method=S256") && url.contains("login_hint=doc%40a.example"), "{url}");
    let http = ou_core::http::test_client();
    let r = http.get(&url).send().await.unwrap();
    let loc = r.headers()["location"].to_str().unwrap().to_string();
    assert!(http.get(&loc).send().await.unwrap().status().is_success());

    let mut account_id = String::new();
    for _ in 0..100 {
        if let Response::Status { accounts, .. } = req(&home, Request::Status {}).await {
            if let Some(a) = accounts.iter().find(|a| a.state == SessionState::SignedIn) {
                assert_eq!(a.label, "doc@a.example");
                account_id = a.id.clone();
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!account_id.is_empty(), "signed in");

    // URL policy through the agent: foreign and non-https links refused, deployment link allowed.
    for bad in ["https://evil.example/", "file:///C:/Windows/System32/calc.exe", "javascript:alert(1)"] {
        let r = req(&home, Request::OpenExternal { account_id: account_id.clone(), url: bad.into() }).await;
        assert!(matches!(r, Response::Error { .. }), "{bad}");
    }
    std::fs::remove_file(&bf).unwrap();
    assert!(matches!(req(&home, Request::OpenService { account_id: account_id.clone(), service: Service::Portal }).await, Response::Ok));
    assert_eq!(std::fs::read_to_string(&bf).unwrap(), format!("{base}/portal/"));
    assert!(matches!(req(&home, Request::OpenService { account_id: account_id.clone(), service: Service::Chat }).await, Response::Error { .. }));
    assert!(matches!(req(&home, Request::SignOut { account_id: "../../x".into() }).await, Response::Error { .. }), "bad id");

    // `ou-agent token --account <id>` (rclone bearer_token_command): token on stdout only, nothing else.
    let out = Command::new(env!("CARGO_BIN_EXE_ou-agent")).env("OU_DESKTOP_HOME", &home).args(["token", "--account", &account_id]).output().unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "at-1");
    let bad = Command::new(env!("CARGO_BIN_EXE_ou-agent")).env("OU_DESKTOP_HOME", &home).args(["token", "--account", "../x"]).output().unwrap();
    assert!(!bad.status.success() && bad.stdout.is_empty());

    // Nothing secret on disk outside the (here: in-memory) credential store.
    for f in walk(&home) {
        let s = String::from_utf8_lossy(&std::fs::read(&f).unwrap()).to_string();
        assert!(!s.contains("rt-") && !s.contains("at-1") && !s.contains("code_verifier"), "secret in {}", f.display());
    }

    // Sign out revokes at the IdP.
    assert!(matches!(req(&home, Request::SignOut { account_id: account_id.clone() }).await, Response::Ok));
    assert!(idp.lock().unwrap().refresh.values().all(|active| !active), "refresh token revoked");
    let Response::Status { accounts, .. } = req(&home, Request::Status {}).await else { panic!() };
    assert_eq!(accounts[0].state, SessionState::SignedOut);

    assert!(matches!(req(&home, Request::RemoveAccount { account_id: account_id.clone() }).await, Response::Ok));
    let Response::Status { accounts, .. } = req(&home, Request::Status {}).await else { panic!() };
    assert!(accounts.is_empty());

    assert!(matches!(req(&home, Request::Shutdown {}).await, Response::Ok));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(ou_agent::client::request(&home, &Request::Status {}).await.is_err(), "agent exited");
    std::fs::remove_dir_all(&home).unwrap();
}

#[tokio::test]
async fn endpoint_rejects_garbage_and_oversize() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let home = std::env::temp_dir().join(format!("ou-agent-test-{}", ou_core::accounts::new_account_id()));
    std::fs::create_dir_all(&home).unwrap();
    let _agent = spawn(&home, "{}", &home.join("b"));
    wait_endpoint(&home).await;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let sock = std::fs::read_to_string(home.join("agent.endpoint")).unwrap();
        assert_eq!(std::fs::metadata(sock.trim()).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(home.join("run")).unwrap().permissions().mode() & 0o777, 0o700);
    }
    let conn = ou_agent::endpoint::connect(&home).await.unwrap();
    let (r, mut w) = tokio::io::split(conn);
    let mut lines = BufReader::new(r).lines();
    w.write_all(b"{\"type\":\"exec\",\"cmd\":\"calc\"}\n").await.unwrap();
    assert!(lines.next_line().await.unwrap().unwrap().contains("invalid request"));
    w.write_all(&vec![b'a'; 70 * 1024]).await.unwrap();
    w.write_all(b"\n").await.unwrap();
    assert!(lines.next_line().await.unwrap().unwrap().contains("too large"));
    let _ = req(&home, Request::Shutdown {}).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let _ = std::fs::remove_dir_all(&home);
}

fn walk(p: &PathBuf) -> Vec<PathBuf> {
    let mut out = vec![];
    for e in std::fs::read_dir(p).unwrap().flatten() {
        let path = e.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else if path.extension().map(|x| x != "sock").unwrap_or(true) && !path.ends_with("agent.sock") {
            out.push(path);
        }
    }
    out
}
