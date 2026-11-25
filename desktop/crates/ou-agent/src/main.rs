//! `ou-agent` - Office Unbound Desktop background agent.
//!   ou-agent            run (exits at once if an agent of this user is already running)
//!   ou-agent --status   print the running agent's status as JSON
//!   ou-agent --quit     ask the running agent to exit
//!   ou-agent token --account <id>   print a fresh access token for that account (rclone bearer_token_command); same user only
//!   ou-agent --version
#![cfg_attr(windows, windows_subsystem = "windows")]

use std::sync::Arc;

use ou_agent::{endpoint, info, log, server, state::Agent};
use ou_core::accounts::default_root;
use ou_core::ipc::Request;

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    let root = default_root();
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("runtime");
    let code = rt.block_on(async {
        match arg.as_str() {
            "--version" => {
                println!("ou-agent {}", ou_core::VERSION);
                0
            }
            "--status" | "--quit" => {
                let req = if arg == "--status" { Request::Status {} } else { Request::Shutdown {} };
                match ou_agent::client::request(&root, &req).await {
                    Ok(r) => {
                        println!("{}", serde_json::to_string(&r).unwrap());
                        0
                    }
                    Err(e) => {
                        eprintln!("{e}");
                        3
                    }
                }
            }
            "token" => token(&root).await,
            "" | "--background" => run(root).await,
            _ => {
                eprintln!("usage: ou-agent [--status|--quit|--version]");
                2
            }
        }
    });
    std::process::exit(code);
}

/// `ou-agent token --account <id>`: stdout gets the token only (no newline), nothing is logged; errors go to stderr without it.
async fn token(root: &std::path::Path) -> i32 {
    let args: Vec<String> = std::env::args().collect();
    let id = match (args.get(2).map(String::as_str), args.get(3)) {
        (Some("--account"), Some(id)) if ou_core::ipc::valid_id(id) => id.clone(),
        _ => {
            eprintln!("usage: ou-agent token --account <account-id>");
            return 2;
        }
    };
    match ou_agent::client::request(root, &Request::AccessToken { account_id: id }).await {
        Ok(ou_core::ipc::Response::AccessToken { token }) => {
            use std::io::Write;
            let mut out = std::io::stdout().lock();
            let _ = out.write_all(token.0.as_bytes());
            let _ = out.flush();
            0
        }
        Ok(ou_core::ipc::Response::Error { message }) => {
            eprintln!("{message}");
            4
        }
        Ok(_) => 4,
        Err(e) => {
            eprintln!("{e}");
            3
        }
    }
}

async fn run(root: std::path::PathBuf) -> i32 {
    if let Err(e) = std::fs::create_dir_all(&root) {
        eprintln!("cannot create {}: {e}", root.display());
        return 1;
    }
    log::init(&root);
    let srv = match endpoint::Server::bind(&root) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            // Single instance per user: a second start is a no-op.
            return 0;
        }
        Err(e) => {
            ou_agent::warn!("cannot open the agent endpoint: {e}");
            return 1;
        }
    };
    let store: Arc<dyn ou_core::secrets::SecretStore> = Arc::from(ou_core::secrets::platform_store());
    let agent = match Agent::new(root, store) {
        Ok(a) => a,
        Err(e) => {
            ou_agent::warn!("{e}");
            return 1;
        }
    };
    info!("agent {} started", ou_core::VERSION);
    agent.restore().await;
    tokio::spawn(agent.clone().keepalive_loop());
    tokio::spawn(server::serve(agent.clone(), srv));
    agent.shutdown.notified().await;
    info!("agent exiting");
    0
}
