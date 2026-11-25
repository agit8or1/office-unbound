//! Serves the endpoint: one task per connection, one JSON line per request, bounded line length, idle timeout.

use std::sync::Arc;
use std::time::Duration;

use ou_core::ipc::{decode_request, encode, Response, MAX_LINE};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use crate::endpoint::{Conn, Server};
use crate::state::Agent;
use crate::warn;

const IDLE: Duration = Duration::from_secs(300);

pub async fn serve(agent: Arc<Agent>, mut server: Server) {
    loop {
        match server.accept().await {
            Ok(conn) => {
                let a = agent.clone();
                tokio::spawn(async move { connection(a, conn).await });
            }
            Err(e) => {
                warn!("endpoint accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

async fn connection(agent: Arc<Agent>, conn: Box<dyn Conn>) {
    let (r, mut w) = tokio::io::split(conn);
    let mut reader = BufReader::new(r);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = match tokio::time::timeout(IDLE, (&mut reader).take((MAX_LINE + 1) as u64).read_until(b'\n', &mut buf)).await {
            Ok(Ok(n)) => n,
            _ => return,
        };
        if n == 0 {
            return;
        }
        let resp = if buf.len() > MAX_LINE {
            let _ = w.write_all(encode(&Response::Error { message: "message too large".into() }).as_bytes()).await;
            return;
        } else {
            match std::str::from_utf8(&buf).ok().map(|s| decode_request(s.trim_end())) {
                Some(Ok(req)) => agent.handle(req).await,
                _ => Response::Error { message: "invalid request".into() },
            }
        };
        if w.write_all(encode(&resp).as_bytes()).await.is_err() {
            return;
        }
    }
}
