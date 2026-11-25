//! Client side of the agent endpoint, used by the GUI and by `ou-agent --status`.

use std::path::Path;
use std::time::Duration;

use ou_core::ipc::{decode_line, encode, Request, Response};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub async fn request(root: &Path, req: &Request) -> Result<Response, String> {
    let conn = crate::endpoint::connect(root).await.map_err(|e| format!("agent not running ({e})"))?;
    let (r, mut w) = tokio::io::split(conn);
    w.write_all(encode(req).as_bytes()).await.map_err(|e| e.to_string())?;
    let mut lines = BufReader::new(r).lines();
    let line = tokio::time::timeout(Duration::from_secs(30), lines.next_line())
        .await
        .map_err(|_| "agent did not answer".to_string())?
        .map_err(|e| e.to_string())?
        .ok_or("agent closed the connection")?;
    decode_line::<Response>(&line).map_err(|e| e.to_string())
}
