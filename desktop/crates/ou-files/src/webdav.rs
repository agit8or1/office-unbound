//! OpenCloud client: spaces via Graph (`/graph/v1.0/me/drives`), WebDAV PROPFIND/GET/PUT/DELETE/MKCOL with ETag preconditions,
//! resumable TUS uploads (creation + PATCH + HEAD resume), checksum verification, and the per-space trash bin.
//!
//! Security: every URL the server hands back (space `webDavUrl`, TUS `Location`) must stay on the account's cloud origin before
//! a bearer token is sent to it. TLS is always verified (ou-core's rustls provider); http:// is only accepted for loopback
//! mock servers in test builds.

use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use percent_encoding::percent_decode_str;
use quick_xml::events::Event;
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use tokio::io::AsyncWriteExt;
use url::Url;

use crate::guard::{Health, RemoteItem, RemoteListing};

#[derive(Debug, thiserror::Error)]
pub enum FilesError {
    #[error("not signed in or the sign-in expired")]
    Auth,
    #[error("server unreachable: {0}")]
    Offline(String),
    #[error("the file changed on the server since it was last synced")]
    PreconditionFailed,
    #[error("not found")]
    NotFound,
    #[error("already exists")]
    Exists,
    #[error("HTTP {0}")]
    Status(u16),
    #[error("unexpected server answer: {0}")]
    Protocol(String),
    #[error("checksum mismatch ({0})")]
    Checksum(String),
    #[error("refused by policy: {0}")]
    Policy(String),
    #[error("local file error: {0}")]
    Io(#[from] std::io::Error),
}

impl FilesError {
    /// The guard's view of a failed probe. Only `Ok` lets the engine run.
    pub fn health(&self) -> Health {
        match self {
            Self::Auth => Health::AuthFailed,
            Self::Offline(_) => Health::Offline,
            Self::NotFound => Health::SpaceGone,
            e => Health::ServerError(e.to_string()),
        }
    }
}

fn net(e: reqwest::Error) -> FilesError {
    // Never include the URL query or headers; reqwest's Display may contain the URL, which carries no secret here.
    FilesError::Offline(ou_core::redact::redact(&e.to_string()))
}

/// Supplies short-lived access tokens. The lead's agent implements this over ou-core's refresh-token store; tests use a command.
pub trait TokenProvider: Send + Sync {
    fn access_token(&self) -> Pin<Box<dyn Future<Output = Result<String, FilesError>> + Send + '_>>;
}

/// A fixed token (tests, or a token the caller already refreshed).
pub struct StaticToken(pub String);

impl TokenProvider for StaticToken {
    fn access_token(&self) -> Pin<Box<dyn Future<Output = Result<String, FilesError>> + Send + '_>> {
        let t = self.0.clone();
        Box::pin(async move { Ok(t) })
    }
}

/// Runs a command that prints an access token on stdout (rclone's `bearer_token_command` contract). Output is never logged.
pub struct CommandToken(pub Vec<String>);

impl TokenProvider for CommandToken {
    fn access_token(&self) -> Pin<Box<dyn Future<Output = Result<String, FilesError>> + Send + '_>> {
        Box::pin(async move {
            let (exe, args) = self.0.split_first().ok_or(FilesError::Auth)?;
            let out = tokio::process::Command::new(exe).args(args).stdin(std::process::Stdio::null()).output().await?;
            if !out.status.success() {
                return Err(FilesError::Auth);
            }
            let t = String::from_utf8(out.stdout).map_err(|_| FilesError::Auth)?.trim().to_string();
            if t.is_empty() || t.contains(char::is_whitespace) {
                return Err(FilesError::Auth);
            }
            Ok(t)
        })
    }
}

/// Caches tokens of an inner provider until 60 s before the JWT `exp` (unknown expiry: 60 s). One refresh at a time.
pub struct CachedToken<P> {
    inner: P,
    cache: tokio::sync::Mutex<Option<(String, std::time::Instant)>>,
}

impl<P: TokenProvider> CachedToken<P> {
    pub fn new(inner: P) -> Self {
        Self { inner, cache: tokio::sync::Mutex::new(None) }
    }
}

/// Seconds until the JWT's `exp`, read without verifying (the server verifies; this only schedules refreshes).
pub fn jwt_lifetime(token: &str) -> Option<u64> {
    let payload = token.split('.').nth(1)?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    let exp = serde_json::from_slice::<serde_json::Value>(&raw).ok()?.get("exp")?.as_u64()?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    exp.checked_sub(now)
}

impl<P: TokenProvider> TokenProvider for CachedToken<P> {
    fn access_token(&self) -> Pin<Box<dyn Future<Output = Result<String, FilesError>> + Send + '_>> {
        Box::pin(async move {
            let mut g = self.cache.lock().await;
            if let Some((t, until)) = g.as_ref() {
                if std::time::Instant::now() < *until {
                    return Ok(t.clone());
                }
            }
            let t = self.inner.access_token().await?;
            let life = jwt_lifetime(&t).map(|s| s.saturating_sub(60)).unwrap_or(60);
            *g = Some((t.clone(), std::time::Instant::now() + Duration::from_secs(life)));
            Ok(t)
        })
    }
}

/// HTTP client for transfers: like `ou_core::http::client()` (HTTPS only, verified TLS, no cookies) but without a total timeout,
/// so large transfers are bounded by a read (idle) timeout instead. Proposed as `ou_core::http::transfer_client()`.
pub fn transfer_client() -> Result<reqwest::Client, FilesError> {
    // ou-core installs the process-wide rustls crypto provider on first use.
    let _ = ou_core::http::client().map_err(|e| FilesError::Protocol(e.to_string()))?;
    reqwest::Client::builder()
        .https_only(true)
        .user_agent(ou_core::http::user_agent())
        .connect_timeout(Duration::from_secs(10))
        .read_timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| FilesError::Protocol(e.to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Space {
    pub id: String,
    /// `personal`, `project` (team/department library), `virtual` (Shares jail), `mountpoint`.
    pub drive_type: String,
    pub name: String,
    pub webdav_url: Url,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DavEntry {
    /// Path relative to the space root, `/`-separated, decoded; "" is the root itself.
    pub rel: String,
    pub dir: bool,
    pub size: u64,
    pub etag: Option<String>,
    pub file_id: Option<String>,
    /// OpenCloud permission letters (S shared, R shareable, M mounted, D deletable, N renamable, V movable, W writable, C/K create).
    pub permissions: Option<String>,
    /// e.g. `SHA1:… MD5:… ADLER32:…`.
    pub checksums: Option<String>,
    pub last_modified: Option<String>,
}

impl DavEntry {
    pub fn sha1(&self) -> Option<String> {
        self.checksums.as_deref()?.split_whitespace().find_map(|c| c.strip_prefix("SHA1:").map(|h| h.to_ascii_lowercase()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrashItem {
    pub key: String,
    pub original_name: String,
    pub original_location: String,
}

/// Precondition for writes, so the client never silently overwrites a newer server version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Precondition {
    /// Create only (atomic: temp upload + `MOVE` with `Overwrite: F`; OpenCloud ignores `If-None-Match: *`).
    MustNotExist,
    /// Replace only the version we synced (`If-Match: <etag>`).
    Matches(String),
    /// Unconditional; only for conflict copies with a fresh unique name.
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    pub bytes: u64,
    pub sha1: String,
    pub sha256: String,
    pub etag: Option<String>,
}

pub struct Client {
    http: reqwest::Client,
    origin: Url,
    tokens: Arc<dyn TokenProvider>,
    /// TUS chunk size (server `max_chunk_size`, 10 MB on OpenCloud).
    pub chunk_size: usize,
    /// Files above this size go through TUS; below, one PUT.
    pub tus_threshold: u64,
}

const PROPFIND_BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop>
<d:resourcetype/><d:getcontentlength/><d:getetag/><d:getlastmodified/><oc:size/><oc:fileid/><oc:permissions/><oc:checksums/>
</d:prop></d:propfind>"#;

const TRASH_BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop>
<oc:trashbin-original-filename/><oc:trashbin-original-location/><oc:trashbin-delete-datetime/><d:resourcetype/>
</d:prop></d:propfind>"#;

fn propfind() -> Method {
    Method::from_bytes(b"PROPFIND").expect("static method")
}

impl Client {
    pub fn new(http: reqwest::Client, origin: Url, tokens: Arc<dyn TokenProvider>) -> Result<Self, FilesError> {
        ou_core::http::require_allowed(&origin).map_err(|e| FilesError::Policy(e.to_string()))?;
        Ok(Self { http, origin, tokens, chunk_size: 10_000_000, tus_threshold: 10_000_000 })
    }

    fn same_origin(&self, u: &Url) -> Result<(), FilesError> {
        if u.scheme() == self.origin.scheme() && u.host_str() == self.origin.host_str() && u.port_or_known_default() == self.origin.port_or_known_default()
        {
            Ok(())
        } else {
            Err(FilesError::Policy(format!("server pointed to another origin ({})", u.host_str().unwrap_or("?"))))
        }
    }

    async fn req(&self, method: Method, url: &Url) -> Result<reqwest::RequestBuilder, FilesError> {
        self.same_origin(url)?;
        let token = self.tokens.access_token().await?;
        Ok(self.http.request(method, url.clone()).bearer_auth(token))
    }

    fn check(resp: &reqwest::Response) -> Result<(), FilesError> {
        match resp.status() {
            s if s.is_success() => Ok(()),
            StatusCode::UNAUTHORIZED => Err(FilesError::Auth),
            StatusCode::NOT_FOUND => Err(FilesError::NotFound),
            StatusCode::PRECONDITION_FAILED => Err(FilesError::PreconditionFailed),
            StatusCode::METHOD_NOT_ALLOWED => Err(FilesError::Exists), // MKCOL on an existing folder
            s => Err(FilesError::Status(s.as_u16())),
        }
    }

    /// Spaces the user can see: personal, shared-with-me (virtual "Shares"), and project spaces (team/department libraries).
    pub async fn list_spaces(&self) -> Result<Vec<Space>, FilesError> {
        #[derive(Deserialize)]
        struct Root {
            #[serde(rename = "webDavUrl")]
            web_dav_url: Option<String>,
        }
        #[derive(Deserialize)]
        struct Drive {
            id: String,
            #[serde(rename = "driveType")]
            drive_type: String,
            name: Option<String>,
            root: Root,
            #[serde(default)]
            deleted: Option<serde_json::Value>,
        }
        #[derive(Deserialize)]
        struct List {
            value: Vec<Drive>,
        }
        let url = self.origin.join("graph/v1.0/me/drives").map_err(|e| FilesError::Protocol(e.to_string()))?;
        let resp = self.req(Method::GET, &url).await?.send().await.map_err(net)?;
        Self::check(&resp)?;
        let list: List = resp.json().await.map_err(|e| FilesError::Protocol(e.to_string()))?;
        let mut out = Vec::new();
        for d in list.value {
            if d.deleted.is_some() {
                continue; // disabled space
            }
            let Some(w) = d.root.web_dav_url else { continue };
            let webdav_url = Url::parse(&w).map_err(|e| FilesError::Protocol(e.to_string()))?;
            self.same_origin(&webdav_url)?;
            out.push(Space { id: d.id, drive_type: d.drive_type, name: d.name.unwrap_or_default(), webdav_url });
        }
        Ok(out)
    }

    /// URL of `rel` inside the space; each component is percent-encoded as one segment (no traversal possible).
    pub fn item_url(space: &Space, rel: &str, dir: bool) -> Result<Url, FilesError> {
        let mut u = space.webdav_url.clone();
        {
            let mut segs = u.path_segments_mut().map_err(|_| FilesError::Protocol("base URL".into()))?;
            segs.pop_if_empty();
            for c in rel.split('/').filter(|c| !c.is_empty()) {
                if c == ".." || c == "." {
                    return Err(FilesError::Policy("path traversal".into()));
                }
                segs.push(c);
            }
            if dir {
                segs.push("");
            }
        }
        Ok(u)
    }

    /// PROPFIND with Depth 0 or 1. Entries come back relative to the space root.
    pub async fn propfind(&self, space: &Space, rel: &str, depth: u8) -> Result<Vec<DavEntry>, FilesError> {
        let url = Self::item_url(space, rel, true)?;
        let resp = self
            .req(propfind(), &url)
            .await?
            .header("Depth", depth.to_string())
            .header("Content-Type", "application/xml; charset=utf-8")
            .body(PROPFIND_BODY)
            .send()
            .await
            .map_err(net)?;
        Self::check(&resp)?;
        if resp.status().as_u16() != 207 {
            return Err(FilesError::Protocol(format!("PROPFIND answered {}", resp.status().as_u16())));
        }
        let body = resp.text().await.map_err(net)?;
        parse_multistatus(&body, space.webdav_url.path())
    }

    /// Cheap change probe: the space root ETag changes whenever anything below it changes (OpenCloud propagates ETags).
    pub async fn root_etag(&self, space: &Space) -> Result<Option<String>, FilesError> {
        Ok(self.propfind(space, "", 0).await?.into_iter().next().and_then(|e| e.etag))
    }

    /// Health probe for the guard.
    pub async fn probe(&self, space: &Space) -> Health {
        match self.propfind(space, "", 0).await {
            Ok(v) if !v.is_empty() => Health::Ok,
            Ok(_) => Health::ServerError("empty answer for the space root".into()),
            Err(e) => e.health(),
        }
    }

    /// Recursive listing (breadth-first Depth 1, which OpenCloud always allows). Any failure marks the listing incomplete; it is
    /// then never used as evidence of deletion. `max_entries` bounds memory on huge trees (also marks incomplete).
    pub async fn list_tree(&self, space: &Space, root_rel: &str, max_entries: usize) -> RemoteListing {
        let mut out = RemoteListing { complete: true, ..Default::default() };
        let base = root_rel.trim_matches('/').to_string();
        let mut queue = vec![base.clone()];
        while let Some(dir) = queue.pop() {
            match self.propfind(space, &dir, 1).await {
                Ok(entries) => {
                    for e in entries {
                        if e.rel == dir {
                            continue;
                        }
                        let rel = if base.is_empty() { e.rel.clone() } else { e.rel.strip_prefix(&format!("{base}/")).unwrap_or(&e.rel).to_string() };
                        if e.dir {
                            queue.push(e.rel.clone());
                        }
                        out.entries.insert(rel, RemoteItem { dir: e.dir, size: e.size, etag: e.etag });
                        if out.entries.len() > max_entries {
                            out.complete = false;
                            return out;
                        }
                    }
                }
                Err(_) => out.complete = false,
            }
        }
        out
    }

    pub async fn mkcol(&self, space: &Space, rel: &str) -> Result<(), FilesError> {
        let url = Self::item_url(space, rel, true)?;
        let resp = self.req(Method::from_bytes(b"MKCOL").expect("static"), &url).await?.send().await.map_err(net)?;
        Self::check(&resp)
    }

    /// Deletes to the space's trash bin (recoverable), optionally only if the ETag still matches.
    pub async fn delete(&self, space: &Space, rel: &str, if_match: Option<&str>) -> Result<(), FilesError> {
        if rel.trim_matches('/').is_empty() {
            return Err(FilesError::Policy("refusing to delete the space root".into()));
        }
        let url = Self::item_url(space, rel, false)?;
        let mut rb = self.req(Method::DELETE, &url).await?;
        if let Some(e) = if_match {
            rb = rb.header("If-Match", e);
        }
        let resp = rb.send().await.map_err(net)?;
        Self::check(&resp)
    }

    /// One-request upload with a precondition and an OC-Checksum the server verifies.
    ///
    /// OpenCloud ignores `If-None-Match: *` on PUT (measured on officeunbound8, 2026-11-25: a second create answered 204 and
    /// replaced the file). "Create only" is therefore done as PUT to a unique hidden `.part` name (excluded by every OpenCloud
    /// client's default exclude list) followed by `MOVE` with `Overwrite: F`, which the server refuses atomically with 412.
    pub async fn put(&self, space: &Space, rel: &str, data: Vec<u8>, pre: &Precondition) -> Result<Transfer, FilesError> {
        if *pre == Precondition::MustNotExist {
            let tmp = temp_sibling(rel)?;
            let t = Box::pin(self.put(space, &tmp, data, &Precondition::None)).await?;
            return self.finish_create(space, &tmp, rel, t).await;
        }
        let url = Self::item_url(space, rel, false)?;
        let (sha1, sha256) = (hex(&Sha1::digest(&data)), hex(&Sha256::digest(&data)));
        let bytes = data.len() as u64;
        let mut rb = self.req(Method::PUT, &url).await?.header("OC-Checksum", format!("SHA1:{sha1}"));
        if let Precondition::Matches(e) = pre {
            rb = rb.header("If-Match", e.as_str());
        }
        let resp = rb.body(data).send().await.map_err(net)?;
        Self::check(&resp)?;
        let etag = header(&resp, "etag").or_else(|| header(&resp, "oc-etag"));
        Ok(Transfer { bytes, sha1, sha256, etag })
    }

    /// Moves the uploaded temp file onto `rel` only if `rel` does not exist; otherwise removes the temp file (and its trash entry is
    /// purged from the trash) and reports PreconditionFailed.
    async fn finish_create(&self, space: &Space, tmp: &str, rel: &str, mut t: Transfer) -> Result<Transfer, FilesError> {
        match self.move_item(space, tmp, rel, false).await {
            Ok(()) => {
                t.etag = self.propfind(space, rel, 0).await?.first().and_then(|e| e.etag.clone()).or(t.etag);
                Ok(t)
            }
            Err(e) => {
                // The temp file is ours (never user data): delete it and purge it from the trash so it does not litter it.
                if self.delete(space, tmp, None).await.is_ok() {
                    let name = tmp.rsplit('/').next().unwrap_or(tmp);
                    if let Ok(items) = self.list_trash(space).await {
                        for t in items.iter().filter(|t| t.original_name == name) {
                            let _ = self.purge_trash_item(space, &t.key).await;
                        }
                    }
                }
                Err(e)
            }
        }
    }

    /// WebDAV MOVE inside one space. `overwrite = false` sends `Overwrite: F` (412 if the target exists).
    pub async fn move_item(&self, space: &Space, from: &str, to: &str, overwrite: bool) -> Result<(), FilesError> {
        let src = Self::item_url(space, from, false)?;
        let dst = Self::item_url(space, to, false)?;
        let resp = self
            .req(Method::from_bytes(b"MOVE").expect("static"), &src)
            .await?
            .header("Destination", dst.as_str())
            .header("Overwrite", if overwrite { "T" } else { "F" })
            .send()
            .await
            .map_err(net)?;
        Self::check(&resp)
    }

    /// Creates a TUS upload for `rel` (creation extension); returns the upload URL (checked to be on our origin).
    pub async fn tus_create(&self, space: &Space, rel: &str, length: u64) -> Result<Url, FilesError> {
        let (parent, name) = split_parent(rel)?;
        let url = Self::item_url(space, parent, true)?;
        let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
        let resp = self
            .req(Method::POST, &url)
            .await?
            .header("Tus-Resumable", "1.0.0")
            .header("Upload-Length", length.to_string())
            .header("Upload-Metadata", format!("filename {}", b64(name)))
            .header("Content-Length", "0")
            .send()
            .await
            .map_err(net)?;
        Self::check(&resp)?;
        let loc = header(&resp, "location").ok_or_else(|| FilesError::Protocol("TUS creation without Location".into()))?;
        let loc = url.join(&loc).map_err(|e| FilesError::Protocol(e.to_string()))?;
        self.same_origin(&loc)?;
        Ok(loc)
    }

    /// Current server offset of a TUS upload (resume point).
    pub async fn tus_offset(&self, upload: &Url) -> Result<u64, FilesError> {
        let resp = self.req(Method::HEAD, upload).await?.header("Tus-Resumable", "1.0.0").send().await.map_err(net)?;
        Self::check(&resp)?;
        header(&resp, "upload-offset").and_then(|v| v.parse().ok()).ok_or_else(|| FilesError::Protocol("HEAD without Upload-Offset".into()))
    }

    /// Sends one chunk at `offset`; returns the new offset. On a 409 offset mismatch the caller resumes from `tus_offset`.
    pub async fn tus_patch(&self, upload: &Url, offset: u64, chunk: Vec<u8>) -> Result<(u64, Option<String>), FilesError> {
        let resp = self
            .req(Method::PATCH, upload)
            .await?
            .header("Tus-Resumable", "1.0.0")
            .header("Upload-Offset", offset.to_string())
            .header("Content-Type", "application/offset+octet-stream")
            .body(chunk)
            .send()
            .await
            .map_err(net)?;
        if resp.status() == StatusCode::CONFLICT {
            return Err(FilesError::Status(409));
        }
        Self::check(&resp)?;
        let next = header(&resp, "upload-offset").and_then(|v| v.parse().ok()).ok_or_else(|| FilesError::Protocol("PATCH without Upload-Offset".into()))?;
        Ok((next, header(&resp, "etag").or_else(|| header(&resp, "oc-etag"))))
    }

    /// Uploads a local file. Small files: one PUT with the precondition. Large files: TUS in `chunk_size` pieces, resuming from the
    /// server offset after an interrupted PATCH (up to `retries` times). For TUS the precondition is checked by a PROPFIND just
    /// before creation (OpenCloud's TUS creation has no If-Match), and the result is verified against the server's SHA1.
    pub async fn upload_file(&self, space: &Space, rel: &str, local: &Path, pre: &Precondition, retries: u32) -> Result<Transfer, FilesError> {
        let len = tokio::fs::metadata(local).await?.len();
        if len <= self.tus_threshold {
            let data = tokio::fs::read(local).await?;
            return self.put(space, rel, data, pre).await;
        }
        if *pre == Precondition::MustNotExist {
            let tmp = temp_sibling(rel)?;
            let t = Box::pin(self.upload_file(space, &tmp, local, &Precondition::None, retries)).await?;
            return self.finish_create(space, &tmp, rel, t).await;
        }
        // Replace: OpenCloud's TUS creation takes no If-Match, so the ETag is checked right before creation (a narrow race
        // remains; the engine's own uploads use its journal ETags the same way).
        match (pre, self.propfind(space, rel, 0).await) {
            (Precondition::Matches(e), Ok(v)) if v.first().and_then(|x| x.etag.as_deref()) != Some(e.as_str()) => {
                return Err(FilesError::PreconditionFailed)
            }
            (Precondition::Matches(_), Err(FilesError::NotFound)) => return Err(FilesError::PreconditionFailed),
            (_, Err(FilesError::NotFound)) | (_, Ok(_)) => {}
            (_, Err(e)) => return Err(e),
        }
        let upload = self.tus_create(space, rel, len).await?;
        let (sha1, sha256) = hash_file(local).await?;
        let mut file = tokio::fs::File::open(local).await?;
        let mut offset = 0u64;
        let mut failures = 0;
        let mut etag = None;
        while offset < len {
            use tokio::io::{AsyncReadExt, AsyncSeekExt};
            file.seek(std::io::SeekFrom::Start(offset)).await?;
            let want = (len - offset).min(self.chunk_size as u64) as usize;
            let mut buf = vec![0u8; want];
            file.read_exact(&mut buf).await?;
            match self.tus_patch(&upload, offset, buf).await {
                Ok((next, e)) => {
                    offset = next;
                    etag = e.or(etag);
                }
                Err(FilesError::Auth) => return Err(FilesError::Auth),
                Err(e) => {
                    failures += 1;
                    if failures > retries {
                        return Err(e);
                    }
                    tokio::time::sleep(Duration::from_millis(500 * u64::from(failures))).await;
                    offset = self.tus_offset(&upload).await?;
                }
            }
        }
        let after = self.propfind(space, rel, 0).await?;
        let server = after.first().ok_or(FilesError::NotFound)?;
        if server.size != len {
            return Err(FilesError::Checksum(format!("server size {} != local {len}", server.size)));
        }
        if let Some(s) = server.sha1() {
            if s != sha1 {
                return Err(FilesError::Checksum("server SHA1 differs from the local file".into()));
            }
        }
        Ok(Transfer { bytes: len, sha1, sha256, etag: server.etag.clone().or(etag) })
    }

    /// Downloads to `dest` through `dest.ou-part`, verifying length and the server's SHA1 (OC-Checksum) when present.
    /// The final rename only happens when the content is complete; an existing `dest` is replaced only if `overwrite`.
    pub async fn download(&self, space: &Space, rel: &str, dest: &Path, overwrite: bool) -> Result<Transfer, FilesError> {
        if !overwrite && tokio::fs::try_exists(dest).await? {
            return Err(FilesError::Exists);
        }
        let url = Self::item_url(space, rel, false)?;
        let mut resp = self.req(Method::GET, &url).await?.send().await.map_err(net)?;
        Self::check(&resp)?;
        let expected_len = resp.content_length();
        let server_sha1 = header(&resp, "oc-checksum")
            .and_then(|v| v.split_whitespace().find_map(|c| c.strip_prefix("SHA1:").map(|h| h.to_ascii_lowercase())));
        let etag = header(&resp, "etag").or_else(|| header(&resp, "oc-etag"));
        let mut part = dest.as_os_str().to_owned();
        part.push(".ou-part");
        let part = std::path::PathBuf::from(part);
        let mut f = tokio::fs::File::create(&part).await?;
        let (mut s1, mut s256, mut n) = (Sha1::new(), Sha256::new(), 0u64);
        let res: Result<(), FilesError> = async {
            while let Some(chunk) = resp.chunk().await.map_err(net)? {
                s1.update(&chunk);
                s256.update(&chunk);
                n += chunk.len() as u64;
                f.write_all(&chunk).await?;
            }
            f.flush().await?;
            f.sync_all().await?;
            Ok(())
        }
        .await;
        drop(f);
        let sha1 = hex(&s1.finalize());
        let verdict = res.and_then(|_| match (expected_len, &server_sha1) {
            (Some(l), _) if l != n => Err(FilesError::Checksum(format!("got {n} of {l} bytes"))),
            (_, Some(s)) if *s != sha1 => Err(FilesError::Checksum("SHA1 differs from the server's".into())),
            _ => Ok(()),
        });
        if let Err(e) = verdict {
            let _ = tokio::fs::remove_file(&part).await; // only our own partial file, never user data
            return Err(e);
        }
        tokio::fs::rename(&part, dest).await?;
        Ok(Transfer { bytes: n, sha1, sha256: hex(&s256.finalize()), etag })
    }

    /// The OpenCloud user name (Graph `onPremisesSamAccountName`), needed for Basic auth with app tokens.
    pub async fn username(&self) -> Result<String, FilesError> {
        let url = self.origin.join("graph/v1.0/me").map_err(|e| FilesError::Protocol(e.to_string()))?;
        let resp = self.req(Method::GET, &url).await?.send().await.map_err(net)?;
        Self::check(&resp)?;
        let v: serde_json::Value = resp.json().await.map_err(|e| FilesError::Protocol(e.to_string()))?;
        v.get("onPremisesSamAccountName").and_then(|x| x.as_str()).map(str::to_string).ok_or_else(|| FilesError::Protocol("no user name".into()))
    }

    /// Mints a short-lived OpenCloud app token (auth-app service) from the OIDC session, for the sync engine: `opencloudcmd`
    /// only speaks HTTP Basic `user:token` (src/cmd/tokencredentials.cpp), not OIDC bearer tokens. Requires the server's
    /// `PROXY_ENABLE_APP_AUTH=true` (on in Office Unbound deployments). `label` must be unique; it identifies the token for deletion.
    pub async fn create_app_token(&self, expiry_minutes: u32, label: &str) -> Result<String, FilesError> {
        let mut url = self.origin.join("auth-app/tokens").map_err(|e| FilesError::Protocol(e.to_string()))?;
        url.query_pairs_mut().append_pair("expiry", &format!("{}m", expiry_minutes.max(1))).append_pair("label", label);
        let resp = self.req(Method::POST, &url).await?.send().await.map_err(net)?;
        Self::check(&resp)?;
        let v: serde_json::Value = resp.json().await.map_err(|e| FilesError::Protocol(e.to_string()))?;
        v.get("token").and_then(|t| t.as_str()).map(str::to_string).ok_or_else(|| FilesError::Protocol("no app token".into()))
    }

    /// Labels of the user's app tokens (for diagnostics and tests; no secrets in the listing).
    pub async fn app_token_labels(&self) -> Result<Vec<String>, FilesError> {
        let url = self.origin.join("auth-app/tokens").map_err(|e| FilesError::Protocol(e.to_string()))?;
        let resp = self.req(Method::GET, &url).await?.send().await.map_err(net)?;
        Self::check(&resp)?;
        let list: Option<Vec<serde_json::Value>> = resp.json().await.map_err(|e| FilesError::Protocol(e.to_string()))?;
        Ok(list.unwrap_or_default().iter().filter_map(|t| t.get("label").and_then(|l| l.as_str()).map(str::to_string)).collect())
    }

    /// Deletes every app token with this label (the listing shows ids, never secrets). Returns how many were deleted.
    pub async fn delete_app_tokens(&self, label: &str) -> Result<usize, FilesError> {
        let url = self.origin.join("auth-app/tokens").map_err(|e| FilesError::Protocol(e.to_string()))?;
        let resp = self.req(Method::GET, &url).await?.send().await.map_err(net)?;
        Self::check(&resp)?;
        let list: Option<Vec<serde_json::Value>> = resp.json().await.map_err(|e| FilesError::Protocol(e.to_string()))?;
        let mut n = 0;
        for t in list.unwrap_or_default() {
            if t.get("label").and_then(|l| l.as_str()) != Some(label) {
                continue;
            }
            let Some(id) = t.get("token").and_then(|x| x.as_str()) else { continue };
            let mut del = url.clone();
            del.query_pairs_mut().append_pair("token", id);
            let r = self.req(Method::DELETE, &del).await?.send().await.map_err(net)?;
            Self::check(&r)?;
            n += 1;
        }
        Ok(n)
    }

    fn trash_url(&self, space: &Space) -> Result<Url, FilesError> {
        let mut u = self.origin.join("dav/spaces/trash-bin/").map_err(|e| FilesError::Protocol(e.to_string()))?;
        u.path_segments_mut().map_err(|_| FilesError::Protocol("base URL".into()))?.pop_if_empty().push(&space.id).push("");
        Ok(u)
    }

    pub async fn list_trash(&self, space: &Space) -> Result<Vec<TrashItem>, FilesError> {
        let url = self.trash_url(space)?;
        let resp = self
            .req(propfind(), &url)
            .await?
            .header("Depth", "1")
            .header("Content-Type", "application/xml; charset=utf-8")
            .body(TRASH_BODY)
            .send()
            .await
            .map_err(net)?;
        Self::check(&resp)?;
        let body = resp.text().await.map_err(net)?;
        Ok(parse_trash(&body, url.path()))
    }

    /// Permanently removes one trash item (by key). Whole-trash purges are deliberately not offered.
    pub async fn purge_trash_item(&self, space: &Space, key: &str) -> Result<(), FilesError> {
        if key.is_empty() || key.contains('/') {
            return Err(FilesError::Policy("invalid trash key".into()));
        }
        let mut url = self.trash_url(space)?;
        url.path_segments_mut().map_err(|_| FilesError::Protocol("base URL".into()))?.pop_if_empty().push(key);
        let resp = self.req(Method::DELETE, &url).await?.send().await.map_err(net)?;
        Self::check(&resp)
    }
}

/// Hidden sibling name for an upload in progress: `.ou-upload-<random>.part` (OpenCloud clients exclude `*.part`).
fn temp_sibling(rel: &str) -> Result<String, FilesError> {
    let (parent, _) = split_parent(rel)?;
    let name = format!(".ou-upload-{}.part", ou_core::oidc::random_token(9));
    Ok(if parent.is_empty() { name } else { format!("{parent}/{name}") })
}

fn split_parent(rel: &str) -> Result<(&str, &str), FilesError> {
    let rel = rel.trim_matches('/');
    match rel.rsplit_once('/') {
        Some((p, n)) if !n.is_empty() => Ok((p, n)),
        None if !rel.is_empty() => Ok(("", rel)),
        _ => Err(FilesError::Policy("empty file name".into())),
    }
}

fn header(resp: &reqwest::Response, name: &str) -> Option<String> {
    resp.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_string)
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub async fn hash_file(p: &Path) -> Result<(String, String), FilesError> {
    use tokio::io::AsyncReadExt;
    let mut f = tokio::fs::File::open(p).await?;
    let (mut a, mut b) = (Sha1::new(), Sha256::new());
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        a.update(&buf[..n]);
        b.update(&buf[..n]);
    }
    Ok((hex(&a.finalize()), hex(&b.finalize())))
}

fn decode(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

/// Maps an href to a path relative to `base_path` (both percent-decoded). Hrefs outside the base are dropped.
fn rel_of(href: &str, base_path: &str) -> Option<String> {
    let path = Url::parse(href).map(|u| u.path().to_string()).unwrap_or_else(|_| href.to_string());
    let (p, b) = (decode(&path), decode(base_path));
    let rest = p.strip_prefix(b.trim_end_matches('/'))?;
    if !(rest.is_empty() || rest.starts_with('/')) {
        return None;
    }
    let rel = rest.trim_matches('/').to_string();
    if rel.split('/').any(|c| c == ".." || c == ".") {
        return None;
    }
    Some(rel)
}

/// Parses a WebDAV 207 multistatus. Only `200 OK` propstats are taken; a `404` propstat just means the property is absent.
pub fn parse_multistatus(xml: &str, base_path: &str) -> Result<Vec<DavEntry>, FilesError> {
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut out = Vec::new();
    let mut cur: Option<(DavEntry, Option<String>)> = None; // entry + href
    let mut props = DavEntry::default();
    let mut in_ok_propstat = true;
    let mut stack: Vec<String> = Vec::new();
    let mut text = String::new();
    loop {
        let ev = reader.read_event().map_err(|e| FilesError::Protocol(format!("XML: {e}")))?;
        match ev {
            Event::Start(e) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                match name.as_str() {
                    "response" => cur = Some((DavEntry::default(), None)),
                    "propstat" => props = DavEntry::default(),
                    _ => {}
                }
                stack.push(name);
                text.clear();
            }
            Event::Empty(e) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                if name == "collection" && stack.iter().any(|s| s == "resourcetype") {
                    props.dir = true;
                }
            }
            Event::Text(t) => text.push_str(&t.xml_content().map_err(|e| FilesError::Protocol(format!("XML: {e}")))?),
            Event::GeneralRef(r) => {
                // Entity and character references (&amp; &#x26; …) inside names.
                let raw = String::from_utf8_lossy(r.as_ref()).into_owned();
                let resolved = match raw.as_str() {
                    "amp" => Some('&'),
                    "lt" => Some('<'),
                    "gt" => Some('>'),
                    "quot" => Some('"'),
                    "apos" => Some('\''),
                    s if s.starts_with("#x") => u32::from_str_radix(&s[2..], 16).ok().and_then(char::from_u32),
                    s if s.starts_with('#') => s[1..].parse().ok().and_then(char::from_u32),
                    _ => None,
                };
                if let Some(c) = resolved {
                    text.push(c);
                }
            }
            Event::End(e) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                let t = std::mem::take(&mut text);
                match name.as_str() {
                    "href" if stack.len() >= 2 && stack[stack.len() - 2] == "response" => {
                        if let Some(c) = cur.as_mut() {
                            c.1 = Some(t.trim().to_string());
                        }
                    }
                    "status" if stack.iter().any(|s| s == "propstat") => in_ok_propstat = t.contains(" 200"),
                    "getcontentlength" | "size" => {
                        if let Ok(n) = t.trim().parse() {
                            props.size = n;
                        }
                    }
                    "getetag" => props.etag = Some(t.trim().to_string()).filter(|s| !s.is_empty()),
                    "fileid" => props.file_id = Some(t.trim().to_string()),
                    "permissions" => props.permissions = Some(t.trim().to_string()),
                    "checksum" => props.checksums = Some(t.trim().to_string()),
                    "getlastmodified" => props.last_modified = Some(t.trim().to_string()),
                    "propstat" => {
                        if in_ok_propstat {
                            if let Some((c, _)) = cur.as_mut() {
                                c.dir |= props.dir;
                                c.size = c.size.max(props.size);
                                c.etag = c.etag.take().or(props.etag.take());
                                c.file_id = c.file_id.take().or(props.file_id.take());
                                c.permissions = c.permissions.take().or(props.permissions.take());
                                c.checksums = c.checksums.take().or(props.checksums.take());
                                c.last_modified = c.last_modified.take().or(props.last_modified.take());
                            }
                        }
                        in_ok_propstat = true;
                    }
                    "response" => {
                        if let Some((mut c, Some(href))) = cur.take() {
                            if let Some(rel) = rel_of(&href, base_path) {
                                c.rel = rel;
                                out.push(c);
                            }
                        }
                    }
                    _ => {}
                }
                stack.pop();
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(out)
}

fn parse_trash(xml: &str, base_path: &str) -> Vec<TrashItem> {
    // Same shape as a multistatus; reuse the generic walker by reading the three trash properties.
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut out = Vec::new();
    let (mut href, mut name, mut loc) = (String::new(), String::new(), String::new());
    let mut text = String::new();
    while let Ok(ev) = reader.read_event() {
        match ev {
            Event::Start(_) => text.clear(),
            Event::Text(t) => text.push_str(&t.xml_content().unwrap_or_default()),
            Event::GeneralRef(r) if r.as_ref() == b"amp" => text.push('&'),
            Event::End(e) => {
                let t = std::mem::take(&mut text);
                match e.local_name().as_ref() {
                    b"href" => href = t.trim().to_string(),
                    b"trashbin-original-filename" => name = t.trim().to_string(),
                    b"trashbin-original-location" => loc = t.trim().to_string(),
                    b"response" => {
                        if let Some(key) = rel_of(&href, base_path).filter(|k| !k.is_empty() && !k.contains('/')) {
                            out.push(TrashItem { key, original_name: name.clone(), original_location: loc.clone() });
                        }
                        name.clear();
                        loc.clear();
                    }
                    _ => {}
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "/dav/spaces/c43b$bf0c";

    #[test]
    fn multistatus_parsing() {
        let xml = r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
<d:response><d:href>/dav/spaces/c43b$bf0c/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype>
<d:getetag>"root1"</d:getetag><oc:size>42</oc:size><oc:permissions>RDNVCKZP</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
<d:propstat><d:prop><d:getcontentlength/></d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat></d:response>
<d:response><d:href>/dav/spaces/c43b%24bf0c/%5BOU-TEST%5D%20a%20%26%20b.txt</d:href><d:propstat><d:prop><d:resourcetype/>
<d:getcontentlength>42</d:getcontentlength><d:getetag>&quot;e1&quot;</d:getetag><oc:fileid>id1</oc:fileid>
<oc:checksums><oc:checksum>SHA1:ABCDEF MD5:00 ADLER32:01</oc:checksum></oc:checksums></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
<d:response><d:href>/dav/spaces/c43b$bf0c/sub%20dir/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
<d:response><d:href>/dav/spaces/OTHER/evil</d:href><d:propstat><d:prop/><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
</d:multistatus>"#;
        let v = parse_multistatus(xml, BASE).unwrap();
        assert_eq!(v.len(), 3, "foreign href dropped");
        assert_eq!(v[0].rel, "");
        assert!(v[0].dir);
        assert_eq!(v[0].etag.as_deref(), Some("\"root1\""));
        assert_eq!(v[1].rel, "[OU-TEST] a & b.txt");
        assert!(!v[1].dir);
        assert_eq!(v[1].size, 42);
        assert_eq!(v[1].etag.as_deref(), Some("\"e1\""));
        assert_eq!(v[1].sha1().as_deref(), Some("abcdef"));
        assert_eq!(v[2].rel, "sub dir");
        assert!(v[2].dir);
    }

    #[test]
    fn hrefs_cannot_escape_the_space() {
        assert_eq!(rel_of("/dav/spaces/c43b$bf0c/a/../../x", BASE), None);
        assert_eq!(rel_of("/dav/spaces/c43b$bf0cX/a", BASE), None, "prefix must end at a segment");
        assert_eq!(rel_of("https://cloud.example/dav/spaces/c43b$bf0c/a/b", BASE).as_deref(), Some("a/b"));
    }

    #[test]
    fn item_urls_encode_each_segment() {
        let s = Space {
            id: "x".into(),
            drive_type: "personal".into(),
            name: "n".into(),
            webdav_url: Url::parse("https://cloud.example/dav/spaces/c43b$bf0c").unwrap(),
        };
        let u = Client::item_url(&s, "[OU-TEST] dir/a #1?.txt", false).unwrap();
        assert_eq!(u.as_str(), "https://cloud.example/dav/spaces/c43b$bf0c/[OU-TEST]%20dir/a%20%231%3F.txt");
        assert!(Client::item_url(&s, "a/../b", false).is_err());
        assert_eq!(Client::item_url(&s, "", true).unwrap().as_str(), "https://cloud.example/dav/spaces/c43b$bf0c/");
    }

    #[test]
    fn trash_parsing() {
        let xml = r#"<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
<d:response><d:href>/dav/spaces/trash-bin/sp/</d:href><d:propstat><d:prop/></d:propstat></d:response>
<d:response><d:href>/dav/spaces/trash-bin/sp/k1/</d:href><d:propstat><d:prop><oc:trashbin-original-filename>[OU-TEST] x</oc:trashbin-original-filename>
<oc:trashbin-original-location>[OU-TEST] x</oc:trashbin-original-location></d:prop></d:propstat></d:response></d:multistatus>"#;
        let v = parse_trash(xml, "/dav/spaces/trash-bin/sp/");
        assert_eq!(v, vec![TrashItem { key: "k1".into(), original_name: "[OU-TEST] x".into(), original_location: "[OU-TEST] x".into() }]);
    }

    #[test]
    fn errors_map_to_health() {
        assert_eq!(FilesError::Auth.health(), Health::AuthFailed);
        assert_eq!(FilesError::Offline("x".into()).health(), Health::Offline);
        assert_eq!(FilesError::NotFound.health(), Health::SpaceGone);
        assert!(matches!(FilesError::Status(502).health(), Health::ServerError(_)));
    }

    #[test]
    fn jwt_lifetime_reads_exp() {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let p = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{{\"exp\":{}}}", now + 300));
        let l = jwt_lifetime(&format!("h.{p}.s")).unwrap();
        assert!((298..=300).contains(&l));
        assert_eq!(jwt_lifetime("opaque"), None);
    }

    #[tokio::test]
    async fn cached_token_reuses_until_expiry() {
        struct Count(std::sync::atomic::AtomicU32);
        impl TokenProvider for Count {
            fn access_token(&self) -> Pin<Box<dyn Future<Output = Result<String, FilesError>> + Send + '_>> {
                let n = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Box::pin(async move { Ok(format!("t{n}")) })
            }
        }
        let c = CachedToken::new(Count(Default::default()));
        assert_eq!(c.access_token().await.unwrap(), "t0");
        assert_eq!(c.access_token().await.unwrap(), "t0");
        assert_eq!(c.inner.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn parent_split() {
        assert_eq!(split_parent("a/b/c.txt").unwrap(), ("a/b", "c.txt"));
        assert_eq!(split_parent("c.txt").unwrap(), ("", "c.txt"));
        assert!(split_parent("/").is_err());
    }
}
