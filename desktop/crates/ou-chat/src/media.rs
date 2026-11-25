//! Attachments. In encrypted rooms matrix-sdk encrypts the file (AES-CTR, key in the event) before upload, and decrypts on
//! download; the server only ever stores ciphertext. Downloads use authenticated media (Synapse `enable_authenticated_media`).

use std::path::{Path, PathBuf};

use matrix_sdk::attachment::AttachmentConfig;
use matrix_sdk::media::{MediaFormat, MediaRequestParameters};
use matrix_sdk::ruma::events::room::MediaSource;
use matrix_sdk::ruma::UInt;
use serde::{Deserialize, Serialize};

use crate::{mx, ChatClient, ChatError};

/// A file in a message. `source` is opaque to the GUI (an mxc URL, or an encrypted-file descriptor with the key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentRef {
    pub name: String,
    pub mime: Option<String>,
    pub size: Option<u64>,
    pub encrypted: bool,
    #[serde(skip_serializing)]
    pub source: Option<MediaSource>,
}

impl PartialEq for AttachmentRef {
    fn eq(&self, o: &Self) -> bool {
        (&self.name, &self.mime, self.size, self.encrypted) == (&o.name, &o.mime, o.size, o.encrypted)
            && serde_json::to_value(&self.source).ok() == serde_json::to_value(&o.source).ok()
    }
}

impl AttachmentRef {
    pub fn new(source: MediaSource, name: String, mime: Option<String>, size: Option<UInt>) -> Self {
        let encrypted = matches!(source, MediaSource::Encrypted(_));
        Self { name, mime, size: size.map(u64::from), encrypted, source: Some(source) }
    }
}

/// MIME type from the file extension (the GUI may pass a better one from the OS). Unknown -> application/octet-stream.
pub fn guess_mime(name: &str) -> &'static str {
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "pdf" => "application/pdf",
        "txt" | "log" => "text/plain",
        "csv" => "text/csv",
        "zip" => "application/zip",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "odt" => "application/vnd.oasis.opendocument.text",
        "mp4" => "video/mp4",
        "mp3" => "audio/mpeg",
        _ => "application/octet-stream",
    }
}

/// A name that is safe to create in a Windows folder: no path parts, no reserved names or characters, bounded length.
pub fn safe_file_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let mut s: String = base.chars().map(|c| if c.is_control() || "<>:\"|?*".contains(c) { '_' } else { c }).collect();
    s = s.trim_matches([' ', '.']).to_owned();
    if s.chars().count() > 120 {
        let (stem, ext) = match s.rsplit_once('.') {
            Some((a, b)) if b.len() <= 10 => (a.to_owned(), format!(".{b}")),
            _ => (s.clone(), String::new()),
        };
        let head: String = stem.chars().take(120 - ext.len()).collect();
        s = format!("{head}{ext}");
    }
    if s.is_empty() || ou_core::safety::windows_name_problem(&s).is_some() {
        s = format!("attachment-{s}");
        if ou_core::safety::windows_name_problem(&s).is_some() || s == "attachment-" {
            s = "attachment".into();
        }
    }
    s
}

/// `dir/name`, or `dir/name (1).ext` ... if it exists. Never overwrites a file.
pub fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let name = safe_file_name(name);
    let p = dir.join(&name);
    if !p.exists() {
        return p;
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((a, b)) if !a.is_empty() => (a.to_owned(), format!(".{b}")),
        _ => (name.clone(), String::new()),
    };
    (1..10_000).map(|i| dir.join(format!("{stem} ({i}){ext}"))).find(|p| !p.exists()).unwrap_or_else(|| dir.join(format!("{stem} ({}){ext}", ou_core::oidc::random_token(4))))
}

impl ChatClient {
    /// Server upload limit (`m.upload.size`), cached by the SDK.
    pub async fn max_upload(&self) -> Result<u64, ChatError> {
        self.client.load_or_fetch_max_upload_size().await.map(u64::from).map_err(mx)
    }

    /// Sends a file to the room. Checked against the server's limit first so the user gets a clear message.
    pub async fn send_file(&self, room_id: &str, name: &str, mime: Option<&str>, data: Vec<u8>) -> Result<String, ChatError> {
        let limit = self.max_upload().await?;
        if data.len() as u64 > limit {
            return Err(ChatError::TooLarge { limit });
        }
        let name = safe_file_name(name);
        let mime: mime::Mime = mime.unwrap_or_else(|| guess_mime(&name)).parse().unwrap_or(mime::APPLICATION_OCTET_STREAM);
        let room = self.room(room_id)?;
        let r = room.send_attachment(&name, &mime, data, AttachmentConfig::new()).await.map_err(mx)?;
        Ok(r.event_id.to_string())
    }

    /// The attachment of a message, looked up by event id (the GUI only knows ids: media sources and file keys stay in the agent).
    pub async fn attachment_of(&self, room_id: &str, event_id: &str) -> Result<AttachmentRef, ChatError> {
        let room = self.room(room_id)?;
        let id = matrix_sdk::ruma::EventId::parse(event_id).map_err(|_| ChatError::Refused("bad event id".into()))?;
        let ev = room.event(&id, None).await.map_err(mx)?;
        match crate::messages::to_message(&ev).map(|m| m.body) {
            Some(crate::messages::Body::File { attachment }) => Ok(attachment),
            _ => Err(ChatError::Refused("message has no attachment".into())),
        }
    }

    /// Downloads (and, for encrypted rooms, decrypts) an attachment.
    pub async fn download(&self, a: &AttachmentRef) -> Result<Vec<u8>, ChatError> {
        let source = a.source.clone().ok_or_else(|| ChatError::Refused("attachment has no source".into()))?;
        let req = MediaRequestParameters { source, format: MediaFormat::File };
        self.client.media().get_media_content(&req, true).await.map_err(mx)
    }

    /// Downloads into `dir` under a safe, unique name and returns the path. Writes to a temporary name first.
    pub async fn download_to(&self, a: &AttachmentRef, dir: &Path) -> Result<PathBuf, ChatError> {
        let bytes = self.download(a).await?;
        let target = unique_path(dir, &a.name);
        let tmp = dir.join(format!(".ou-part-{}", ou_core::oidc::random_token(6)));
        std::fs::write(&tmp, &bytes).map_err(|e| ChatError::Refused(format!("could not save: {e}")))?;
        if let Err(e) = std::fs::rename(&tmp, &target) {
            let _ = std::fs::remove_file(&tmp);
            return Err(ChatError::Refused(format!("could not save: {e}")));
        }
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(safe_file_name("..\\..\\Windows\\evil.exe"), "evil.exe");
        assert_eq!(safe_file_name("a/b/c.txt"), "c.txt");
        assert_eq!(safe_file_name("CON"), "attachment-CON");
        assert_eq!(safe_file_name("con.txt"), "attachment-con.txt");
        assert_eq!(safe_file_name("we?ird:na*me.pdf"), "we_ird_na_me.pdf");
        assert_eq!(safe_file_name("trailing. . "), "trailing");
        assert_eq!(safe_file_name(""), "attachment");
        assert_eq!(safe_file_name(".."), "attachment");
        let long = format!("{}.docx", "x".repeat(300));
        let s = safe_file_name(&long);
        assert!(s.ends_with(".docx") && s.chars().count() == 120, "{s}");
    }

    #[test]
    fn mime() {
        assert_eq!(guess_mime("Report.PDF"), "application/pdf");
        assert_eq!(guess_mime("noext"), "application/octet-stream");
    }

    #[test]
    fn unique_never_overwrites() {
        let d = std::env::temp_dir().join(format!("ou-chat-test-{}", ou_core::oidc::random_token(6)));
        std::fs::create_dir_all(&d).unwrap();
        let a = unique_path(&d, "f.txt");
        std::fs::write(&a, b"1").unwrap();
        let b = unique_path(&d, "f.txt");
        assert_eq!(b.file_name().unwrap(), "f (1).txt");
        std::fs::remove_dir_all(&d).unwrap();
    }
}
