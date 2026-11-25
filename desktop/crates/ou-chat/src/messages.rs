//! Timeline: history, sending text, replies-free edits and redaction.
//! Encrypted rooms are handled by matrix-sdk (Megolm via vodozemac); messages that cannot be decrypted yet are shown as such,
//! never dropped silently and never sent in the clear.

use matrix_sdk::deserialized_responses::TimelineEvent;
use matrix_sdk::room::MessagesOptions;
use matrix_sdk::ruma::events::room::message::{MessageType, RoomMessageEventContent, SyncRoomMessageEvent};
use matrix_sdk::ruma::events::{AnySyncMessageLikeEvent, AnySyncTimelineEvent};
use matrix_sdk::ruma::{EventId, UInt};
use serde::Serialize;

use crate::media::AttachmentRef;
use crate::{mx, ChatClient, ChatError};

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Body {
    Text { body: String },
    Notice { body: String },
    Emote { body: String },
    File { attachment: AttachmentRef },
    /// Encrypted and no key yet (key backup / another device may provide it later).
    Undecryptable,
    Redacted,
    Other { event_type: String },
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ChatMessage {
    pub event_id: String,
    pub sender: String,
    pub ts_ms: u64,
    pub body: Body,
    pub encrypted: bool,
}

pub(crate) fn from_message_type(m: &MessageType) -> Body {
    match m {
        MessageType::Text(t) => Body::Text { body: t.body.clone() },
        MessageType::Notice(t) => Body::Notice { body: t.body.clone() },
        MessageType::Emote(t) => Body::Emote { body: t.body.clone() },
        MessageType::File(f) => Body::File { attachment: AttachmentRef::new(f.source.clone(), f.filename().to_owned(), f.info.as_ref().and_then(|i| i.mimetype.clone()), f.info.as_ref().and_then(|i| i.size)) },
        MessageType::Image(f) => Body::File { attachment: AttachmentRef::new(f.source.clone(), f.filename().to_owned(), f.info.as_ref().and_then(|i| i.mimetype.clone()), f.info.as_ref().and_then(|i| i.size)) },
        MessageType::Video(f) => Body::File { attachment: AttachmentRef::new(f.source.clone(), f.filename().to_owned(), f.info.as_ref().and_then(|i| i.mimetype.clone()), f.info.as_ref().and_then(|i| i.size)) },
        MessageType::Audio(f) => Body::File { attachment: AttachmentRef::new(f.source.clone(), f.filename().to_owned(), f.info.as_ref().and_then(|i| i.mimetype.clone()), f.info.as_ref().and_then(|i| i.size)) },
        other => Body::Other { event_type: other.msgtype().to_owned() },
    }
}

/// Converts one timeline event; `None` for events the chat view does not show (state, reactions, receipts...).
pub fn to_message(ev: &TimelineEvent) -> Option<ChatMessage> {
    let encrypted = ev.encryption_info().is_some();
    let parsed = ev.raw().deserialize().ok()?;
    let (body, encrypted) = match &parsed {
        AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomMessage(SyncRoomMessageEvent::Original(m))) => {
            if m.content.relates_to.as_ref().is_some_and(|r| matches!(r, matrix_sdk::ruma::events::room::message::Relation::Replacement(_))) {
                return None; // edits are applied by the view through the original event
            }
            (from_message_type(&m.content.msgtype), encrypted)
        }
        AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomMessage(SyncRoomMessageEvent::Redacted(_))) => (Body::Redacted, encrypted),
        AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomEncrypted(_)) => (Body::Undecryptable, true),
        _ => return None,
    };
    Some(ChatMessage {
        event_id: parsed.event_id().to_string(),
        sender: parsed.sender().to_string(),
        ts_ms: u64::from(parsed.origin_server_ts().0),
        body,
        encrypted,
    })
}

impl ChatClient {
    /// The latest `limit` messages, oldest first.
    pub async fn history(&self, room_id: &str, limit: u32) -> Result<Vec<ChatMessage>, ChatError> {
        let room = self.room(room_id)?;
        let mut opts = MessagesOptions::backward();
        opts.limit = UInt::from(limit.min(200));
        let page = room.messages(opts).await.map_err(mx)?;
        let mut out: Vec<_> = page.chunk.iter().filter_map(to_message).collect();
        out.reverse();
        Ok(out)
    }

    /// Sends plain text (encrypted automatically in encrypted rooms). Returns the event id.
    pub async fn send_text(&self, room_id: &str, body: &str) -> Result<String, ChatError> {
        if body.trim().is_empty() {
            return Err(ChatError::Refused("empty message".into()));
        }
        let room = self.room(room_id)?;
        let r = room.send(RoomMessageEventContent::text_plain(body)).await.map_err(mx)?;
        Ok(r.response.event_id.to_string())
    }

    /// Deletes (redacts) one of the user's messages. The server keeps no content of a redacted event.
    pub async fn redact(&self, room_id: &str, event_id: &str, reason: Option<&str>) -> Result<(), ChatError> {
        let room = self.room(room_id)?;
        let id = EventId::parse(event_id).map_err(|_| ChatError::Refused("bad event id".into()))?;
        room.redact(&id, reason, None).await.map(|_| ()).map_err(mx)
    }

    /// Marks everything up to `event_id` as read (read receipt + fully-read marker), clearing the unread counts.
    pub async fn mark_read(&self, room_id: &str, event_id: &str) -> Result<(), ChatError> {
        use matrix_sdk::ruma::api::client::receipt::create_receipt::v3::ReceiptType;
        use matrix_sdk::ruma::events::receipt::ReceiptThread;
        let room = self.room(room_id)?;
        let id = EventId::parse(event_id).map_err(|_| ChatError::Refused("bad event id".into()))?;
        room.send_single_receipt(ReceiptType::Read, ReceiptThread::Unthreaded, id).await.map_err(mx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use matrix_sdk::ruma::serde::Raw;

    fn ev(json: serde_json::Value) -> TimelineEvent {
        TimelineEvent::from_plaintext(Raw::new(&json).unwrap().cast_unchecked())
    }

    #[test]
    fn converts_text_file_encrypted_and_skips_state() {
        let t = to_message(&ev(serde_json::json!({"type":"m.room.message","event_id":"$1","sender":"@a:x","origin_server_ts":5,
            "content":{"msgtype":"m.text","body":"hi"}}))).unwrap();
        assert_eq!(t.body, Body::Text { body: "hi".into() });
        assert_eq!((t.sender.as_str(), t.ts_ms, t.encrypted), ("@a:x", 5, false));

        let f = to_message(&ev(serde_json::json!({"type":"m.room.message","event_id":"$2","sender":"@a:x","origin_server_ts":6,
            "content":{"msgtype":"m.file","body":"report.pdf","url":"mxc://x/abc","info":{"mimetype":"application/pdf","size":12}}}))).unwrap();
        match f.body {
            Body::File { attachment } => {
                assert_eq!(attachment.name, "report.pdf");
                assert_eq!(attachment.size, Some(12));
                assert!(!attachment.encrypted);
            }
            other => panic!("{other:?}"),
        }

        let e = to_message(&ev(serde_json::json!({"type":"m.room.encrypted","event_id":"$3","sender":"@a:x","origin_server_ts":7,
            "content":{"algorithm":"m.megolm.v1.aes-sha2","ciphertext":"AwgA","sender_key":"k","device_id":"D","session_id":"s"}}))).unwrap();
        assert_eq!(e.body, Body::Undecryptable);
        assert!(e.encrypted);

        assert!(to_message(&ev(serde_json::json!({"type":"m.room.topic","state_key":"","event_id":"$4","sender":"@a:x","origin_server_ts":8,"content":{"topic":"t"}}))).is_none());
        let edit = serde_json::json!({"type":"m.room.message","event_id":"$5","sender":"@a:x","origin_server_ts":9,
            "content":{"msgtype":"m.text","body":"* hi2","m.new_content":{"msgtype":"m.text","body":"hi2"},"m.relates_to":{"rel_type":"m.replace","event_id":"$1"}}});
        assert!(to_message(&ev(edit)).is_none());
    }
}
