//! Desktop-notification hook. matrix-sdk evaluates the user's push rules (mentions, keywords, muted rooms, DMs) on every synced
//! event, after decryption, and calls us only for events that should notify. The GUI implements [`Notifier`] with Windows toast
//! notifications; the agent can implement it to update the tray badge.

use std::sync::Arc;

use matrix_sdk::ruma::events::room::message::SyncRoomMessageEvent;
use matrix_sdk::ruma::events::{AnySyncMessageLikeEvent, AnySyncTimelineEvent};
use matrix_sdk::ruma::push::Action;
use matrix_sdk::deserialized_responses::RawAnySyncOrStrippedTimelineEvent;
use matrix_sdk::sync::Notification;
use matrix_sdk::Room;
use serde::Serialize;

use crate::messages::{from_message_type, Body};
use crate::ChatClient;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ChatNotification {
    pub room_id: String,
    pub room_name: String,
    pub sender: String,
    /// Short preview (at most 140 characters). `None` when the event is not a readable message (e.g. undecryptable).
    pub preview: Option<String>,
    /// A mention or keyword (push rule `highlight` tweak).
    pub highlight: bool,
    /// The push rule asked for a sound.
    pub sound: bool,
    pub invite: bool,
}

/// Implemented by the GUI/agent. Must not block: hand the notification to the UI thread and return.
pub trait Notifier: Send + Sync {
    fn notify(&self, n: ChatNotification);
}

pub fn preview(body: &Body) -> Option<String> {
    let s = match body {
        Body::Text { body } | Body::Notice { body } | Body::Emote { body } => body.clone(),
        Body::File { attachment } => format!("Sent a file: {}", attachment.name),
        _ => return None,
    };
    let one_line: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    Some(if one_line.chars().count() > 140 { one_line.chars().take(139).collect::<String>() + "\u{2026}" } else { one_line })
}

/// Builds the notification from what the SDK hands us; `None` when push rules say not to notify.
pub fn build(actions: &[Action], event: &RawAnySyncOrStrippedTimelineEvent, room_id: &str, room_name: &str) -> Option<ChatNotification> {
    if !actions.iter().any(|a| a.should_notify()) {
        return None;
    }
    let highlight = actions.iter().any(|a| a.is_highlight());
    let sound = actions.iter().any(|a| a.sound().is_some());
    match event {
        RawAnySyncOrStrippedTimelineEvent::Sync(raw) => {
            let ev = raw.deserialize().ok()?;
            let preview = match &ev {
                AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomMessage(SyncRoomMessageEvent::Original(m))) => preview(&from_message_type(&m.content.msgtype)),
                _ => None,
            };
            Some(ChatNotification { room_id: room_id.into(), room_name: room_name.into(), sender: ev.sender().to_string(), preview, highlight, sound, invite: false })
        }
        RawAnySyncOrStrippedTimelineEvent::Stripped(raw) => {
            let ev = raw.deserialize().ok()?;
            Some(ChatNotification { room_id: room_id.into(), room_name: room_name.into(), sender: ev.sender().to_string(), preview: None, highlight, sound, invite: true })
        }
    }
}

impl ChatClient {
    /// Registers the desktop notifier. Own messages never notify (default push rule `.m.rule.master`/sender checks in the SDK).
    pub async fn register_notifier(&self, notifier: Arc<dyn Notifier>) {
        self.client
            .register_notification_handler(move |n: Notification, room: Room, _| {
                let notifier = notifier.clone();
                async move {
                    let name = room.display_name().await.map(|d| d.to_string()).unwrap_or_else(|_| room.room_id().to_string());
                    if let Some(cn) = build(&n.actions, &n.event, room.room_id().as_str(), &name) {
                        notifier.notify(cn);
                    }
                }
            })
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use matrix_sdk::ruma::push::Tweak;
    use matrix_sdk::ruma::serde::Raw;

    fn sync_ev(body: &str) -> RawAnySyncOrStrippedTimelineEvent {
        let j = serde_json::json!({"type":"m.room.message","event_id":"$1","sender":"@b:x","origin_server_ts":1,"content":{"msgtype":"m.text","body":body}});
        RawAnySyncOrStrippedTimelineEvent::Sync(Raw::new(&j).unwrap().cast_unchecked())
    }

    #[test]
    fn respects_push_actions() {
        assert!(build(&[], &sync_ev("hi"), "!r:x", "Team").is_none(), "no notify action -> nothing");
        let n = build(&[Action::Notify, Action::SetTweak(Tweak::Highlight(matrix_sdk::ruma::push::HighlightTweakValue::Yes)), Action::SetTweak(Tweak::Sound("default".into()))], &sync_ev("hey @doc"), "!r:x", "Team").unwrap();
        assert!(n.highlight && n.sound && !n.invite);
        assert_eq!(n.preview.as_deref(), Some("hey @doc"));
        assert_eq!(n.sender, "@b:x");
        let plain = build(&[Action::Notify], &sync_ev("a\n\nb"), "!r:x", "Team").unwrap();
        assert!(!plain.highlight && !plain.sound);
        assert_eq!(plain.preview.as_deref(), Some("a b"));
    }

    #[test]
    fn preview_is_bounded() {
        let p = preview(&Body::Text { body: "x".repeat(500) }).unwrap();
        assert_eq!(p.chars().count(), 140);
        assert!(preview(&Body::Undecryptable).is_none());
    }
}
