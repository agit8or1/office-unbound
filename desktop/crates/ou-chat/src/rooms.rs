//! Room list with unread counts, favourites, create / leave / forget.

use matrix_sdk::ruma::api::client::room::create_room::v3::{Request as CreateRoomRequest, RoomPreset};
use matrix_sdk::ruma::events::room::encryption::RoomEncryptionEventContent;
use matrix_sdk::ruma::events::InitialStateEvent;
use matrix_sdk::ruma::{OwnedRoomId, RoomId};
use matrix_sdk::{Room, RoomState};
use serde::Serialize;

use crate::{mx, ChatClient, ChatError};

/// What the room list shows. Serializable for the GUI (IPC).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RoomSummary {
    pub room_id: String,
    pub name: String,
    pub is_direct: bool,
    pub encrypted: bool,
    pub favourite: bool,
    pub low_priority: bool,
    /// Server-side push counts (respect the user's push rules, e.g. muted rooms count 0).
    pub notifications: u64,
    pub highlights: u64,
    /// Client-side count of unread messages (also for encrypted rooms, after decryption).
    pub unread_messages: u64,
    pub invited: bool,
}

impl RoomSummary {
    pub async fn of(room: &Room) -> Self {
        let counts = room.unread_notification_counts();
        let name = match room.display_name().await {
            Ok(n) => n.to_string(),
            Err(_) => room.room_id().to_string(),
        };
        Self {
            room_id: room.room_id().to_string(),
            name,
            is_direct: room.is_direct().await.unwrap_or(false),
            encrypted: room.encryption_state().is_encrypted(),
            favourite: room.is_favourite(),
            low_priority: room.is_low_priority(),
            notifications: counts.notification_count,
            highlights: counts.highlight_count,
            unread_messages: room.num_unread_messages(),
            invited: room.state() == RoomState::Invited,
        }
    }
}

/// Teams-like ordering: favourites first, then rooms with highlights, then unread, then by name.
pub fn sort_for_list(rooms: &mut [RoomSummary]) {
    rooms.sort_by(|a, b| {
        b.favourite
            .cmp(&a.favourite)
            .then(a.low_priority.cmp(&b.low_priority))
            .then((b.highlights > 0).cmp(&(a.highlights > 0)))
            .then((b.unread_messages > 0 || b.notifications > 0).cmp(&(a.unread_messages > 0 || a.notifications > 0)))
            .then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
}

/// Total for the tray badge: the push counts, so muted rooms (push rule "dont_notify") add nothing.
pub fn badge_count(rooms: &[RoomSummary]) -> u64 {
    rooms.iter().map(|r| r.notifications).sum()
}

impl ChatClient {
    /// Joined and invited rooms, sorted for display.
    pub async fn rooms(&self) -> Vec<RoomSummary> {
        let mut out = Vec::new();
        for r in self.client.joined_rooms().into_iter().chain(self.client.invited_rooms()) {
            out.push(RoomSummary::of(&r).await);
        }
        sort_for_list(&mut out);
        out
    }

    pub fn room(&self, room_id: &str) -> Result<Room, ChatError> {
        let id = RoomId::parse(room_id).map_err(|_| ChatError::NoSuchRoom)?;
        self.client.get_room(&id).ok_or(ChatError::NoSuchRoom)
    }

    /// Creates a private room. `encrypted` defaults to true in the GUI; ou-chat never turns encryption off in an existing room.
    pub async fn create_room(&self, name: &str, encrypted: bool, invite: &[String]) -> Result<OwnedRoomId, ChatError> {
        let mut req = CreateRoomRequest::new();
        req.name = Some(name.to_owned());
        req.preset = Some(RoomPreset::PrivateChat);
        req.invite = invite.iter().filter_map(|u| u.parse().ok()).collect();
        if encrypted {
            req.initial_state = vec![InitialStateEvent::with_empty_state_key(RoomEncryptionEventContent::with_recommended_defaults()).to_raw_any()];
        }
        let room = self.client.create_room(req).await.map_err(mx)?;
        Ok(room.room_id().to_owned())
    }

    pub async fn set_favourite(&self, room_id: &str, on: bool) -> Result<(), ChatError> {
        self.room(room_id)?.set_is_favourite(on, None).await.map_err(mx)
    }

    /// Leaves and forgets a room (it disappears from the list and the local store).
    pub async fn leave_and_forget(&self, room_id: &str) -> Result<(), ChatError> {
        let room = self.room(room_id)?;
        if room.state() != RoomState::Left {
            room.leave().await.map_err(mx)?;
        }
        let room = self.room(room_id)?;
        room.forget().await.map_err(mx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(name: &str, fav: bool, hl: u64, unread: u64) -> RoomSummary {
        RoomSummary {
            room_id: format!("!{name}:x"),
            name: name.into(),
            is_direct: false,
            encrypted: true,
            favourite: fav,
            low_priority: false,
            notifications: unread,
            highlights: hl,
            unread_messages: unread,
            invited: false,
        }
    }

    #[test]
    fn ordering() {
        let mut v = vec![r("zeta", false, 0, 0), r("alpha", false, 0, 0), r("mention", false, 1, 1), r("fav", true, 0, 0), r("unread", false, 0, 3)];
        sort_for_list(&mut v);
        let names: Vec<_> = v.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, ["fav", "mention", "unread", "alpha", "zeta"]);
        assert_eq!(badge_count(&v), 4);
    }
}
