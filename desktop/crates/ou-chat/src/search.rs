//! Message search through the homeserver (`POST /search`). Synapse can only search rooms it can read: **unencrypted** rooms.
//! Encrypted rooms need a local index on the device (matrix-sdk `experimental-search`, tantivy); that is not enabled yet
//! (binary size, index encryption at rest not reviewed). Results say which rooms were not searched.

use matrix_sdk::ruma::api::client::filter::RoomEventFilter;
use matrix_sdk::ruma::api::client::search::search_events::v3::{Categories, Criteria, Request};
use matrix_sdk::ruma::events::room::message::SyncRoomMessageEvent;
use matrix_sdk::ruma::events::{AnySyncMessageLikeEvent, AnySyncTimelineEvent, AnyTimelineEvent};
use matrix_sdk::ruma::OwnedRoomId;
use serde::Serialize;

use crate::messages::{from_message_type, Body};
use crate::{mx, ChatClient, ChatError};

#[derive(Debug, Clone, Serialize)]
pub struct SearchHit {
    pub room_id: String,
    pub event_id: String,
    pub sender: String,
    pub ts_ms: u64,
    pub body: Body,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchResult {
    pub hits: Vec<SearchHit>,
    pub total: Option<u64>,
    /// Encrypted rooms the server cannot search.
    pub not_searched: Vec<String>,
}

pub(crate) fn hit_of(ev: &AnyTimelineEvent) -> Option<SearchHit> {
    let room_id = ev.room_id().to_string();
    let sync: AnySyncTimelineEvent = ev.clone().into();
    match &sync {
        AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomMessage(SyncRoomMessageEvent::Original(m))) => Some(SearchHit {
            room_id,
            event_id: m.event_id.to_string(),
            sender: m.sender.to_string(),
            ts_ms: u64::from(m.origin_server_ts.0),
            body: from_message_type(&m.content.msgtype),
        }),
        _ => None,
    }
}

impl ChatClient {
    /// Full-text search in the given rooms (all joined rooms when empty).
    pub async fn search(&self, term: &str, rooms: &[String]) -> Result<SearchResult, ChatError> {
        let term = term.trim();
        if term.is_empty() || term.len() > 256 {
            return Err(ChatError::Refused("search term must be 1..256 characters".into()));
        }
        let candidates: Vec<_> = if rooms.is_empty() {
            self.client.joined_rooms()
        } else {
            rooms.iter().map(|r| self.room(r)).collect::<Result<_, _>>()?
        };
        let (enc, plain): (Vec<_>, Vec<_>) = candidates.into_iter().partition(|r| r.encryption_state().is_encrypted());
        let not_searched = enc.iter().map(|r| r.room_id().to_string()).collect();
        if plain.is_empty() {
            return Ok(SearchResult { hits: vec![], total: Some(0), not_searched });
        }
        let ids: Vec<OwnedRoomId> = plain.iter().map(|r| r.room_id().to_owned()).collect();
        let mut filter = RoomEventFilter::default();
        filter.rooms = Some(ids);
        let mut crit = Criteria::new(term.to_owned());
        crit.filter = filter;
        let mut cats = Categories::new();
        cats.room_events = Some(crit);
        let resp = self.client.send(Request::new(cats)).await.map_err(mx)?;
        let re = resp.search_categories.room_events;
        let hits = re.results.iter().filter_map(|r| r.result.as_ref()?.deserialize().ok()).filter_map(|e| hit_of(&e)).collect();
        Ok(SearchResult { hits, total: re.count.map(u64::from), not_searched })
    }
}
