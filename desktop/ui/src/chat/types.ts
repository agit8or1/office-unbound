// Chat payloads the agent sends to the GUI (mirror of the Serialize types in desktop/crates/ou-chat). Type contract only:
// no UI framework is chosen yet, and this file is not compiled or tested. Tokens never appear in these types.

export interface RoomSummary {
  room_id: string;
  name: string;
  is_direct: boolean;
  encrypted: boolean;
  favourite: boolean;
  low_priority: boolean;
  /** server push counts (muted rooms: 0) */
  notifications: number;
  highlights: number;
  /** client-side unread messages, also in encrypted rooms */
  unread_messages: number;
  invited: boolean;
}

export interface AttachmentRef {
  name: string;
  mime: string | null;
  size: number | null;
  encrypted: boolean;
}

export type Body =
  | { kind: "text"; body: string }
  | { kind: "notice"; body: string }
  | { kind: "emote"; body: string }
  | { kind: "file"; attachment: AttachmentRef }
  | { kind: "undecryptable" }
  | { kind: "redacted" }
  | { kind: "other"; event_type: string };

export interface ChatMessage {
  event_id: string;
  sender: string;
  ts_ms: number;
  body: Body;
  encrypted: boolean;
}

export interface ChatNotification {
  room_id: string;
  room_name: string;
  sender: string;
  /** at most 140 characters; null when not readable */
  preview: string | null;
  highlight: boolean;
  sound: boolean;
  invite: boolean;
}

export interface SearchHit {
  room_id: string;
  event_id: string;
  sender: string;
  ts_ms: number;
  body: Body;
}

export interface SearchResult {
  hits: SearchHit[];
  total: number | null;
  /** encrypted rooms the server cannot search */
  not_searched: string[];
}

export type Recovery = "unknown" | "enabled" | "incomplete" | "disabled";
