//! In-memory event queue for the GUI (`PollEvents` long poll). Bounded: the oldest events are dropped first; a GUI that was away
//! simply re-reads the status. Nothing is persisted, nothing secret is queued.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use ou_core::ipc::{Event, MAX_POLL_MS};
use tokio::sync::Notify;

const CAP: usize = 500;

#[derive(Default)]
pub struct Events {
    inner: Mutex<(u64, VecDeque<(u64, Event)>)>,
    notify: Notify,
}

impl Events {
    pub fn push(&self, e: Event) {
        let mut g = self.inner.lock().unwrap();
        g.0 += 1;
        let seq = g.0;
        g.1.push_back((seq, e));
        while g.1.len() > CAP {
            g.1.pop_front();
        }
        drop(g);
        self.notify.notify_waiters();
    }

    fn after(&self, since: u64) -> (u64, Vec<(u64, Event)>) {
        let g = self.inner.lock().unwrap();
        (g.0, g.1.iter().filter(|(s, _)| *s > since).cloned().collect())
    }

    /// Events with sequence > `since`; waits up to `wait_ms` (capped) when there are none yet.
    pub async fn poll(&self, since: u64, wait_ms: u32) -> (u64, Vec<(u64, Event)>) {
        let wait = Duration::from_millis(wait_ms.min(MAX_POLL_MS) as u64);
        let notified = self.notify.notified();
        let r = self.after(since);
        if !r.1.is_empty() || wait.is_zero() {
            return r;
        }
        let _ = tokio::time::timeout(wait, notified).await;
        self.after(since)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn poll_returns_new_events_and_waits() {
        let ev = std::sync::Arc::new(Events::default());
        assert!(ev.poll(0, 0).await.1.is_empty());
        let e2 = ev.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            e2.push(Event::ChatBadge { account_id: "a".into(), count: 1 });
        });
        let (next, got) = ev.poll(0, 2000).await;
        assert_eq!((next, got.len()), (1, 1));
        assert!(ev.poll(next, 0).await.1.is_empty());
        for i in 0..(CAP + 10) {
            ev.push(Event::ChatBadge { account_id: "a".into(), count: i as u64 });
        }
        assert_eq!(ev.poll(0, 0).await.1.len(), CAP, "bounded");
    }
}
