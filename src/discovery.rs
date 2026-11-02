//! Presence tracking uses fresh events, never a backend's accumulated scan cache.
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

pub const BLE_EXPIRY: Duration = Duration::from_secs(15);

struct Entry<T> {
    value: T,
    advertised: Option<Instant>,
    system: Option<Instant>,
}
pub struct Nearby<T> {
    entries: BTreeMap<String, Entry<T>>,
}
impl<T> Default for Nearby<T> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }
}
impl<T> Nearby<T> {
    pub fn get(&self, id: &str) -> Option<&T> {
        self.entries.get(id).map(|e| &e.value)
    }
    pub fn advertised(&mut self, id: String, value: T, now: Instant) {
        match self.entries.entry(id) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                entry.get_mut().value = value;
                entry.get_mut().advertised = Some(now);
            }
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(Entry {
                    value,
                    advertised: Some(now),
                    system: None,
                });
            }
        }
    }
    pub fn system_snapshot(&mut self, values: impl IntoIterator<Item = (String, T)>, now: Instant) {
        for entry in self.entries.values_mut() {
            entry.system = None;
        }
        for (id, value) in values {
            match self.entries.entry(id) {
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    entry.get_mut().value = value;
                    entry.get_mut().system = Some(now);
                }
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(Entry {
                        value,
                        advertised: None,
                        system: Some(now),
                    });
                }
            }
        }
    }
    pub fn expire(&mut self, now: Instant) {
        self.entries.retain(|_, entry| {
            [entry.advertised, entry.system]
                .into_iter()
                .flatten()
                .any(|at| now.saturating_duration_since(at) < BLE_EXPIRY)
        });
    }
    pub fn current(&self, now: Instant) -> impl Iterator<Item = (&T, bool)> {
        self.entries.values().map(move |e| {
            (
                &e.value,
                e.system
                    .is_some_and(|at| now.saturating_duration_since(at) < BLE_EXPIRY),
            )
        })
    }
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn advertisements_expire_unless_a_fresh_event_arrives() {
        let now = Instant::now();
        let mut nearby = Nearby::default();
        nearby.advertised("a".into(), 1, now);
        nearby.expire(now + BLE_EXPIRY - Duration::from_secs(1));
        assert_eq!(nearby.current(now).count(), 1);
        // Reading an accumulated backend cache must not renew presence.
        assert_eq!(nearby.get("a"), Some(&1));
        nearby.expire(now + BLE_EXPIRY);
        assert_eq!(nearby.current(now).count(), 0);
        nearby.advertised("a".into(), 3, now + BLE_EXPIRY);
        assert_eq!(nearby.current(now + BLE_EXPIRY).count(), 1);
    }
    #[test]
    fn connected_devices_need_no_advertisement_and_disappear_when_removed() {
        let now = Instant::now();
        let mut nearby = Nearby::default();
        nearby.system_snapshot([("a".into(), 1)], now);
        assert_eq!(nearby.current(now).collect::<Vec<_>>(), vec![(&1, true)]);
        nearby.system_snapshot([], now + Duration::from_secs(2));
        nearby.expire(now + Duration::from_secs(2));
        assert_eq!(nearby.current(now).count(), 0);
        nearby.system_snapshot([("a".into(), 1)], now);
        // A failed system lookup supplies no replacement snapshot; stale presence still expires.
        nearby.expire(now + BLE_EXPIRY);
        assert_eq!(nearby.current(now + BLE_EXPIRY).count(), 0);
    }
    #[test]
    fn overlapping_sources_deduplicate_and_system_failures_eventually_expire() {
        let now = Instant::now();
        let mut nearby = Nearby::default();
        nearby.advertised("a".into(), 1, now);
        nearby.system_snapshot([("a".into(), 2)], now);
        assert_eq!(nearby.current(now).count(), 1);
        nearby.system_snapshot([], now + Duration::from_secs(2));
        nearby.expire(now + Duration::from_secs(2));
        assert_eq!(nearby.current(now).collect::<Vec<_>>(), vec![(&2, false)]);
        nearby.expire(now + BLE_EXPIRY);
        assert_eq!(nearby.current(now).count(), 0);
    }
}
