use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use super::foundation::HandleEntry;

pub(crate) struct HandleRegistry {
    next: u64,
    entries: HashMap<u64, HandleEntry>,
}

impl HandleRegistry {
    fn new() -> Self {
        Self {
            next: 1,
            entries: HashMap::new(),
        }
    }

    pub(crate) fn insert(&mut self, entry: HandleEntry) -> Result<u64, ()> {
        for _ in 0..u64::MAX {
            let handle = self.next;
            self.next = self.next.checked_add(1).unwrap_or(1);
            if handle != 0 && !self.entries.contains_key(&handle) {
                self.entries.insert(handle, entry);
                return Ok(handle);
            }
        }
        Err(())
    }

    pub(crate) fn remove(&mut self, handle: u64) -> Option<HandleEntry> {
        self.entries.remove(&handle)
    }

    pub(crate) fn get(&self, handle: u64) -> Option<&HandleEntry> {
        self.entries.get(&handle)
    }

    pub(crate) fn get_mut(&mut self, handle: u64) -> Option<&mut HandleEntry> {
        self.entries.get_mut(&handle)
    }

    pub(crate) fn remove_endpoint_children(&mut self, endpoint: u64) {
        self.entries.retain(|_, entry| {
            !matches!(
                entry,
                HandleEntry::PreparedSend { endpoint: owner, .. }
                    | HandleEntry::PreparedReceive { endpoint: owner, .. }
                    if *owner == endpoint
            )
        });
    }

    pub(crate) fn restore(&mut self, handle: u64, entry: HandleEntry) {
        self.entries.insert(handle, entry);
    }
}

pub(crate) fn registry() -> &'static Mutex<HandleRegistry> {
    static REGISTRY: OnceLock<Mutex<HandleRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HandleRegistry::new()))
}
