/// A test-only FIFO transport with explicit availability and logical time.
pub struct InMemoryTransport {
    events: VecDeque<TransportEvent>,
    clock: TransportTimestamp,
    available: bool,
}

impl InMemoryTransport {
    pub fn new() -> Self {
        Self {
            events: VecDeque::new(),
            clock: TransportTimestamp::default(),
            available: true,
        }
    }

    pub fn set_available(&mut self, available: bool) {
        self.available = available;
    }

    pub const fn is_available(&self) -> bool {
        self.available
    }

    pub const fn now(&self) -> TransportTimestamp {
        self.clock
    }

    pub fn advance_time(&mut self, ticks: u64) -> Result<(), TransportError> {
        self.clock = TransportTimestamp::new(
            self.clock
                .ticks()
                .checked_add(ticks)
                .ok_or(TransportError::DelayOverflow)?,
        );
        Ok(())
    }

    pub fn inject_event(&mut self, event: TransportEvent) -> Result<(), TransportError> {
        if !self.available {
            return Err(TransportError::Unavailable);
        }
        self.events.push_back(event);
        Ok(())
    }

    pub fn queued_events(&self) -> usize {
        self.events.len()
    }
}

impl Default for InMemoryTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for InMemoryTransport {
    type Error = TransportError;

    fn send(&mut self, packet: PacketBytes) -> Result<(), Self::Error> {
        if !self.available {
            return Err(TransportError::Unavailable);
        }
        self.events.push_back(TransportEvent::new(
            packet,
            DeliveryStatus::Accepted,
            self.clock,
            RetryMetadata::default(),
        ));
        Ok(())
    }

    fn receive(&mut self) -> Result<Option<TransportEvent>, Self::Error> {
        if !self.available {
            return Err(TransportError::Unavailable);
        }
        Ok(self.events.pop_front())
    }
}
use crate::foundation::*;
use linkchat_protocol::DeliveryStatus;
use std::collections::VecDeque;
