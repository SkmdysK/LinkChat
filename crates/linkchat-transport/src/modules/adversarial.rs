/// Endpoint label used only by the adversarial harness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AdversaryEndpoint {
    Alice,
    Bob,
}

/// Attack labels are harness observations, not protocol commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttackKind {
    Drop,
    Delay,
    Duplicate,
    Reorder,
    MalformedPacket,
    InvalidAck,
    InvalidSack,
    OldPackageReplay,
    RollbackAttempt,
    MaliciousEndpoint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AttackObservation {
    kind: AttackKind,
    endpoint: Option<AdversaryEndpoint>,
}

impl AttackObservation {
    pub const fn kind(self) -> AttackKind {
        self.kind
    }

    pub const fn endpoint(self) -> Option<AdversaryEndpoint> {
        self.endpoint
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeliveryPlan {
    Normal,
    Drop,
    Delay(u64),
    Duplicate(usize),
    Reorder,
}

struct ScheduledEvent {
    ready_at: TransportTimestamp,
    event: TransportEvent,
}

/// Test-only transport harness for malicious delivery behavior.
///
/// Reordering, retry, duplicate delivery, replay, and malformed control
/// packets are represented as transport events.  Nothing in this harness
/// invokes or mutates `linkchat-core`.
pub struct AdversarialTransportHarness {
    events: VecDeque<ScheduledEvent>,
    plans: VecDeque<DeliveryPlan>,
    reorder_pending: Option<ScheduledEvent>,
    observations: VecDeque<AttackObservation>,
    clock: TransportTimestamp,
    available: bool,
}

impl AdversarialTransportHarness {
    pub fn new() -> Self {
        Self {
            events: VecDeque::new(),
            plans: VecDeque::new(),
            reorder_pending: None,
            observations: VecDeque::new(),
            clock: TransportTimestamp::default(),
            available: true,
        }
    }

    pub fn set_available(&mut self, available: bool) {
        self.available = available;
    }

    pub fn plan_drop(&mut self) {
        self.plans.push_back(DeliveryPlan::Drop);
    }

    pub fn plan_delay(&mut self, ticks: u64) {
        self.plans.push_back(DeliveryPlan::Delay(ticks));
    }

    pub fn plan_duplicate(&mut self, copies: usize) {
        self.plans.push_back(DeliveryPlan::Duplicate(copies.max(1)));
    }

    pub fn plan_reorder(&mut self) {
        self.plans.push_back(DeliveryPlan::Reorder);
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

    pub fn observations(&mut self) -> Vec<AttackObservation> {
        self.observations.drain(..).collect()
    }

    pub fn inject_malformed_packet(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.inject_attack(
            PacketBytes::from_bytes(bytes)?,
            AttackObservation {
                kind: AttackKind::MalformedPacket,
                endpoint: None,
            },
        )
    }

    pub fn inject_invalid_ack(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.inject_attack(
            PacketBytes::from_bytes(bytes)?,
            AttackObservation {
                kind: AttackKind::InvalidAck,
                endpoint: None,
            },
        )
    }

    pub fn inject_invalid_sack(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.inject_attack(
            PacketBytes::from_bytes(bytes)?,
            AttackObservation {
                kind: AttackKind::InvalidSack,
                endpoint: None,
            },
        )
    }

    pub fn replay_old_package(&mut self, package: PacketBytes) -> Result<(), TransportError> {
        self.inject_attack(
            package,
            AttackObservation {
                kind: AttackKind::OldPackageReplay,
                endpoint: None,
            },
        )
    }

    pub fn attempt_rollback(&mut self, old_packet: PacketBytes) -> Result<(), TransportError> {
        self.inject_attack(
            old_packet,
            AttackObservation {
                kind: AttackKind::RollbackAttempt,
                endpoint: None,
            },
        )
    }

    pub fn inject_malicious_endpoint(
        &mut self,
        endpoint: AdversaryEndpoint,
        packet: PacketBytes,
    ) -> Result<(), TransportError> {
        self.inject_attack(
            packet,
            AttackObservation {
                kind: AttackKind::MaliciousEndpoint,
                endpoint: Some(endpoint),
            },
        )
    }

    fn inject_attack(
        &mut self,
        packet: PacketBytes,
        observation: AttackObservation,
    ) -> Result<(), TransportError> {
        if !self.available {
            return Err(TransportError::Unavailable);
        }
        self.observations.push_back(observation);
        self.events.push_back(ScheduledEvent {
            ready_at: self.clock,
            event: TransportEvent::new(
                packet,
                DeliveryStatus::Rejected,
                self.clock,
                RetryMetadata::new(0, false),
            ),
        });
        Ok(())
    }

    fn enqueue_planned(&mut self, packet: PacketBytes) -> Result<(), TransportError> {
        let plan = self.plans.pop_front().unwrap_or(DeliveryPlan::Normal);
        let (ready_at, copies, reorder, kind) = match plan {
            DeliveryPlan::Normal => (self.clock, 1, false, None),
            DeliveryPlan::Drop => {
                let observation = AttackObservation {
                    kind: AttackKind::Drop,
                    endpoint: None,
                };
                self.observations.push_back(observation);
                return Ok(());
            }
            DeliveryPlan::Delay(ticks) => {
                let ready_at = self
                    .clock
                    .ticks()
                    .checked_add(ticks)
                    .ok_or(TransportError::DelayOverflow)?;
                (
                    TransportTimestamp::new(ready_at),
                    1,
                    false,
                    Some(AttackObservation {
                        kind: AttackKind::Delay,
                        endpoint: None,
                    }),
                )
            }
            DeliveryPlan::Duplicate(copies) => (
                self.clock,
                copies,
                false,
                Some(AttackObservation {
                    kind: AttackKind::Duplicate,
                    endpoint: None,
                }),
            ),
            DeliveryPlan::Reorder => (
                self.clock,
                1,
                true,
                Some(AttackObservation {
                    kind: AttackKind::Reorder,
                    endpoint: None,
                }),
            ),
        };
        if let Some(kind) = kind {
            self.observations.push_back(kind);
        }
        let mut scheduled_events = Vec::with_capacity(copies);
        for index in 0..copies {
            let event = TransportEvent::new(
                packet.clone(),
                DeliveryStatus::Accepted,
                self.clock,
                RetryMetadata::new(index as u32, index > 0),
            );
            scheduled_events.push(ScheduledEvent { ready_at, event });
        }
        if reorder {
            self.reorder_pending = scheduled_events.into_iter().next();
        } else {
            for scheduled in scheduled_events {
                self.events.push_back(scheduled);
            }
            if let Some(pending) = self.reorder_pending.take() {
                self.events.push_back(pending);
            }
        }
        Ok(())
    }

    fn pop_ready(&mut self) -> Option<TransportEvent> {
        let index = self
            .events
            .iter()
            .position(|scheduled| scheduled.ready_at.ticks() <= self.clock.ticks())?;
        let scheduled = self.events.remove(index)?;
        Some(scheduled.event)
    }
}

impl Default for AdversarialTransportHarness {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for AdversarialTransportHarness {
    type Error = TransportError;

    fn send(&mut self, packet: PacketBytes) -> Result<(), Self::Error> {
        if !self.available {
            return Err(TransportError::Unavailable);
        }
        self.enqueue_planned(packet)
    }

    fn receive(&mut self) -> Result<Option<TransportEvent>, Self::Error> {
        if !self.available {
            return Err(TransportError::Unavailable);
        }
        Ok(self.pop_ready())
    }
}
use crate::foundation::*;
use linkchat_protocol::DeliveryStatus;
use std::collections::VecDeque;
