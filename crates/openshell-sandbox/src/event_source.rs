// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The in-pod [`EventSource`] interface (RFC 0012 runtime contract).
//!
//! Adapts the orchestrator's denial channel (fed by the proxy and the bypass
//! monitor) into the placement-neutral [`BoundaryEvent`] stream the contract
//! exposes. A delegated backend would instead forward its guest-side events;
//! the orchestrator drains either identically.
//!
//! The in-pod denial channel is single-consumer, so a second
//! [`subscribe`](EventSource::subscribe) returns an explicit error rather than a
//! silently empty stream.
//!
//! Adoption note: the live denial/activity aggregators still consume the rich
//! [`DenialEvent`]/`ActivityEvent` channels directly, because `BoundaryEvent`
//! is lossier than those types (it carries no binary/ancestor/L7 detail that
//! the proposal flow uses). The in-pod `events()` source therefore carries
//! boundary-lifecycle events natively; unifying denial/activity onto
//! `EventSource` requires enriching `BoundaryEvent`. See the POC handoff.

use std::sync::Mutex;

use openshell_core::denial::DenialEvent;
use openshell_isolation::contract::{BackendError, BoundaryEvent, EventSource, EventStream};
use tokio::sync::mpsc::UnboundedReceiver;

/// In-pod event source over a backend-fed [`BoundaryEvent`] receiver.
///
/// Single-consumer, mirroring how the orchestrator owns the one receiver: a
/// second `subscribe` returns an explicit error.
pub struct InPodEvents {
    /// Taken on the first `subscribe`.
    rx: Mutex<Option<UnboundedReceiver<BoundaryEvent>>>,
}

impl InPodEvents {
    /// Wrap a backend-fed [`BoundaryEvent`] receiver as an [`EventSource`].
    #[must_use]
    pub fn new(rx: UnboundedReceiver<BoundaryEvent>) -> Self {
        Self {
            rx: Mutex::new(Some(rx)),
        }
    }
}

impl EventSource for InPodEvents {
    fn subscribe(&self) -> Result<EventStream, BackendError> {
        let Some(rx) = self.rx.lock().expect("InPodEvents rx lock").take() else {
            return Err(BackendError::Process(
                "in-pod event source is single-consumer; already subscribed".to_string(),
            ));
        };
        Ok(Box::pin(futures::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|event| (event, rx))
        })))
    }
}

/// Map an in-pod [`DenialEvent`] to the placement-neutral [`BoundaryEvent`].
///
/// Used by the tee that would route denials through `EventSource` once
/// `BoundaryEvent` carries the fields the aggregator needs.
#[must_use]
pub fn denial_to_event(denial: DenialEvent) -> BoundaryEvent {
    BoundaryEvent::Denial {
        host: denial.host,
        port: denial.port,
        reason: denial.deny_reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn denial(host: &str, port: u16, reason: &str) -> DenialEvent {
        DenialEvent {
            host: host.to_string(),
            port,
            binary: "/usr/bin/agent".to_string(),
            ancestors: vec![],
            deny_reason: reason.to_string(),
            denial_stage: "connect".to_string(),
            l7_method: None,
            l7_path: None,
        }
    }

    /// Stands in for the orchestrator's aggregator: drain the interface, count denials.
    async fn count_denials(source: &dyn EventSource) -> usize {
        use futures::StreamExt;
        source
            .subscribe()
            .expect("first subscribe")
            .filter(|e| std::future::ready(matches!(e, BoundaryEvent::Denial { .. })))
            .count()
            .await
    }

    #[tokio::test]
    async fn in_pod_denials_surface_through_the_event_interface() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        // The tee maps rich denials to BoundaryEvents before they reach the
        // event source; exercise that mapping here.
        tx.send(denial_to_event(denial(
            "evil.test",
            443,
            "no matching allow rule",
        )))
        .unwrap();
        tx.send(denial_to_event(denial("evil.test", 80, "internal address")))
            .unwrap();
        drop(tx); // close the channel so the stream terminates

        let events = InPodEvents::new(rx);
        assert_eq!(count_denials(&events).await, 2);
    }

    #[tokio::test]
    async fn second_subscribe_fails_explicitly() {
        let (_tx, rx) = tokio::sync::mpsc::unbounded_channel::<BoundaryEvent>();
        let events = InPodEvents::new(rx);
        assert!(events.subscribe().is_ok());
        assert!(events.subscribe().is_err());
    }
}
