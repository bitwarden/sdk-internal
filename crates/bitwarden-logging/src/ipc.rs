//! Aggregation of Flight Recorder events from several contexts of one client over
//! [`bitwarden_ipc`].
//!
//! Clients with more than one context (browser popup + background, desktop renderer + main) run
//! one context as the collector and the others as forwarders. Once forwarding is enabled, a
//! forwarder sends captured events to the collector and keeps only events from the IPC stack
//! itself locally, since sending those would loop. The collector stores
//! received events in its own buffer, attributed to the sending process, and answers read
//! requests from its forwarders.
//!
//! Collectors only accept messages from their own client's forwarder endpoint. The browser
//! background also receives IPC traffic from web pages, which must not be able to read or inject
//! events.

use std::{
    num::NonZeroUsize,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use bitwarden_ipc::{
    Endpoint, IpcClient, IpcClientExt, IpcClientTypedSubscription, PayloadTypeName, RpcHandler,
    RpcRequest, RpcRequestInfo, Source, SubscribeError, TypedReceiveError,
};
use bitwarden_threading::{
    cancellation_token::CancellationToken,
    spawn,
    time::{sleep, timeout},
};
use serde::{Deserialize, Serialize};

use crate::{
    CircularBuffer, FlightRecorderEvent, FlightRecorderSink, get_flight_recorder_buffer,
    read_flight_recorder, set_flight_recorder_sink, without_flight_recorder,
};

/// Target prefixes kept in the forwarder's local buffer instead of forwarded, as a backstop for
/// events the IPC stack emits outside [`without_flight_recorder`] (e.g. from tasks it spawns).
const UNFORWARDED_TARGETS: &[&str] = &["bitwarden_ipc", "bitwarden_threading"];

/// How long a flush waits before draining, so events logged close together share one IPC message.
const FLUSH_INTERVAL: Duration = Duration::from_millis(250);

/// How long an aggregated read waits for the collector when the caller gives no cancellation token.
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Events sent from a forwarder to its collector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlightRecorderBatch {
    /// Events in capture order.
    pub events: Vec<FlightRecorderEvent>,
}

impl PayloadTypeName for FlightRecorderBatch {
    const PAYLOAD_TYPE_NAME: &'static str = "platform.flight-recorder.batch";
}

/// RPC request from a forwarder for the collector's events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadFlightRecorderRequest;

/// RPC response for [`ReadFlightRecorderRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadFlightRecorderResponse {
    /// Events in the collector's buffer, each attributed to a process.
    pub events: Vec<FlightRecorderEvent>,
}

/// Why the collector refused a [`ReadFlightRecorderRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReadFlightRecorderError {
    /// The request did not come from the collector's forwarder.
    SourceNotAccepted,
}

impl RpcRequest for ReadFlightRecorderRequest {
    type Response = Result<ReadFlightRecorderResponse, ReadFlightRecorderError>;

    const NAME: &str = "ReadFlightRecorder";
}

/// The context that collects events for its client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[bitwarden_ffi::wasm_record]
pub enum FlightRecorderCollectorRole {
    /// Browser extension background, collecting from extension pages (popup, popout, sidebar).
    BrowserBackground,
    /// Desktop main process, collecting from the renderer.
    DesktopMain,
}

impl FlightRecorderCollectorRole {
    /// Process label for events produced by the collector itself.
    fn label(self) -> &'static str {
        match self {
            Self::BrowserBackground => "browser-background",
            Self::DesktopMain => "desktop-main",
        }
    }

    /// Whether messages from `source` come from this client's forwarder.
    fn accepts(self, source: &Source) -> bool {
        match self {
            Self::BrowserBackground => matches!(source, Source::BrowserForeground { .. }),
            Self::DesktopMain => matches!(source, Source::DesktopRenderer),
        }
    }
}

/// Process label for events received from `source`.
fn process_label(source: &Source) -> &'static str {
    match source {
        Source::Web { .. } => "web",
        Source::BrowserForeground { .. } => "browser-popup",
        Source::BrowserBackground { .. } => "browser-background",
        Source::Cli { .. } => "cli",
        Source::DesktopRenderer => "desktop-renderer",
        Source::DesktopMain => "desktop-main",
    }
}

struct ForwarderState {
    client: Arc<dyn IpcClient>,
    destination: Endpoint,
    local: Arc<CircularBuffer<FlightRecorderEvent>>,
    pending: CircularBuffer<FlightRecorderEvent>,
    flushing: AtomicBool,
    /// Number of aggregated reads in flight. Flushes wait while it is non-zero.
    reading: AtomicUsize,
}

/// Sink that forwards events to a collector over IPC.
///
/// Events wait in a bounded pending buffer. One flush task at a time waits 250 ms, drains the
/// buffer, and sends the drained events as a single [`FlightRecorderBatch`], so at most one batch
/// goes out per interval. Flushes do not drain while an aggregated read is in flight, so the read
/// still finds in `pending` every event the collector's answer lacks. Send failures drop the batch.
/// When the buffer is full, the oldest events are dropped. Events from the IPC stack itself go to
/// `local` and are never forwarded.
#[derive(Clone)]
pub struct IpcForwardSink(Arc<ForwarderState>);

impl IpcForwardSink {
    /// Create a sink forwarding to `destination`, holding at most `capacity` unsent events.
    /// Events from the IPC stack are stored in `local` instead.
    pub fn new(
        client: Arc<dyn IpcClient>,
        destination: Endpoint,
        capacity: NonZeroUsize,
        local: Arc<CircularBuffer<FlightRecorderEvent>>,
    ) -> Self {
        Self(Arc::new(ForwarderState {
            client,
            destination,
            local,
            pending: CircularBuffer::new(capacity),
            flushing: AtomicBool::new(false),
            reading: AtomicUsize::new(0),
        }))
    }

    fn enqueue(&self, event: FlightRecorderEvent) {
        self.0.pending.push(event);
    }

    fn schedule_flush(&self) {
        if !self.0.flushing.swap(true, Ordering::AcqRel) {
            spawn(without_flight_recorder(flush(Arc::clone(&self.0))));
        }
    }

    /// Read the collector's events followed by this context's IPC events and unsent events. The
    /// collector's events are omitted if it refuses, fails, or does not answer in time.
    async fn read_aggregated(
        &self,
        cancellation_token: Option<CancellationToken>,
    ) -> Vec<FlightRecorderEvent> {
        let state = &self.0;
        let _reading = ReadingGuard::new(&state.reading);
        // `request` accepts the answer only from `destination`.
        let request = without_flight_recorder(state.client.request(
            ReadFlightRecorderRequest,
            state.destination.clone(),
            cancellation_token.clone(),
        ));
        let response = match cancellation_token {
            Some(_) => request.await.ok(),
            None => timeout(DEFAULT_READ_TIMEOUT, request)
                .await
                .ok()
                .and_then(Result::ok),
        };

        let mut events = response
            .and_then(Result::ok)
            .map(|response| response.events)
            .unwrap_or_default();
        events.extend(state.local.read());
        events.extend(state.pending.read());
        events
    }
}

impl FlightRecorderSink for IpcForwardSink {
    fn push(&self, event: FlightRecorderEvent) {
        if UNFORWARDED_TARGETS
            .iter()
            .any(|prefix| event.target.starts_with(prefix))
        {
            self.0.local.push(event);
            return;
        }
        self.enqueue(event);
        self.schedule_flush();
    }
}

async fn flush(state: Arc<ForwarderState>) {
    loop {
        sleep(FLUSH_INTERVAL).await;
        if state.reading.load(Ordering::Acquire) > 0 {
            continue;
        }
        let events = state.pending.take_all();
        if events.is_empty() {
            if release_flush(&state) {
                return;
            }
            continue;
        }

        // Best-effort: a failed send drops the batch.
        let _ = state
            .client
            .send_typed(FlightRecorderBatch { events }, state.destination.clone())
            .await;
    }
}

/// Marks an aggregated read in flight until dropped, including when the read is cancelled.
struct ReadingGuard<'a>(&'a AtomicUsize);

impl<'a> ReadingGuard<'a> {
    fn new(reading: &'a AtomicUsize) -> Self {
        reading.fetch_add(1, Ordering::AcqRel);
        Self(reading)
    }
}

impl Drop for ReadingGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// End a flush that drained an empty buffer. Returns false if the flush must keep running.
fn release_flush(state: &ForwarderState) -> bool {
    state.flushing.store(false, Ordering::Release);
    // An event pushed after the drain but before the store above found a flush in progress and
    // did not schedule one. Take over unless another flush already has.
    state.pending.is_empty() || state.flushing.swap(true, Ordering::AcqRel)
}

static FORWARDER: OnceLock<IpcForwardSink> = OnceLock::new();

/// Make this context a forwarder: send captured events to the collector at `destination`, except
/// events from the IPC stack itself, which stay in the local buffer.
///
/// Events captured before this call are sent first. Only the first call has effect. No-op if the
/// Flight Recorder is disabled.
pub fn enable_flight_recorder_forwarding(client: Arc<dyn IpcClient>, destination: Endpoint) {
    let Some(buffer) = get_flight_recorder_buffer() else {
        return;
    };
    let capacity = NonZeroUsize::new(buffer.capacity()).expect("buffer capacity is non-zero");
    let sink = IpcForwardSink::new(client, destination, capacity, Arc::clone(&buffer));
    if FORWARDER.set(sink.clone()).is_err() {
        return;
    }

    // Swap before draining so no event lands in the local buffer after the drain.
    set_flight_recorder_sink(Arc::new(sink.clone()));
    for event in buffer.take_all() {
        sink.enqueue(event);
    }
    sink.schedule_flush();
}

static COLLECTING: AtomicBool = AtomicBool::new(false);

/// Make this context the collector for its client, storing events from `role`'s forwarders and
/// answering their read requests. Only the first successful call has effect. No-op if the Flight
/// Recorder is disabled.
pub async fn enable_flight_recorder_collection(
    client: Arc<dyn IpcClient>,
    role: FlightRecorderCollectorRole,
) -> Result<(), SubscribeError> {
    let Some(buffer) = get_flight_recorder_buffer() else {
        return Ok(());
    };
    // A second collector would store every received event twice.
    if COLLECTING.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    let result = start_collector(client, buffer, role).await;
    if result.is_err() {
        COLLECTING.store(false, Ordering::Release);
    }
    result
}

async fn start_collector(
    client: Arc<dyn IpcClient>,
    buffer: Arc<CircularBuffer<FlightRecorderEvent>>,
    role: FlightRecorderCollectorRole,
) -> Result<(), SubscribeError> {
    let batches = client.subscribe_typed::<FlightRecorderBatch>().await?;
    client
        .register_rpc_handler(ReadFlightRecorderHandler {
            buffer: Arc::clone(&buffer),
            role,
        })
        .await;
    spawn(collect_batches(batches, buffer, role));
    Ok(())
}

fn is_closed(error: &TypedReceiveError) -> bool {
    matches!(
        error,
        TypedReceiveError::Channel(tokio::sync::broadcast::error::RecvError::Closed)
    )
}

async fn collect_batches(
    mut batches: IpcClientTypedSubscription<FlightRecorderBatch>,
    buffer: Arc<CircularBuffer<FlightRecorderEvent>>,
    role: FlightRecorderCollectorRole,
) {
    loop {
        match batches.receive(None).await {
            Ok(message) => {
                if !role.accepts(&message.source) {
                    continue;
                }
                // Attribute from the transport-provided source; forwarders do not self-declare.
                let process = process_label(&message.source);
                for mut event in message.payload.events {
                    event.process = Some(process.to_owned());
                    buffer.push(event);
                }
            }
            Err(error) if is_closed(&error) => return,
            Err(_) => continue,
        }
    }
}

/// RPC handler for [`ReadFlightRecorderRequest`], answering only `role`'s forwarder.
struct ReadFlightRecorderHandler {
    buffer: Arc<CircularBuffer<FlightRecorderEvent>>,
    role: FlightRecorderCollectorRole,
}

impl RpcHandler for ReadFlightRecorderHandler {
    type Request = ReadFlightRecorderRequest;

    async fn handle(
        &self,
        _request: Self::Request,
        info: RpcRequestInfo,
    ) -> Result<ReadFlightRecorderResponse, ReadFlightRecorderError> {
        if !self.role.accepts(&info.source) {
            return Err(ReadFlightRecorderError::SourceNotAccepted);
        }
        Ok(ReadFlightRecorderResponse {
            events: attribute(self.buffer.read(), self.role.label()),
        })
    }
}

fn attribute(mut events: Vec<FlightRecorderEvent>, process: &str) -> Vec<FlightRecorderEvent> {
    for event in &mut events {
        if event.process.is_none() {
            event.process = Some(process.to_owned());
        }
    }
    events
}

/// Read the Flight Recorder events for this client.
///
/// In a forwarder, requests the collector's events and appends this context's IPC events and
/// events not yet sent. If the collector cannot be reached or does not answer before
/// `cancellation_token` is cancelled, only this context's events are returned. Without a token,
/// the wait is bounded at 5 seconds. Elsewhere, reads the local buffer.
pub async fn read_flight_recorder_aggregated(
    cancellation_token: Option<CancellationToken>,
) -> Vec<FlightRecorderEvent> {
    match FORWARDER.get() {
        Some(forwarder) => forwarder.read_aggregated(cancellation_token).await,
        None => read_flight_recorder(),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, time::Duration};

    use bitwarden_ipc::{
        InMemorySessionRepository, IncomingMessage, IpcClientImpl, NoEncryptionCryptoProvider,
        OutgoingMessage, TestCommunicationBackend, TypedIncomingMessage, TypedOutgoingMessage,
    };

    use super::*;

    fn event(target: &str, message: &str) -> FlightRecorderEvent {
        FlightRecorderEvent {
            timestamp: 0,
            level: "INFO".to_string(),
            target: target.to_string(),
            message: message.to_string(),
            fields: HashMap::new(),
            process: None,
        }
    }

    async fn start_client(backend: &TestCommunicationBackend) -> Arc<dyn IpcClient> {
        let client: Arc<dyn IpcClient> = Arc::new(IpcClientImpl::new(
            NoEncryptionCryptoProvider,
            backend.clone(),
            InMemorySessionRepository::<()>::default(),
        ));
        client.start(None).await.expect("client starts");
        client
    }

    fn incoming<P: Serialize + PayloadTypeName>(payload: P, source: Source) -> IncomingMessage {
        TypedIncomingMessage {
            payload,
            destination: Endpoint::BrowserBackground {
                id: bitwarden_ipc::HostId::Own,
            },
            source,
        }
        .try_into()
        .expect("serializes")
    }

    fn decode<P: serde::de::DeserializeOwned + PayloadTypeName>(
        messages: &[OutgoingMessage],
    ) -> Vec<P> {
        messages
            .iter()
            .filter(|m| m.topic.as_deref() == Some(P::PAYLOAD_TYPE_NAME))
            .map(|m| {
                TypedOutgoingMessage::<P>::try_from(m.clone())
                    .expect("deserializes")
                    .payload
            })
            .collect()
    }

    async fn settle() {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    async fn wait_for_flush() {
        tokio::time::sleep(FLUSH_INTERVAL + Duration::from_millis(50)).await;
    }

    fn popup() -> Source {
        Source::BrowserForeground { id: 1 }
    }

    fn web_page() -> Source {
        Source::Web {
            tab_id: 1,
            document_id: "doc".to_string(),
            origin: "https://example.com".to_string(),
        }
    }

    fn buffer() -> Arc<CircularBuffer<FlightRecorderEvent>> {
        Arc::new(CircularBuffer::new(
            NonZeroUsize::new(100).expect("non-zero"),
        ))
    }

    #[tokio::test(start_paused = true)]
    async fn test_forward_sink_batches_events_pushed_within_the_interval() {
        let backend = TestCommunicationBackend::new();
        let client = start_client(&backend).await;
        let sink = IpcForwardSink::new(
            client,
            Endpoint::DesktopMain,
            NonZeroUsize::new(10).expect("non-zero"),
            buffer(),
        );

        sink.push(event("app", "one"));
        tokio::time::sleep(FLUSH_INTERVAL / 2).await;
        assert!(decode::<FlightRecorderBatch>(&backend.outgoing().await).is_empty());

        sink.push(event("app", "two"));
        wait_for_flush().await;

        let batches = decode::<FlightRecorderBatch>(&backend.outgoing().await);
        assert_eq!(batches.len(), 1);
        assert_eq!(messages(&batches[0].events), ["one", "two"]);

        // The flush stopped once its queue was empty, so a later event starts a new batch.
        sink.push(event("app", "three"));
        wait_for_flush().await;
        assert_eq!(
            decode::<FlightRecorderBatch>(&backend.outgoing().await).len(),
            2
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_forward_sink_keeps_ipc_targets_locally() {
        let backend = TestCommunicationBackend::new();
        let client = start_client(&backend).await;
        let local = buffer();
        let sink = IpcForwardSink::new(
            client,
            Endpoint::DesktopMain,
            NonZeroUsize::new(10).expect("non-zero"),
            Arc::clone(&local),
        );

        sink.push(event("bitwarden_ipc::ipc_client", "ipc"));
        sink.push(event("bitwarden_threading", "threading"));
        wait_for_flush().await;

        assert!(decode::<FlightRecorderBatch>(&backend.outgoing().await).is_empty());
        let kept: Vec<_> = local.read().into_iter().map(|e| e.message).collect();
        assert_eq!(kept, ["ipc", "threading"]);
    }

    #[tokio::test(start_paused = true)]
    async fn test_collector_stores_batches_from_its_forwarder_only() {
        let backend = TestCommunicationBackend::new();
        let client = start_client(&backend).await;
        let buffer = buffer();
        start_collector(
            client,
            Arc::clone(&buffer),
            FlightRecorderCollectorRole::BrowserBackground,
        )
        .await
        .expect("collector starts");

        let batch = |message: &str| FlightRecorderBatch {
            events: vec![FlightRecorderEvent {
                process: Some("spoofed".to_string()),
                ..event("typescript", message)
            }],
        };
        backend.push_incoming(incoming(batch("from popup"), popup()));
        backend.push_incoming(incoming(batch("from web"), web_page()));
        settle().await;

        let events = buffer.read();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].message, "from popup");
        assert_eq!(events[0].process.as_deref(), Some("browser-popup"));
    }

    fn background() -> Source {
        Source::BrowserBackground {
            id: bitwarden_ipc::HostId::Own,
        }
    }

    /// Deliver the messages sent through `from` to `to`, as if they came from `source`.
    async fn relay(from: &TestCommunicationBackend, to: &TestCommunicationBackend, source: Source) {
        for message in from.drain_outgoing().await {
            to.push_incoming(IncomingMessage {
                payload: message.payload,
                destination: message.destination,
                source: source.clone(),
                topic: message.topic,
            });
        }
    }

    async fn start_test_collector(events: &[&str]) -> TestCommunicationBackend {
        let backend = TestCommunicationBackend::new();
        let buffer = buffer();
        for message in events {
            buffer.push(event("app", message));
        }
        start_collector(
            start_client(&backend).await,
            buffer,
            FlightRecorderCollectorRole::BrowserBackground,
        )
        .await
        .expect("collector starts");
        backend
    }

    fn messages(events: &[FlightRecorderEvent]) -> Vec<&str> {
        events.iter().map(|e| e.message.as_str()).collect()
    }

    #[tokio::test(start_paused = true)]
    async fn test_collector_answers_reads_from_its_forwarder_only() {
        let collector = start_test_collector(&["own event"]).await;
        let backend = TestCommunicationBackend::new();
        let client = start_client(&backend).await;

        let read_as = async |source: Source| {
            let request = tokio::spawn({
                let client = Arc::clone(&client);
                async move {
                    client
                        .request(ReadFlightRecorderRequest, background().to_endpoint(), None)
                        .await
                }
            });
            settle().await;
            relay(&backend, &collector, source).await;
            settle().await;
            relay(&collector, &backend, background()).await;
            request
                .await
                .expect("task joins")
                .expect("request succeeds")
        };

        let from_web = read_as(web_page()).await;
        assert!(matches!(
            from_web,
            Err(ReadFlightRecorderError::SourceNotAccepted)
        ));

        let events = read_as(popup()).await.expect("popup is accepted").events;
        assert_eq!(messages(&events), ["own event"]);
        assert_eq!(events[0].process.as_deref(), Some("browser-background"));
    }

    #[tokio::test(start_paused = true)]
    async fn test_forwarder_read_returns_collector_events_then_local_and_pending() {
        let collector = start_test_collector(&["collected"]).await;
        let backend = TestCommunicationBackend::new();
        let local = buffer();
        local.push(event("bitwarden_ipc", "ipc"));
        let sink = IpcForwardSink::new(
            start_client(&backend).await,
            background().to_endpoint(),
            NonZeroUsize::new(10).expect("non-zero"),
            local,
        );
        sink.enqueue(event("app", "unsent"));

        let read = tokio::spawn({
            let sink = sink.clone();
            async move { sink.read_aggregated(None).await }
        });
        settle().await;
        relay(&backend, &collector, popup()).await;
        settle().await;
        relay(&collector, &backend, background()).await;

        let events = read.await.expect("task joins");
        assert_eq!(messages(&events), ["collected", "ipc", "unsent"]);
    }

    #[tokio::test(start_paused = true)]
    async fn test_forwarder_read_falls_back_to_local_and_pending_without_an_answer() {
        let backend = TestCommunicationBackend::new();
        let local = buffer();
        local.push(event("bitwarden_ipc", "ipc"));
        let sink = IpcForwardSink::new(
            start_client(&backend).await,
            background().to_endpoint(),
            NonZeroUsize::new(10).expect("non-zero"),
            local,
        );
        sink.enqueue(event("app", "unsent"));

        let cancellation_token = CancellationToken::new();
        let read = tokio::spawn({
            let sink = sink.clone();
            let cancellation_token = cancellation_token.clone();
            async move { sink.read_aggregated(Some(cancellation_token)).await }
        });
        settle().await;
        cancellation_token.cancel();

        let events = read.await.expect("task joins");
        assert_eq!(messages(&events), ["ipc", "unsent"]);
    }

    #[tokio::test(start_paused = true)]
    async fn test_forwarder_read_keeps_pending_events_a_flush_would_send_mid_read() {
        let collector = start_test_collector(&["collected"]).await;
        let backend = TestCommunicationBackend::new();
        let sink = IpcForwardSink::new(
            start_client(&backend).await,
            background().to_endpoint(),
            NonZeroUsize::new(10).expect("non-zero"),
            buffer(),
        );
        sink.push(event("app", "just before read"));

        let read = tokio::spawn({
            let sink = sink.clone();
            async move { sink.read_aggregated(None).await }
        });
        settle().await;
        relay(&backend, &collector, popup()).await;
        // The flush interval elapses while the collector's answer is on its way.
        wait_for_flush().await;
        relay(&collector, &backend, background()).await;

        let events = read.await.expect("task joins");
        assert_eq!(messages(&events), ["collected", "just before read"]);

        // The paused flush sends the event once the read is done.
        wait_for_flush().await;
        let batches = decode::<FlightRecorderBatch>(&backend.outgoing().await);
        assert_eq!(batches.len(), 1);
        assert_eq!(messages(&batches[0].events), ["just before read"]);
    }

    #[tokio::test(start_paused = true)]
    async fn test_flush_keeps_running_for_an_event_pushed_after_its_drain() {
        let backend = TestCommunicationBackend::new();
        let sink = IpcForwardSink::new(
            start_client(&backend).await,
            Endpoint::DesktopMain,
            NonZeroUsize::new(10).expect("non-zero"),
            buffer(),
        );
        let state = &sink.0;

        // A flush is running and has just drained an empty buffer, so this push schedules nothing.
        state.flushing.store(true, Ordering::Release);
        sink.push(event("app", "late"));

        assert!(!release_flush(state));
        assert!(state.flushing.load(Ordering::Acquire));

        // The rest of the running flush.
        flush(Arc::clone(state)).await;
        let batches = decode::<FlightRecorderBatch>(&backend.outgoing().await);
        assert_eq!(batches.len(), 1);
        assert_eq!(messages(&batches[0].events), ["late"]);
        assert!(!state.flushing.load(Ordering::Acquire));
    }
}
