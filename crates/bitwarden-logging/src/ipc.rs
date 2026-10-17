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
//! Every payload stays under 48 KiB of JSON, so it fits one Noise message:
//! forwarders split large batches, reads are paginated by buffer sequence number, and events too
//! large on their own have their message truncated.
//!
//! Collectors only accept messages from their own client's forwarder endpoint. The browser
//! background also receives IPC traffic from web pages, which must not be able to read or inject
//! events.

use std::{
    iter::Peekable,
    num::NonZeroUsize,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
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

/// Upper bound on the JSON size of one batch or read page, below the 65535-byte Noise message
/// limit to leave room for the RPC envelope and the AEAD tag.
const MAX_PAYLOAD_LEN: usize = 48 * 1024;

/// Appended to a message cut short to fit [`MAX_PAYLOAD_LEN`].
const TRUNCATION_MARKER: &str = "… [truncated]";

/// Events sent from a forwarder to its collector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlightRecorderBatch {
    /// Events in capture order.
    pub events: Vec<FlightRecorderEvent>,
}

impl PayloadTypeName for FlightRecorderBatch {
    const PAYLOAD_TYPE_NAME: &'static str = "platform.flight-recorder.batch";
}

/// RPC request from a forwarder for one page of the collector's events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadFlightRecorderRequest {
    /// Sequence number of the first event to return. Events older than the oldest retained one
    /// are gone, so `0` starts at the oldest retained event.
    pub from: u64,
}

/// RPC response for [`ReadFlightRecorderRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadFlightRecorderResponse {
    /// Events in the collector's buffer from the requested sequence number on, each attributed to
    /// a process, up to 48 KiB of JSON.
    pub events: Vec<FlightRecorderEvent>,
    /// Sequence number to request the next page from, or `None` if this page ends the read.
    pub next: Option<u64>,
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
}

/// Sink that forwards events to a collector over IPC.
///
/// Events wait in a bounded pending buffer. One flush task at a time waits [`FLUSH_INTERVAL`],
/// drains the buffer, and sends the drained events in order as [`FlightRecorderBatch`] messages of
/// at most 48 KiB of JSON each. A send failure drops that batch. When the buffer is full, the
/// oldest events are dropped. Events from the IPC stack itself go to `local` and are never
/// forwarded.
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

    /// Read the collector's events followed by this context's IPC events and unsent events. If the
    /// collector refuses, fails, or does not finish in time, only the pages received so far are
    /// included.
    async fn read_aggregated(
        &self,
        cancellation_token: Option<CancellationToken>,
    ) -> Vec<FlightRecorderEvent> {
        let state = &self.0;
        let mut events = Vec::new();
        // The token or the default timeout bounds the whole read, not each page.
        let read = self.read_collector(&mut events, cancellation_token.clone());
        match cancellation_token {
            Some(_) => read.await,
            None => {
                let _ = timeout(DEFAULT_READ_TIMEOUT, read).await;
            }
        }

        events.extend(state.local.read());
        events.extend(state.pending.read());
        events
    }

    /// Append the collector's events to `events` page by page, until the last page or the first
    /// failed request.
    async fn read_collector(
        &self,
        events: &mut Vec<FlightRecorderEvent>,
        cancellation_token: Option<CancellationToken>,
    ) {
        let state = &self.0;
        let mut from = 0;
        loop {
            // `request` accepts the answer only from `destination`.
            let response = without_flight_recorder(state.client.request(
                ReadFlightRecorderRequest { from },
                state.destination.clone(),
                cancellation_token.clone(),
            ))
            .await;
            let Ok(Ok(page)) = response else {
                return;
            };
            events.extend(page.events);
            match page.next {
                // A cursor that does not advance would request the same page forever.
                Some(next) if next > from => from = next,
                _ => return,
            }
        }
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
        let events = state.pending.take_all();
        if events.is_empty() {
            if release_flush(&state) {
                return;
            }
            continue;
        }

        let overhead = serialized_len(&FlightRecorderBatch { events: Vec::new() });
        let mut events = events.into_iter().peekable();
        while events.peek().is_some() {
            let events = take_chunk(&mut events, overhead);
            // Best-effort: a failed send drops this batch only.
            let _ = state
                .client
                .send_typed(FlightRecorderBatch { events }, state.destination.clone())
                .await;
        }
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
        request: Self::Request,
        info: RpcRequestInfo,
    ) -> Result<ReadFlightRecorderResponse, ReadFlightRecorderError> {
        if !self.role.accepts(&info.source) {
            return Err(ReadFlightRecorderError::SourceNotAccepted);
        }
        // Sequence numbers keep pages stable while the buffer keeps receiving and evicting events.
        let (first, retained) = self.buffer.read_from(request.from);
        let mut retained = retained
            .into_iter()
            .map(|event| attribute(event, self.role.label()))
            .peekable();
        let overhead = serialized_len(&ReadFlightRecorderResponse {
            events: Vec::new(),
            next: Some(u64::MAX),
        });
        let events = take_chunk(&mut retained, overhead);
        let next = retained
            .peek()
            .is_some()
            .then(|| first + events.len() as u64);
        Ok(ReadFlightRecorderResponse { events, next })
    }
}

fn attribute(mut event: FlightRecorderEvent, process: &str) -> FlightRecorderEvent {
    if event.process.is_none() {
        event.process = Some(process.to_owned());
    }
    event
}

/// Length of `value` serialized as JSON, as `bitwarden_ipc` serializes payloads.
fn serialized_len<T: Serialize>(value: &T) -> usize {
    serde_json::to_vec(value)
        .expect("Flight Recorder payloads serialize to JSON")
        .len()
}

/// Take events from the front of `events` while their JSON, plus `overhead` bytes for the
/// enclosing payload, fits [`MAX_PAYLOAD_LEN`]. Takes at least one event, fitted by [`fit_event`].
fn take_chunk<I: Iterator<Item = FlightRecorderEvent>>(
    events: &mut Peekable<I>,
    overhead: usize,
) -> Vec<FlightRecorderEvent> {
    let limit = MAX_PAYLOAD_LEN - overhead;
    let mut chunk = Vec::new();
    let mut len = 0;
    while let Some(event) = events.peek_mut() {
        // Every event after the first is preceded by a comma.
        let event_len = fit_event(event, limit) + usize::from(!chunk.is_empty());
        if !chunk.is_empty() && len + event_len > limit {
            break;
        }
        len += event_len;
        chunk.extend(events.next());
    }
    chunk
}

/// Shrink `event` to at most `limit` bytes of JSON if possible, by truncating its message at a char
/// boundary with [`TRUNCATION_MARKER`] and then dropping its fields. Returns its JSON length.
fn fit_event(event: &mut FlightRecorderEvent, limit: usize) -> usize {
    let len = serialized_len(event);
    if len <= limit {
        return len;
    }
    // Each byte cut from the message shortens the JSON by at least one byte.
    let mut cut = event
        .message
        .len()
        .saturating_sub(len - limit + TRUNCATION_MARKER.len());
    while !event.message.is_char_boundary(cut) {
        cut -= 1;
    }
    event.message.truncate(cut);
    event.message.push_str(TRUNCATION_MARKER);

    let len = serialized_len(event);
    if len <= limit || event.fields.is_empty() {
        return len;
    }
    event.fields.clear();
    serialized_len(event)
}

/// Read the Flight Recorder events for this client.
///
/// In a forwarder, requests the collector's events page by page and appends this context's IPC
/// events and events not yet sent. If the collector cannot be reached, refuses, or does not finish
/// before `cancellation_token` is cancelled, the pages received so far are followed by this
/// context's events. Without a token, the whole read is bounded at 5 seconds. Elsewhere, reads the
/// local buffer.
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
        CommunicationBackend, CommunicationBackendReceiver, InMemorySessionRepository,
        IncomingMessage, IpcClientImpl, NoEncryptionCryptoProvider, NoiseCryptoProvider,
        OutgoingMessage, TestCommunicationBackend, TypedIncomingMessage, TypedOutgoingMessage,
    };
    use tokio::sync::{Mutex, broadcast};

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
                        .request(
                            ReadFlightRecorderRequest { from: 0 },
                            background().to_endpoint(),
                            None,
                        )
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

    /// An event with a message of `len` bytes and its `index` in `fields`.
    fn sized_event(index: usize, len: usize) -> FlightRecorderEvent {
        let prefix = format!("event {index} ");
        let message = format!("{prefix}{}", "x".repeat(len.saturating_sub(prefix.len())));
        FlightRecorderEvent {
            fields: HashMap::from([("index".to_string(), index.to_string())]),
            ..event("app", &message)
        }
    }

    fn sized_events(range: std::ops::Range<usize>, len: usize) -> Vec<FlightRecorderEvent> {
        range.map(|index| sized_event(index, len)).collect()
    }

    fn filled_buffer(
        capacity: usize,
        range: std::ops::Range<usize>,
    ) -> Arc<CircularBuffer<FlightRecorderEvent>> {
        let buffer = Arc::new(CircularBuffer::new(
            NonZeroUsize::new(capacity).expect("non-zero"),
        ));
        for event in sized_events(range, 200) {
            buffer.push(event);
        }
        buffer
    }

    fn indices(events: &[FlightRecorderEvent]) -> Vec<usize> {
        events
            .iter()
            .map(|e| e.fields["index"].parse().expect("index field"))
            .collect()
    }

    fn collector_handler(
        buffer: Arc<CircularBuffer<FlightRecorderEvent>>,
    ) -> ReadFlightRecorderHandler {
        ReadFlightRecorderHandler {
            buffer,
            role: FlightRecorderCollectorRole::BrowserBackground,
        }
    }

    async fn read_page(
        handler: &ReadFlightRecorderHandler,
        from: u64,
    ) -> ReadFlightRecorderResponse {
        let page = handler
            .handle(
                ReadFlightRecorderRequest { from },
                RpcRequestInfo { source: popup() },
            )
            .await
            .expect("popup is accepted");
        assert!(serialized_len(&page) <= MAX_PAYLOAD_LEN);
        page
    }

    #[tokio::test(start_paused = true)]
    async fn test_flush_splits_events_over_the_budget_into_ordered_batches() {
        let backend = TestCommunicationBackend::new();
        let sink = IpcForwardSink::new(
            start_client(&backend).await,
            Endpoint::DesktopMain,
            NonZeroUsize::new(1000).expect("non-zero"),
            buffer(),
        );

        for event in sized_events(0..1000, 200) {
            sink.push(event);
        }
        wait_for_flush().await;

        let outgoing = backend.outgoing().await;
        assert!(outgoing.len() > 1);
        assert!(outgoing.iter().all(|m| m.payload.len() <= MAX_PAYLOAD_LEN));
        let events: Vec<_> = decode::<FlightRecorderBatch>(&outgoing)
            .into_iter()
            .flat_map(|batch| batch.events)
            .collect();
        assert_eq!(indices(&events), (0..1000).collect::<Vec<_>>());
    }

    #[tokio::test(start_paused = true)]
    async fn test_collector_pages_return_each_event_once_in_order() {
        // More than the capacity, so the oldest events are already evicted.
        let buffer = filled_buffer(1000, 0..1200);
        let handler = collector_handler(buffer);

        let mut events = Vec::new();
        let mut pages = 0;
        let mut from = 0;
        loop {
            let page = read_page(&handler, from).await;
            pages += 1;
            events.extend(page.events);
            match page.next {
                Some(next) => from = next,
                None => break,
            }
        }

        assert!(pages > 1);
        assert_eq!(indices(&events), (200..1200).collect::<Vec<_>>());
        assert!(
            events
                .iter()
                .all(|e| e.process.as_deref() == Some("browser-background"))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_collector_pages_do_not_repeat_events_logged_during_a_read() {
        let buffer = filled_buffer(1000, 0..1000);
        let handler = collector_handler(Arc::clone(&buffer));

        let first = read_page(&handler, 0).await;
        // New events evict the oldest ones, shifting every retained event's position.
        for event in sized_events(1000..1100, 200) {
            buffer.push(event);
        }
        let mut events = first.events;
        let mut next = first.next;
        while let Some(from) = next {
            let page = read_page(&handler, from).await;
            events.extend(page.events);
            next = page.next;
        }

        assert_eq!(indices(&events), (0..1100).collect::<Vec<_>>());
    }

    #[tokio::test(start_paused = true)]
    async fn test_oversized_event_is_truncated_and_delivered() {
        let backend = TestCommunicationBackend::new();
        let sink = IpcForwardSink::new(
            start_client(&backend).await,
            Endpoint::DesktopMain,
            NonZeroUsize::new(10).expect("non-zero"),
            buffer(),
        );

        // Multi-byte characters check that the cut lands on a char boundary.
        sink.push(event("app", &"é".repeat(MAX_PAYLOAD_LEN)));
        sink.push(event("app", "after"));
        wait_for_flush().await;

        let outgoing = backend.outgoing().await;
        assert!(outgoing.iter().all(|m| m.payload.len() <= MAX_PAYLOAD_LEN));
        let events: Vec<_> = decode::<FlightRecorderBatch>(&outgoing)
            .into_iter()
            .flat_map(|batch| batch.events)
            .collect();
        assert_eq!(events.len(), 2);
        assert!(events[0].message.starts_with("éé"));
        assert!(events[0].message.ends_with(TRUNCATION_MARKER));
        assert_eq!(events[1].message, "after");
    }

    #[tokio::test(start_paused = true)]
    async fn test_forwarder_read_keeps_pages_received_before_the_timeout() {
        let collector_buffer = filled_buffer(1000, 0..1000);
        let collector = TestCommunicationBackend::new();
        start_collector(
            start_client(&collector).await,
            collector_buffer,
            FlightRecorderCollectorRole::BrowserBackground,
        )
        .await
        .expect("collector starts");
        let backend = TestCommunicationBackend::new();
        let sink = IpcForwardSink::new(
            start_client(&backend).await,
            background().to_endpoint(),
            NonZeroUsize::new(10).expect("non-zero"),
            buffer(),
        );
        sink.enqueue(sized_event(1000, 10));

        let read = tokio::spawn({
            let sink = sink.clone();
            async move { sink.read_aggregated(None).await }
        });
        // Answer the first page only. The timeout spans the whole read, so it still ends.
        settle().await;
        relay(&backend, &collector, popup()).await;
        settle().await;
        relay(&collector, &backend, background()).await;

        let events = read.await.expect("task joins");
        let indices = indices(&events);
        assert!(indices.len() > 1 && indices.len() < 1001);
        let (pending, collected) = indices.split_last().expect("not empty");
        assert_eq!(*pending, 1000);
        assert_eq!(collected, (0..collected.len()).collect::<Vec<_>>());
    }

    /// One side of an in-memory link between two clients, receiving the other side's messages as
    /// coming from `peer`.
    #[derive(Clone)]
    struct LinkBackend {
        outgoing: broadcast::Sender<OutgoingMessage>,
        incoming: broadcast::Sender<OutgoingMessage>,
        peer: Source,
    }

    impl LinkBackend {
        fn pair(one: Source, two: Source) -> (Self, Self) {
            let (one_out, _) = broadcast::channel(1024);
            let (two_out, _) = broadcast::channel(1024);
            (
                Self {
                    outgoing: one_out.clone(),
                    incoming: two_out.clone(),
                    peer: two,
                },
                Self {
                    outgoing: two_out,
                    incoming: one_out,
                    peer: one,
                },
            )
        }
    }

    struct LinkReceiver {
        incoming: Mutex<broadcast::Receiver<OutgoingMessage>>,
        peer: Source,
    }

    impl CommunicationBackend for LinkBackend {
        type SendError = ();
        type Receiver = LinkReceiver;

        async fn send(&self, message: OutgoingMessage) -> Result<(), ()> {
            // Sending fails only when the other side has no receiver yet, as with a real link.
            let _ = self.outgoing.send(message);
            Ok(())
        }

        async fn subscribe(&self) -> LinkReceiver {
            LinkReceiver {
                incoming: Mutex::new(self.incoming.subscribe()),
                peer: self.peer.clone(),
            }
        }
    }

    impl CommunicationBackendReceiver for LinkReceiver {
        type ReceiveError = ();

        async fn receive(&self) -> Result<IncomingMessage, ()> {
            let message = self.incoming.lock().await.recv().await.map_err(|_| ())?;
            Ok(IncomingMessage {
                payload: message.payload,
                destination: message.destination,
                source: self.peer.clone(),
                topic: message.topic,
            })
        }
    }

    async fn start_noise_client(backend: LinkBackend) -> Arc<dyn IpcClient> {
        let client: Arc<dyn IpcClient> = Arc::new(IpcClientImpl::new(
            NoiseCryptoProvider::new(),
            backend,
            InMemorySessionRepository::default(),
        ));
        client.start(None).await.expect("client starts");
        client
    }

    #[tokio::test(start_paused = true)]
    async fn test_full_buffers_travel_over_noise() {
        let (renderer, main) = LinkBackend::pair(Source::DesktopRenderer, Source::DesktopMain);
        let collector_buffer = filled_buffer(3000, 0..1500);
        start_collector(
            start_noise_client(main).await,
            Arc::clone(&collector_buffer),
            FlightRecorderCollectorRole::DesktopMain,
        )
        .await
        .expect("collector starts");
        let sink = IpcForwardSink::new(
            start_noise_client(renderer).await,
            Endpoint::DesktopMain,
            NonZeroUsize::new(1000).expect("non-zero"),
            buffer(),
        );

        // One flush of a full forwarder buffer, then a read of the whole collector buffer.
        for event in sized_events(1500..2500, 200) {
            sink.push(event);
        }
        wait_for_flush().await;
        settle().await;
        assert_eq!(collector_buffer.len(), 2500);

        let events = sink.read_aggregated(None).await;
        assert_eq!(indices(&events), (0..2500).collect::<Vec<_>>());
        assert_eq!(events[0].process.as_deref(), Some("desktop-main"));
        assert_eq!(events[2499].process.as_deref(), Some("desktop-renderer"));
    }
}
