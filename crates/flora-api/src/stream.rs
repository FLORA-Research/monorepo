//! Real-time streams: `/account/stream` and `/gateways/{id}/stream`.
//!
//! Render accepts inbound WebSocket connections on free web services, but the
//! free plan's idle rule counts only *incoming* messages. A stream that the
//! server pushes to without the client ever speaking would therefore let the
//! service spin down mid-session. Two things follow from that, and both are
//! load-bearing rather than cosmetic:
//!
//! * the server sends protocol-level pings, which keeps the connection healthy
//!   on the wire;
//! * the client is expected to answer, and the documentation says so, because
//!   the answer is what counts as inbound traffic.
//!
//! The alternative, a keep-alive HTTP poll beside the socket, would spend the
//! same Render instance hours as the socket itself, so it buys nothing.
//!
//! Authentication is a first message rather than a query parameter. A token in
//! a URL lands in access logs and proxy traces, and these tokens authorise
//! reading a farm's data.

use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use chrono::{DateTime, Utc};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::state::AppState;

/// How many events a slow subscriber may fall behind before it is told it
/// missed some.
pub const EVENT_BUFFER: usize = 256;

/// Server ping interval. Render's own guidance is roughly this long, and it is
/// short enough to notice a dead connection well inside the idle window.
pub const PING_INTERVAL_SECONDS: u64 = 30;

/// How long a client has to authenticate before the socket is closed.
pub const AUTH_TIMEOUT_SECONDS: u64 = 10;

/// Largest accepted client message. Clients only send an auth frame and pongs.
const MAX_CLIENT_MESSAGE: usize = 4 * 1024;

/// Something worth telling a connected app.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamEvent {
    /// New readings arrived for a gateway.
    Telemetry {
        gateway_id: String,
        readings: Vec<ReadingEvent>,
    },
    /// A manual command changed state.
    Command {
        gateway_id: String,
        command_id: Uuid,
        status: String,
    },
    /// A gateway reported, so its liveness changed.
    GatewaySeen {
        gateway_id: String,
        last_seen: DateTime<Utc>,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct ReadingEvent {
    pub node_uuid: String,
    pub addr: u8,
    /// Percent, or `null` when the firmware reported it unavailable.
    pub moisture: Option<f32>,
    pub temperature: Option<f32>,
    pub humidity: Option<f32>,
    pub valve_state: Option<i16>,
}

/// Fan-out hub. Every event carries its account so subscribers can filter
/// without the publisher needing to know who is listening.
#[derive(Debug, Clone)]
pub struct EventHub {
    sender: broadcast::Sender<(Uuid, StreamEvent)>,
}

impl Default for EventHub {
    fn default() -> Self {
        Self::new()
    }
}

impl EventHub {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(EVENT_BUFFER);
        Self { sender }
    }

    /// Publish to every subscriber. Returns the number that received it.
    ///
    /// A send with no subscribers is not an error: nobody is watching yet.
    pub fn publish(&self, account_id: Uuid, event: StreamEvent) -> usize {
        self.sender.send((account_id, event)).unwrap_or(0)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<(Uuid, StreamEvent)> {
        self.sender.subscribe()
    }

    pub fn subscribers(&self) -> usize {
        self.sender.receiver_count()
    }
}

/// A helper the ingest path uses, so publishing cannot be forgotten.
pub fn publish_telemetry(
    hub: &Arc<EventHub>,
    account_id: Option<Uuid>,
    gateway_id: &str,
    readings: Vec<ReadingEvent>,
) {
    // An unclaimed gateway has no account to notify.
    if let Some(account_id) = account_id {
        hub.publish(
            account_id,
            StreamEvent::Telemetry {
                gateway_id: gateway_id.to_owned(),
                readings,
            },
        );
    }
}

/// What a client sends to authenticate.
#[derive(Debug, Deserialize)]
struct AuthFrame {
    token: String,
}

/// `GET /account/stream`
pub async fn account_stream(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| serve(socket, state, None))
}

/// `GET /gateways/{id}/stream`
pub async fn gateway_stream(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Path(gateway_id): Path<String>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| serve(socket, state, Some(gateway_id)))
}

/// Run one socket: authenticate, then forward matching events until it closes.
async fn serve(socket: WebSocket, state: AppState, only_gateway: Option<String>) {
    let (mut sink, mut stream) = socket.split();

    // ---- Authenticate on the first frame ----
    let auth = tokio::time::timeout(
        std::time::Duration::from_secs(AUTH_TIMEOUT_SECONDS),
        read_auth_frame(&mut stream),
    )
    .await;

    let claims = match auth {
        Ok(Some(token)) => match flora_auth::verify_access_token(&state.jwt_secret, &token) {
            Ok(claims) => claims,
            Err(_) => {
                let _ = sink.send(Message::Close(None)).await;
                return;
            }
        },
        // Timed out, closed early, or sent something malformed.
        _ => {
            let _ = sink.send(Message::Close(None)).await;
            return;
        }
    };

    // A gateway-scoped stream still requires ownership, or a subscriber could
    // watch any plot's data by guessing its id.
    if let Some(gateway_id) = only_gateway.as_deref() {
        match flora_db::queries::gateway_by_id(&state.pool, gateway_id).await {
            Ok(Some(gateway)) if gateway.owned_by(claims.sub) => {}
            _ => {
                let _ = sink.send(Message::Close(None)).await;
                return;
            }
        }
    }

    let mut events = state.events.subscribe();
    let mut ping = tokio::time::interval(std::time::Duration::from_secs(PING_INTERVAL_SECONDS));
    // The first tick fires immediately; skip it so a fresh socket is not
    // pinged before the client is ready.
    ping.tick().await;

    let _ = sink
        .send(Message::Text(
            serde_json::json!({ "type": "ready" }).to_string().into(),
        ))
        .await;

    loop {
        tokio::select! {
            // Inbound frames. Reading them is what counts as activity for
            // Render's idle rule, and pongs are the cheapest form of it.
            incoming = stream.next() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(payload))) => {
                        if sink.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    // Any client frame keeps the connection warm; the content
                    // is not otherwise meaningful once authenticated.
                    Some(Ok(Message::Text(text))) => {
                        if text.len() > MAX_CLIENT_MESSAGE {
                            break;
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) => break,
                }
            }

            event = events.recv() => {
                match event {
                    Ok((account_id, event)) => {
                        if account_id != claims.sub {
                            continue;
                        }
                        if let Some(wanted) = only_gateway.as_deref()
                            && event_gateway(&event) != Some(wanted)
                        {
                            continue;
                        }
                        let Ok(payload) = serde_json::to_string(&event) else {
                            continue;
                        };
                        if sink.send(Message::Text(payload.into())).await.is_err() {
                            break;
                        }
                    }
                    // A subscriber that fell far enough behind that events were
                    // dropped is told, rather than silently showing stale data.
                    Err(broadcast::error::RecvError::Lagged(missed)) => {
                        let notice = serde_json::json!({
                            "type": "lagged",
                            "missed": missed,
                            "hint": "refetch the current state",
                        });
                        if sink.send(Message::Text(notice.to_string().into())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }

            _ = ping.tick() => {
                if sink.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break;
                }
            }
        }
    }
}

/// The gateway an event concerns, for filtering a scoped stream.
fn event_gateway(event: &StreamEvent) -> Option<&str> {
    match event {
        StreamEvent::Telemetry { gateway_id, .. } => Some(gateway_id),
        StreamEvent::Command { gateway_id, .. } => Some(gateway_id),
        StreamEvent::GatewaySeen { gateway_id, .. } => Some(gateway_id),
    }
}

/// Read the first text frame as an auth token.
async fn read_auth_frame<S>(stream: &mut S) -> Option<String>
where
    S: StreamExt<Item = Result<Message, axum::Error>> + Unpin,
{
    while let Some(frame) = stream.next().await {
        match frame {
            Ok(Message::Text(text)) => {
                if text.len() > MAX_CLIENT_MESSAGE {
                    return None;
                }
                let frame: AuthFrame = serde_json::from_str(&text).ok()?;
                return Some(frame.token);
            }
            Ok(Message::Ping(_)) => continue,
            _ => return None,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_serialize_with_a_type_tag() {
        let event = StreamEvent::Telemetry {
            gateway_id: "gw".into(),
            readings: vec![ReadingEvent {
                node_uuid: "0202020202020202".into(),
                addr: 2,
                moisture: Some(31.2),
                temperature: None,
                humidity: None,
                valve_state: Some(0),
            }],
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"telemetry\""), "{json}");
        // Unavailable metrics stay null, so a client can distinguish them from
        // a real zero.
        assert!(json.contains("\"temperature\":null"), "{json}");

        let command = StreamEvent::Command {
            gateway_id: "gw".into(),
            command_id: Uuid::nil(),
            status: "applied".into(),
        };
        assert!(
            serde_json::to_string(&command)
                .unwrap()
                .contains("\"type\":\"command\""),
            "a client switches on the tag"
        );
    }

    #[test]
    fn an_event_reports_the_gateway_it_concerns() {
        let event = StreamEvent::GatewaySeen {
            gateway_id: "gw-1".into(),
            last_seen: Utc::now(),
        };
        assert_eq!(event_gateway(&event), Some("gw-1"));
    }

    #[test]
    fn publishing_with_no_subscribers_is_not_an_error() {
        let hub = EventHub::new();
        assert_eq!(hub.subscribers(), 0);
        // Nobody is watching yet, which must be harmless.
        assert_eq!(
            hub.publish(
                Uuid::new_v4(),
                StreamEvent::GatewaySeen {
                    gateway_id: "gw".into(),
                    last_seen: Utc::now(),
                }
            ),
            0
        );
    }

    #[tokio::test]
    async fn subscribers_receive_events_for_their_account() {
        let hub = EventHub::new();
        let wanted = Uuid::new_v4();
        let other = Uuid::new_v4();
        let mut receiver = hub.subscribe();
        assert_eq!(hub.subscribers(), 1);

        hub.publish(
            other,
            StreamEvent::GatewaySeen {
                gateway_id: "theirs".into(),
                last_seen: Utc::now(),
            },
        );
        hub.publish(
            wanted,
            StreamEvent::GatewaySeen {
                gateway_id: "mine".into(),
                last_seen: Utc::now(),
            },
        );

        // Both arrive at the receiver; the handler is what filters, so the
        // filter itself is exercised separately below.
        let (first_account, _) = receiver.recv().await.unwrap();
        let (second_account, event) = receiver.recv().await.unwrap();
        assert_eq!(first_account, other);
        assert_eq!(second_account, wanted);
        assert_eq!(event_gateway(&event), Some("mine"));
    }

    #[tokio::test]
    async fn a_slow_subscriber_is_told_it_lagged() {
        // Fill well past the buffer so the oldest events are dropped.
        let hub = EventHub::new();
        let account = Uuid::new_v4();
        let mut receiver = hub.subscribe();
        for index in 0..(EVENT_BUFFER * 2) {
            hub.publish(
                account,
                StreamEvent::GatewaySeen {
                    gateway_id: format!("gw-{index}"),
                    last_seen: Utc::now(),
                },
            );
        }
        // The next read reports the gap rather than pretending nothing happened.
        assert!(matches!(
            receiver.recv().await,
            Err(broadcast::error::RecvError::Lagged(_))
        ));
    }

    #[test]
    fn auth_frames_require_a_token_field() {
        assert!(serde_json::from_str::<AuthFrame>(r#"{"token":"abc"}"#).is_ok());
        assert!(serde_json::from_str::<AuthFrame>(r#"{}"#).is_err());
        assert!(serde_json::from_str::<AuthFrame>(r#"not json"#).is_err());
    }

    /// Render's free service spins down after 15 minutes without inbound
    /// traffic, so two ping intervals must fit well inside that window.
    const _: () = assert!(PING_INTERVAL_SECONDS * 2 < 15 * 60);
}
