//! Read-only HTTP API. No auth: bind it to 127.0.0.1 or a trusted LAN.
//!
//! GET /health   liveness + version
//! GET /status   latest status event
//! GET /devices  every device in view (flagged first), refreshed every second
//! GET /events   history from the database: ?since=<ms>&event=<type>&limit=<n> (max 1000)
//! GET /stream   live Server-Sent Events, same JSON as --json: ?events=alert,match

use crate::store;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Json};
use axum::routing::get;
use axum::Router;
use futures::stream::{self, Stream};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast;

pub struct Shared {
    pub devices: RwLock<Value>,
    pub status: RwLock<Value>,
    pub events: broadcast::Sender<Arc<Value>>,
    pub db: Option<String>,
    pub started: i64,
}

type Params = Query<HashMap<String, String>>;

pub async fn serve(addr: String, shared: Arc<Shared>) -> std::io::Result<()> {
    let app = Router::new()
        .route("/health", get(health))
        .route("/status", get(|State(s): State<Arc<Shared>>| async move { Json(s.status.read().unwrap().clone()) }))
        .route("/devices", get(|State(s): State<Arc<Shared>>| async move { Json(s.devices.read().unwrap().clone()) }))
        .route("/events", get(events))
        .route("/stream", get(stream))
        .with_state(shared);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await
}

async fn health(State(s): State<Arc<Shared>>) -> Json<Value> {
    Json(json!({"ok": true, "version": env!("CARGO_PKG_VERSION"), "schema": crate::events::SCHEMA_VERSION,
        "uptime_s": (crate::detect::now_ms() - s.started) / 1000}))
}

async fn events(State(s): State<Arc<Shared>>, Query(q): Params) -> impl IntoResponse {
    let Some(db) = s.db.clone() else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "no database configured (set db = ...)"})));
    };
    let since = q.get("since").and_then(|v| v.parse().ok()).unwrap_or(0);
    let limit = q.get("limit").and_then(|v| v.parse().ok()).unwrap_or(100).clamp(1, 1000);
    let event = q.get("event").cloned();
    let res = tokio::task::spawn_blocking(move || store::query_events(&db, since, event.as_deref(), limit)).await;
    match res {
        Ok(Ok(rows)) => (StatusCode::OK, Json(Value::Array(rows))),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))),
    }
}

async fn stream(State(s): State<Arc<Shared>>, Query(q): Params) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let only: Option<Vec<String>> = q.get("events").map(|v| v.split(',').map(str::to_string).collect());
    let rx = s.events.subscribe();
    let st = stream::unfold((rx, only), |(mut rx, only)| async move {
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    let kind = ev["event"].as_str().unwrap_or("");
                    if only.as_ref().is_none_or(|o| o.iter().any(|e| e == kind)) {
                        let e = Event::default().event(kind).data(ev.to_string());
                        return Some((Ok(e), (rx, only)));
                    }
                }
                // A slow client misses events rather than slowing the scanner.
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Sse::new(st).keep_alive(KeepAlive::default())
}
