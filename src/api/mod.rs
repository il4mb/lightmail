use axum::{
    routing::{get, post},
    Router,
    extract::{State, Request},
    middleware::{self, Next},
    response::Response,
    http::{StatusCode, HeaderMap},
    Json,
};
use tower_http::trace::TraceLayer;
use std::sync::Arc;
use crate::runtime::Runtime;
use crate::storage::models::calendar;
use tracing::info;
use serde::Deserialize;

pub async fn run_api(runtime: Arc<Runtime>) -> anyhow::Result<()> {
    let config = &runtime.config;
    let bind_addr = config.get_value("api", "bind").unwrap_or("0.0.0.0").to_string();
    let port = config.get_value("api", "port").unwrap_or("8080").to_string();
    let addr = format!("{}:{}", bind_addr, port);

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/stats", get(get_stats))
        .route("/calendar", post(create_calendar))
        .route("/calendar/event", post(add_event))
        .route("/calendar/events", get(list_events))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn_with_state(runtime.clone(), auth_middleware))
        .with_state(runtime);

    info!("API server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health_check() -> &'static str {
    "OK"
}

async fn get_stats(State(runtime): State<Arc<Runtime>>) -> String {
    let max_size = runtime.config.get_int("lmtp", "max_message_size", 50 * 1024 * 1024);
    let av_enabled = runtime.config.get_bool("antivirus", "enabled", false);
    format!("lmtp_max_bytes={} antivirus_enabled={}", max_size, av_enabled)
}

async fn auth_middleware(
    State(runtime): State<Arc<Runtime>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = runtime.config.get_value("api", "token").unwrap_or("secret");
    
    match headers.get("Authorization") {
        Some(auth_header) => {
            let auth_str = auth_header.to_str().map_err(|_| StatusCode::UNAUTHORIZED)?;
            if auth_str == format!("Bearer {}", token) {
                Ok(next.run(request).await)
            } else {
                Err(StatusCode::UNAUTHORIZED)
            }
        }
        None => Err(StatusCode::UNAUTHORIZED),
    }
}

#[derive(Deserialize)]
struct CreateCalendarRequest {
    user_id: i64,
    name: String,
}

async fn create_calendar(
    State(runtime): State<Arc<Runtime>>,
    Json(payload): Json<CreateCalendarRequest>,
) -> Result<String, StatusCode> {
    let db = runtime.db.get().unwrap();
    match calendar::create_calendar(db.pool(), payload.user_id, &payload.name).await {
        Ok(cal) => Ok(format!("Calendar created: {}", cal.id)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

#[derive(Deserialize)]
struct AddEventRequest {
    calendar_id: i64,
    content: String,
    summary: Option<String>,
}

async fn add_event(
    State(runtime): State<Arc<Runtime>>,
    Json(payload): Json<AddEventRequest>,
) -> Result<String, StatusCode> {
    match calendar::add_event(&runtime, payload.calendar_id, &payload.content, None, None, payload.summary).await {
        Ok(event) => Ok(format!("Event added: {}", event.id)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

#[derive(Deserialize)]
struct ListEventsRequest {
    calendar_id: i64,
}

async fn list_events(
    State(runtime): State<Arc<Runtime>>,
    Json(payload): Json<ListEventsRequest>,
) -> Result<Json<Vec<calendar::CalendarEvent>>, StatusCode> {
    let db = runtime.db.get().unwrap();
    match calendar::list_events(db.pool(), payload.calendar_id).await {
        Ok(events) => Ok(Json(events)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
