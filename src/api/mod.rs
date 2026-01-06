use axum::{
    routing::{get, post, put, delete},
    Router,
    extract::{State, Request, Path, Query},
    middleware::{self, Next},
    response::Response,
    http::{StatusCode, HeaderMap},
    Json,
};
use tower_http::trace::TraceLayer;
use std::sync::Arc;
use crate::runtime::Runtime;
use crate::storage::models::calendar;
use crate::storage::models::{ account, mailbox, message };
use tracing::info;
use serde::{Deserialize, Serialize};

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
        // Admin endpoints
        .route("/admin/health", get(admin_health))
        .route("/admin/info", get(admin_info))
        .route("/admin/status", get(admin_status))
        .route("/admin/imap/config", get(admin_imap_config))
        .route("/admin/db/status", get(admin_db_status))
        .route("/admin/s3/status", get(admin_s3_status))
        // Admin: Accounts
        .route("/admin/accounts", get(admin_list_accounts))
        .route("/admin/accounts", post(admin_create_account))
        .route("/admin/accounts/{id}", put(admin_update_account_password))
        .route("/admin/accounts/{id}", delete(admin_delete_account))
        // Admin: Mailboxes
        .route("/admin/accounts/{account_id}/mailboxes", get(admin_list_mailboxes))
        .route("/admin/accounts/{account_id}/mailboxes", post(admin_create_mailbox))
        .route("/admin/mailboxes/{mailbox_id}", delete(admin_delete_mailbox))
        // Admin: Messages
        .route("/admin/mailboxes/{mailbox_id}/messages", get(admin_list_messages))
        .route("/admin/messages/{message_id}", delete(admin_delete_message))
        .route("/admin/messages/{message_id}/copy", post(admin_copy_message))
        .route("/admin/messages/{message_id}/move", post(admin_move_message))
            .route("/admin/send", post(admin_send_email))
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

#[derive(Serialize)]
struct AdminHealth { status: &'static str }

async fn admin_health() -> Json<AdminHealth> {
    Json(AdminHealth { status: "ok" })
}

#[derive(Serialize)]
struct AdminInfo {
    hostname: String,
    version: String,
}

async fn admin_info(State(runtime): State<Arc<Runtime>>) -> Json<AdminInfo> {
    let hostname = runtime.config.get_value("system", "hostname").unwrap_or("localhost").to_string();
    let version = env!("CARGO_PKG_VERSION").to_string();
    Json(AdminInfo { hostname, version })
}

#[derive(Serialize)]
struct AdminStatus {
    db_ok: bool,
    s3_ok: bool,
    imap_enabled: bool,
    lmtp_enabled: bool,
    pop3_enabled: bool,
    api_enabled: bool,
}

async fn admin_status(State(runtime): State<Arc<Runtime>>) -> Json<AdminStatus> {
    let db_ok = if let Some(db) = runtime.db.get() { db.ping().await.is_ok() } else { false };
    let s3_ok = runtime.s3.get().is_some();
    let imap_enabled = runtime.config.is_section_exists("imap");
    let lmtp_enabled = runtime.config.is_section_exists("lmtp");
    let pop3_enabled = runtime.config.is_section_exists("pop3");
    let api_enabled = runtime.config.is_section_exists("api");
    Json(AdminStatus { db_ok, s3_ok, imap_enabled, lmtp_enabled, pop3_enabled, api_enabled })
}


#[derive(Serialize)]
struct ImapConfig {
    bind: String,
    port: String,
    ssl_port: String,
    enable_ssl: bool,
    max_connections: usize,
}

async fn admin_imap_config(State(runtime): State<Arc<Runtime>>) -> Json<ImapConfig> {
    let bind = runtime.config.get_value("imap", "bind").unwrap_or("0.0.0.0").to_string();
    let port = runtime.config.get_value("imap", "port").unwrap_or("143").to_string();
    let ssl_port = runtime.config.get_value("imap", "ssl_port").unwrap_or("993").to_string();
    let enable_ssl = runtime.config
        .get_value("imap", "enable_ssl")
        .map(|v| v == "true" || v == "1").unwrap_or(false);
    let max_connections = runtime
        .config
        .get_value("imap", "max_connections")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);
    Json(ImapConfig { bind, port, ssl_port, enable_ssl, max_connections })
}

#[derive(Serialize)]
struct DbStatus { ok: bool }

async fn admin_db_status(State(runtime): State<Arc<Runtime>>) -> Json<DbStatus> {
    let ok = if let Some(db) = runtime.db.get() { db.ping().await.is_ok() } else { false };
    Json(DbStatus { ok })
}

#[derive(Serialize)]
struct S3Status { ok: bool, bucket: Option<String> }

async fn admin_s3_status(State(runtime): State<Arc<Runtime>>) -> Json<S3Status> {
    if let Some(s3) = runtime.s3.get() {
        Json(S3Status { ok: true, bucket: Some(s3.bucket().to_string()) })
    } else {
        Json(S3Status { ok: false, bucket: None })
    }
}

// ---------------------- Admin: Accounts ----------------------
#[derive(Serialize)]
struct AccountSummary { id: i64, username: String, is_active: bool }

async fn admin_list_accounts(State(runtime): State<Arc<Runtime>>) -> Result<Json<Vec<AccountSummary>>, StatusCode> {
    let db = runtime.db.get().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let rows: Vec<(i64, String, bool)> = sqlx::query_as("SELECT id, username, is_active FROM accounts ORDER BY id")
        .fetch_all(db.pool()).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let list = rows.into_iter().map(|(id, username, is_active)| AccountSummary { id, username, is_active }).collect();
    Ok(Json(list))
}

#[derive(Deserialize)]
struct CreateAccountReq { username: String, password: String }

async fn admin_create_account(State(runtime): State<Arc<Runtime>>, Json(req): Json<CreateAccountReq>) -> Result<Json<serde_json::Value>, StatusCode> {
    let db = runtime.db.get().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    match account::create_account(db.pool(), &req.username, &req.password).await {
        Ok(acc) => Ok(Json(serde_json::json!({"id": acc.id, "username": acc.username}))),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

#[derive(Deserialize)]
struct UpdatePasswordReq { password: String }

async fn admin_update_account_password(State(runtime): State<Arc<Runtime>>, Path(id): Path<i64>, Json(req): Json<UpdatePasswordReq>) -> Result<Json<serde_json::Value>, StatusCode> {
    let db = runtime.db.get().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    // Fetch account to get username
    let acc: Option<account::state::Account> = sqlx::query_as("SELECT * FROM accounts WHERE id = ?")
        .bind(id)
        .fetch_optional(db.pool()).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let acc = acc.ok_or(StatusCode::NOT_FOUND)?;
    // Hash new password and update
    let hash = bcrypt::hash(&req.password, bcrypt::DEFAULT_COST).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    sqlx::query("UPDATE accounts SET password_hash = ?, updated_at = NOW() WHERE id = ?")
        .bind(hash)
        .bind(id)
        .execute(db.pool()).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({"id": id, "username": acc.username, "updated": true})))
}

async fn admin_delete_account(State(runtime): State<Arc<Runtime>>, Path(id): Path<i64>) -> Result<Json<serde_json::Value>, StatusCode> {
    let db = runtime.db.get().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    sqlx::query("DELETE FROM accounts WHERE id = ?").bind(id).execute(db.pool()).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({"deleted": true, "id": id})))
}

// ---------------------- Admin: Mailboxes ----------------------
#[derive(Serialize)]
struct MailboxSummary { id: i64, name: String, flags: String }

async fn admin_list_mailboxes(State(runtime): State<Arc<Runtime>>, Path(account_id): Path<i64>) -> Result<Json<Vec<MailboxSummary>>, StatusCode> {
    let db = runtime.db.get().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    match mailbox::get_mailboxes(db.pool(), account_id).await {
        Ok(list) => {
            let res = list.into_iter().map(|m| MailboxSummary { id: m.id, name: m.name, flags: m.flags }).collect();
            Ok(Json(res))
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

#[derive(Deserialize)]
struct CreateMailboxReq { name: String, flags: Option<String> }

async fn admin_create_mailbox(State(runtime): State<Arc<Runtime>>, Path(account_id): Path<i64>, Json(req): Json<CreateMailboxReq>) -> Result<Json<serde_json::Value>, StatusCode> {
    let db = runtime.db.get().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let mb = crate::storage::models::mailbox::state::Mailbox {
        id: 0,
        account_id,
        name: req.name.clone(),
        flags: req.flags.unwrap_or_else(|| "".to_string()),
        quota: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        uidvalidity: Some(crate::utils::generate_uidvalidity()),
    };
    match mailbox::create_mailbox(db.pool(), &mb).await {
        Ok(m) => Ok(Json(serde_json::json!({"id": m.id, "name": m.name}))),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn admin_delete_mailbox(State(runtime): State<Arc<Runtime>>, Path(mailbox_id): Path<i64>) -> Result<Json<serde_json::Value>, StatusCode> {
    let db = runtime.db.get().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    // Soft delete mailbox when supported
    let res = sqlx::query("UPDATE mailboxes SET deleted_at = NOW() WHERE id = ?")
        .bind(mailbox_id)
        .execute(db.pool()).await;
    match res {
        Ok(_) => Ok(Json(serde_json::json!({"deleted": true, "id": mailbox_id}))),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

// ---------------------- Admin: Messages ----------------------
#[derive(Deserialize)]
struct ListMessagesQuery { limit: Option<i64>, offset: Option<i64> }

#[derive(Serialize)]
struct MessageSummary { id: i64, subject: String, sender: String, size: i64, uid: i64 }

async fn admin_list_messages(State(runtime): State<Arc<Runtime>>, Path(mailbox_id): Path<i64>, Query(q): Query<ListMessagesQuery>) -> Result<Json<Vec<MessageSummary>>, StatusCode> {
    let db = runtime.db.get().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let limit = q.limit.unwrap_or(50);
    let offset = q.offset.unwrap_or(0);
    match message::get_messages(db.pool(), mailbox_id, limit, offset).await {
        Ok(msgs) => {
            let res = msgs.into_iter().map(|m| MessageSummary { id: m.id, subject: m.subject, sender: m.sender, size: m.size, uid: m.uid }).collect();
            Ok(Json(res))
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn admin_delete_message(State(runtime): State<Arc<Runtime>>, Path(message_id): Path<i64>) -> Result<Json<serde_json::Value>, StatusCode> {
    let db = runtime.db.get().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    match message::mark_deleted(db.pool(), message_id).await {
        Ok(_) => Ok(Json(serde_json::json!({"deleted": true, "id": message_id}))),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

#[derive(Deserialize)]
struct MoveCopyReq { dest_mailbox_id: i64 }

async fn admin_copy_message(State(runtime): State<Arc<Runtime>>, Path(message_id): Path<i64>, Json(req): Json<MoveCopyReq>) -> Result<Json<serde_json::Value>, StatusCode> {
    let db = runtime.db.get().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    match message::copy_message_to_mailbox(db.pool(), message_id, req.dest_mailbox_id).await {
        Ok(new_msg) => Ok(Json(serde_json::json!({"copied": true, "new_id": new_msg.id}))),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn admin_move_message(State(runtime): State<Arc<Runtime>>, Path(message_id): Path<i64>, Json(req): Json<MoveCopyReq>) -> Result<Json<serde_json::Value>, StatusCode> {
    let db = runtime.db.get().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    match message::copy_message_to_mailbox(db.pool(), message_id, req.dest_mailbox_id).await {
        Ok(new_msg) => {
            let _ = message::delete_message(db.pool(), message_id).await;
            Ok(Json(serde_json::json!({"moved": true, "new_id": new_msg.id})))
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
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
