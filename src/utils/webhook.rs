use std::{sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use serde::Serialize;
use tracing::{debug, warn};

use crate::runtime::Runtime;

#[derive(Debug, Clone, Serialize)]
pub struct WebhookEvent {
    pub event: String,
    pub protocol: String,
    pub timestamp: DateTime<Utc>,

    pub message_id: i64,
    pub mailbox_id: i64,
    pub object_id: i64,
    pub object_key: String,

    pub sender: String,
    pub recipient: Option<String>,
    pub subject: String,
    pub size: i64,
}

impl WebhookEvent {
    pub fn message_delivered(
        protocol: &str,
        message_id: i64,
        mailbox_id: i64,
        object_id: i64,
        object_key: String,
        sender: String,
        recipient: Option<String>,
        subject: String,
        size: i64,
    ) -> Self {
        Self {
            event: "message.delivered".to_string(),
            protocol: protocol.to_string(),
            timestamp: Utc::now(),
            message_id,
            mailbox_id,
            object_id,
            object_key,
            sender,
            recipient,
            subject,
            size,
        }
    }
}

fn parse_events_list(raw: Option<&str>) -> Vec<String> {
    let raw = raw.unwrap_or("message.delivered");
    raw.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

pub fn spawn_webhook_event(runtime: Arc<Runtime>, event: WebhookEvent) {
    let cfg = &runtime.config;

    let enabled = cfg.get_bool("webhook", "enabled", false);
    if !enabled {
        return;
    }

    let url = match cfg.get_value("webhook", "url") {
        Some(u) if !u.trim().is_empty() => u.trim().to_string(),
        _ => {
            warn!("webhook.enabled=true but webhook.url is missing");
            return;
        }
    };

    let subscribed = parse_events_list(cfg.get_value("webhook", "events"));
    if !subscribed.iter().any(|e| e == &event.event) {
        debug!("Webhook event '{}' ignored (not subscribed)", event.event);
        return;
    }

    let timeout_ms = cfg.get_int("webhook", "timeout_ms", 2000);
    let timeout = Duration::from_millis(timeout_ms.max(1) as u64);

    let token = cfg.get_value("webhook", "token").map(|s| s.trim().to_string());

    tokio::spawn(async move {
        let client = reqwest::Client::new();

        let mut req = client.post(&url).json(&event).timeout(timeout);
        if let Some(t) = token.as_ref().filter(|t| !t.is_empty()) {
            req = req.bearer_auth(t);
        }

        match req.send().await {
            Ok(resp) => {
                if !resp.status().is_success() {
                    warn!("Webhook POST failed: url={} status={}", url, resp.status());
                }
            }
            Err(e) => {
                warn!("Webhook POST error: url={} err={}", url, e);
            }
        }
    });
}
