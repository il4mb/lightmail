// src/protocol/imap/state.rs
use std::collections::{ HashMap, HashSet };
use std::sync::Arc;
use parking_lot::RwLock;
use tracing::{ debug };
use uuid::Uuid;

use crate::utils::uuid7;

/// IMAP session state
/// RFC 3501: Each IMAP session has states: Not Authenticated, Authenticated, Selected, Logout
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImapState {
    NotAuthenticated, // Not logged in yet
    Authenticated, // Logged in, no mailbox selected
    Selected, // Mailbox selected
    Logout, // Logging out
}

// ignore unused, it will be implemented later
#[allow(unused)]
/// Mailbox metadata for selected mailbox
#[derive(Debug, Clone)]
pub struct SelectedMailbox {
    pub id: i64,
    pub name: String,
    pub uid_validity: i64,
    pub uid_next: i64,
    pub exists: i64, // Number of messages
    pub recent: i64, // Number of recent messages
    pub unseen: i64, // Number of unseen messages
    pub flags: Vec<String>, // Supported flags
    pub permanent_flags: Vec<String>,
    pub read_write: bool, // True if mailbox opened READ-WRITE
}

// ignore unused, it will be implemented later
#[allow(unused)]
/// Session flags and capabilities
#[derive(Debug, Clone)]
pub struct SessionFlags {
    pub idle_supported: bool,
    pub condstore_supported: bool,
    pub qresync_supported: bool,
    pub enable_sent: bool,
    pub literal_plus_supported: bool,
}

// ignore unused, it will be implemented later
#[allow(unused)]
/// IMAP session data
pub struct ImapSession {
    pub id: String,
    pub state: ImapState,
    pub selected_mailbox: Option<SelectedMailbox>,
    pub authenticated_user: Option<String>,
    pub authenticated_user_id: Option<i64>,
    pub capabilities: Vec<String>,
    pub session_flags: SessionFlags,
    pub tag_counter: u32,
    pub compression_active: bool,
    pub idle_active: bool,
    pub referenced_ids: HashSet<u32>,
    pub recent_uids: HashSet<u32>,
    pub enabled_features: HashSet<String>,

    // Connection info
    pub peer_addr: String,
    pub tls_active: bool,
    pub login_timestamp: Option<std::time::SystemTime>,

    // State for pipelining
    pub pending_commands: Vec<String>,
    pub in_literal: bool,
    pub literal_remaining: usize,
    pub literal_buffer: String,

    // Mailbox cache for performance
    mailbox_cache: Arc<RwLock<HashMap<Uuid, MailboxCacheEntry>>>,
}


/// Cache entry for mailbox data
// ignore unused, it will be implemented later
#[allow(unused)]
#[derive(Debug, Clone)]
pub struct MailboxCacheEntry {
    uid_validity: u32,
    uid_next: u32,
    exists: u32,
    recent: u32,
    unseen: u32,
    last_updated: std::time::SystemTime,
}

impl ImapSession {
    pub fn new(client_id: String) -> Self {
        let mut capabilities = vec![
            "IMAP4rev1".to_string(),
            "IDLE".to_string(),
            "UIDPLUS".to_string(),
            "MOVE".to_string(),
            "LITERAL+".to_string(),
            "SASL-IR".to_string(),
            "ENABLE".to_string(),
            "CONDSTORE".to_string(),
            "UTF8=ACCEPT".to_string(),
            "UTF8=ONLY".to_string()
        ];

        // Add AUTH mechanisms
        capabilities.push("AUTH=PLAIN".to_string());
        capabilities.push("AUTH=LOGIN".to_string());

        Self {
            id: uuid7(),
            state: ImapState::NotAuthenticated,
            selected_mailbox: None,
            authenticated_user: None,
            authenticated_user_id: None,
            capabilities,
            session_flags: SessionFlags {
                idle_supported: true,
                condstore_supported: true,
                qresync_supported: true,
                enable_sent: false,
                literal_plus_supported: true,
            },
            tag_counter: 1,
            compression_active: false,
            idle_active: false,
            referenced_ids: HashSet::new(),
            recent_uids: HashSet::new(),
            enabled_features: HashSet::new(),
            peer_addr: client_id,
            tls_active: false,
            login_timestamp: None,
            pending_commands: Vec::new(),
            in_literal: false,
            literal_remaining: 0,
            literal_buffer: String::new(),
            mailbox_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    // ignore unused, it will be implemented later
    #[allow(unused)]
    pub fn next_tag(&mut self) -> String {
        let tag = format!("A{:04}", self.tag_counter);
        self.tag_counter += 1;
        tag
    }

    pub fn authenticate(&mut self, username: String, user_id: i64) {
        self.authenticated_user = Some(username);
        self.authenticated_user_id = Some(user_id);
        self.state = ImapState::Authenticated;
        self.login_timestamp = Some(std::time::SystemTime::now());
        debug!("User authenticated: {}", self.authenticated_user.as_ref().unwrap());
    }

    pub fn logout(&mut self) {
        self.state = ImapState::Logout;
        self.authenticated_user = None;
        self.authenticated_user_id = None;
        self.selected_mailbox = None;
        self.idle_active = false;
        debug!("Session logged out: {}", self.id);
    }

    pub fn select_mailbox(&mut self, mailbox: SelectedMailbox, read_write: bool) {
        self.selected_mailbox = Some(mailbox);
        self.state = ImapState::Selected;
        if let Some(mb) = &mut self.selected_mailbox {
            mb.read_write = read_write;
        }
        debug!("Mailbox selected: {:?}", self.selected_mailbox.as_ref().unwrap().name);
    }

    pub fn unselect_mailbox(&mut self) {
        self.selected_mailbox = None;
        self.state = ImapState::Authenticated;
        debug!("Mailbox unselected");
    }

    // ignore unused, it will be implemented later
    #[allow(unused)]
    pub fn enable_feature(&mut self, feature: &str) -> bool {
        match feature {
            "CONDSTORE" => {
                self.enabled_features.insert(feature.to_string());
                self.session_flags.condstore_supported = true;
                true
            }
            "QRESYNC" => {
                self.enabled_features.insert(feature.to_string());
                self.session_flags.qresync_supported = true;
                true
            }
            _ => false,
        }
    }

    pub fn start_idle(&mut self) {
        self.idle_active = true;
        debug!("IDLE mode started");
    }

    pub fn stop_idle(&mut self) {
        self.idle_active = false;
        debug!("IDLE mode stopped");
    }

    // ignore unused, it will be implemented later
    #[allow(unused)]
    pub fn is_idle_active(&self) -> bool {
        self.idle_active
    }

    pub fn get_capabilities_string(&self) -> String {
        // Return configured capability list; STARTTLS and authentication policy
        // are handled by the handler/greeting layer per connection state.
        self.capabilities.join(" ")
    }

    // ignore unused, it will be implemented later
    #[allow(unused)]
    pub fn update_mailbox_cache(
        &self,
        mailbox_id: Uuid,
        uid_validity: u32,
        uid_next: u32,
        exists: u32,
        recent: u32,
        unseen: u32
    ) {
        let mut cache = self.mailbox_cache.write();
        cache.insert(mailbox_id, MailboxCacheEntry {
            uid_validity,
            uid_next,
            exists,
            recent,
            unseen,
            last_updated: std::time::SystemTime::now(),
        });
    }
    // ignore unused, it will be implemented later
    #[allow(unused)]
    pub fn get_mailbox_cache(&self, mailbox_id: &Uuid) -> Option<MailboxCacheEntry> {
        let cache = self.mailbox_cache.read();
        cache.get(mailbox_id).cloned()
    }

    // ignore unused, it will be implemented later
    #[allow(unused)]
    pub fn invalidate_mailbox_cache(&self, mailbox_id: &Uuid) {
        let mut cache = self.mailbox_cache.write();
        cache.remove(mailbox_id);
    }

    // ignore unused, it will be implemented later
    #[allow(unused)]
    pub fn add_recent_uid(&mut self, uid: u32) {
        self.recent_uids.insert(uid);
    }

    // ignore unused, it will be implemented later
    #[allow(unused)]
    pub fn clear_recent_uids(&mut self) {
        self.recent_uids.clear();
    }

    // ignore unused, it will be implemented later
    #[allow(unused)]
    pub fn is_recent_uid(&self, uid: u32) -> bool {
        self.recent_uids.contains(&uid)
    }
}
