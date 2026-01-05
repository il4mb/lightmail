use chrono::{ DateTime, Utc };

// ignore unused, it will be implemented later
#[allow(unused)]
#[derive(Debug, sqlx::FromRow)]
pub struct Mailbox {
    pub id: i64,
    pub account_id: i64,
    pub name: String,
    pub flags: String,
    pub quota: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub uidvalidity: Option<i64>,
}

// ignore unused, it will be implemented later
#[allow(unused)]
#[derive(Debug, sqlx::FromRow)]
pub struct MailboxStats {
    pub total: i64,
    pub seen: i64,
    pub unseen: i64,
    pub recent: i64,
}
