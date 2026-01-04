use chrono::{ DateTime, Utc };
use tracing::info;

#[derive(Debug, sqlx::FromRow)]
pub struct Mailbox {
    pub id: i64,
    pub account_id: i64,
    pub name: String,
    pub flags: String,
    pub quota: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub async fn get_mailbox(
    pool: &sqlx::MySqlPool,
    uid: &i64,
    id: i64
) -> anyhow::Result<Option<Mailbox>> {
    let query = "SELECT * FROM mailboxes WHERE id = ? AND account_id = ?";
    let mailbox = sqlx
        ::query_as::<_, Mailbox>(query)
        .bind(id)
        .bind(uid)
        .fetch_optional(pool).await?;
    Ok(mailbox)
}

pub async fn find_by_name(
    pool: &sqlx::MySqlPool,
    uid: &i64,
    name: &str
) -> anyhow::Result<Option<Mailbox>> {
    let query = "SELECT * FROM mailboxes WHERE name = ? AND account_id = ?";
    let mailbox = sqlx
        ::query_as::<_, Mailbox>(query)
        .bind(name)
        .bind(uid)
        .fetch_optional(pool).await?;

    Ok(mailbox)
}

pub async fn get_mailboxes(
    pool: &sqlx::MySqlPool,
    account_id: i64
) -> anyhow::Result<Vec<Mailbox>> {
    let query = "SELECT * FROM mailboxes WHERE account_id = ?";
    let mailboxes = sqlx::query_as(query).bind(account_id).fetch_all(pool).await?;
    Ok(mailboxes)
}

pub async fn create_mailbox(pool: &sqlx::MySqlPool, mailbox: &Mailbox) -> anyhow::Result<Mailbox> {
    let query =
        "INSERT INTO mailboxes (account_id, name, flags, created_at, updated_at) VALUES (?, ?, ?, ?, ?) RETURNING *";
    let mailbox = sqlx
        ::query_as(query)
        .bind(mailbox.account_id)
        .bind(mailbox.name.clone())
        .bind(mailbox.flags.clone())
        .bind(mailbox.created_at.clone())
        .bind(mailbox.updated_at.clone())
        .fetch_one(pool).await?;
    Ok(mailbox)
}

pub async fn check_quota(pool: &sqlx::MySqlPool, mailbox_id: i64) -> anyhow::Result<bool> {
    let query =
        r#"
        SELECT
            (SELECT COUNT(*) FROM messages WHERE mailbox_id = ?) AS msg_count,
            (SELECT quota FROM mailboxes WHERE id = ?) AS quota
    "#;

    let (count, quota): (i64, Option<i64>) = sqlx
        ::query_as(query)
        .bind(mailbox_id)
        .bind(mailbox_id)
        .fetch_one(pool).await?;

    // No quota means unlimited
    let quota = quota.unwrap_or(i64::MAX);

    Ok(count < quota)
}
