use sqlx::MySqlPool;
use sqlx::types::Json;
use serde_json::Value;
use chrono::{ DateTime, Utc };

#[derive(Debug, sqlx::FromRow)]
pub struct Message {
    pub id: i64,
    pub mailbox_id: i64,
    pub object_id: i64,
    pub sender: String,
    pub subject: String,
    pub header: Json<Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[sqlx(default)]
    pub size: i64,
    #[sqlx(default)]
    pub uid: i64,
}

// ignore unused, it will be implemented later
#[allow(unused)]
pub async fn get_messages(
    pool: &MySqlPool,
    mailbox_id: i64,
    limit: i64,
    offset: i64
) -> anyhow::Result<Vec<Message>> {
    let query =
        "SELECT m.*, o.size, m.id as uid FROM messages m JOIN object_keys o ON m.object_id = o.id WHERE m.mailbox_id = ? AND m.deleted_at IS NULL ORDER BY m.created_at DESC LIMIT ? OFFSET ?";
    let messages = sqlx
        ::query_as(query)
        .bind(mailbox_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool).await?;
    Ok(messages)
}

// ignore unused, it will be implemented later
#[allow(unused)]
pub async fn get_message(pool: &MySqlPool, id: i64) -> anyhow::Result<Option<Message>> {
    let query = "SELECT m.*, o.size, m.id as uid FROM messages m JOIN object_keys o ON m.object_id = o.id WHERE m.id = ? AND m.deleted_at IS NULL";
    let message = sqlx::query_as::<_, Message>(query).bind(id).fetch_optional(pool).await?;
    // let message = match message {
    //     Some(mut msg) => {
    //         msg.body = s3::get_content(msg.id.to_string().as_str()).await?;
    //         Some(msg)
    //     }
    //     None => { None }
    // };

    Ok(message)
}

pub async fn get_flags(pool: &MySqlPool, message_id: i64) -> anyhow::Result<Option<String>> {
    let query = "SELECT flags FROM messages WHERE id = ?";
    let row: Option<(Option<String>,)> = sqlx::query_as(query)
        .bind(message_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.and_then(|t| t.0))
}

pub async fn update_flags(pool: &MySqlPool, message_id: i64, flags: &str) -> anyhow::Result<()> {
    let query = "UPDATE messages SET flags = ? WHERE id = ?";
    sqlx::query(query)
        .bind(flags)
        .bind(message_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_message(pool: &MySqlPool, message_id: i64) -> anyhow::Result<()> {
    let query = "DELETE FROM messages WHERE id = ?";
    sqlx::query(query)
        .bind(message_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn copy_message_to_mailbox(pool: &MySqlPool, message_id: i64, dest_mailbox_id: i64) -> anyhow::Result<Message> {
    if let Some(src) = get_message(pool, message_id).await? {
        let new_msg = Message {
            id: 0,
            mailbox_id: dest_mailbox_id,
            object_id: src.object_id,
            sender: src.sender.clone(),
            subject: src.subject.clone(),
            header: src.header.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            size: src.size,
            uid: 0,
        };
        let created = create_message(pool, &new_msg).await?;
        // Preserve flags if present
        if let Some(f) = src_header_flags(&src) {
            let _ = update_flags(pool, created.id, &f).await;
        } else if let Some(f) = src_flags_str(&src) {
            let _ = update_flags(pool, created.id, &f).await;
        }
        Ok(created)
    } else {
        Err(anyhow::anyhow!("Source message not found"))
    }
}

fn src_header_flags(_src: &Message) -> Option<String> {
    // In future, parse flags from header if needed
    None
}

fn src_flags_str(src: &Message) -> Option<String> {
    // Messages.flags may be NULL; return as-is if set
    // We don't have direct field for flags in struct; fetch via query when needed.
    // Placeholder: None
    let _ = src; // suppress unused
    None
}

pub async fn create_message(pool: &MySqlPool, message: &Message) -> anyhow::Result<Message> {
    let query =
        r#"
        INSERT INTO messages
        (mailbox_id, object_id, sender, subject, header, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    "#;

    let result = sqlx
        ::query(query)
        .bind(message.mailbox_id)
        .bind(message.object_id)
        .bind(&message.sender)
        .bind(&message.subject)
        .bind(&message.header)
        .bind(message.created_at)
        .bind(message.updated_at)
        .execute(pool).await?;

    let id = result.last_insert_id() as i64;

    // Fetch the full row
    let message = sqlx
        ::query_as::<_, Message>("SELECT m.*, o.size, m.id as uid FROM messages m JOIN object_keys o ON m.object_id = o.id WHERE m.id = ?")
        .bind(id)
        .fetch_one(pool).await?;

    Ok(message)
}

// ignore unused, it will be implemented later
#[allow(unused)]
pub async fn get_messages_by_uid_range(
    pool: &MySqlPool,
    mailbox_id: i64,
    start_uid: i64,
    end_uid: i64
) -> anyhow::Result<Vec<Message>> {
    let query =
        "SELECT m.*, o.size, m.id as uid FROM messages m JOIN object_keys o ON m.object_id = o.id WHERE m.mailbox_id = ? AND m.deleted_at IS NULL AND m.id >= ? AND m.id <= ? ORDER BY m.id ASC";
    let messages = sqlx
        ::query_as(query)
        .bind(mailbox_id)
        .bind(start_uid)
        .bind(end_uid)
        .fetch_all(pool).await?;
    Ok(messages)
}

// ignore unused, it will be implemented later
#[allow(unused)]
pub async fn get_messages_by_sequence_range(
    pool: &MySqlPool,
    mailbox_id: i64,
    start_seq: i64,
    end_seq: i64
) -> anyhow::Result<Vec<Message>> {
    let query =
        "SELECT m.*, o.size, m.id as uid FROM messages m JOIN object_keys o ON m.object_id = o.id WHERE m.mailbox_id = ? AND m.deleted_at IS NULL ORDER BY m.created_at ASC LIMIT ? OFFSET ?";
    let limit = end_seq - start_seq + 1;
    let offset = start_seq - 1;
    let messages = sqlx
        ::query_as(query)
        .bind(mailbox_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool).await?;
    Ok(messages)
}

// ignore unused, it will be implemented later
#[allow(unused)]
pub async fn get_message_count(pool: &MySqlPool, mailbox_id: i64) -> anyhow::Result<i64> {
    let query = "SELECT COUNT(*) as count FROM messages WHERE mailbox_id = ? AND deleted_at IS NULL";
    let (count,): (i64,) = sqlx::query_as(query).bind(mailbox_id).fetch_one(pool).await?;
    Ok(count)
}

pub async fn mark_deleted(pool: &MySqlPool, message_id: i64) -> anyhow::Result<()> {
    let query = "UPDATE messages SET deleted_at = NOW() WHERE id = ? AND deleted_at IS NULL";
    sqlx::query(query).bind(message_id).execute(pool).await?;
    Ok(())
}
