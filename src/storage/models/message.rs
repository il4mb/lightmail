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
        "SELECT * FROM messages WHERE mailbox_id = ? LIMIT ? OFFSET ? ORDER BY created_at DESC";
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
    let query = "SELECT * FROM messages WHERE id = ?";
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
        ::query_as::<_, Message>("SELECT * FROM messages WHERE id = ?")
        .bind(id)
        .fetch_one(pool).await?;

    Ok(message)
}
