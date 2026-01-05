use sqlx::MySqlPool;
use chrono::{DateTime, Utc};
use crate::runtime::Runtime;
use crate::storage::models::object;
use serde::Serialize;

#[derive(Debug, sqlx::FromRow, Serialize)]
pub struct Calendar {
    pub id: i64,
    pub user_id: i64,
    pub name: String,
    pub color: Option<String>,
}

#[derive(Debug, sqlx::FromRow, Serialize)]
pub struct CalendarEvent {
    pub id: i64,
    pub calendar_id: i64,
    pub object_id: i64, // Link to S3 object
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub summary: Option<String>,
}

pub async fn create_calendar(pool: &MySqlPool, user_id: i64, name: &str) -> anyhow::Result<Calendar> {
    let result = sqlx::query("INSERT INTO calendars (user_id, name) VALUES (?, ?)")
        .bind(user_id)
        .bind(name)
        .execute(pool).await?;
    
    Ok(Calendar {
        id: result.last_insert_id() as i64,
        user_id,
        name: name.to_string(),
        color: None,
    })
}

pub async fn add_event(
    runtime: &Runtime,
    calendar_id: i64,
    ics_content: &str,
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
    summary: Option<String>
) -> anyhow::Result<CalendarEvent> {
    let key = format!("calendars/{}/{}", calendar_id, crate::utils::uuid7());
    let object = object::add_object(runtime, &key, ics_content).await?;
    
    let pool = runtime.db.get().unwrap().pool();
    let result = sqlx::query(
        "INSERT INTO calendar_events (calendar_id, object_id, start_time, end_time, summary) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(calendar_id)
    .bind(object.id)
    .bind(start_time)
    .bind(end_time)
    .bind(&summary)
    .execute(pool).await?;

    Ok(CalendarEvent {
        id: result.last_insert_id() as i64,
        calendar_id,
        object_id: object.id,
        start_time,
        end_time,
        summary,
    })
}

pub async fn list_events(pool: &MySqlPool, calendar_id: i64) -> anyhow::Result<Vec<CalendarEvent>> {
    let events = sqlx::query_as::<_, CalendarEvent>("SELECT * FROM calendar_events WHERE calendar_id = ?")
        .bind(calendar_id)
        .fetch_all(pool).await?;
    Ok(events)
}
