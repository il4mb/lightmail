use sqlx::FromRow;

use crate::runtime::{ Runtime };

#[derive(Debug, FromRow)]
pub struct S3Object {
    pub id: i64,
    pub size: i64,
}

pub async fn delete_record(runtime: &Runtime, id: i64) -> anyhow::Result<()> {
    let db = runtime.db.get().ok_or_else(|| anyhow::anyhow!("DB not initialized"))?;
    sqlx::query("DELETE FROM object_keys WHERE id = ?").bind(id).execute(db.pool()).await?;
    Ok(())
}

pub async fn add_object(runtime: &Runtime, key: &str, content: &str) -> anyhow::Result<S3Object> {
    let s3 = runtime.s3.get().ok_or_else(|| anyhow::anyhow!("S3 not initialized"))?;

    let db = runtime.db.get().ok_or_else(|| anyhow::anyhow!("DB not initialized"))?;

    let pool = db.pool();
    let size = content.len() as i64;

    // 1️⃣ Upload to S3 first
    s3.put_content(key, content).await.map_err(|e| anyhow::anyhow!("S3 upload failed: {}", e))?;

    // 2️⃣ Insert metadata
    let result = sqlx
        ::query("INSERT INTO object_keys (`key`, size) VALUES (?, ?)")
        .bind(key)
        .bind(size)
        .execute(pool).await
        .map_err(|e| anyhow::anyhow!("DB insert failed: {}", e))?;

    let id = result.last_insert_id() as i64;

    Ok(S3Object { id, size })
}

pub async fn get_content(runtime: &Runtime, key: &str) -> anyhow::Result<String> {
    let s3 = runtime.s3.get().ok_or_else(|| anyhow::anyhow!("S3 not initialized"))?;
    let content = s3.get_content(key).await.map_err(|e| anyhow::anyhow!("S3 get failed: {}", e))?;
    Ok(content.unwrap_or("".to_string()).to_string())
}
