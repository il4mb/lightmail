use std::time::Duration;
use std::sync::Arc;
use std::time::Instant;
use anyhow::Result;
use tracing::{info, warn};

use crate::runtime::Runtime;
use crate::storage::models::object::get_key_by_id;

pub async fn run_garbage_worker(runtime: Arc<Runtime>) -> Result<()> {
    let db = runtime.db.get().ok_or_else(|| anyhow::anyhow!("DB not initialized"))?;
    let s3 = runtime.s3.get().ok_or_else(|| anyhow::anyhow!("S3 not initialized"))?;
    let pool = db.pool();

    // Configurable settings
    let batch_size = runtime.config.get_int("garbage", "batch_size", 100).max(1) as i64;
    let idle_interval = runtime.config.get_int("garbage", "idle_seconds", 60).max(1) as u64;
    let pause_seconds = runtime.config.get_int("garbage", "pause_seconds", 5).max(1) as u64;

    info!("Garbage worker started batch_size={} idle={}s pause={}s", batch_size, idle_interval, pause_seconds);

    // Metrics counters
    let mut total_processed: u64 = 0;
    let mut total_s3_failed: u64 = 0;
    let mut total_orphan_deleted: u64 = 0;
    let mut total_db_failed: u64 = 0;
    let mut total_batches: u64 = 0;

    loop {
        let batch_start = Instant::now();
        // Select a batch of soft-deleted messages
        let rows: Vec<(i64, i64)> = sqlx::query_as(
            "SELECT id, object_id FROM messages WHERE deleted_at IS NOT NULL LIMIT ?"
        )
        .bind(batch_size)
        .fetch_all(pool).await.unwrap_or_default();

        if rows.is_empty() {
            tokio::time::sleep(Duration::from_secs(idle_interval)).await;
            continue;
        }

        let mut processed = 0usize;
        let mut s3_failed = 0usize;
        let mut orphan_deleted = 0usize;
        let mut db_failed = 0usize;
        for (msg_id, object_id) in rows {
            // Get S3 key
            match get_key_by_id(pool, object_id).await {
                Ok(Some(key)) => {
                    // Attempt delete S3 content
                    match s3.delete_content(&key).await {
                        Ok(_) => {
                            // Sequential delete of DB metadata (object_keys then messages)
                            let res1 = sqlx::query("DELETE FROM object_keys WHERE id = ?")
                                .bind(object_id)
                                .execute(pool).await;
                            let res2 = sqlx::query("DELETE FROM messages WHERE id = ?")
                                .bind(msg_id)
                                .execute(pool).await;
                            if res1.is_ok() && res2.is_ok() {
                                processed += 1;
                                info!("Garbage collected message {} (key={})", msg_id, key);
                            } else {
                                db_failed += 1;
                                warn!("Failed deletes for msg_id={} object_id={} (res1_ok={} res2_ok={})", msg_id, object_id, res1.is_ok(), res2.is_ok());
                            }
                        }
                        Err(e) => {
                            warn!("Failed to delete S3 object for msg {}: {}", msg_id, e);
                            s3_failed += 1;
                        }
                    }
                }
                Ok(None) => {
                    // No object key: just delete message row to avoid leak
                    match sqlx::query("DELETE FROM messages WHERE id = ?")
                        .bind(msg_id)
                        .execute(pool).await {
                        Ok(_) => {
                            processed += 1;
                            orphan_deleted += 1;
                            warn!("Deleted orphaned message {} without object key (object_id={})", msg_id, object_id);
                        }
                        Err(e) => {
                            db_failed += 1;
                            warn!("Failed to delete orphaned message {}: {}", msg_id, e);
                        }
                    }
                }
                Err(e) => warn!("Error fetching object key for {}: {}", msg_id, e),
            }
        }

        total_processed += processed as u64;
        total_s3_failed += s3_failed as u64;
        total_orphan_deleted += orphan_deleted as u64;
        total_db_failed += db_failed as u64;
        total_batches += 1;

        let elapsed_ms = batch_start.elapsed().as_millis();
        info!(
            "Garbage batch processed={} s3_failed={} orphan_deleted={} db_failed={} duration={}ms pause={}s totals: processed={} s3_failed={} orphan_deleted={} db_failed={} batches={}",
            processed, s3_failed, orphan_deleted, db_failed, elapsed_ms, pause_seconds,
            total_processed, total_s3_failed, total_orphan_deleted, total_db_failed, total_batches
        );
        // Short pause between batches
        tokio::time::sleep(Duration::from_secs(pause_seconds)).await;
    }
}
