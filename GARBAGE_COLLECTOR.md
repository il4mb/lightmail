# Garbage Collector (Soft Delete)

LightMail uses a non-blocking, soft-delete strategy to ensure user-facing operations remain fast and resilient while handling large object deletions (S3).

## Design Goals
- Avoid blocking IMAP/POP3/API requests on slow S3 deletions
- Ensure safe, idempotent cleanup even across restarts
- Log and retry failures without impacting live sessions

## How It Works
1. Frontline operations (IMAP EXPUNGE, POP3 DELE, API delete) set `deleted_at = NOW()` on rows.
2. The background Garbage Worker periodically:
   - Queries soft-deleted items
   - Deletes corresponding S3 objects
   - Hard-deletes metadata rows from MySQL
   - Logs results with `tracing`

## Schema
On startup, the runtime ensures `deleted_at TIMESTAMP NULL` exists on key tables:
- `messages`
- `mailboxes`
- `calendars` (if present)

## Worker Behavior
- Batch size: configurable (`garbage.batch_size`, default 100)
- Sleep intervals: configurable (`garbage.pause_seconds` between batches; `garbage.idle_seconds` when idle)
- Resilient to errors: logs failures, leaves records for future retries
- Deletes `object_keys` row after successful S3 delete, then hard-deletes `messages` row

### Configuration

```
[garbage]
batch_size = 100
idle_seconds = 60
pause_seconds = 5
```

### Metrics
- Per-batch: processed, S3 failures, orphan deletions, DB failures, batch duration
- Totals: accumulated counters across runtime

## IMAP EXPUNGE
- Marks messages flagged with `\Deleted` as soft-deleted
- Emits untagged `n EXPUNGE` for each removed sequence number
- Finishes with `OK EXPUNGE completed`

## Future Improvements
- Dedicated retry queue with exponential backoff
- Quarantine mode for antivirus policies
- Metrics: deletion throughput, error rates, retry counts
