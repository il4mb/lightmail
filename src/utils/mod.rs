pub mod config;
pub mod garbage;

use uuid::{NoContext, Timestamp, Uuid};

/// Generate UUIDv7 (for object keys, message IDs, etc.)
pub fn uuid7() -> String {
    let ts = Timestamp::now(NoContext);
    Uuid::new_v7(ts).to_string()
}

/// Generate IMAP UIDVALIDITY from UUIDv7 timestamp
/// RFC 3501 compliant: non-zero, stable, integer
pub fn generate_uidvalidity() -> i64 {
    let ts = Timestamp::now(NoContext);

    // UUIDv7 timestamp is milliseconds since Unix epoch
    let millis = ts.to_unix().0;

    // IMAP servers usually use seconds
    (millis / 1000) as i64
}
