pub mod state;

use sqlx::MySqlPool;
use state::{ MailboxStats, Mailbox };

use crate::utils::generate_uidvalidity;

// ignore unused, it will be implemented later
#[allow(unused)]
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

// ignore unused, it will be implemented later
#[allow(unused)]
pub async fn get_mailboxes(
    pool: &sqlx::MySqlPool,
    account_id: i64
) -> anyhow::Result<Vec<Mailbox>> {
    let query = "SELECT * FROM mailboxes WHERE account_id = ?";
    let mailboxes = sqlx::query_as(query).bind(account_id).fetch_all(pool).await?;
    Ok(mailboxes)
}

pub async fn list_mailboxes(
    pool: &sqlx::MySqlPool,
    account_id: i64,
    reference: &str,
    pattern: &str
) -> anyhow::Result<Vec<Mailbox>> {
    // Handle special patterns
    let (pattern_sql, _pattern_params): (String, Vec<()>) = match pattern {
        // Empty pattern means list all mailboxes
        "" => {
            if reference.is_empty() {
                ("%".to_string(), vec![])
            } else {
                // With reference, list mailboxes under that reference
                let ref_pattern = format!("{}%", reference.trim_end_matches('%'));
                (ref_pattern, vec![])
            }
        }
        // "%" wildcard - list all mailboxes
        "%" => ("%".to_string(), vec![]),
        // "*" wildcard - list all mailboxes (IMAP standard)
        "*" => ("%".to_string(), vec![]),
        // Pattern with % wildcards
        p if p.contains('%') => {
            let processed_pattern = if reference.is_empty() {
                p.to_string()
            } else {
                // Combine reference and pattern
                let ref_clean = reference.trim_end_matches('%');
                format!("{}{}", ref_clean, p)
            };
            (processed_pattern, vec![])
        }
        // Literal mailbox name
        p => {
            let exact_pattern = if reference.is_empty() {
                p.to_string()
            } else {
                format!("{}{}", reference, p)
            };
            (exact_pattern, vec![])
        }
    };

    // Build query based on subscription filter
    let query =
        r#"
            SELECT * 
            FROM mailboxes 
            WHERE account_id = ?
              AND name LIKE ?
            ORDER BY name
        "#;

    // Execute query
    let mut mailboxes = sqlx
        ::query_as::<_, Mailbox>(query)
        .bind(account_id)
        .bind(&pattern_sql)
        .fetch_all(pool).await?;

    // generate uidvalidity if it null
    for mailbox in &mut mailboxes {
        if Some(mailbox.uidvalidity).is_none() {
            let uid = generate_uidvalidity();
            set_uidvalidity(pool, mailbox.id, uid).await?;
            mailbox.uidvalidity = Some(uid);
        }
    }

    Ok(mailboxes)
}

pub async fn create_mailbox(pool: &sqlx::MySqlPool, mailbox: &Mailbox) -> anyhow::Result<Mailbox> {

    let account_id = mailbox.account_id;
    let name = mailbox.name.clone();
    let flags = mailbox.flags.clone();
    let created_at = mailbox.created_at.clone();
    let updated_at = mailbox.updated_at.clone();
    let uidvalidity = mailbox.uidvalidity.unwrap_or(generate_uidvalidity());

    let query ="INSERT INTO mailboxes (account_id, name, flags,  created_at, updated_at, uidvalidity) VALUES (?, ?, ?, ?, ?, ?)";
    let result = sqlx::query(query)
        .bind(account_id)
        .bind(name)
        .bind(flags)
        .bind(created_at)
        .bind(updated_at)
        .bind(uidvalidity)
        .execute(pool).await?;

    let last_id = result.last_insert_id() as i64;
    let mailbox = sqlx
        ::query_as::<_, Mailbox>("SELECT * FROM mailboxes WHERE id = ?")
        .bind(last_id)
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

pub async fn get_mailbox_stats(
    pool: &sqlx::MySqlPool,
    mailbox_id: i64
) -> anyhow::Result<MailboxStats> {
    let query =
        r#"
            SELECT 
            COUNT(*) AS total,
            CAST(COALESCE(SUM(flags LIKE '%\\Seen%'), 0) AS SIGNED) AS seen,
            CAST(
                COALESCE(
                SUM(
                    flags IS NULL
                    OR flags = ''
                    OR flags NOT LIKE '%\\Seen%'
                ),
                0
                ) AS SIGNED
            ) AS unseen,
            CAST(
                COALESCE(
                SUM(created_at > DATE_SUB(NOW(), INTERVAL 1 DAY)),
                0
                ) AS SIGNED
            ) AS recent
            FROM messages
            WHERE mailbox_id = ? AND deleted_at IS NULL
        "#;

    let (total, seen, unseen, recent): (i64, i64, i64, i64) = sqlx
        ::query_as(query)
        .bind(mailbox_id)
        .fetch_one(pool).await?;

    Ok(MailboxStats { total, seen, unseen, recent })
}

// ignore unused, it will be implemented later
#[allow(unused)]
pub async fn update_uidvalidity(pool: &sqlx::MySqlPool, mailbox_id: i64) -> anyhow::Result<()> {
    let uid = generate_uidvalidity();
    let query = "UPDATE mailboxes SET uidvalidity = ? WHERE id = ?";
    sqlx::query(query).bind(uid).bind(mailbox_id).execute(pool).await?;
    Ok(())
}

/*-----------------------------------------------------------------------
 * --------------------------- STATIC FUNCTION --------------------------
 * ----------------------------------------------------------------------
 */

async fn set_uidvalidity(
    pool: &MySqlPool,
    mailbox_id: i64,
    uidvalidity: i64
) -> anyhow::Result<()> {
    let query = "UPDATE mailboxes SET uidvalidity = ? WHERE id = ?";
    sqlx::query(query).bind(uidvalidity).bind(mailbox_id).execute(pool).await?;
    Ok(())
}
