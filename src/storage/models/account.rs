use sqlx::{ self, MySqlPool };
use sqlx::FromRow;
use chrono::{ DateTime, Utc };
use tracing::info;

#[derive(Debug, FromRow)]
pub struct Account {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub async fn find_account(pool: &MySqlPool, username: &str) -> anyhow::Result<Option<Account>> {
    let query = "SELECT * FROM accounts WHERE username = ?";
    let user = sqlx::query_as::<_, Account>(query).bind(username).fetch_optional(pool).await?;
    Ok(user)
}

pub async fn create_account(
    pool: &MySqlPool,
    username: &str,
    password_hash: &str
) -> anyhow::Result<Account> {
    let query = "INSERT INTO accounts (username, password_hash) VALUES (?, ?)";
    let user = sqlx
        ::query_as::<_, Account>(query)
        .bind(username)
        .bind(password_hash)
        .fetch_one(pool).await?;
    Ok(user)
}

pub async fn update_account(pool: &MySqlPool, user: &Account) -> anyhow::Result<Account> {
    let query = "UPDATE accounts SET username = ?, password_hash = ? WHERE id = ?";
    let user = sqlx
        ::query_as::<_, Account>(query)
        .bind(user.username.clone())
        .bind(user.password_hash.clone())
        .bind(user.id)
        .fetch_one(pool).await?;
    Ok(user)
}

pub async fn is_exist(pool: &MySqlPool, username: &str) -> anyhow::Result<bool> {
    let query = "SELECT EXISTS(SELECT 1 FROM accounts WHERE username = ?)";
    let (exist,): (bool,) = sqlx::query_as(query).bind(username).fetch_one(pool).await?;
    Ok(exist)
}
