pub mod state;
use state::{ Account, AuthError };

use sqlx::{ self, MySqlPool };
use bcrypt;

pub async fn find_account(pool: &MySqlPool, username: &str) -> anyhow::Result<Option<Account>> {
    let query = "SELECT * FROM accounts WHERE username = ?";
    let user = sqlx::query_as::<_, Account>(query).bind(username).fetch_optional(pool).await?;
    Ok(user)
}

// ignore unused, it will be implemented later
#[allow(unused)]
pub async fn create_account(
    pool: &MySqlPool,
    username: &str,
    password: &str
) -> anyhow::Result<Account> {
    let password_hash = bcrypt::hash(password, bcrypt::DEFAULT_COST)?;
    let query = "INSERT INTO accounts (username, password_hash) VALUES (?, ?)";
    let user = sqlx
        ::query_as::<_, Account>(query)
        .bind(username)
        .bind(password_hash)
        .fetch_one(pool).await?;
    Ok(user)
}

// ignore unused, it will be implemented later
#[allow(unused)]
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

pub async fn authenticate(
    pool: &MySqlPool,
    username: &str,
    password: &str
) -> Result<i64, AuthError> {

    let query = "SELECT id, password_hash FROM accounts WHERE username = ?";
    let row: Option<(i64, String)> = sqlx
        ::query_as(query)
        .bind(username)
        .fetch_optional(pool).await?;

    let (id, password_hash) = match row {
        Some(r) => r,
        None => {
            return Err(AuthError::InvalidCredentials);
        }
    };

    let verified = bcrypt::verify(password, &password_hash)?;
    if !verified {
        return Err(AuthError::InvalidCredentials);
    }

    Ok(id)
}

// ignore unused, it will be implemented later
#[allow(unused)]
pub async fn is_exist(pool: &MySqlPool, username: &str) -> anyhow::Result<bool> {
    let query = "SELECT EXISTS(SELECT 1 FROM accounts WHERE username = ?)";
    let (exist,): (bool,) = sqlx::query_as(query).bind(username).fetch_one(pool).await?;
    Ok(exist)
}
