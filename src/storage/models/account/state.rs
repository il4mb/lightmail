use sqlx::FromRow;
use chrono::{ DateTime, Utc };
use thiserror::Error;
use bcrypt;

// ignore unused, it will be implemented later
#[allow(unused)]
#[derive(Debug, FromRow)]
pub struct Account {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("account not found or password is incorrect")]
    InvalidCredentials,

    #[error(transparent)] Database(#[from] sqlx::Error),

    #[error(transparent)] Crypto(#[from] bcrypt::BcryptError),
}