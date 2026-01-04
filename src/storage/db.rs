use percent_encoding::{ utf8_percent_encode, NON_ALPHANUMERIC };
use sqlx::{ mysql::MySqlPoolOptions, MySqlPool };
use anyhow::{ Context, Result };
use tracing::{ debug, info };
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub socket: Option<String>,
    pub user: String,
    pub password: String,
    pub database: String,
    pub pool_size: Option<u32>,
    pub pool_idle_timeout: Option<u64>,
    pub pool_max_lifetime: Option<u64>,
    pub connect_timeout: Option<u64>,
}

impl DatabaseConfig {
    pub fn build_url(&self) -> String {
        let encoded_pass = utf8_percent_encode(&self.password, NON_ALPHANUMERIC).to_string();
        let host = if self.host.trim() == "localhost" {
            "127.0.0.1".to_string()
        } else {
            self.host.to_string()
        };

        if let Some(socket) = &self.socket {
            format!(
                "mysql://{}:{}@localhost/{}?socket={}?ssl-mode=DISABLED",
                self.user,
                encoded_pass,
                self.database,
                socket
            )
        } else {
            format!(
                "mysql://{}:{}@{}:{}/{}?ssl-mode=DISABLED",
                self.user,
                encoded_pass,
                host,
                self.port,
                self.database
            )
        }
    }
}

#[derive(Debug, Clone)]
pub struct Database {
    config: DatabaseConfig,
    pool: MySqlPool,
}

impl Database {
    pub async fn new(config: DatabaseConfig) -> Result<Self> {
        let url = config.build_url();
        debug!("Connecting to database: {}", config.database);

        let pool = MySqlPoolOptions::new()
            .max_connections(config.pool_size.unwrap_or(10))
            .acquire_timeout(Duration::from_secs(config.connect_timeout.unwrap_or(30)))
            .idle_timeout(config.pool_idle_timeout.map(Duration::from_secs))
            .max_lifetime(config.pool_max_lifetime.map(Duration::from_secs))
            .connect(&url).await
            .with_context(|| format!("Failed to connect to database: {}", config.database))?;

        info!("Database connected successfully: {}", config.database);

        Ok(Self { config, pool })
    }

    pub fn pool(&self) -> &MySqlPool {
        &self.pool
    }

    pub async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await.context("Database ping failed")?;
        Ok(())
    }

    pub async fn close(&self) {
        self.pool.close().await;
        debug!("Database connection pool closed");
    }
}
