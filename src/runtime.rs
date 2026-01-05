use std::sync::Arc;

use crate::{ protocol, storage::{ db, s3 }, utils::config::Config };

use tokio::sync::OnceCell;

pub struct Runtime {
    pub config: Arc<Config>,
    pub db: OnceCell<db::Database>,
    pub s3: OnceCell<s3::S3Client>,
}

impl Runtime {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config, db: OnceCell::const_new(), s3: OnceCell::const_new() }
    }

    async fn init_db(&self) -> anyhow::Result<()> {
        let db_config = db::DatabaseConfig {
            host: self.config.get_value("database", "host").unwrap_or("localhost").to_string(),

            port: self.config.get_value("database", "port").unwrap_or("3306").parse()?,

            socket: self.config.get_value("database", "socket").map(str::to_string),

            user: self.config.get_value("database", "user").unwrap_or("root").to_string(),

            password: self.config.get_value("database", "password").unwrap_or("").to_string(),

            database: self.config
                .get_value("database", "database")
                .unwrap_or("lightmail")
                .to_string(),

            pool_size: self.config
                .get_value("database", "pool_size")
                .map(|p| p.parse())
                .transpose()?,

            pool_idle_timeout: self.config
                .get_value("database", "pool_idle_timeout")
                .map(|p| p.parse())
                .transpose()?,

            pool_max_lifetime: self.config
                .get_value("database", "pool_max_lifetime")
                .map(|p| p.parse())
                .transpose()?,

            connect_timeout: self.config
                .get_value("database", "connect_timeout")
                .map(|p| p.parse())
                .transpose()?,
        };

        let db = db::Database
            ::new(db_config).await
            .map_err(|e| anyhow::anyhow!("DB init failed: {}", e))?;

        self.db.set(db).map_err(|_| anyhow::anyhow!("Database already initialized"))?;

        tracing::info!("Database initialized");
        Ok(())
    }

    async fn init_s3(&self) -> anyhow::Result<()> {
        if !self.config.is_section_exists("s3") {
            panic!("S3 config not found");
        }
        if self.config.get_value("s3", "endpoint").is_none() {
            panic!("S3 endpoint not found");
        }
        if self.config.get_value("s3", "bucket").is_none() {
            panic!("S3 bucket not found");
        }
        if self.config.get_value("s3", "access_key").is_none() {
            panic!("S3 access key not found");
        }
        if self.config.get_value("s3", "secret_key").is_none() {
            panic!("S3 secret key not found");
        }

        let s3_config = s3::S3Config {
            endpoint: self.config.get_value("s3", "endpoint").unwrap_or("").to_string(),
            bucket: self.config.get_value("s3", "bucket").unwrap_or("").to_string(),
            region: self.config.get_value("s3", "region").map(str::to_string),
            access_key: self.config.get_value("s3", "access_key").unwrap_or("").to_string(),
            secret_key: self.config.get_value("s3", "secret_key").unwrap_or("").to_string()
        };

        let s3 = s3::S3Client
            ::new(s3_config).await
            .map_err(|e| anyhow::anyhow!("S3 init failed: {}", e))?;

        self.s3.set(s3).map_err(|_| anyhow::anyhow!("S3 already initialized"))?;

        tracing::info!("S3 initialized");
        Ok(())
    }

    pub async fn run(self: Arc<Self>,tasks: &mut Vec<tokio::task::JoinHandle<()>>) -> anyhow::Result<()> {
        
        self.init_db().await?;
        self.init_s3().await?;

        if self.config.is_section_exists("imap") {
            let rt = Arc::clone(&self);
            tasks.push(
                tokio::spawn(async move {
                    let _ = protocol::imap::run_imap(rt).await;
                })
            );
        }

        if self.config.is_section_exists("lmtp") {
            let rt = Arc::clone(&self);
            tasks.push(
                tokio::spawn(async move {
                    protocol::lmtp::run_lmtp(rt).await;
                })
            );
        }

        Ok(())
    }
}
