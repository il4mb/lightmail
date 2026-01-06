mod runtime;
mod utils;
mod protocol;
mod storage;
mod api;

use std::{ env, sync::Arc };
use std::path::Path;
use anyhow::Result;
use tracing::{ info, error };
use tracing_subscriber::filter::LevelFilter;

use crate::runtime::Runtime;
use crate::utils::config::{ ConfigLoader };

#[tokio::main]
async fn main() -> Result<()> {

    // Ensure rustls has an active crypto provider (required by rustls 0.23+).
    // Ignore errors if already installed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut config_path = String::from("/etc/lightmail/config.ini");
    let mut reload = false;
    let mut stop = false;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--reload" | "-r" => {
                reload = true;
            }
            "--config" | "-c" => {
                config_path = args.next().unwrap();
            }
            "--stop" | "-s" => {
                stop = true;
            }
            _ => {}
        }
    }

    if stop && reload {
        error!("--stop and --reload are mutually exclusive");
        std::process::exit(1);
    }

    // Resolve config path: honor CLI arg, else fallback for dev
    let resolved_path = if Path::new(&config_path).exists() {
        config_path.clone()
    } else {
        let dev_path = "config/lightmail.conf";
        if Path::new(dev_path).exists() {
            info!("Using dev config at {}", dev_path);
            dev_path.to_string()
        } else {
            config_path.clone()
        }
    };

    let loader = match ConfigLoader::new(resolved_path).load().await {
        Ok(loader) => loader,
        Err(e) => {
            error!("Failed to load config: {}", e);
            std::process::exit(1);
        }
    };
    let data = loader.get_config().clone();
    let config = Arc::new(data);

    // Initialize logging based on config
    // Defaults: plain logs; if logging.json=true, enable JSON format
    let json_enabled = config.get_value("logging", "json").map(|v| v == "true" || v == "1").unwrap_or(false);
    let level = match config.get_value("logging", "level").unwrap_or("info").to_lowercase().as_str() {
        "trace" => LevelFilter::TRACE,
        "debug" => LevelFilter::DEBUG,
        "info" => LevelFilter::INFO,
        "warn" => LevelFilter::WARN,
        "error" => LevelFilter::ERROR,
        _ => LevelFilter::INFO,
    };
    if json_enabled {
        tracing_subscriber::fmt().with_max_level(level).json().init();
    } else {
        tracing_subscriber::fmt().with_max_level(level).init();
    }

    let runtime = Arc::new(Runtime::new(config));
    let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    info!("LightMail Starting");
    runtime.run(&mut tasks).await?;

    // wait forever (or until one fails)
    for task in tasks {
        task.await?;
    }

    Ok(())
}
