mod runtime;
mod utils;
mod protocol;
mod storage;
mod api;

use std::{ env, sync::Arc };
use anyhow::Result;
use tracing::{ info, error };

use crate::runtime::Runtime;
use crate::utils::config::{ ConfigLoader };

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

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

    let loader = ConfigLoader::new(config_path).load().await?;
    let data = loader.get_config().clone();
    let config = Arc::new(data);

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
