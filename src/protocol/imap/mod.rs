pub mod handler;
pub mod parser;
pub mod state;
pub mod command;

use std::sync::Arc;

use crate::runtime::Runtime;

pub async fn run_imap(runtime: Arc<Runtime>) {

    let config = &runtime.config;
    let port = config.get_value("imap", "port").unwrap_or("143");
    let ssl_port = config.get_value("imap", "ssl_port").unwrap_or("993");

    // println!("port: {port}, ssl_port: {ssl_port}")
}
