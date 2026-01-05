use tokio::net::TcpStream;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use std::sync::Arc;
use crate::runtime::Runtime;
use std::net::SocketAddr;
use anyhow::Result;
use tracing::{info};
use crate::storage::models::{account, mailbox, message, object};

pub struct Pop3Handler {
    runtime: Arc<Runtime>,
    _addr: SocketAddr,
    state: State,
    username: Option<String>,
    account_id: Option<i64>,
    messages: Vec<message::Message>,
    deleted: Vec<bool>,
}

#[derive(Debug, PartialEq)]
enum State {
    Authorization,
    Transaction,
    Update,
}

impl Pop3Handler {
    pub fn new(runtime: Arc<Runtime>, addr: SocketAddr) -> Self {
        Self {
            runtime,
            _addr: addr,
            state: State::Authorization,
            username: None,
            account_id: None,
            messages: Vec::new(),
            deleted: Vec::new(),
        }
    }

    pub async fn run(&mut self, stream: TcpStream) -> Result<()> {
        let (reader, writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut writer = BufWriter::new(writer);

        writer.write_all(b"+OK LightMail POP3 Server ready\r\n").await?;
        writer.flush().await?;

        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).await? == 0 {
                break;
            }

            let parts: Vec<&str> = line.trim().splitn(2, ' ').collect();
            if parts.is_empty() { continue; }
            let cmd = parts[0].to_uppercase();
            let arg = if parts.len() > 1 { Some(parts[1]) } else { None };

            match self.state {
                State::Authorization => {
                    match cmd.as_str() {
                        "USER" => self.handle_user(&mut writer, arg).await?,
                        "PASS" => self.handle_pass(&mut writer, arg).await?,
                        "QUIT" => {
                            writer.write_all(b"+OK Bye\r\n").await?;
                            writer.flush().await?;
                            return Ok(());
                        },
                        "CAPA" => {
                             writer.write_all(b"+OK Capability list follows\r\nUSER\r\nUIDL\r\nTOP\r\n.\r\n").await?;
                             writer.flush().await?;
                        }
                        _ => {
                            writer.write_all(b"-ERR Unknown command\r\n").await?;
                            writer.flush().await?;
                        }
                    }
                },
                State::Transaction => {
                    match cmd.as_str() {
                        "STAT" => self.handle_stat(&mut writer).await?,
                        "LIST" => self.handle_list(&mut writer, arg).await?,
                        "RETR" => self.handle_retr(&mut writer, arg).await?,
                        "DELE" => self.handle_dele(&mut writer, arg).await?,
                        "NOOP" => {
                            writer.write_all(b"+OK\r\n").await?;
                            writer.flush().await?;
                        },
                        "RSET" => self.handle_rset(&mut writer).await?,
                        "QUIT" => {
                            self.state = State::Update;
                            self.handle_update().await?;
                            writer.write_all(b"+OK Bye\r\n").await?;
                            writer.flush().await?;
                            return Ok(());
                        },
                        "UIDL" => self.handle_uidl(&mut writer, arg).await?,
                        _ => {
                            writer.write_all(b"-ERR Unknown command\r\n").await?;
                            writer.flush().await?;
                        }
                    }
                },
                State::Update => break,
            }
        }
        Ok(())
    }

    async fn handle_user(&mut self, writer: &mut BufWriter<tokio::net::tcp::OwnedWriteHalf>, arg: Option<&str>) -> Result<()> {
        if let Some(user) = arg {
            self.username = Some(user.to_string());
            writer.write_all(b"+OK User accepted\r\n").await?;
        } else {
            writer.write_all(b"-ERR User required\r\n").await?;
        }
        writer.flush().await?;
        Ok(())
    }

    async fn handle_pass(&mut self, writer: &mut BufWriter<tokio::net::tcp::OwnedWriteHalf>, arg: Option<&str>) -> Result<()> {
        if let Some(pass) = arg {
            if let Some(username) = &self.username {
                let db = self.runtime.db.get().unwrap();
                match account::authenticate(db.pool(), username, pass).await {
                    Ok(id) => {
                        self.account_id = Some(id);
                        self.state = State::Transaction;
                        
                        // Load messages from INBOX
                        if let Some(mailbox) = mailbox::find_by_name(db.pool(), &id, "INBOX").await? {
                             self.messages = message::get_messages(db.pool(), mailbox.id, 1000, 0).await?; // Limit 1000 for now
                             self.deleted = vec![false; self.messages.len()];
                             writer.write_all(b"+OK Pass accepted\r\n").await?;
                        } else {
                             writer.write_all(b"-ERR INBOX not found\r\n").await?;
                             self.state = State::Authorization; // Reset
                        }
                    },
                    Err(_) => {
                        writer.write_all(b"-ERR Authentication failed\r\n").await?;
                    }
                }
            } else {
                writer.write_all(b"-ERR User required\r\n").await?;
            }
        } else {
            writer.write_all(b"-ERR Password required\r\n").await?;
        }
        writer.flush().await?;
        Ok(())
    }

    async fn handle_stat(&mut self, writer: &mut BufWriter<tokio::net::tcp::OwnedWriteHalf>) -> Result<()> {
        let mut count = 0;
        let mut size = 0;
        
        for (i, msg) in self.messages.iter().enumerate() {
            if !self.deleted[i] {
                count += 1;
                size += msg.size; 
            }
        }
        writer.write_all(format!("+OK {} {}\r\n", count, size).as_bytes()).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn handle_list(&mut self, writer: &mut BufWriter<tokio::net::tcp::OwnedWriteHalf>, arg: Option<&str>) -> Result<()> {
        if let Some(arg) = arg {
            if let Ok(idx) = arg.parse::<usize>() {
                if idx > 0 && idx <= self.messages.len() && !self.deleted[idx-1] {
                    let msg = &self.messages[idx-1];
                    writer.write_all(format!("+OK {} {}\r\n", idx, msg.size).as_bytes()).await?;
                } else {
                    writer.write_all(b"-ERR No such message\r\n").await?;
                }
            } else {
                writer.write_all(b"-ERR Invalid argument\r\n").await?;
            }
        } else {
            writer.write_all(b"+OK List follows\r\n").await?;
            for (i, msg) in self.messages.iter().enumerate() {
                if !self.deleted[i] {
                    writer.write_all(format!("{} {}\r\n", i+1, msg.size).as_bytes()).await?;
                }
            }
            writer.write_all(b".\r\n").await?;
        }
        writer.flush().await?;
        Ok(())
    }

    async fn handle_retr(&mut self, writer: &mut BufWriter<tokio::net::tcp::OwnedWriteHalf>, arg: Option<&str>) -> Result<()> {
        if let Some(arg) = arg {
            if let Ok(idx) = arg.parse::<usize>() {
                if idx > 0 && idx <= self.messages.len() && !self.deleted[idx-1] {
                    let msg = &self.messages[idx-1];
                    let db = self.runtime.db.get().unwrap();
                    
                    // Get S3 key
                    if let Some(key) = object::get_key_by_id(db.pool(), msg.object_id).await? {
                        let s3 = self.runtime.s3.get().unwrap();
                        match s3.get_content(&key).await {
                            Ok(Some(content)) => {
                                writer.write_all(format!("+OK {} octets\r\n", content.len()).as_bytes()).await?;
                                // POP3 uses byte-stuffing for lines starting with .
                                for line in content.lines() {
                                    if line.starts_with('.') {
                                        writer.write_all(b".").await?;
                                    }
                                    writer.write_all(line.as_bytes()).await?;
                                    writer.write_all(b"\r\n").await?;
                                }
                                writer.write_all(b".\r\n").await?;
                            },
                            _ => {
                                writer.write_all(b"-ERR Message content not found\r\n").await?;
                            }
                        }
                    } else {
                        writer.write_all(b"-ERR Message key not found\r\n").await?;
                    }
                } else {
                    writer.write_all(b"-ERR No such message\r\n").await?;
                }
            } else {
                writer.write_all(b"-ERR Invalid argument\r\n").await?;
            }
        } else {
            writer.write_all(b"-ERR Argument required\r\n").await?;
        }
        writer.flush().await?;
        Ok(())
    }

    async fn handle_dele(&mut self, writer: &mut BufWriter<tokio::net::tcp::OwnedWriteHalf>, _arg: Option<&str>) -> Result<()> {
        // Read-only POP3: refuse deletions to prevent state drift from IMAP/LMTP
        writer.write_all(b"-ERR Deletion disabled
").await?;
        writer.flush().await?;
        Ok(())
    }

    async fn handle_rset(&mut self, writer: &mut BufWriter<tokio::net::tcp::OwnedWriteHalf>) -> Result<()> {
        for i in 0..self.deleted.len() {
            self.deleted[i] = false;
        }
        writer.write_all(b"+OK\r\n").await?;
        writer.flush().await?;
        Ok(())
    }

    async fn handle_uidl(&mut self, writer: &mut BufWriter<tokio::net::tcp::OwnedWriteHalf>, arg: Option<&str>) -> Result<()> {
        if let Some(arg) = arg {
            if let Ok(idx) = arg.parse::<usize>() {
                if idx > 0 && idx <= self.messages.len() && !self.deleted[idx-1] {
                    let msg = &self.messages[idx-1];
                    writer.write_all(format!("+OK {} {}\r\n", idx, msg.uid).as_bytes()).await?;
                } else {
                    writer.write_all(b"-ERR No such message\r\n").await?;
                }
            } else {
                writer.write_all(b"-ERR Invalid argument\r\n").await?;
            }
        } else {
            writer.write_all(b"+OK UIDL follows\r\n").await?;
            for (i, msg) in self.messages.iter().enumerate() {
                if !self.deleted[i] {
                    writer.write_all(format!("{} {}\r\n", i+1, msg.uid).as_bytes()).await?;
                }
            }
            writer.write_all(b".\r\n").await?;
        }
        writer.flush().await?;
        Ok(())
    }

    async fn handle_update(&mut self) -> Result<()> {
        let _db = self.runtime.db.get().unwrap();
        for (i, deleted) in self.deleted.iter().enumerate() {
            if *deleted {
                let msg = &self.messages[i];
                info!("Deleting message {}", msg.id);
                // TODO: Implement actual deletion
                // sqlx::query("DELETE FROM messages WHERE id = ?").bind(msg.id).execute(db.pool()).await?;
            }
        }
        Ok(())
    }
}
