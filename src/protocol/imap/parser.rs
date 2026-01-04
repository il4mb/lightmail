use super::command::Command;

pub fn parse(line: &str) -> (String, Command) {
    let mut parts = line.trim().split_whitespace();
    let tag = parts.next().unwrap_or("").to_string();

    let cmd = match parts.next().map(|s| s.to_uppercase()) {
        Some(ref c) if c == "NOOP" => Command::Noop,
        Some(ref c) if c == "LOGOUT" => Command::Logout,
        Some(ref c) if c == "LOGIN" => {
            let user = parts.next().unwrap_or("").to_string();
            let pass = parts.next().unwrap_or("").to_string();
            Command::Login { user, pass }
        }
        _ => Command::Unknown,
    };

    (tag, cmd)
}
