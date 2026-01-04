#[derive(Debug)]
pub enum Command {
    Noop,
    Logout,
    Login { user: String, pass: String },
    Unknown,
}
