#[derive(Debug)]
pub enum SessionState {
    NotAuthenticated,
    Authenticated {
        user: String,
    },
    Logout,
}
