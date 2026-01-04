use super::{command::Command, state::SessionState};

pub fn handle(
    state: &mut SessionState,
    tag: &str,
    cmd: Command,
) -> Option<String> {
    match (&state, cmd) {
        (_, Command::Noop) => {
            Some(format!("{tag} OK NOOP completed\r\n"))
        }

        (SessionState::NotAuthenticated, Command::Login { user, .. }) => {
            *state = SessionState::Authenticated { user };
            Some(format!("{tag} OK LOGIN completed\r\n"))
        }

        (_, Command::Logout) => {
            *state = SessionState::Logout;
            Some(format!(
                "* BYE Logging out\r\n{tag} OK LOGOUT completed\r\n"
            ))
        }

        _ => {
            Some(format!("{tag} BAD Invalid command\r\n"))
        }
    }
}
