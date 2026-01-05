/// IMAP command as defined in RFC 3501 (without optional subscription commands)
#[derive(Debug, Clone, PartialEq)]
pub enum ImapCommand {
    // Any state
    Capability,
    Noop,
    Logout,
    StartTls,

    // Not authenticated state
    Login {
        username: String,
        password: String,
    },
    Authenticate {
        mechanism: String,
        initial_response: Option<String>,
    },

    // Authenticated state
    Select {
        mailbox: String,
    },
    Examine {
        mailbox: String,
    },
    Create {
        mailbox: String,
    },
    Delete {
        mailbox: String,
    },
    Rename {
        from: String,
        to: String,
    },
    List {
        reference: String,
        pattern: String,
    },
    Status {
        mailbox: String,
        items: Vec<String>,
    },
    Append {
        mailbox: String,
        flags: Vec<String>,
        date_time: Option<String>,
        message: String,
    },

    // Selected state
    Check,
    Close,
    Expunge,
    Unselect,
    Search {
        criteria: SearchCriteria,
        charset: Option<String>,
    },
    Fetch {
        sequence_set: SequenceSet,
        items: Vec<FetchItem>,
    },
    Store {
        sequence_set: SequenceSet,
        flags: Vec<String>,
        operation: StoreOperation,
    },
    Copy {
        sequence_set: SequenceSet,
        mailbox: String,
    },
    Move {
        sequence_set: SequenceSet,
        mailbox: String,
    },
    Uid {
        command: Box<UidCommand>,
    },

    // Extensions (optional)
    Idle,
    #[allow(dead_code)]
    IdDone,
    Enable {
        features: Vec<String>,
    },
    Namespace,

    // Invalid/unknown
    Unknown {
        command: String,
    },
}

// ignore unused, it will be implemented later
#[allow(unused)]
#[derive(Debug, Clone, PartialEq)]
pub enum UidCommand {
    Fetch {
        sequence_set: SequenceSet,
        items: Vec<FetchItem>,
    },
    Search {
        criteria: SearchCriteria,
        charset: Option<String>,
    },
    Store {
        sequence_set: SequenceSet,
        flags: Vec<String>,
        operation: StoreOperation,
    },
    Copy {
        sequence_set: SequenceSet,
        mailbox: String,
    },
    Move {
        sequence_set: SequenceSet,
        mailbox: String,
    },
    Expunge,
}

// ignore unused, it will be implemented later
#[allow(unused)]
#[derive(Debug, Clone, PartialEq)]
pub enum SearchCriteria {
    All,
    Answered,
    Bcc(String),
    Before(String),
    Body(String),
    Cc(String),
    Deleted,
    Draft,
    Flagged,
    From(String),
    Header(String, String),
    Keyword(String),
    Larger(u32),
    New,
    Not(Box<SearchCriteria>),
    Old,
    On(String),
    Or(Box<SearchCriteria>, Box<SearchCriteria>),
    Recent,
    Seen,
    SentBefore(String),
    SentOn(String),
    SentSince(String),
    Since(String),
    Smaller(u32),
    Subject(String),
    Text(String),
    To(String),
    Uid(SequenceSet),
    Unanswered,
    Undeleted,
    Undraft,
    Unflagged,
    Unkeyword(String),
    Unseen,
    SequenceSet(SequenceSet),
}

// ignore unused, it will be implemented later
#[allow(unused)]
/// Sequence set (e.g., "1", "1:3", "1:*")
#[derive(Debug, Clone, PartialEq)]
pub struct SequenceSet {
    pub ranges: Vec<SequenceRange>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SequenceRange {
    Single(u32),
    Range(u32, u32), // start:end
    From(u32), // n:*
    To(u32), // *:n (less common)
}

// ignore unused, it will be implemented later
#[allow(unused)]
/// Fetch items
#[derive(Debug, Clone, PartialEq)]
pub enum FetchItem {
    All,
    Fast,
    Full,
    Body,
    BodyStructure,
    Envelope,
    Flags,
    InternalDate,
    Rfc822,
    Rfc822Header,
    Rfc822Size,
    Rfc822Text,
    Uid,
    BodySection {
        section: Option<Vec<u32>>,
        partial: Option<(u32, u32)>,
        peek: bool,
    },
    Binary {
        section: Vec<u32>,
        partial: Option<(u32, u32)>,
    },
    BinarySize {
        section: Vec<u32>,
    },
}

/// Store operation
#[derive(Debug, Clone, PartialEq)]
pub enum StoreOperation {
    Set, // +FLAGS
    Add, // +FLAGS.SILENT
    Remove, // -FLAGS
    Replace, // FLAGS
}
