pub mod state;

use crate::protocol::imap::{ parser::{ parse_astring } };
use crate::protocol::imap::command::state::UidCommand;
use self::state::{
    ImapCommand,
    SearchCriteria,
    SequenceRange,
    SequenceSet,
    FetchItem,
    StoreOperation,
};
use nom::{
    IResult,
    Parser,
    branch::alt,
    bytes::complete::{ tag, take_while, take_while1 },
    character::complete::{ char, digit1, space0, space1 },
    combinator::{ map, opt },
    multi::{ many0, many1 },
    sequence::{ delimited, preceded, separated_pair, terminated },
};

/// Parse IMAP command line
pub fn parse_command(input: &str) -> IResult<&str, (String, ImapCommand)> {
    let (input, tag) = parse_tag(input)?;
    let (input, _) = space1(input)?;
    let (input, command) = parse_command_body(input)?;

    Ok((input, (tag.to_string(), command)))
}

fn parse_tag(input: &str) -> IResult<&str, &str> {
    // Tag can be any ASCII string except + or *
    take_while1(|c: char| c.is_ascii() && c != '+' && c != '*' && !c.is_whitespace()).parse(input)
}

fn parse_command_body(input: &str) -> IResult<&str, ImapCommand> {
    alt([
        // Core required commands
        parse_capability,
        parse_noop,
        parse_logout,
        parse_login,
        parse_authenticate,
        parse_starttls,
        parse_select,
        // parse_examine,
        parse_create,
        parse_delete,
        parse_rename,
        parse_list,
        parse_lsub,
        parse_status,
        parse_append,
        parse_check,
        parse_close,
        parse_expunge,
        parse_unselect,
        parse_search,
        parse_fetch,
        parse_store,
        parse_copy,
        parse_move,
        parse_uid,

        // Optional extensions (still parsing but can return "NO" in handler)
        parse_idle,
        parse_enable,
        parse_namespace,

        // Unknown command
        parse_unknown,
    ]).parse(input)
}

// Core command parsers
fn parse_capability(input: &str) -> IResult<&str, ImapCommand> {
    map(tag_no_case("CAPABILITY"), |_| ImapCommand::Capability).parse(input)
}

fn parse_noop(input: &str) -> IResult<&str, ImapCommand> {
    map(tag_no_case("NOOP"), |_| ImapCommand::Noop).parse(input)
}

fn parse_logout(input: &str) -> IResult<&str, ImapCommand> {
    map(tag_no_case("LOGOUT"), |_| ImapCommand::Logout).parse(input)
}

fn parse_login(input: &str) -> IResult<&str, ImapCommand> {
    let (input, _) = tag_no_case("LOGIN").parse(input)?;
    let (input, _) = space1(input)?;
    let (input, username) = parse_astring(input)?;
    let (input, _) = space1(input)?;
    let (input, password) = parse_astring(input)?;

    Ok((
        input,
        ImapCommand::Login {
            username: username.to_string(),
            password: password.to_string(),
        },
    ))
}

fn parse_select(input: &str) -> IResult<&str, ImapCommand> {
    let (input, cmd) = alt((tag_no_case("SELECT"), tag_no_case("EXAMINE"))).parse(input)?;

    let (input, _) = space1(input)?;
    let (input, mailbox) = parse_mailbox(input)?;

    let command = match cmd.to_uppercase().as_str() {
        "SELECT" => ImapCommand::Select { mailbox: mailbox.to_string() },
        "EXAMINE" => ImapCommand::Examine { mailbox: mailbox.to_string() },
        _ => unreachable!(),
    };

    Ok((input, command))
}

fn parse_fetch(input: &str) -> IResult<&str, ImapCommand> {
    let (input, _) = tag_no_case("FETCH").parse(input)?;
    let (input, _) = space1(input)?;
    let (input, sequence_set) = parse_sequence_set(input)?;
    let (input, _) = space1(input)?;
    let (input, items) = parse_fetch_items(input)?;

    Ok((input, ImapCommand::Fetch { sequence_set, items }))
}

fn parse_store(input: &str) -> IResult<&str, ImapCommand> {
    let (input, _) = tag_no_case("STORE").parse(input)?;
    let (input, _) = space1(input)?;
    let (input, sequence_set) = parse_sequence_set(input)?;
    let (input, _) = space1(input)?;
    let (input, (operation, flags)) = parse_store_operation(input)?;

    Ok((
        input,
        ImapCommand::Store {
            sequence_set,
            flags,
            operation,
        },
    ))
}

fn parse_search(input: &str) -> IResult<&str, ImapCommand> {
    let (input, _) = tag_no_case("SEARCH").parse(input)?;
    let (input, charset) = opt(preceded(space1, parse_charset)).parse(input)?;
    let (input, criteria) = parse_search_criteria(input)?;

    Ok((input, ImapCommand::Search { criteria, charset }))
}

fn parse_uid(input: &str) -> IResult<&str, ImapCommand> {
    let (input, _) = tag_no_case("UID").parse(input)?;
    let (input, _) = space1(input)?;

    alt((
        map(parse_uid_fetch, |(seq, items)| {
            ImapCommand::Uid { command: Box::new(UidCommand::Fetch { sequence_set: seq, items }) }
        }),
        map(parse_uid_search, |(criteria, charset)| {
            ImapCommand::Uid { command: Box::new(UidCommand::Search { criteria, charset }) }
        }),
        map(parse_uid_store, |(seq, operation, flags)| {
            ImapCommand::Uid {
                command: Box::new(UidCommand::Store { sequence_set: seq, flags, operation }),
            }
        }),
    )).parse(input)
}

// Mailbox management parsers
fn parse_create(input: &str) -> IResult<&str, ImapCommand> {
    let (input, _) = tag_no_case("CREATE").parse(input)?;
    let (input, _) = space1(input)?;
    let (input, mailbox) = parse_mailbox(input)?;

    Ok((input, ImapCommand::Create { mailbox: mailbox.to_string() }))
}

fn parse_delete(input: &str) -> IResult<&str, ImapCommand> {
    let (input, _) = tag_no_case("DELETE").parse(input)?;
    let (input, _) = space1(input)?;
    let (input, mailbox) = parse_mailbox(input)?;

    Ok((input, ImapCommand::Delete { mailbox: mailbox.to_string() }))
}

fn parse_rename(input: &str) -> IResult<&str, ImapCommand> {
    let (input, _) = tag_no_case("RENAME").parse(input)?;
    let (input, _) = space1(input)?;
    let (input, from) = parse_mailbox(input)?;
    let (input, _) = space1(input)?;
    let (input, to) = parse_mailbox(input)?;

    Ok((
        input,
        ImapCommand::Rename {
            from: from.to_string(),
            to: to.to_string(),
        },
    ))
}

fn parse_list(input: &str) -> IResult<&str, ImapCommand> {
    let (input, _) = tag_no_case("LIST").parse(input)?;
    let (input, _) = space1(input)?;
    let (input, reference) = parse_mailbox(input)?;
    let (input, _) = space1(input)?;
    let (input, pattern) = parse_mailbox(input)?;

    Ok((
        input,
        ImapCommand::List {
            reference: reference.to_string(),
            pattern: pattern.to_string(),
        },
    ))
}

fn parse_lsub(input: &str) -> IResult<&str, ImapCommand> {
    let (input, _) = tag_no_case("LSUB").parse(input)?;
    let (input, _) = space1(input)?;
    let (input, reference) = parse_mailbox(input)?;
    let (input, _) = space1(input)?;
    let (input, pattern) = parse_mailbox(input)?;

    Ok((
        input,
        ImapCommand::Lsub {
            reference: reference.to_string(),
            pattern: pattern.to_string(),
        },
    ))
}

fn parse_status(input: &str) -> IResult<&str, ImapCommand> {
    let (input, _) = tag_no_case("STATUS").parse(input)?;
    let (input, _) = space1(input)?;
    let (input, mailbox) = parse_mailbox(input)?;
    let (input, _) = space1(input)?;
    let (input, items) = parse_status_items(input)?;

    Ok((
        input,
        ImapCommand::Status {
            mailbox: mailbox.to_string(),
            items,
        },
    ))
}

fn parse_append(input: &str) -> IResult<&str, ImapCommand> {
    let (input, _) = tag_no_case("APPEND").parse(input)?;
    let (input, _) = space1(input)?;
    let (input, mailbox) = parse_mailbox(input)?;
    let (input, flags) = opt(preceded(space1, parse_flag_list)).parse(input)?;
    let (input, date_time) = opt(preceded(space1, parse_datetime)).parse(input)?;

    Ok((
        input,
        ImapCommand::Append {
            mailbox: mailbox.to_string(),
            flags: flags.unwrap_or_default(),
            date_time: date_time.unwrap_or_default(),
            message: String::new(), // Placeholder - will be handled as literal
        },
    ))
}

// Selected state parsers
fn parse_check(input: &str) -> IResult<&str, ImapCommand> {
    map(tag_no_case("CHECK"), |_| ImapCommand::Check).parse(input)
}

fn parse_close(input: &str) -> IResult<&str, ImapCommand> {
    map(tag_no_case("CLOSE"), |_| ImapCommand::Close).parse(input)
}

fn parse_expunge(input: &str) -> IResult<&str, ImapCommand> {
    map(tag_no_case("EXPUNGE"), |_| ImapCommand::Expunge).parse(input)
}

fn parse_unselect(input: &str) -> IResult<&str, ImapCommand> {
    map(tag_no_case("UNSELECT"), |_| ImapCommand::Unselect).parse(input)
}

fn parse_copy(input: &str) -> IResult<&str, ImapCommand> {
    let (input, _) = tag_no_case("COPY").parse(input)?;
    let (input, _) = space1(input)?;
    let (input, sequence_set) = parse_sequence_set(input)?;
    let (input, _) = space1(input)?;
    let (input, mailbox) = parse_mailbox(input)?;

    Ok((
        input,
        ImapCommand::Copy {
            sequence_set,
            mailbox: mailbox.to_string(),
        },
    ))
}

fn parse_move(input: &str) -> IResult<&str, ImapCommand> {
    let (input, _) = tag_no_case("MOVE").parse(input)?;
    let (input, _) = space1(input)?;
    let (input, sequence_set) = parse_sequence_set(input)?;
    let (input, _) = space1(input)?;
    let (input, mailbox) = parse_mailbox(input)?;

    Ok((
        input,
        ImapCommand::Move {
            sequence_set,
            mailbox: mailbox.to_string(),
        },
    ))
}

// Authentication/security parsers
fn parse_starttls(input: &str) -> IResult<&str, ImapCommand> {
    map(tag_no_case("STARTTLS"), |_| ImapCommand::StartTls).parse(input)
}

fn parse_authenticate(input: &str) -> IResult<&str, ImapCommand> {
    let (input, _) = tag_no_case("AUTHENTICATE").parse(input)?;
    let (input, _) = space1(input)?;
    let (input, mechanism) = parse_auth_mechanism(input)?;
    let (input, initial_response) = opt(preceded(space1, parse_initial_response)).parse(input)?;

    Ok((
        input,
        ImapCommand::Authenticate {
            mechanism: mechanism.to_string(),
            initial_response: initial_response.map(|s| s.unwrap().to_string()),
        },
    ))
}

// Extension parsers (optional)
fn parse_idle(input: &str) -> IResult<&str, ImapCommand> {
    map(tag_no_case("IDLE"), |_| ImapCommand::Idle).parse(input)
}

fn parse_enable(input: &str) -> IResult<&str, ImapCommand> {
    let (input, _) = tag_no_case("ENABLE").parse(input)?;
    let (input, _) = space1(input)?;
    let (input, features) = parse_enable_features(input)?;

    Ok((input, ImapCommand::Enable { features }))
}

fn parse_namespace(input: &str) -> IResult<&str, ImapCommand> {
    map(tag_no_case("NAMESPACE"), |_| ImapCommand::Namespace).parse(input)
}

fn parse_unknown(input: &str) -> IResult<&str, ImapCommand> {
    map(
        take_while1(|c: char| !c.is_whitespace()),
        |cmd: &str| { ImapCommand::Unknown { command: cmd.to_string() } }
    ).parse(input)
}

// Helper parsers
fn tag_no_case(tag: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input: &str| {
        if input.len() < tag.len() {
            return Err(nom::Err::Error(nom::error::make_error(input, nom::error::ErrorKind::Tag)));
        }

        let prefix = &input[..tag.len()];
        if prefix.eq_ignore_ascii_case(tag) {
            Ok((&input[tag.len()..], prefix))
        } else {
            Err(nom::Err::Error(nom::error::make_error(input, nom::error::ErrorKind::Tag)))
        }
    }
}

// fn parse_astring(input: &str) -> IResult<&str, &str> {
//     // Simplified astring parser - for production use RFC 3501 complete grammar
//     take_while1(|c: char| c.is_ascii() && !c.is_whitespace() && c != '{').parse(input)
// }

fn parse_mailbox(input: &str) -> IResult<&str, &str> {
    // Mailbox can be quoted or literal
    alt((
        // Quoted string
        delimited(
            char('"'),
            take_while(|c: char| c != '"'),
            char('"')
        ),
        // Literal string
        delimited(
            char('\''),
            take_while(|c: char| c != '\''),
            char('\'')
        ),
        // Astring (simplified)
        take_while1(
            |c: char|
                c.is_ascii_graphic() &&
                c != '{' &&
                c != '(' &&
                c != ')' &&
                c != '%' &&
                c != '*' &&
                c != '"' &&
                c != '\'' &&
                !c.is_whitespace()
        ),
    )).parse(input)
}

fn parse_sequence_set(input: &str) -> IResult<&str, SequenceSet> {
    let (input, ranges) = many1(
        terminated(parse_sequence_range, opt(preceded(opt(space0), char(','))))
    ).parse(input)?;

    Ok((input, SequenceSet { ranges }))
}

fn parse_sequence_range(input: &str) -> IResult<&str, SequenceRange> {
    alt((
        // n:m range
        map(
            separated_pair(parse_seq_number, char(':'), parse_seq_number),
            |(start, end): (SeqNumber, SeqNumber)| {
                match (start, end) {
                    (SeqNumber::Value(s), SeqNumber::Value(e)) => SequenceRange::Range(s, e),
                    (SeqNumber::Value(s), SeqNumber::Star) => SequenceRange::From(s),
                    (SeqNumber::Star, SeqNumber::Value(e)) => SequenceRange::To(e),
                    (SeqNumber::Star, SeqNumber::Star) => SequenceRange::Range(1, u32::MAX), // *:*
                }
            }
        ),
        // Single number or *
        map(parse_seq_number, |num| {
            match num {
                SeqNumber::Value(n) => SequenceRange::Single(n),
                SeqNumber::Star => SequenceRange::Single(u32::MAX), // Treat * as max
            }
        }),
    )).parse(input)
}

#[derive(Debug, Clone, PartialEq)]
enum SeqNumber {
    Value(u32),
    Star,
}

fn parse_seq_number(input: &str) -> IResult<&str, SeqNumber> {
    alt((
        map(tag("*"), |_| SeqNumber::Star),
        map(digit1, |s: &str| SeqNumber::Value(s.parse().unwrap())),
    )).parse(input)
}

fn parse_fetch_items(input: &str) -> IResult<&str, Vec<FetchItem>> {
    let (input, _) = char('(').parse(input)?;
    let (input, items) = many0(
        terminated(
            map(
                take_while1(|c: char| c.is_ascii_alphabetic() || c == '.' || c == '[' ),
                |s: &str| {
                    match s.to_uppercase().as_str() {
                        "ALL" => FetchItem::All,
                        "FAST" => FetchItem::Fast,
                        "FULL" => FetchItem::Full,
                        "FLAGS" => FetchItem::Flags,
                        "UID" => FetchItem::Uid,
                        "RFC822.SIZE" => FetchItem::Rfc822Size,
                        _ => FetchItem::Rfc822, // Default
                    }
                }
            ),
            opt(char(' '))
        )
    ).parse(input)?;
    let (input, _) = char(')').parse(input)?;

    Ok((input, items))
}

fn parse_store_operation(input: &str) -> IResult<&str, (StoreOperation, Vec<String>)> {
    let (input, op_str) = take_while1(
        |c: char| c.is_ascii_alphabetic() || c == '.' || c == '+' || c == '-' 
    ).parse(input)?;
    let (input, _) = space1(input)?;
    let (input, flags) = parse_flag_list(input)?;

    let operation = match op_str.to_uppercase().as_str() {
        s if s.starts_with("+FLAGS") => StoreOperation::Add,
        s if s.starts_with("-FLAGS") => StoreOperation::Remove,
        s if s.starts_with("FLAGS") => StoreOperation::Replace,
        _ => StoreOperation::Set,
    };

    Ok((input, (operation, flags)))
}

fn parse_flag_list(input: &str) -> IResult<&str, Vec<String>> {
    let (input, _) = char('(').parse(input)?;
    let (input, flags) = many0(
        terminated(
            map(
                take_while1(|c: char| c.is_ascii_alphabetic() || c == '\\' ),
                |s: &str| s.to_string()
            ),
            opt(char(' '))
        )
    ).parse(input)?;
    let (input, _) = char(')').parse(input)?;

    Ok((input, flags))
}

fn parse_charset(input: &str) -> IResult<&str, String> {
    let (input, _) = tag_no_case("CHARSET").parse(input)?;
    let (input, _) = space1(input)?;
    let (input, charset) = parse_astring(input)?;

    Ok((input, charset.to_string()))
}

fn parse_search_criteria(input: &str) -> IResult<&str, SearchCriteria> {
    // Simplified - implement full search criteria parser
    preceded(
        space0,
        map(
            take_while1(|c: char| c.is_ascii() && !c.is_whitespace()),
            |s: &str| {
                match s.to_uppercase().as_str() {
                    "ALL" => SearchCriteria::All,
                    "UNSEEN" => SearchCriteria::Unseen,
                    "SEEN" => SearchCriteria::Seen,
                    "ANSWERED" => SearchCriteria::Answered,
                    "FLAGGED" => SearchCriteria::Flagged,
                    "DELETED" => SearchCriteria::Deleted,
                    "DRAFT" => SearchCriteria::Draft,
                    "RECENT" => SearchCriteria::Recent,
                    _ => SearchCriteria::All, // Default
                }
            }
        )
    ).parse(input)
}

// UID command parsers
fn parse_uid_fetch(input: &str) -> IResult<&str, (SequenceSet, Vec<FetchItem>)> {
    let (input, _) = tag_no_case("FETCH").parse(input)?;
    let (input, _) = space1(input)?;
    let (input, sequence_set) = parse_sequence_set(input)?;
    let (input, _) = space1(input)?;
    let (input, items) = parse_fetch_items(input)?;

    Ok((input, (sequence_set, items)))
}

fn parse_uid_search(input: &str) -> IResult<&str, (SearchCriteria, Option<String>)> {
    let (input, _) = tag_no_case("SEARCH").parse(input)?;
    let (input, charset) = opt(preceded(space1, parse_charset)).parse(input)?;
    let (input, criteria) = parse_search_criteria(input)?;

    Ok((input, (criteria, charset)))
}

fn parse_uid_store(input: &str) -> IResult<&str, (SequenceSet, StoreOperation, Vec<String>)> {
    let (input, _) = tag_no_case("STORE").parse(input)?;
    let (input, _) = space1(input)?;
    let (input, sequence_set) = parse_sequence_set(input)?;
    let (input, _) = space1(input)?;
    let (input, (operation, flags)) = parse_store_operation(input)?;

    Ok((input, (sequence_set, operation, flags)))
}

fn parse_status_items(input: &str) -> IResult<&str, Vec<String>> {
    delimited(
        char('('),
        many0(
            terminated(
                take_while1(|c: char| c.is_ascii_alphabetic()),
                opt(space0)
            )
        ),
        char(')')
    )
        .parse(input)
        .map(|(rest, items)| (
            rest,
            items
                .into_iter()
                .map(|s: &str| s.to_string())
                .collect(),
        ))
}

fn parse_datetime(input: &str) -> IResult<&str, Option<String>> {
    // Simplified datetime parser
    let (input, datetime) = delimited(
        char('"'),
        take_while(|c: char| c != '"'),
        char('"')
    ).parse(input)?;

    Ok((input, Some(datetime.to_string())))
}

fn parse_auth_mechanism(input: &str) -> IResult<&str, &str> {
    take_while1(|c: char| c.is_ascii_alphabetic() || c == '-' ).parse(input)
}

fn parse_initial_response(input: &str) -> IResult<&str, Option<String>> {
    // Could be literal or empty
    if input.starts_with('"') {
        let (input, response) = delimited(
            char('"'),
            take_while(|c: char| c != '"'),
            char('"')
        ).parse(input)?;
        Ok((input, Some(response.to_string())))
    } else {
        Ok((input, None))
    }
}

fn parse_enable_features(input: &str) -> IResult<&str, Vec<String>> {
    many1(
        terminated(
            take_while1(|c: char| c.is_ascii_alphabetic()),
            space0
        )
    )
        .parse(input)
        .map(|(rest, features)| (
            rest,
            features
                .into_iter()
                .map(|s: &str| s.to_string())
                .collect(),
        ))
}
