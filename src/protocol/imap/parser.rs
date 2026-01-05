use std::borrow::Cow;
use nom::{
    IResult,
    Parser,
    bytes::complete::{ take_until, take_while1 },
    character::complete::{ char, space0 },
    sequence::delimited,
};

fn is_atom_char(c: char) -> bool {
    c.is_ascii() &&
        !c.is_ascii_control() &&
        !matches!(c, '(' | ')' | '{' | ' ' | '%' | '*' | '"' | '\\')
}

fn parse_atom(input: &str) -> IResult<&str, &str> {
    take_while1(is_atom_char).parse(input)
}

fn parse_quoted(input: &str) -> IResult<&str, &str> {
    delimited(char('"'), take_until("\""), char('"')).parse(input)
}

// ignore unused, it will be implemented later
#[allow(unused)]
// Parse literal: {size}CRLF*data
fn parse_literal(input: &str) -> IResult<&str, String> {
    let (input, size_str) = delimited(char('{'), take_until("}"), char('}')).parse(input)?;

    let size: usize = size_str
        .parse()
        .map_err(|_| {
            nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Digit))
        })?;

    // Skip optional space and CRLF (in real IMAP, literal is followed by CRLF)
    let (input, _) = space0(input)?;

    // Take exactly 'size' characters
    if input.len() < size {
        return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Eof)));
    }

    let (remaining, literal_data) = input.split_at(size);
    let literal_string = remaining.to_string();

    Ok((literal_data, literal_string))
}

// Alternative: Just parse the literal size without consuming data
// (Useful if you want to handle the literal data separately)
fn parse_literal_size(input: &str) -> IResult<&str, usize> {
    let (input, size_str) = delimited(char('{'), take_until("}"), char('}')).parse(input)?;

    let size: usize = size_str
        .parse()
        .map_err(|_| {
            nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Digit))
        })?;

    Ok((input, size))
}

// More complete string parsing that handles literals properly
pub fn parse_astring(input: &str) -> IResult<&str, Cow<'_, str>> {
    // Try quoted first
    if let Ok((remaining, quoted)) = parse_quoted(input) {
        return Ok((remaining, Cow::Borrowed(quoted)));
    }

    // Try atom
    if let Ok((remaining, atom)) = parse_atom(input) {
        return Ok((remaining, Cow::Borrowed(atom)));
    }

    // Try literal
    if let Ok((remaining, size)) = parse_literal_size(input) {
        // Skip optional whitespace
        let (input_after_ws, _) = space0(remaining)?;

        // Check if we have enough data
        if input_after_ws.len() < size {
            return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Eof)));
        }

        // Take the literal data
        let (remaining_after_literal, literal_data) = input_after_ws.split_at(size);
        let literal_string = remaining_after_literal.to_string();

        return Ok((literal_data, Cow::Owned(literal_string)));
    }

    Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Alt)))
}

// Test the parsers
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atom() {
        assert_eq!(parse_atom("INBOX"), Ok(("", "INBOX")));
        assert_eq!(parse_atom("INBOX "), Ok((" ", "INBOX")));
        assert!(parse_atom("\"INBOX\"").is_err());
    }

    #[test]
    fn test_quoted() {
        assert_eq!(parse_quoted("\"Hello World\""), Ok(("", "Hello World")));
        assert_eq!(parse_quoted("\"Hello World\" rest"), Ok((" rest", "Hello World")));
    }

    #[test]
    fn test_literal_size() {
        assert_eq!(parse_literal_size("{10}"), Ok(("", 10)));
        assert_eq!(parse_literal_size("{123}"), Ok(("", 123)));
        assert_eq!(parse_literal_size("{0}"), Ok(("", 0)));
    }

    #[test]
    fn test_literal_parsing() {
        // Note: In real IMAP, literals have CRLF after the size
        assert_eq!(parse_literal("{5}Hello"), Ok(("", "Hello".to_string())));
        assert_eq!(parse_literal("{5} Hello"), Ok(("", "Hello".to_string())));
        assert_eq!(parse_literal("{11}Hello World"), Ok(("", "Hello World".to_string())));
    }
}
