# RFC Compliance

LightMail aims to comply with the following RFCs:

## IMAP (Internet Message Access Protocol)

- **RFC 3501**: IMAP4rev1 (Core Protocol)
  - [x] LOGIN / AUTH
  - [x] LIST / LSUB
  - [x] SELECT / EXAMINE
  - [x] FETCH
  - [x] STORE
  - [x] UID
  - [x] EXPUNGE
  - [x] CAPABILITY
  - [x] NOOP
  - [x] LOGOUT

- **RFC 2177**: IMAP4 IDLE command
  - [x] IDLE

- **RFC 4315**: IMAP UIDPLUS Extension
  - [x] UID EXPUNGE

- **RFC 6154**: IMAP LIST Extension for Special-Use Mailboxes
  - [x] SPECIAL-USE (`\Inbox`, `\Trash`, `\Sent`, `\Drafts`, `\Archive`)

- **RFC 7162**: IMAP Extensions: QUICKRESYNC and CONDSTORE
  - [ ] CONDSTORE (Planned)

- **RFC 2971**: IMAP4 ID Extension
  - [ ] ID

## POP3 (Post Office Protocol)

- **RFC 1939**: POP3
  - [x] USER / PASS
  - [x] STAT
  - [x] LIST
  - [x] RETR
  - [x] DELE
  - [x] NOOP
  - [x] RSET
  - [x] QUIT
  - [ ] UIDL (Recommended)
  - [ ] TOP (Optional)

## LMTP (Local Mail Transfer Protocol)

- **RFC 2033**: LMTP
  - [x] LHLO
  - [x] MAIL FROM
  - [x] RCPT TO
  - [x] DATA
  - [x] RSET
  - [x] QUIT

## Calendar

- **RFC 4791**: CalDAV (Calendar Extensions to WebDAV)
  - [ ] Core features (Planned)

- **RFC 5545**: iCalendar Object Specification
  - [x] .ics object storage

## Security

- **RFC 2595**: Using TLS with IMAP, POP3 and ACAP
  - [x] STARTTLS (Implicit/Explicit)

- **RFC 4959**: IMAP Extension for SASL Initial Client Response
  - [ ] SASL-IR
