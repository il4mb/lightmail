# LightMail Admin HTTP API

This document describes the admin-only HTTP API exposed by LightMail. All endpoints require a Bearer token and are intended for administrative management of server resources.

## Overview
- Base URL: `http://<bind>:<port>` from config `api.bind` and `api.port`.
- Authentication: `Authorization: Bearer <token>` where `<token>` comes from `api.token` in config.
- Content type: JSON for request/response bodies unless noted.

Example base using default config:
- Bind: `0.0.0.0`
- Port: `8080`
- Token: `supersecrettoken`

## Authentication
Include the header in every admin request:

```
Authorization: Bearer supersecrettoken
```

If missing or incorrect, the API returns `401 Unauthorized`.

## Health and System Info
- GET `/health`
  - Public minimal health check. Returns plain text `OK`.

- GET `/admin/health`
  - Admin health JSON.
  - Response: `{ "status": "ok" }`

- GET `/admin/info`
  - Returns hostname and build version.
  - Response:
    ```json
    { "hostname": "mail.example.local", "version": "0.1.0" }
    ```

- GET `/admin/status`
  - Returns system component status flags.
  - Response:
    ```json
    {
      "db_ok": true,
      "s3_ok": true,
      "imap_enabled": true,
      "lmtp_enabled": true,
      "pop3_enabled": false,
      "api_enabled": true
    }
    ```


## Configuration Introspection
- GET `/admin/imap/config`
  - Returns the current IMAP config summary.
  - Response:
    ```json
    {
      "bind": "0.0.0.0",
      "port": "1143",
      "ssl_port": "1993",
      "enable_ssl": false,
      "max_connections": 1000
    }
    ```

- GET `/admin/db/status`
  - Pings the database. Response: `{ "ok": true }` or `{ "ok": false }`.

- GET `/admin/s3/status`
  - Checks S3 connectivity.
  - Response: `{ "ok": true, "bucket": "mails" }` or `{ "ok": false, "bucket": null }`.

## Accounts (Admin)
- GET `/admin/accounts`
  - List accounts.
  - Response: `[{ "id": 1, "username": "alice", "is_active": true }]`

- POST `/admin/accounts`
  - Create an account.
  - Request:
    ```json
    { "username": "alice", "password": "secret" }
    ```
  - Response:
    ```json
    { "id": 42, "username": "alice" }
    ```

- PUT `/admin/accounts/{id}`
  - Update account password.
  - Request:
    ```json
    { "password": "newSecret" }
    ```
  - Response:
    ```json
    { "id": 42, "username": "alice", "updated": true }
    ```

- DELETE `/admin/accounts/{id}`
  - Delete an account.
  - Response: `{ "deleted": true, "id": 42 }`

## Mailboxes (Admin)
- GET `/admin/accounts/{account_id}/mailboxes`
  - List mailboxes for the account.
  - Response: `[{ "id": 10, "name": "INBOX", "flags": "\\HasNoChildren" }]`

- POST `/admin/accounts/{account_id}/mailboxes`
  - Create a mailbox for the account.
  - Request:
    ```json
    { "name": "Projects", "flags": "\\Noselect" }
    ```
  - Response:
    ```json
    { "id": 10, "name": "Projects" }
    ```

- DELETE `/admin/mailboxes/{mailbox_id}`
  - Soft-delete a mailbox (sets `deleted_at`).
  - Response: `{ "deleted": true, "id": 10 }`

## Messages (Admin)
- GET `/admin/mailboxes/{mailbox_id}/messages?limit=50&offset=0`
  - List messages in a mailbox.
  - Response:
    ```json
    [
      { "id": 1001, "subject": "Hello", "sender": "me@example.com", "size": 12345, "uid": 1001 }
    ]
    ```

- DELETE `/admin/messages/{message_id}`
  - Soft-delete a message (sets `deleted_at`).
  - Response: `{ "deleted": true, "id": 1001 }`

- POST `/admin/messages/{message_id}/copy`
  - Copy a message to another mailbox.
  - Request:
    ```json
    { "dest_mailbox_id": 11 }
    ```
  - Response:
    ```json
    { "copied": true, "new_id": 2002 }
    ```

- POST `/admin/messages/{message_id}/move`
  - Move a message to another mailbox.
  - Request:
    ```json
    { "dest_mailbox_id": 11 }
    ```
  - Response:
    ```json
    { "moved": true, "new_id": 2002 }
    ```

## Calendar (Admin)
These endpoints exist for event management and require the same Bearer token.

- POST `/calendar`
  - Create a calendar.
  - Request: `{ "user_id": 1, "name": "Work" }`
  - Response: `"Calendar created: <id>"`

- POST `/calendar/event`
  - Add an event.
  - Request: `{ "calendar_id": 1, "content": "BEGIN:VCALENDAR...", "summary": "Standup" }`
  - Response: `"Event added: <id>"`

- GET `/calendar/events`
  - List events.
  - Request body: `{ "calendar_id": 1 }`
  - Response: `[{ ...events... }]`

## Error Handling
- `401 Unauthorized`: missing/invalid token.
- `500 Internal Server Error`: unexpected backend error.
- `404 Not Found`: when targeted resource does not exist.

## Curl Examples
Replace `TOKEN` with your configured token and `HOST:PORT` with your binding.

```bash
# Admin health
curl -H "Authorization: Bearer TOKEN" http://HOST:PORT/admin/health

# Create account
curl -X POST -H "Authorization: Bearer TOKEN" -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"secret"}' \
  http://HOST:PORT/admin/accounts

# Create mailbox
curl -X POST -H "Authorization: Bearer TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"INBOX"}' \
  http://HOST:PORT/admin/accounts/1/mailboxes

# List messages
curl -H "Authorization: Bearer TOKEN" http://HOST:PORT/admin/mailboxes/10/messages?limit=50

# Move message
curl -X POST -H "Authorization: Bearer TOKEN" -H "Content-Type: application/json" \
  -d '{"dest_mailbox_id":11}' \
  http://HOST:PORT/admin/messages/1001/move

```

## Notes
- All admin endpoints are protected by token-based middleware.
- Some operations (delete mailbox/message) use soft-deletes to cooperate with garbage collection.
- IMAP limits like `max_failed_attempts` can be configured in `imap` section and affect session behavior, separate from the admin API.
