# Kelexy

Private, mobile-first chatroom. This repository starts with an empty application and contains no demo accounts, messages, or tickets.

## Run

```bash
npm install
npm start
```

Set `JWT_SECRET` and `OWNER_USERNAME` in production. Run `npm run cron` hourly (or use the included cron endpoint through your scheduler).

## Security

- Registration has no email field and validates usernames case-insensitively.
- IP registration limits and IP mutes are enforced server-side.
- Public chat is text-only; ticket attachments are handled separately.
- Moderation durations are restricted to the product rules.
- SQLite schema contains no seeded/demo data.
