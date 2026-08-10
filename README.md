# Onion Forum

A lightweight, self-hosted forum for Tor. The backend is written in Rust with Axum and SQLite, and the interface uses server-rendered HTML and CSS without JavaScript.

## Features

- Tor v3 onion service included in the Docker image
- Accounts, categories, threads, replies, and comments
- Admin management for users, categories, threads, and registration
- CAPTCHA and login rate limiting
- CSRF protection, expiring sessions, HTML sanitization, and strict browser headers
- Persistent forum data and Tor identity in one directory

## Start

```bash
docker compose up -d --build
```

Follow the startup logs to see the onion address:

```bash
docker compose logs -f onion-forum
```

Press `Ctrl+C` after the address appears. The container will continue running.

## Data

Everything is stored under `./data`:

```text
data/
|-- forum.db
|-- .env
`-- tor/
```

The first start generates a Tor identity. Its raw key remains in `data/tor`, while a base64 backup is saved as `TOR_PRIVATE_KEY_B64` in `data/.env`. The private key is never printed in logs.

Back up the complete `data` directory to preserve the forum and its onion address. Never publish this directory or its private keys.

## Commands

```bash
# Stop
docker compose down

# Start again
docker compose up -d

# View logs
docker compose logs -f onion-forum

# Read the onion hostname
docker compose exec onion-forum cat /data/tor/hs/hostname
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | Internal forum HTTP port |
| `FORUM_DB_PATH` | `/data/forum.db` | SQLite database path |
| `TOR_PRIVATE_KEY_B64` | generated | Optional existing Tor identity to import |

To import an existing base64 key, copy `.env.example` to `.env`, add the key, and start Compose. New installations do not require a root `.env` file.

## Contributing

Issues and pull requests are welcome. Keep changes lightweight, privacy-focused, and usable without JavaScript.

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).
