# Onion Forum 🧅

Lightweight, privacy-focused forum designed for Tor v3 services. Built with Rust, Axum, Tokio, and SQLite with a server-rendered, zero-JavaScript interface.

---

## 🚀 Quick Start

### 1. Run via Docker Compose (Recommended)
```bash
docker compose up -d --build
```

On the first start, Tor generates the onion-service identity. The container preserves the raw key under `./data/tor` and automatically writes its base64 representation to `TOR_PRIVATE_KEY_B64` in `./data/.env`. The key value is never printed to the container logs.

Keep the complete `data` directory private and back it up regularly. It contains the forum database and onion identity.

Get your live `.onion` address:
```bash
docker exec onion-forum-app cat /data/tor/hs/hostname
```

### 2. Run via Rust (`cargo`)
```bash
cargo run
```
Access locally at `http://localhost:8080`.

---

## 🛠 Features

- **Privacy First:** Server-rendered UI with zero external JS dependencies.
- **SQLite Database:** Single-file persistent storage (`forum.db`).
- **CSRF & Security:** Strict CSP, HTML sanitization, and rate limiting.
- **Built-in Tor Layer:** Auto-packages Tor v3 hidden service capabilities.

---

## 📚 Documentation

Detailed documentation and guides are available in the [`docs/`](file:///e:/cyber/onion-forum-web/docs) directory:

- 🔑 **[Tor Keys & Onion Setup](file:///e:/cyber/onion-forum-web/docs/tor-keys-and-onion-setup.md):** How to generate static/vanity `.onion` keys and set `TOR_PRIVATE_KEY_B64`.
- 💻 **[Commands & CLI Reference](file:///e:/cyber/onion-forum-web/docs/commands-and-cli-reference.md):** Complete reference for Cargo, Docker, backups, health checks, and Akash Web3 deployment.

---

## 📜 Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | Application HTTP listening port |
| `FORUM_DB_PATH` | `/data/forum.db` | Absolute path to SQLite storage file |
| `TOR_PRIVATE_KEY_B64` | *Optional* | Base64-encoded static Tor Ed25519 key |
