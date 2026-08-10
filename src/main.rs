use axum::{
    extract::{DefaultBodyLimit, Form, Path, Query, Request, State},
    http::{header, HeaderName, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use minijinja::{Environment, context};
use rusqlite::{params, Connection, Result as SqlResult};
use serde::Deserialize;
use std::{
    env,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tower_http::services::ServeDir;
use uuid::Uuid;
use captcha::{Captcha, filters::{Noise, Wave, Dots}};

struct AppState {
    db: Mutex<Connection>,
    jinja: Environment<'static>,
}

const SESSION_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;

fn now_ts() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn generate_session_token() -> String {
    use argon2::password_hash::rand_core::RngCore;
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let mut s = String::with_capacity(64);
    for b in bytes { s.push_str(&format!("{:02x}", b)); }
    s
}

fn session_cookie(token: String) -> Cookie<'static> {
    Cookie::build(("session_id", token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Strict)
        .max_age(time::Duration::seconds(SESSION_TTL_SECONDS))
        .build()
}

fn ensure_csrf_token(jar: CookieJar) -> (CookieJar, String) {
    if let Some(cookie) = jar.get("csrf_token") {
        let token = cookie.value().to_owned();
        return (jar, token);
    }
    let token = generate_session_token();
    let cookie = Cookie::build(("csrf_token", token.clone()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Strict)
        .max_age(time::Duration::seconds(SESSION_TTL_SECONDS))
        .build();
    (jar.add(cookie), token)
}

fn valid_csrf(jar: &CookieJar, submitted_token: &str) -> bool {
    submitted_token.len() == 64
        && jar.get("csrf_token").map(|cookie| cookie.value() == submitted_token).unwrap_or(false)
}

fn csrf_rejected() -> Response {
    (StatusCode::FORBIDDEN, "Invalid or missing CSRF token.").into_response()
}

fn valid_username(username: &str) -> bool {
    (3..=20).contains(&username.len())
        && username.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-')
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'none'; object-src 'none'; connect-src 'none'; img-src 'self'; style-src 'self' 'unsafe-inline'"));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(HeaderName::from_static("permissions-policy"), HeaderValue::from_static("camera=(), geolocation=(), microphone=(), payment=(), usb=()"));
    headers.insert(HeaderName::from_static("cross-origin-resource-policy"), HeaderValue::from_static("same-origin"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(HeaderName::from_static("x-dns-prefetch-control"), HeaderValue::from_static("off"));
    response
}

fn clamp_text(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let boundary = s.char_indices()
            .take_while(|(i, _)| *i < max_len - 1)
            .last()
            .map(|(i, c)| i + c.len_utf8())
            .unwrap_or(0);
        let mut clamped = s[..boundary].trim_end().to_string();
        clamped.push('…');
        clamped
    }
}

fn datetimeformat(value: i64) -> Result<String, minijinja::Error> {
    if let Ok(dt) = time::OffsetDateTime::from_unix_timestamp(value) {
        let format = time::format_description::parse("[year]-[month]-[day] [hour]:[minute] UTC").unwrap();
        Ok(dt.format(&format).unwrap_or_default())
    } else {
        Ok("".to_string())
    }
}

fn nl2br(value: String) -> Result<String, minijinja::Error> {
    let s = value.replace("\r\n", "\n").replace('\r', "\n");
    let s = s.replace("&lt;br&gt;", "<br>").replace("&lt;br/&gt;", "<br>").replace("&lt;br /&gt;", "<br>");
    Ok(s.replace('\n', "<br>"))
}

fn markdown_to_html(text: String) -> Result<String, minijinja::Error> {
    let mut options = pulldown_cmark::Options::empty();
    options.insert(pulldown_cmark::Options::ENABLE_STRIKETHROUGH);
    let parser = pulldown_cmark::Parser::new_ext(&text, options);
    let mut html_output = String::new();
    pulldown_cmark::html::push_html(&mut html_output, parser);
    Ok(ammonia::clean(&html_output))
}

fn init_db(conn: &Connection) -> SqlResult<()> {
    conn.execute_batch(
        "
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;
        PRAGMA foreign_keys=ON;
        PRAGMA cache_size=-2000;
        PRAGMA temp_store=MEMORY;
        PRAGMA wal_autocheckpoint=500;

        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at    INTEGER NOT NULL,
            is_admin      INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token      TEXT PRIMARY KEY,
            user_id    INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS captchas (
            id         TEXT PRIMARY KEY,
            solution   TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS login_attempts (
            username     TEXT NOT NULL,
            attempt_time INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_login_attempts ON login_attempts(username, attempt_time);

        CREATE TABLE IF NOT EXISTS categories (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            slug    TEXT UNIQUE NOT NULL,
            name    TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS threads (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            title           TEXT NOT NULL,
            posts_count     INTEGER NOT NULL DEFAULT 0,
            created_at      INTEGER NOT NULL,
            last_activity_at INTEGER NOT NULL,
            category_id     INTEGER,
            user_id         INTEGER REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS posts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            thread_id   INTEGER NOT NULL,
            author      TEXT,
            content     TEXT NOT NULL,
            created_at  INTEGER NOT NULL,
            user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY(thread_id) REFERENCES threads(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_threads_last_activity ON threads(last_activity_at DESC);
        CREATE INDEX IF NOT EXISTS idx_posts_thread_id ON posts(thread_id);

        CREATE TABLE IF NOT EXISTS comments (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id     INTEGER NOT NULL,
            author      TEXT,
            content     TEXT NOT NULL,
            created_at  INTEGER NOT NULL,
            user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_comments_post_id ON comments(post_id);
        CREATE INDEX IF NOT EXISTS idx_threads_category ON threads(category_id);

        CREATE TABLE IF NOT EXISTS app_settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        INSERT OR IGNORE INTO app_settings (key, value) VALUES ('registration_enabled', '1');
        "
    )?;

    let _ = conn.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0", []);
    let _ = conn.execute("ALTER TABLE threads ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE SET NULL", []);
    let _ = conn.execute("ALTER TABLE posts ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE SET NULL", []);
    let _ = conn.execute("ALTER TABLE comments ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE SET NULL", []);
    let has_session_expiry: i64 = conn.query_row("SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name = 'expires_at'", [], |row| row.get(0))?;
    if has_session_expiry == 0 {
        conn.execute("ALTER TABLE sessions ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0", [])?;
    }
    conn.execute("DELETE FROM sessions WHERE expires_at <= ?", params![now_ts()])?;

    let count: i64 = conn.query_row("SELECT COUNT(*) FROM categories", [], |row| row.get(0))?;
    if count == 0 {
        let mut stmt = conn.prepare("INSERT INTO categories (slug, name) VALUES (?, ?)")?;
        stmt.execute(params!["technology", "Technology"])?;
        stmt.execute(params!["learning", "Learning"])?;
        stmt.execute(params!["politics", "Politics"])?;
        stmt.execute(params!["secret", "Secret"])?;
    }

    let default_cat_id: Option<i64> = conn.query_row("SELECT id FROM categories ORDER BY id ASC LIMIT 1", [], |row| row.get(0)).ok();
    if let Some(cat_id) = default_cat_id {
        conn.execute("UPDATE threads SET category_id = COALESCE(category_id, ?) WHERE category_id IS NULL", params![cat_id])?;
    }

    Ok(())
}

fn get_current_user(db: &Connection, jar: &CookieJar) -> Option<(i64, String, bool)> {
    if let Some(cookie) = jar.get("session_id") {
        if let Ok(mut stmt) = db.prepare_cached("SELECT u.id, u.username, u.is_admin FROM users u JOIN sessions s ON s.user_id = u.id WHERE s.token = ? AND s.expires_at > ?") {
            if let Ok(row) = stmt.query_row(params![cookie.value(), now_ts()], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)? == 1))) {
                return Some(row);
            }
        }
    }
    None
}

fn is_registration_enabled(db: &Connection) -> bool {
    db.query_row("SELECT value FROM app_settings WHERE key = 'registration_enabled'", [], |row| row.get::<_, String>(0))
        .map(|value| value == "1")
        .unwrap_or(true)
}

#[derive(Deserialize)]
struct IndexQuery { cat: Option<String>, page: Option<i64> }

async fn index(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(query): Query<IndexQuery>,
) -> impl IntoResponse {
    let (jar, csrf_token) = ensure_csrf_token(jar);
    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
    let current_user = get_current_user(&db, &jar);
    let current_username = current_user.as_ref().map(|u| u.1.clone());
    let is_admin = current_user.as_ref().map(|u| u.2).unwrap_or(false);
    
    let mut categories = Vec::new();
    if let Ok(mut stmt) = db.prepare_cached("SELECT id, slug, name FROM categories ORDER BY name ASC") {
        if let Ok(iter) = stmt.query_map([], |row| {
            Ok(minijinja::value::Value::from(context! { id => row.get::<_, i64>(0)?, slug => row.get::<_, String>(1)?, name => row.get::<_, String>(2)? }))
        }) {
            for c in iter.flatten() { categories.push(c); }
        }
    }

    let page = query.page.unwrap_or(1).max(1);
    let per_page = 20;
    let offset = (page - 1) * per_page;

    let mut cat_ctx = minijinja::value::Value::UNDEFINED;
    let mut cat_id = None;
    if let Some(cat_slug) = query.cat {
        if let Ok(row) = db.query_row("SELECT id, slug, name FROM categories WHERE slug = ?", params![cat_slug], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))) {
            cat_id = Some(row.0);
            cat_ctx = minijinja::value::Value::from(context! { id => row.0, slug => row.1, name => row.2 });
        }
    }

    let mut threads = Vec::new();
    let total_threads = if let Some(cid) = cat_id {
        db.query_row("SELECT COUNT(*) FROM threads WHERE category_id = ?", params![cid], |r| r.get(0)).unwrap_or(0)
    } else {
        db.query_row("SELECT COUNT(*) FROM threads", [], |r| r.get(0)).unwrap_or(0)
    };

    let q = if cat_id.is_some() {
        "SELECT t.id, t.title, t.posts_count, t.created_at, t.last_activity_at, c.name, c.slug, u.username FROM threads t LEFT JOIN categories c ON c.id = t.category_id LEFT JOIN users u ON u.id = t.user_id WHERE t.category_id = ? ORDER BY t.last_activity_at DESC, t.id DESC LIMIT ? OFFSET ?"
    } else {
        "SELECT t.id, t.title, t.posts_count, t.created_at, t.last_activity_at, c.name, c.slug, u.username FROM threads t LEFT JOIN categories c ON c.id = t.category_id LEFT JOIN users u ON u.id = t.user_id ORDER BY t.last_activity_at DESC, t.id DESC LIMIT ? OFFSET ?"
    };
    
    if let Ok(mut stmt) = db.prepare_cached(q) {
        let p: Vec<&dyn rusqlite::ToSql> = if let Some(cid) = &cat_id { vec![cid, &per_page, &offset] } else { vec![&per_page, &offset] };
        if let Ok(iter) = stmt.query_map(&*p, |row| {
            Ok(minijinja::value::Value::from(context! {
                id => row.get::<_, i64>(0)?, title => row.get::<_, String>(1)?, posts_count => row.get::<_, i64>(2)?,
                created_at => row.get::<_, i64>(3)?, last_activity_at => row.get::<_, i64>(4)?,
                category_name => row.get::<_, Option<String>>(5)?, category_slug => row.get::<_, Option<String>>(6)?,
                author => row.get::<_, Option<String>>(7)?
            }))
        }) {
            for t in iter.flatten() { threads.push(t); }
        }
    }

    let total_pages = 1.max((total_threads + per_page - 1) / per_page);

    let mut recent_posts = Vec::new();
    if let Ok(mut stmt) = db.prepare_cached(
        "SELECT p.id, p.created_at, COALESCE(u.username, p.author) as author, p.content, t.id, t.title, c.name, c.slug 
         FROM posts p JOIN threads t ON t.id = p.thread_id LEFT JOIN categories c ON c.id = t.category_id LEFT JOIN users u ON u.id = p.user_id
         ORDER BY p.id DESC LIMIT 10"
    ) {
        if let Ok(iter) = stmt.query_map([], |row| {
            Ok(minijinja::value::Value::from(context! {
                post_id => row.get::<_, i64>(0)?, created_at => row.get::<_, i64>(1)?, author => row.get::<_, Option<String>>(2)?,
                content => row.get::<_, String>(3)?, thread_id => row.get::<_, i64>(4)?, thread_title => row.get::<_, String>(5)?,
                category_name => row.get::<_, Option<String>>(6)?, category_slug => row.get::<_, Option<String>>(7)?
            }))
        }) {
            for p in iter.flatten() { recent_posts.push(p); }
        }
    }

    let mut all_users = Vec::new();
    if is_admin {
        if let Ok(mut stmt) = db.prepare_cached("SELECT id, username, created_at FROM users WHERE is_admin = 0 ORDER BY created_at DESC") {
            if let Ok(iter) = stmt.query_map([], |row| {
                Ok(minijinja::value::Value::from(context! { id => row.get::<_, i64>(0)?, username => row.get::<_, String>(1)?, created_at => row.get::<_, i64>(2)? }))
            }) {
                for u in iter.flatten() { all_users.push(u); }
            }
        }
    }

    let tmpl = match state.jinja.get_template("index.html") { Ok(t) => t, Err(e) => return (jar, Html(format!("<pre>{}</pre>", e))).into_response() };
    let html = tmpl.render(context! {
        current_user => current_username, is_admin => is_admin, all_users => all_users, threads => threads, categories => categories, cat => cat_ctx, 
        recent_posts => recent_posts, page => page, total_pages => total_pages, csrf_token => csrf_token
    }).unwrap_or_else(|e| format!("<pre>{}</pre>", e));
    (jar, Html(html)).into_response()
}

#[derive(Deserialize)]
struct ThreadQuery { page: Option<i64> }

async fn thread_view(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(thread_id): Path<i64>,
    Query(query): Query<ThreadQuery>,
) -> impl IntoResponse {
    let (jar, csrf_token) = ensure_csrf_token(jar);
    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
    let current_user = get_current_user(&db, &jar);
    let current_username = current_user.as_ref().map(|u| u.1.clone());
    let is_admin = current_user.as_ref().map(|u| u.2).unwrap_or(false);

    let thread_opt = db.query_row(
        "SELECT t.id, t.title, t.posts_count, t.created_at, t.last_activity_at, c.name, c.slug, u.username
         FROM threads t LEFT JOIN categories c ON c.id = t.category_id LEFT JOIN users u ON u.id = t.user_id WHERE t.id = ?",
        params![thread_id], |row| {
            Ok(minijinja::value::Value::from(context! {
                id => row.get::<_, i64>(0)?, title => row.get::<_, String>(1)?, posts_count => row.get::<_, i64>(2)?,
                created_at => row.get::<_, i64>(3)?, last_activity_at => row.get::<_, i64>(4)?,
                category_name => row.get::<_, Option<String>>(5)?, category_slug => row.get::<_, Option<String>>(6)?,
                author => row.get::<_, Option<String>>(7)?
            }))
        }
    ).ok();
    let thread = match thread_opt { Some(t) => t, None => return (jar, Html("404 Not Found".to_string())).into_response() };

    let page = query.page.unwrap_or(1).max(1);
    let per_page = 50;
    let offset = (page - 1) * per_page;

    let total_posts: i64 = db.query_row("SELECT COUNT(*) FROM posts WHERE thread_id = ?", params![thread_id], |r| r.get(0)).unwrap_or(0);
    let total_pages = 1.max((total_posts + per_page - 1) / per_page);

    let mut posts = Vec::new();
    let mut post_ids: Vec<i64> = Vec::new();
    if let Ok(mut stmt) = db.prepare_cached("SELECT p.id, COALESCE(u.username, p.author), p.content, p.created_at FROM posts p LEFT JOIN users u ON u.id = p.user_id WHERE p.thread_id = ? ORDER BY p.id ASC LIMIT ? OFFSET ?") {
        if let Ok(iter) = stmt.query_map(params![thread_id, per_page, offset], |row| {
            Ok((row.get::<_, i64>(0)?, minijinja::value::Value::from(context! {
                id => row.get::<_, i64>(0)?, author => row.get::<_, Option<String>>(1)?, content => row.get::<_, String>(2)?, created_at => row.get::<_, i64>(3)?
            })))
        }) {
            for item in iter.flatten() { post_ids.push(item.0); posts.push(item.1); }
        }
    }

    let mut comments_by_post: std::collections::HashMap<i64, Vec<minijinja::value::Value>> = std::collections::HashMap::new();
    if !post_ids.is_empty() {
        let placeholders = post_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let q = format!("SELECT c.id, c.post_id, COALESCE(u.username, c.author), c.content, c.created_at FROM comments c LEFT JOIN users u ON u.id = c.user_id WHERE c.post_id IN ({}) ORDER BY c.id ASC", placeholders);
        if let Ok(mut stmt) = db.prepare(&q) {
            let params_vec: Vec<&dyn rusqlite::ToSql> = post_ids.iter().map(|id| id as &dyn rusqlite::ToSql).collect();
            if let Ok(iter) = stmt.query_map(&*params_vec, |row| {
                Ok((row.get::<_, i64>(1)?, minijinja::value::Value::from(context! {
                    id => row.get::<_, i64>(0)?, post_id => row.get::<_, i64>(1)?, author => row.get::<_, Option<String>>(2)?,
                    content => row.get::<_, String>(3)?, created_at => row.get::<_, i64>(4)?
                })))
            }) {
                for c in iter.flatten() { comments_by_post.entry(c.0).or_default().push(c.1); }
            }
        }
    }
    let mut comments_map = std::collections::BTreeMap::new();
    for (pid, cmts) in comments_by_post { comments_map.insert(pid.to_string(), minijinja::value::Value::from_serialize(&cmts)); }

    let tmpl = match state.jinja.get_template("thread.html") { Ok(t) => t, Err(e) => return (jar, Html(format!("<pre>{}</pre>", e))).into_response() };
    let html = tmpl.render(context! { current_user => current_username, is_admin => is_admin, thread => thread, posts => posts, comments_map => comments_map, page => page, total_pages => total_pages, csrf_token => csrf_token }).unwrap_or_else(|e| format!("<pre>{}</pre>", e));
    (jar, Html(html)).into_response()
}

#[derive(Deserialize)]
struct CreateThreadForm { title: String, content: String, category_id: Option<i64>, csrf_token: String }

async fn create_thread(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Form(form): Form<CreateThreadForm>,
) -> impl IntoResponse {
    if !valid_csrf(&jar, &form.csrf_token) { return csrf_rejected(); }
    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
    let current_user = get_current_user(&db, &jar);
    
    let (user_id, mut author_name) = if let Some((uid, uname, _)) = current_user {
        (uid, uname)
    } else {
        return Redirect::to("/login").into_response();
    };

    let title = form.title.trim();
    let content = form.content.trim();
    if title.is_empty() || content.is_empty() { return Redirect::to("/").into_response(); }

    let title = clamp_text(title, 140);
    author_name = clamp_text(&author_name, 32);
    let content = clamp_text(content, 5000);

    let cat_id = form.category_id.unwrap_or_else(|| db.query_row("SELECT id FROM categories ORDER BY id ASC LIMIT 1", [], |r| r.get(0)).unwrap_or(1));
    let ts = now_ts();

    if db.execute("INSERT INTO threads (title, posts_count, created_at, last_activity_at, category_id, user_id) VALUES (?, 0, ?, ?, ?, ?)", params![title, ts, ts, cat_id, user_id]).is_err() {
        return Redirect::to("/").into_response();
    }
    let thread_id = db.last_insert_rowid();

    let _ = db.execute("INSERT INTO posts (thread_id, author, content, created_at, user_id) VALUES (?, ?, ?, ?, ?)", params![thread_id, author_name, content, ts, user_id]);
    let _ = db.execute("UPDATE threads SET posts_count = posts_count + 1, last_activity_at=? WHERE id=?", params![ts, thread_id]);

    Redirect::to(&format!("/thread/{}", thread_id)).into_response()
}

#[derive(Deserialize)]
struct ReplyForm { content: String, csrf_token: String }

async fn reply(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(thread_id): Path<i64>,
    Form(form): Form<ReplyForm>,
) -> impl IntoResponse {
    if !valid_csrf(&jar, &form.csrf_token) { return csrf_rejected(); }
    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
    let current_user = get_current_user(&db, &jar);
    
    let (user_id, mut author_name) = if let Some((uid, uname, _)) = current_user {
        (uid, uname)
    } else {
        return Redirect::to("/login").into_response();
    };

    if db.query_row("SELECT 1 FROM threads WHERE id=?", params![thread_id], |r| r.get::<_, i64>(0)).is_err() { return Redirect::to("/").into_response(); }

    let content = form.content.trim();
    if content.is_empty() { return Redirect::to(&format!("/thread/{}", thread_id)).into_response(); }

    author_name = clamp_text(&author_name, 32);
    let content = clamp_text(content, 5000);
    let ts = now_ts();

    let _ = db.execute("INSERT INTO posts (thread_id, author, content, created_at, user_id) VALUES (?, ?, ?, ?, ?)", params![thread_id, author_name, content, ts, user_id]);
    let _ = db.execute("UPDATE threads SET posts_count = posts_count + 1, last_activity_at=? WHERE id=?", params![ts, thread_id]);

    Redirect::to(&format!("/thread/{}", thread_id)).into_response()
}

async fn comment(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Path(post_id): Path<i64>,
    Form(form): Form<ReplyForm>,
) -> impl IntoResponse {
    if !valid_csrf(&jar, &form.csrf_token) { return csrf_rejected(); }
    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
    let current_user = get_current_user(&db, &jar);
    
    let (user_id, mut author_name) = if let Some((uid, uname, _)) = current_user {
        (uid, uname)
    } else {
        return Redirect::to("/login").into_response();
    };

    let thread_id = match db.query_row("SELECT thread_id FROM posts WHERE id=?", params![post_id], |r| r.get::<_, i64>(0)) { Ok(t) => t, Err(_) => return Redirect::to("/").into_response() };

    let content = form.content.trim();
    if content.is_empty() { return Redirect::to(&format!("/thread/{}", thread_id)).into_response(); }

    author_name = clamp_text(&author_name, 32);
    let content = clamp_text(content, 2000);
    let ts = now_ts();

    let _ = db.execute("INSERT INTO comments (post_id, author, content, created_at, user_id) VALUES (?, ?, ?, ?, ?)", params![post_id, author_name, content, ts, user_id]);
    let _ = db.execute("UPDATE threads SET last_activity_at=? WHERE id=?", params![ts, thread_id]);

    Redirect::to(&format!("/thread/{}#p{}", thread_id, post_id)).into_response()
}

#[derive(Deserialize)]
struct LoginQuery { mode: Option<String> }

async fn login_get(State(state): State<Arc<AppState>>, jar: CookieJar, Query(query): Query<LoginQuery>) -> impl IntoResponse {
    let (jar, csrf_token) = ensure_csrf_token(jar);
    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
    let current_user = get_current_user(&db, &jar);
    let current_username = current_user.map(|u| u.1);
    let mode = query.mode.unwrap_or_else(|| "login".to_string());
    let registration_disabled = !is_registration_enabled(&db);
    
    let captcha_id = Uuid::new_v4().to_string();

    let tmpl = state.jinja.get_template("login.html").unwrap();
    (jar, Html(tmpl.render(context! { current_user => current_username, mode => mode, captcha_id => captcha_id, csrf_token => csrf_token, registration_disabled => registration_disabled }).unwrap()))
}

#[derive(Deserialize)]
struct AuthForm { 
    username: String, 
    password: String, 
    #[serde(default)] action: String,
    captcha_id: String,
    captcha_solution: String,
    csrf_token: String,
}

async fn login_post(State(state): State<Arc<AppState>>, jar: CookieJar, Form(form): Form<AuthForm>) -> impl IntoResponse {
    if !valid_csrf(&jar, &form.csrf_token) { return csrf_rejected(); }
    let csrf_token = jar.get("csrf_token").map(|cookie| cookie.value().to_owned()).unwrap_or_default();
    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
    
    let username = form.username.trim().to_lowercase();
    let password = form.password;
    
    // Rate limit check: max 5 failed attempts in the last 15 minutes
    let ts_15min_ago = now_ts() - 900;
    let recent_attempts: i64 = db.query_row(
        "SELECT COUNT(*) FROM login_attempts WHERE username = ? AND attempt_time > ?",
        params![&username, ts_15min_ago],
        |r| r.get(0)
    ).unwrap_or(0);
    
    if recent_attempts >= 5 {
        let new_captcha_id = Uuid::new_v4().to_string();
        return (jar, Html(state.jinja.get_template("login.html").unwrap().render(context! { error => "Too many failed attempts. Try again in 15 minutes.", mode => form.action, captcha_id => new_captcha_id, csrf_token => csrf_token }).unwrap())).into_response();
    }

    // Verify Captcha
    let stored_solution: Option<String> = db.query_row(
        "SELECT solution FROM captchas WHERE id = ? AND expires_at > ?",
        params![&form.captcha_id, now_ts()],
        |r| r.get(0)
    ).ok();
    
    let _ = db.execute("DELETE FROM captchas WHERE id = ?", params![&form.captcha_id]);

    let cap_valid = match stored_solution {
        Some(s) if s == form.captcha_solution.trim().to_lowercase() => true,
        _ => false,
    };

    if !cap_valid {
        let _ = db.execute("INSERT INTO login_attempts (username, attempt_time) VALUES (?, ?)", params![&username, now_ts()]);
        let new_captcha_id = Uuid::new_v4().to_string();
        return (jar, Html(state.jinja.get_template("login.html").unwrap().render(context! { error => "Invalid CAPTCHA", mode => form.action, captcha_id => new_captcha_id, csrf_token => csrf_token }).unwrap())).into_response();
    }

    if form.action == "register" {
        if !is_registration_enabled(&db) {
            return (jar, Html(state.jinja.get_template("login.html").unwrap().render(context! { error => "Registration is currently disabled by the administrator.", mode => "register", csrf_token => csrf_token, registration_disabled => true }).unwrap())).into_response();
        }
        if !valid_username(&username) || password.len() < 10 || password.len() > 128 {
            let _ = db.execute("INSERT INTO login_attempts (username, attempt_time) VALUES (?, ?)", params![&username, now_ts()]);
            let new_captcha_id = Uuid::new_v4().to_string();
            return (jar, Html(state.jinja.get_template("login.html").unwrap().render(context! { error => "Username must use lowercase letters, numbers, _ or -, and password must be 10-128 characters.", mode => "register", captcha_id => new_captcha_id, csrf_token => csrf_token }).unwrap())).into_response();
        }
        let salt = SaltString::generate(&mut OsRng);
        let params = argon2::Params::new(8192, 2, 1, None).unwrap_or_default();
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let password_hash = match argon2.hash_password(password.as_bytes(), &salt) {
            Ok(h) => h.to_string(),
            Err(_) => return (jar, Html(state.jinja.get_template("login.html").unwrap().render(context! { error => "Account creation failed. Please try again.", mode => "register", captcha_id => Uuid::new_v4().to_string(), csrf_token => csrf_token }).unwrap())).into_response(),
        };

        let user_count: i64 = db.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0)).unwrap_or(0);
        let is_admin = if user_count == 0 { 1 } else { 0 };

        let ts = now_ts();
        if db.execute("INSERT INTO users (username, password_hash, created_at, is_admin) VALUES (?, ?, ?, ?)", params![username.clone(), password_hash, ts, is_admin]).is_err() {
            let _ = db.execute("INSERT INTO login_attempts (username, attempt_time) VALUES (?, ?)", params![&username, ts]);
            let new_captcha_id = Uuid::new_v4().to_string();
            return (jar, Html(state.jinja.get_template("login.html").unwrap().render(context! { error => "Username taken", mode => "register", captcha_id => new_captcha_id, csrf_token => csrf_token }).unwrap())).into_response();
        }
        let user_id = db.last_insert_rowid();

        let token = generate_session_token();
        let _ = db.execute("INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)", params![&token, user_id, ts, ts + SESSION_TTL_SECONDS]);
        let _ = db.execute("DELETE FROM login_attempts WHERE username = ?", params![&username]);
        return (jar.add(session_cookie(token)), Redirect::to("/")).into_response();
    } else {
        let res = db.query_row("SELECT id, password_hash FROM users WHERE username = ?", params![&username], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)));
        if let Ok((user_id, phash)) = res {
            if let Ok(parsed_hash) = PasswordHash::new(&phash) {
                if Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok() {
                    let token = generate_session_token();
                    let created_at = now_ts();
                    let _ = db.execute("INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)", params![&token, user_id, created_at, created_at + SESSION_TTL_SECONDS]);
                    let _ = db.execute("DELETE FROM login_attempts WHERE username = ?", params![&username]);
                    return (jar.add(session_cookie(token)), Redirect::to("/")).into_response();
                }
            }
        }
        
        let _ = db.execute("INSERT INTO login_attempts (username, attempt_time) VALUES (?, ?)", params![&username, now_ts()]);
        let new_captcha_id = Uuid::new_v4().to_string();
        return (jar, Html(state.jinja.get_template("login.html").unwrap().render(context! { error => "Invalid credentials", mode => "login", captcha_id => new_captcha_id, csrf_token => csrf_token }).unwrap())).into_response();
    }
}

async fn logout_post(jar: CookieJar, State(state): State<Arc<AppState>>, Form(form): Form<CsrfForm>) -> impl IntoResponse {
    if !valid_csrf(&jar, &form.csrf_token) { return csrf_rejected(); }
    if let Some(cookie) = jar.get("session_id") {
        let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
        let _ = db.execute("DELETE FROM sessions WHERE token = ?", params![cookie.value()]);
    }
    let mut cookie = session_cookie(String::new());
    cookie.make_removal();
    (jar.add(cookie), Redirect::to("/")).into_response()
}

#[derive(Deserialize)]
struct DeleteUserForm { user_id: i64, csrf_token: String }

async fn admin_delete_user(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Form(form): Form<DeleteUserForm>,
) -> impl IntoResponse {
    if !valid_csrf(&jar, &form.csrf_token) { return csrf_rejected(); }
    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, _, true)) = get_current_user(&db, &jar) {
        let uid = form.user_id;
        let _ = db.execute("DELETE FROM threads WHERE user_id = ?", params![uid]);
        let _ = db.execute("DELETE FROM posts WHERE user_id = ?", params![uid]);
        let _ = db.execute("DELETE FROM comments WHERE user_id = ?", params![uid]);
        let _ = db.execute("DELETE FROM users WHERE id = ?", params![uid]);
    }
    Redirect::to("/").into_response()
}

#[derive(Deserialize)]
struct DeleteThreadForm { thread_id: i64, csrf_token: String }

async fn admin_delete_thread(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Form(form): Form<DeleteThreadForm>,
) -> impl IntoResponse {
    if !valid_csrf(&jar, &form.csrf_token) { return csrf_rejected(); }
    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, _, true)) = get_current_user(&db, &jar) {
        let _ = db.execute("DELETE FROM threads WHERE id = ?", params![form.thread_id]);
    }
    Redirect::to("/").into_response()
}

#[derive(Deserialize)]
struct CreateCategoryForm { name: String, csrf_token: String }

async fn admin_create_category(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Form(form): Form<CreateCategoryForm>,
) -> impl IntoResponse {
    if !valid_csrf(&jar, &form.csrf_token) { return csrf_rejected(); }
    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, _, true)) = get_current_user(&db, &jar) {
        let name = form.name.trim();
        if !name.is_empty() {
            let name_clamped = clamp_text(name, 32);
            let slug = name_clamped
                .to_lowercase()
                .chars()
                .map(|c| if c.is_alphanumeric() { c } else { '-' })
                .collect::<String>()
                .split('-')
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join("-");

            if !slug.is_empty() {
                let _ = db.execute(
                    "INSERT OR IGNORE INTO categories (slug, name) VALUES (?, ?)",
                    params![slug, name_clamped],
                );
            }
        }
    }
    Redirect::to("/").into_response()
}

#[derive(Deserialize)]
struct DeleteCategoryForm { category_id: i64, csrf_token: String }

#[derive(Deserialize)]
struct CsrfForm { csrf_token: String }

#[derive(Deserialize)]
struct RegistrationSettingForm { enabled: String, csrf_token: String }

async fn admin_delete_category(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Form(form): Form<DeleteCategoryForm>,
) -> impl IntoResponse {
    if !valid_csrf(&jar, &form.csrf_token) { return csrf_rejected(); }
    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, _, true)) = get_current_user(&db, &jar) {
        let cat_id = form.category_id;
        let total_cats: i64 = db.query_row("SELECT COUNT(*) FROM categories", [], |r| r.get(0)).unwrap_or(0);
        if total_cats > 1 {
            if let Ok(fallback_id) = db.query_row(
                "SELECT id FROM categories WHERE id != ? ORDER BY id ASC LIMIT 1",
                params![cat_id],
                |r| r.get::<_, i64>(0),
            ) {
                let _ = db.execute(
                    "UPDATE threads SET category_id = ? WHERE category_id = ?",
                    params![fallback_id, cat_id],
                );
                let _ = db.execute("DELETE FROM categories WHERE id = ?", params![cat_id]);
            }
        }
    }
    Redirect::to("/admin").into_response()
}

async fn admin_set_registration(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Form(form): Form<RegistrationSettingForm>,
) -> impl IntoResponse {
    if !valid_csrf(&jar, &form.csrf_token) { return csrf_rejected(); }
    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, _, true)) = get_current_user(&db, &jar) {
        let value = if form.enabled == "1" { "1" } else { "0" };
        let _ = db.execute("INSERT INTO app_settings (key, value) VALUES ('registration_enabled', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", params![value]);
    }
    Redirect::to("/admin").into_response()
}

async fn admin_page(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> impl IntoResponse {
    let (jar, csrf_token) = ensure_csrf_token(jar);
    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
    let current_user = get_current_user(&db, &jar);
    let is_admin = current_user.as_ref().map(|u| u.2).unwrap_or(false);

    if !is_admin {
        return Redirect::to("/").into_response();
    }
    let registration_enabled = is_registration_enabled(&db);

    let current_username = current_user.as_ref().map(|u| u.1.clone());

    let mut categories = Vec::new();
    if let Ok(mut stmt) = db.prepare("SELECT id, slug, name FROM categories ORDER BY name ASC") {
        if let Ok(iter) = stmt.query_map([], |row| {
            Ok(minijinja::value::Value::from(context! { id => row.get::<_, i64>(0)?, slug => row.get::<_, String>(1)?, name => row.get::<_, String>(2)? }))
        }) {
            for c in iter.flatten() { categories.push(c); }
        }
    }

    let mut all_users = Vec::new();
    if let Ok(mut stmt) = db.prepare("SELECT id, username, created_at FROM users WHERE is_admin = 0 ORDER BY created_at DESC") {
        if let Ok(iter) = stmt.query_map([], |row| {
            Ok(minijinja::value::Value::from(context! { id => row.get::<_, i64>(0)?, username => row.get::<_, String>(1)?, created_at => row.get::<_, i64>(2)? }))
        }) {
            for u in iter.flatten() { all_users.push(u); }
        }
    }

    let tmpl = match state.jinja.get_template("admin.html") { Ok(t) => t, Err(e) => return (jar, Html(format!("<pre>{}</pre>", e))).into_response() };
    let html = tmpl.render(context! {
        current_user => current_username,
        is_admin => is_admin,
        categories => categories,
        all_users => all_users, csrf_token => csrf_token, registration_enabled => registration_enabled
    }).unwrap_or_else(|e| format!("<pre>{}</pre>", e));
    (jar, Html(html)).into_response()
}

async fn get_captcha(Path(id): Path<String>, State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if Uuid::parse_str(&id).is_err() { return (StatusCode::BAD_REQUEST, "Invalid CAPTCHA id.").into_response(); }
    let mut captcha = Captcha::new();
    captcha.add_chars(5)
           .apply_filter(Noise::new(0.2))
           .apply_filter(Wave::new(2.0, 10.0))
           .view(200, 60);

    let solution = captcha.chars_as_string().to_lowercase();
    let img_bytes = captcha.as_png().unwrap_or_default();

    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
    let ts = now_ts() + 300; // 5 mins expiration
    let _ = db.execute("INSERT OR REPLACE INTO captchas (id, solution, expires_at) VALUES (?, ?, ?)", params![id, solution, ts]);
    // cleanup old captchas
    let _ = db.execute("DELETE FROM captchas WHERE expires_at < ?", params![now_ts()]);

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "image/png")],
        img_bytes,
    ).into_response()
}

async fn healthz() -> &'static str { "ok" }

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let db_path = env::var("FORUM_DB_PATH").unwrap_or_else(|_| "/data/forum.db".to_string());
    if let Some(parent) = std::path::Path::new(&db_path).parent() { std::fs::create_dir_all(parent).unwrap_or_default(); }
    let conn = Connection::open(&db_path).expect("Failed to open database");
    conn.busy_timeout(std::time::Duration::from_secs(5)).expect("Failed to set busy timeout");
    init_db(&conn).expect("Failed to initialize database");
    
    let mut jinja = Environment::new();
    jinja.add_filter("datetimeformat", datetimeformat);
    jinja.add_filter("nl2br", nl2br);
    jinja.add_filter("markdown", markdown_to_html);
    jinja.set_loader(minijinja::path_loader("templates"));
    let app_state = Arc::new(AppState { db: Mutex::new(conn), jinja });

    let app = Router::new()
        .route("/", get(index))
        .route("/login", get(login_get).post(login_post))
        .route("/logout", post(logout_post))
        .route("/admin", get(admin_page))
        .route("/admin/delete_user", post(admin_delete_user))
        .route("/admin/delete_thread", post(admin_delete_thread))
        .route("/admin/create_category", post(admin_create_category))
        .route("/admin/delete_category", post(admin_delete_category))
        .route("/admin/set_registration", post(admin_set_registration))
        .route("/thread", post(create_thread))
        .route("/thread/:id", get(thread_view))
        .route("/thread/:id/reply", post(reply))
        .route("/post/:id/comment", post(comment))
        .route("/captcha/:id", get(get_captcha))
        .route("/healthz", get(healthz))
        .nest_service("/static", ServeDir::new("static"))
        .with_state(app_state)
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn(security_headers));

    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("0.0.0.0:{}", port);
    println!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
