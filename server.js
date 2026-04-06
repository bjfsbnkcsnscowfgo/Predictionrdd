'use strict';

/**
 * server.js — Entry point for the Predictions platform.
 *
 * Stack:
 *   - Express 4       → HTTP server & routing
 *   - EJS             → Server-side templating
 *   - better-sqlite3  → Synchronous SQLite (no callback hell)
 *   - express-session + connect-sqlite3 → Session persistence
 *   - csrf-sync       → Synchronised CSRF token protection
 *   - helmet          → Security headers
 *   - compression     → Gzip responses
 *   - express-rate-limit → Per-IP rate limiting
 *
 * Quick start:
 *   npm install
 *   npm start          (production)
 *   npm run dev        (development with auto-reload via nodemon)
 */

const path    = require('path');
const fs      = require('fs');
const express = require('express');
const session = require('express-session');
const SQLiteStore  = require('connect-sqlite3')(session);
const cookieParser = require('cookie-parser');
const compression  = require('compression');
const helmet       = require('helmet');
const rateLimit    = require('express-rate-limit');
const { csrfSync } = require('csrf-sync');
const Database     = require('better-sqlite3');

// ─── Environment ─────────────────────────────────────────────────────────────
// Load a .env file if present (no dotenv dependency — keep it simple)
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  fs.readFileSync(envPath, 'utf8')
    .split('\n')
    .forEach(line => {
      const [key, ...rest] = line.split('=');
      if (key && rest.length) process.env[key.trim()] = rest.join('=').trim();
    });
}

const PORT           = process.env.PORT           || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-secret-in-production!';
const NODE_ENV       = process.env.NODE_ENV       || 'development';
const IS_PROD        = NODE_ENV === 'production';

// ─── Database Setup ──────────────────────────────────────────────────────────
// better-sqlite3 is synchronous — no async/await needed for queries.
// The db file is created automatically if it does not exist.
const db = new Database(path.join(__dirname, 'db', 'main.db'), {
  // verbose: console.log,  // Uncomment to log every SQL statement (dev only)
});

// Performance pragmas
db.pragma('journal_mode = WAL');   // Write-Ahead Logging — better concurrency
db.pragma('foreign_keys = ON');    // Enforce FK constraints
db.pragma('synchronous = NORMAL'); // Balance between safety and speed

// ─── Schema ──────────────────────────────────────────────────────────────────
// All CREATE TABLE statements live here so the DB bootstraps itself on first run.
// Add new tables below as the project grows.
db.exec(`
  -- Users table
  CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    email       TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password    TEXT    NOT NULL,
    credits     INTEGER NOT NULL DEFAULT 100,
    role        TEXT    NOT NULL DEFAULT 'user',   -- 'user' | 'admin'
    is_banned   INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  -- Predictions table
  CREATE TABLE IF NOT EXISTS predictions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title        TEXT    NOT NULL,
    description  TEXT,
    outcome_a    TEXT    NOT NULL,   -- Label for option A
    outcome_b    TEXT    NOT NULL,   -- Label for option B
    resolved_as  TEXT,               -- NULL | 'A' | 'B' (set when resolved)
    closes_at    TEXT    NOT NULL,   -- ISO-8601 datetime
    created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  -- Bets table
  CREATE TABLE IF NOT EXISTS bets (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    prediction_id INTEGER NOT NULL REFERENCES predictions(id) ON DELETE CASCADE,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    choice        TEXT    NOT NULL,   -- 'A' | 'B'
    amount        INTEGER NOT NULL,
    placed_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(prediction_id, user_id)    -- One bet per user per prediction
  );

  -- Indexes for common lookups
  CREATE INDEX IF NOT EXISTS idx_predictions_user     ON predictions(user_id);
  CREATE INDEX IF NOT EXISTS idx_predictions_closes   ON predictions(closes_at);
  CREATE INDEX IF NOT EXISTS idx_bets_prediction      ON bets(prediction_id);
  CREATE INDEX IF NOT EXISTS idx_bets_user            ON bets(user_id);
`);

// ─── Express App ─────────────────────────────────────────────────────────────
const app = express();

// ─── View Engine ─────────────────────────────────────────────────────────────
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ─── Trust Proxy (needed when behind Nginx / reverse proxy in production) ────
if (IS_PROD) app.set('trust proxy', 1);

// ─── Security Headers (helmet) ───────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc : ["'self'"],
      scriptSrc  : ["'self'"],
      styleSrc   : ["'self'", "'unsafe-inline'"],
      imgSrc     : ["'self'", 'data:'],
      connectSrc : ["'self'"],
      fontSrc    : ["'self'"],
      objectSrc  : ["'none'"],
      frameSrc   : ["'none'"],
    },
  },
  referrerPolicy: { policy: 'same-origin' },
}));

// ─── Compression ─────────────────────────────────────────────────────────────
app.use(compression());

// ─── Body Parsers ────────────────────────────────────────────────────────────
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(express.json({ limit: '10kb' }));

// ─── Cookie Parser ───────────────────────────────────────────────────────────
app.use(cookieParser());

// ─── Static Files ────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: IS_PROD ? '1d' : 0,   // Cache static assets for 1 day in production
  etag: true,
}));

// ─── Sessions ────────────────────────────────────────────────────────────────
// Sessions are stored in a separate SQLite file inside the /sessions folder.
app.use(session({
  store: new SQLiteStore({
    db   : 'sessions.db',
    dir  : path.join(__dirname, 'sessions'),
    table: 'sessions',
  }),
  secret           : SESSION_SECRET,
  resave           : false,
  saveUninitialized: false,
  name             : 'pred.sid',  // Don't use default 'connect.sid'
  cookie: {
    httpOnly: true,
    secure  : IS_PROD,            // HTTPS only in production
    sameSite: 'lax',
    maxAge  : 7 * 24 * 60 * 60 * 1000,  // 7 days in ms
  },
}));

// ─── CSRF Protection ─────────────────────────────────────────────────────────
// csrf-sync uses the "synchronised" pattern (token stored in session).
// Include a hidden <input name="_csrf" value="<%= csrfToken %>"> in every form.
const { csrfSynchronisedProtection, generateToken } = csrfSync({
  getTokenFromRequest: (req) => {
    // Accept token from form body OR from X-CSRF-Token header (for fetch/AJAX)
    return req.body?._csrf || req.headers['x-csrf-token'];
  },
});

// Inject the CSRF token into res.locals so every EJS template can access it
// as <%= csrfToken %> without any extra work in route handlers.
app.use((req, res, next) => {
  res.locals.csrfToken = generateToken(req);
  next();
});

// ─── Rate Limiting ───────────────────────────────────────────────────────────
// Apply a global rate limit. You can override this per-router for sensitive
// routes like /auth/login (e.g. 5 attempts per 15 minutes).
const globalLimiter = rateLimit({
  windowMs       : 15 * 60 * 1000,   // 15-minute window
  max            : 150,               // Max requests per window per IP
  standardHeaders: true,
  legacyHeaders  : false,
  message        : { error: 'Too many requests. Please slow down.' },
});
app.use(globalLimiter);

// Stricter limiter for auth endpoints — attach this to /auth routes
const authLimiter = rateLimit({
  windowMs       : 15 * 60 * 1000,
  max            : 10,
  standardHeaders: true,
  legacyHeaders  : false,
  message        : { error: 'Too many login attempts. Try again later.' },
});

// ─── App-level Middleware ────────────────────────────────────────────────────
// Attach the database and authLimiter to every request for convenience in routes.
app.use((req, res, next) => {
  req.db          = db;
  req.authLimiter = authLimiter;

  // Make session user available in all EJS templates as `user`
  res.locals.user  = req.session.user  || null;
  res.locals.flash = req.session.flash || null;

  // Clear flash message after reading it
  if (req.session.flash) delete req.session.flash;

  next();
});

// ─── Routes ──────────────────────────────────────────────────────────────────

// Homepage
app.get('/', (req, res) => {
  // Fetch the 10 most recent open predictions for the homepage
  const predictions = db.prepare(`
    SELECT p.id, p.title, p.outcome_a, p.outcome_b, p.closes_at,
           u.username AS author,
           COUNT(b.id) AS bet_count
    FROM   predictions p
    JOIN   users u ON u.id = p.user_id
    LEFT   JOIN bets b ON b.prediction_id = p.id
    WHERE  p.resolved_as IS NULL
    GROUP  BY p.id
    ORDER  BY p.created_at DESC
    LIMIT  10
  `).all();

  res.render('index', {
    title      : 'Predictions — Home',
    predictions,
  });
});

// ─── TODO: Add route files below ─────────────────────────────────────────────
// Example (uncomment and create the file when ready):
//
// const authRoutes       = require('./routes/auth');
// const predRoutes       = require('./routes/predictions');
// const profileRoutes    = require('./routes/profile');
//
// app.use('/auth',        csrfSynchronisedProtection, authRoutes);
// app.use('/predictions', predRoutes);
// app.use('/profile',     profileRoutes);
//
// Pass csrfSynchronisedProtection to any router that handles POST forms.

// ─── 404 Handler ─────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).render('error', {
    title  : '404 — Page Not Found',
    code   : 404,
    message: 'The page you are looking for does not exist.',
  });
});

// ─── Global Error Handler ────────────────────────────────────────────────────
// Must have 4 parameters (err, req, res, next) for Express to recognise it.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[Error]', err.stack || err.message);

  // CSRF errors
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).render('error', {
      title  : '403 — Forbidden',
      code   : 403,
      message: 'Invalid or missing CSRF token. Please refresh and try again.',
    });
  }

  res.status(err.status || 500).render('error', {
    title  : 'Server Error',
    code   : err.status || 500,
    message: IS_PROD
      ? 'Something went wrong. Please try again later.'
      : err.message,
  });
});

// ─── Start ───────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅  Predictions running → http://localhost:${PORT}  [${NODE_ENV}]`);
});

module.exports = app;  // Export for testing
