'use strict';

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
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  fs.readFileSync(envPath, 'utf8')
    .split('\n')
    .forEach(line => {
      const [key, ...rest] = line.split('=');
      if (key && rest.length) process.env[key.trim()] = rest.join('=').trim();
    });
}

const PORT           = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-secret-in-production!';
const NODE_ENV       = process.env.NODE_ENV || 'development';
const IS_PROD        = NODE_ENV === 'production';

// ─── Database Setup ──────────────────────────────────────────────────────────
const db = new Database(path.join(__dirname, 'db', 'main.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('synchronous = NORMAL');

// ─── Schema (same as before) ────────────────────────────────────────────────
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password TEXT NOT NULL,
  credits INTEGER NOT NULL DEFAULT 100,
  role TEXT NOT NULL DEFAULT 'user',
  is_banned INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS predictions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT,
  outcome_a TEXT NOT NULL,
  outcome_b TEXT NOT NULL,
  resolved_as TEXT,
  closes_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS bets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  prediction_id INTEGER NOT NULL REFERENCES predictions(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  choice TEXT NOT NULL,
  amount INTEGER NOT NULL,
  placed_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(prediction_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_predictions_user ON predictions(user_id);
CREATE INDEX IF NOT EXISTS idx_predictions_closes ON predictions(closes_at);
CREATE INDEX IF NOT EXISTS idx_bets_prediction ON bets(prediction_id);
CREATE INDEX IF NOT EXISTS idx_bets_user ON bets(user_id);
`);

// ─── Express App ─────────────────────────────────────────────────────────────
const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

if (IS_PROD) app.set('trust proxy', 1);

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

app.use(compression());
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public'), { maxAge: IS_PROD ? '1d' : 0, etag: true }));

app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: path.join(__dirname, 'sessions'), table: 'sessions' }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'pred.sid',
  cookie: { httpOnly: true, secure: IS_PROD, sameSite: 'lax', maxAge: 7*24*60*60*1000 },
}));

const { csrfSynchronisedProtection, generateToken } = csrfSync({
  getTokenFromRequest: (req) => req.body?._csrf || req.headers['x-csrf-token'],
});

app.use((req, res, next) => {
  res.locals.csrfToken = generateToken(req);
  next();
});

const globalLimiter = rateLimit({ windowMs: 15*60*1000, max: 150, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many requests. Please slow down.' } });
app.use(globalLimiter);

const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 10, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many login attempts. Try again later.' } });

app.use((req, res, next) => {
  req.db = db;
  req.authLimiter = authLimiter;
  res.locals.user = req.session.user || null;
  res.locals.flash = req.session.flash || null;
  if (req.session.flash) delete req.session.flash;
  next();
});

// ─── Routes ──────────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  const predictions = db.prepare(`
    SELECT p.id, p.title, p.outcome_a, p.outcome_b, p.closes_at,
           u.username AS author,
           COUNT(b.id) AS bet_count
    FROM predictions p
    JOIN users u ON u.id = p.user_id
    LEFT JOIN bets b ON b.prediction_id = p.id
    WHERE p.resolved_as IS NULL
    GROUP BY p.id
    ORDER BY p.created_at DESC
    LIMIT 10
  `).all();
  res.render('index', { title: 'Predictions — Home', predictions });
});

// ─── Load external routes (from predictions-routes.zip) ──────────────────────
const predictionsRoutes = require('./routes_drop/routes/predictions');
const authRoutes        = require('./routes_drop/routes/auth');
const profileRoutes     = require('./routes_drop/routes/profile');

app.use('/predictions', predictionsRoutes);
app.use('/auth', csrfSynchronisedProtection, authRoutes);
app.use('/profile', profileRoutes);

// ─── 404 Handler ─────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).render('error', { title: '404 — Page Not Found', code: 404, message: 'The page you are looking for does not exist.' });
});

// ─── Global Error Handler ────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[Error]', err.stack || err.message);
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).render('error', { title: '403 — Forbidden', code: 403, message: 'Invalid or missing CSRF token. Please refresh and try again.' });
  }
  res.status(err.status || 500).render('error', { title: 'Server Error', code: err.status || 500, message: IS_PROD ? 'Something went wrong. Please try again later.' : err.message });
});

// ─── Start ───────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`✅ Predictions running → http://localhost:${PORT} [${NODE_ENV}]`));

module.exports = app;
