'use strict';

/**
 * routes/auth.js — Authentication routes.
 *
 * Mounted at /auth in server.js (with csrfSynchronisedProtection applied).
 *
 * Routes:
 *   GET  /auth/login     → Login page
 *   POST /auth/login     → Authenticate user (rate-limited)
 *   GET  /auth/register  → Registration page
 *   POST /auth/register  → Create account (rate-limited)
 *   POST /auth/logout    → Destroy session
 */

const express  = require('express');
const bcrypt   = require('bcryptjs');
const { requireGuest } = require('../middleware/auth');

const router = express.Router();

// ─── GET /auth/login ─────────────────────────────────────────────────────────
router.get('/login', requireGuest, (req, res) => {
  res.render('auth/login', {
    title: 'Log In — Predictions',
  });
});

// ─── POST /auth/login ─────────────────────────────────────────────────────────
router.post('/login', requireGuest, (req, res, next) => {
  // Apply the strict auth rate limiter (10 attempts / 15 min)
  req.authLimiter(req, res, next);
}, (req, res) => {
  const { username, password } = req.body;

  // Basic input validation
  if (!username?.trim() || !password) {
    req.session.flash = { type: 'error', message: 'Please fill in all fields.' };
    return res.redirect('/auth/login');
  }

  const db   = req.db;
  const user = db.prepare(
    'SELECT * FROM users WHERE username = ? COLLATE NOCASE'
  ).get(username.trim());

  // Constant-time compare to prevent timing attacks
  const valid = user ? bcrypt.compareSync(password, user.password) : false;

  if (!valid) {
    req.session.flash = { type: 'error', message: 'Invalid username or password.' };
    return res.redirect('/auth/login');
  }

  if (user.is_banned) {
    req.session.flash = { type: 'error', message: 'Your account has been suspended.' };
    return res.redirect('/auth/login');
  }

  // Store safe subset in session — never store the password hash
  req.session.user = {
    id      : user.id,
    username: user.username,
    role    : user.role,
    credits : user.credits,
  };

  req.session.flash = { type: 'success', message: `Welcome back, ${user.username}!` };

  // Redirect to intended page (set by requireAuth) or homepage
  const returnTo = req.session.returnTo || '/';
  delete req.session.returnTo;
  res.redirect(returnTo);
});

// ─── GET /auth/register ──────────────────────────────────────────────────────
router.get('/register', requireGuest, (req, res) => {
  res.render('auth/register', {
    title: 'Create Account — Predictions',
  });
});

// ─── POST /auth/register ─────────────────────────────────────────────────────
router.post('/register', requireGuest, (req, res, next) => {
  req.authLimiter(req, res, next);
}, (req, res) => {
  const { username, email, password, confirmPassword } = req.body;

  // ── Validation ─────────────────────────────────────────────────────────────
  if (!username?.trim() || !email?.trim() || !password || !confirmPassword) {
    req.session.flash = { type: 'error', message: 'Please fill in all fields.' };
    return res.redirect('/auth/register');
  }

  if (password !== confirmPassword) {
    req.session.flash = { type: 'error', message: 'Passwords do not match.' };
    return res.redirect('/auth/register');
  }

  if (password.length < 8) {
    req.session.flash = { type: 'error', message: 'Password must be at least 8 characters.' };
    return res.redirect('/auth/register');
  }

  const usernameClean = username.trim().slice(0, 30);
  const emailClean    = email.trim().toLowerCase().slice(0, 255);

  // Username: letters, numbers, underscores, hyphens only
  if (!/^[a-z0-9_-]{3,30}$/i.test(usernameClean)) {
    req.session.flash = {
      type   : 'error',
      message: 'Username must be 3–30 characters and contain only letters, numbers, _ or -.',
    };
    return res.redirect('/auth/register');
  }

  const db = req.db;

  // Check for existing username or email in one query
  const existing = db.prepare(
    'SELECT id FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE LIMIT 1'
  ).get(usernameClean, emailClean);

  if (existing) {
    req.session.flash = { type: 'error', message: 'Username or email is already taken.' };
    return res.redirect('/auth/register');
  }

  // ── Create account ─────────────────────────────────────────────────────────
  const hash = bcrypt.hashSync(password, 12);

  const result = db.prepare(
    'INSERT INTO users (username, email, password) VALUES (?, ?, ?)'
  ).run(usernameClean, emailClean, hash);

  // Log the new user in immediately
  req.session.user = {
    id      : result.lastInsertRowid,
    username: usernameClean,
    role    : 'user',
    credits : 100,  // Default credits from schema
  };

  req.session.flash = {
    type   : 'success',
    message: `Welcome, ${usernameClean}! You've been given 100 starter credits.`,
  };
  res.redirect('/');
});

// ─── POST /auth/logout ───────────────────────────────────────────────────────
router.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) console.error('[Logout error]', err);
    res.clearCookie('pred.sid');
    res.redirect('/auth/login');
  });
});

module.exports = router;
