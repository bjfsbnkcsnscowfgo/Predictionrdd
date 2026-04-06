'use strict';

/**
 * routes/profile.js — User profile routes.
 *
 * Mounted at /profile in server.js.
 *
 * Routes:
 *   GET  /profile              → Own profile (auth required)
 *   GET  /profile/:username    → Public profile for any user
 *   POST /profile/edit         → Update display settings (auth + CSRF)
 */

const express  = require('express');
const bcrypt   = require('bcryptjs');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

// ─── GET /profile ────────────────────────────────────────────────────────────
// Redirect to own public profile
router.get('/', requireAuth, (req, res) => {
  res.redirect(`/profile/${req.session.user.username}`);
});

// ─── GET /profile/:username ──────────────────────────────────────────────────
router.get('/:username', (req, res) => {
  const db       = req.db;
  const username = req.params.username.trim();

  const user = db.prepare(
    'SELECT id, username, credits, role, created_at FROM users WHERE username = ? COLLATE NOCASE'
  ).get(username);

  if (!user) {
    return res.status(404).render('error', {
      title  : '404 — User Not Found',
      code   : 404,
      message: `No user with the username "${username}" exists.`,
    });
  }

  // Fetch user's predictions + their bet counts in one query
  const predictions = db.prepare(`
    SELECT
      p.id, p.title, p.outcome_a, p.outcome_b, p.closes_at, p.resolved_as,
      COUNT(b.id) AS bet_count
    FROM   predictions p
    LEFT   JOIN bets b ON b.prediction_id = p.id
    WHERE  p.user_id = ?
    GROUP  BY p.id
    ORDER  BY p.created_at DESC
    LIMIT  20
  `).all(user.id);

  // Fetch user's recent bets in one query
  const bets = db.prepare(`
    SELECT
      b.choice, b.amount, b.placed_at,
      p.id AS prediction_id, p.title AS prediction_title, p.resolved_as
    FROM   bets b
    JOIN   predictions p ON p.id = b.prediction_id
    WHERE  b.user_id = ?
    ORDER  BY b.placed_at DESC
    LIMIT  20
  `).all(user.id);

  const isOwn = req.session.user?.id === user.id;

  res.render('profile/view', {
    title      : `${user.username}'s Profile`,
    profileUser: user,
    predictions,
    bets,
    isOwn,
  });
});

// ─── POST /profile/edit ──────────────────────────────────────────────────────
// Allows updating password only for now. Extend as needed.
router.post('/edit', requireAuth, (req, res) => {
  const { currentPassword, newPassword, confirmPassword } = req.body;
  const db = req.db;

  if (!currentPassword || !newPassword || !confirmPassword) {
    req.session.flash = { type: 'error', message: 'Please fill in all fields.' };
    return res.redirect(`/profile/${req.session.user.username}`);
  }

  if (newPassword !== confirmPassword) {
    req.session.flash = { type: 'error', message: 'New passwords do not match.' };
    return res.redirect(`/profile/${req.session.user.username}`);
  }

  if (newPassword.length < 8) {
    req.session.flash = { type: 'error', message: 'New password must be at least 8 characters.' };
    return res.redirect(`/profile/${req.session.user.username}`);
  }

  const user = db.prepare('SELECT password FROM users WHERE id = ?').get(req.session.user.id);

  if (!bcrypt.compareSync(currentPassword, user.password)) {
    req.session.flash = { type: 'error', message: 'Current password is incorrect.' };
    return res.redirect(`/profile/${req.session.user.username}`);
  }

  const hash = bcrypt.hashSync(newPassword, 12);
  db.prepare('UPDATE users SET password = ?, updated_at = datetime("now") WHERE id = ?')
    .run(hash, req.session.user.id);

  req.session.flash = { type: 'success', message: 'Password updated successfully.' };
  res.redirect(`/profile/${req.session.user.username}`);
});

module.exports = router;
