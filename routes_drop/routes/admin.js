'use strict';

/**
 * routes/admin.js — Admin panel routes.
 *
 * Mounted at /admin in server.js.
 * Every route requires both requireAuth AND requireAdmin.
 *
 * Routes:
 *   GET  /admin                 → Dashboard (stats overview)
 *   GET  /admin/users           → User list
 *   POST /admin/users/:id/ban   → Ban / unban a user  (CSRF)
 *   POST /admin/users/:id/credits → Adjust credits    (CSRF)
 *   GET  /admin/predictions     → All predictions list
 *   POST /admin/predictions/:id/delete → Delete prediction (CSRF)
 */

const express = require('express');
const { requireAuth, requireAdmin } = require('../middleware/auth');

const router = express.Router();

// Apply auth guards to every admin route
router.use(requireAuth, requireAdmin);

// ─── GET /admin ───────────────────────────────────────────────────────────────
router.get('/', (req, res) => {
  const db = req.db;

  // Two queries covering all dashboard stats
  const stats = db.prepare(`
    SELECT
      (SELECT COUNT(*) FROM users)                              AS total_users,
      (SELECT COUNT(*) FROM users WHERE is_banned = 1)         AS banned_users,
      (SELECT COUNT(*) FROM predictions)                        AS total_predictions,
      (SELECT COUNT(*) FROM predictions WHERE resolved_as IS NULL) AS open_predictions,
      (SELECT COUNT(*) FROM bets)                               AS total_bets,
      (SELECT COALESCE(SUM(amount), 0) FROM bets)               AS total_credits_wagered
  `).get();

  const recentUsers = db.prepare(
    'SELECT id, username, role, credits, is_banned, created_at FROM users ORDER BY created_at DESC LIMIT 10'
  ).all();

  res.render('admin/dashboard', {
    title: 'Admin Dashboard',
    stats,
    recentUsers,
  });
});

// ─── GET /admin/users ─────────────────────────────────────────────────────────
router.get('/users', (req, res) => {
  const db = req.db;
  const page  = Math.max(1, parseInt(req.query.page || '1', 10));
  const limit = 25;
  const offset = (page - 1) * limit;

  const { count } = db.prepare('SELECT COUNT(*) AS count FROM users').get();
  const users = db.prepare(
    'SELECT id, username, email, role, credits, is_banned, created_at FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?'
  ).all(limit, offset);

  res.render('admin/users', {
    title     : 'Manage Users',
    users,
    page,
    totalPages: Math.ceil(count / limit),
  });
});

// ─── POST /admin/users/:id/ban ───────────────────────────────────────────────
router.post('/users/:id/ban', (req, res) => {
  const db  = req.db;
  const id  = parseInt(req.params.id, 10);

  if (id === req.session.user.id) {
    req.session.flash = { type: 'error', message: 'You cannot ban yourself.' };
    return res.redirect('/admin/users');
  }

  const user = db.prepare('SELECT id, is_banned FROM users WHERE id = ?').get(id);
  if (!user) {
    req.session.flash = { type: 'error', message: 'User not found.' };
    return res.redirect('/admin/users');
  }

  const newStatus = user.is_banned ? 0 : 1;
  db.prepare('UPDATE users SET is_banned = ? WHERE id = ?').run(newStatus, id);

  req.session.flash = {
    type   : 'success',
    message: `User ${newStatus ? 'banned' : 'unbanned'} successfully.`,
  };
  res.redirect('/admin/users');
});

// ─── POST /admin/users/:id/credits ───────────────────────────────────────────
router.post('/users/:id/credits', (req, res) => {
  const db     = req.db;
  const id     = parseInt(req.params.id, 10);
  const amount = parseInt(req.body.amount, 10);

  if (isNaN(amount)) {
    req.session.flash = { type: 'error', message: 'Invalid credit amount.' };
    return res.redirect('/admin/users');
  }

  const user = db.prepare('SELECT id FROM users WHERE id = ?').get(id);
  if (!user) {
    req.session.flash = { type: 'error', message: 'User not found.' };
    return res.redirect('/admin/users');
  }

  // Allow negative amounts to deduct credits (floor at 0 using MAX)
  db.prepare(
    'UPDATE users SET credits = MAX(0, credits + ?) WHERE id = ?'
  ).run(amount, id);

  req.session.flash = {
    type   : 'success',
    message: `Credits adjusted by ${amount > 0 ? '+' : ''}${amount}.`,
  };
  res.redirect('/admin/users');
});

// ─── GET /admin/predictions ───────────────────────────────────────────────────
router.get('/predictions', (req, res) => {
  const db    = req.db;
  const page  = Math.max(1, parseInt(req.query.page || '1', 10));
  const limit = 25;
  const offset = (page - 1) * limit;

  const { count } = db.prepare('SELECT COUNT(*) AS count FROM predictions').get();
  const predictions = db.prepare(`
    SELECT
      p.id, p.title, p.closes_at, p.resolved_as, p.created_at,
      u.username AS author,
      COUNT(b.id) AS bet_count
    FROM   predictions p
    JOIN   users u ON u.id = p.user_id
    LEFT   JOIN bets b ON b.prediction_id = p.id
    GROUP  BY p.id
    ORDER  BY p.created_at DESC
    LIMIT  ? OFFSET ?
  `).all(limit, offset);

  res.render('admin/predictions', {
    title      : 'Manage Predictions',
    predictions,
    page,
    totalPages : Math.ceil(count / limit),
  });
});

// ─── POST /admin/predictions/:id/delete ──────────────────────────────────────
router.post('/predictions/:id/delete', (req, res) => {
  const db = req.db;
  const id = parseInt(req.params.id, 10);

  // CASCADE DELETE in schema removes bets automatically
  const result = db.prepare('DELETE FROM predictions WHERE id = ?').run(id);

  if (result.changes === 0) {
    req.session.flash = { type: 'error', message: 'Prediction not found.' };
  } else {
    req.session.flash = { type: 'success', message: 'Prediction deleted.' };
  }

  res.redirect('/admin/predictions');
});

module.exports = router;
