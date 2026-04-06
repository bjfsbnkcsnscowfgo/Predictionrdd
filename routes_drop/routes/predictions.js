'use strict';

/**
 * routes/predictions.js — Prediction CRUD + betting.
 *
 * Mounted at /predictions in server.js.
 *
 * Routes:
 *   GET  /predictions            → List all open predictions
 *   GET  /predictions/new        → New prediction form  (auth required)
 *   POST /predictions/new        → Create prediction    (auth + CSRF)
 *   GET  /predictions/:id        → View a single prediction + bet form
 *   POST /predictions/:id/bet    → Place a bet          (auth + CSRF)
 *   POST /predictions/:id/resolve → Resolve prediction  (auth + owner/admin + CSRF)
 */

const express = require('express');
const { requireAuth, requireAdmin } = require('../middleware/auth');

const router = express.Router();

// ─── GET /predictions ────────────────────────────────────────────────────────
router.get('/', (req, res) => {
  const db = req.db;

  const predictions = db.prepare(`
    SELECT
      p.id, p.title, p.outcome_a, p.outcome_b, p.closes_at, p.resolved_as,
      u.username  AS author,
      COUNT(b.id) AS bet_count
    FROM   predictions p
    JOIN   users u  ON u.id = p.user_id
    LEFT   JOIN bets b ON b.prediction_id = p.id
    GROUP  BY p.id
    ORDER  BY p.resolved_as IS NULL DESC,  -- Open first
              p.closes_at ASC
    LIMIT  50
  `).all();

  res.render('predictions/list', {
    title: 'All Predictions',
    predictions,
  });
});

// ─── GET /predictions/new ────────────────────────────────────────────────────
router.get('/new', requireAuth, (req, res) => {
  res.render('predictions/new', {
    title: 'New Prediction',
  });
});

// ─── POST /predictions/new ───────────────────────────────────────────────────
router.post('/new', requireAuth, (req, res) => {
  const { title, description, outcome_a, outcome_b, closes_at } = req.body;

  // ── Validation ─────────────────────────────────────────────────────────────
  if (!title?.trim() || !outcome_a?.trim() || !outcome_b?.trim() || !closes_at) {
    req.session.flash = { type: 'error', message: 'Please fill in all required fields.' };
    return res.redirect('/predictions/new');
  }

  const closeDate = new Date(closes_at);
  if (isNaN(closeDate.getTime()) || closeDate <= new Date()) {
    req.session.flash = { type: 'error', message: 'Closing date must be in the future.' };
    return res.redirect('/predictions/new');
  }

  const db = req.db;

  db.prepare(`
    INSERT INTO predictions (user_id, title, description, outcome_a, outcome_b, closes_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    req.session.user.id,
    title.trim().slice(0, 200),
    description?.trim().slice(0, 1000) || null,
    outcome_a.trim().slice(0, 100),
    outcome_b.trim().slice(0, 100),
    closeDate.toISOString(),
  );

  req.session.flash = { type: 'success', message: 'Prediction created!' };
  res.redirect('/predictions');
});

// ─── GET /predictions/:id ────────────────────────────────────────────────────
router.get('/:id', (req, res) => {
  const db = req.db;
  const id = parseInt(req.params.id, 10);

  if (!id) return res.redirect('/predictions');

  // One query: prediction + author + bet totals
  const prediction = db.prepare(`
    SELECT
      p.*,
      u.username AS author,
      SUM(CASE WHEN b.choice = 'A' THEN b.amount ELSE 0 END) AS pool_a,
      SUM(CASE WHEN b.choice = 'B' THEN b.amount ELSE 0 END) AS pool_b,
      COUNT(b.id) AS bet_count
    FROM   predictions p
    JOIN   users u ON u.id = p.user_id
    LEFT   JOIN bets b ON b.prediction_id = p.id
    WHERE  p.id = ?
    GROUP  BY p.id
  `).get(id);

  if (!prediction) {
    return res.status(404).render('error', {
      title  : '404 — Not Found',
      code   : 404,
      message: 'Prediction not found.',
    });
  }

  // Current user's existing bet (if any) — only if logged in
  let userBet = null;
  if (req.session.user) {
    userBet = db.prepare(
      'SELECT choice, amount FROM bets WHERE prediction_id = ? AND user_id = ?'
    ).get(id, req.session.user.id);
  }

  res.render('predictions/view', {
    title     : prediction.title,
    prediction,
    userBet,
  });
});

// ─── POST /predictions/:id/bet ───────────────────────────────────────────────
router.post('/:id/bet', requireAuth, (req, res) => {
  const db = req.db;
  const id = parseInt(req.params.id, 10);
  const { choice, amount } = req.body;
  const credits = parseInt(amount, 10);

  // ── Validation ─────────────────────────────────────────────────────────────
  if (!['A', 'B'].includes(choice) || isNaN(credits) || credits < 1) {
    req.session.flash = { type: 'error', message: 'Invalid bet. Choose A or B and enter a valid amount.' };
    return res.redirect(`/predictions/${id}`);
  }

  const prediction = db.prepare(
    'SELECT * FROM predictions WHERE id = ?'
  ).get(id);

  if (!prediction || prediction.resolved_as || new Date(prediction.closes_at) <= new Date()) {
    req.session.flash = { type: 'error', message: 'This prediction is closed or resolved.' };
    return res.redirect(`/predictions/${id}`);
  }

  // Check if user already bet
  const existing = db.prepare(
    'SELECT id FROM bets WHERE prediction_id = ? AND user_id = ?'
  ).get(id, req.session.user.id);

  if (existing) {
    req.session.flash = { type: 'error', message: 'You have already placed a bet on this prediction.' };
    return res.redirect(`/predictions/${id}`);
  }

  // Check user has enough credits
  const user = db.prepare('SELECT credits FROM users WHERE id = ?').get(req.session.user.id);
  if (!user || user.credits < credits) {
    req.session.flash = { type: 'error', message: 'Not enough credits.' };
    return res.redirect(`/predictions/${id}`);
  }

  // ── Place bet (atomic) ─────────────────────────────────────────────────────
  const placeBet = db.transaction(() => {
    db.prepare(
      'INSERT INTO bets (prediction_id, user_id, choice, amount) VALUES (?, ?, ?, ?)'
    ).run(id, req.session.user.id, choice, credits);

    db.prepare(
      'UPDATE users SET credits = credits - ? WHERE id = ?'
    ).run(credits, req.session.user.id);
  });

  placeBet();

  // Keep session credits in sync
  req.session.user.credits -= credits;

  req.session.flash = {
    type   : 'success',
    message: `Bet placed! You wagered ${credits} credit${credits !== 1 ? 's' : ''} on outcome ${choice}.`,
  };
  res.redirect(`/predictions/${id}`);
});

// ─── POST /predictions/:id/resolve ───────────────────────────────────────────
// Only the prediction author OR an admin can resolve.
router.post('/:id/resolve', requireAuth, (req, res) => {
  const db     = req.db;
  const id     = parseInt(req.params.id, 10);
  const { outcome } = req.body;

  if (!['A', 'B'].includes(outcome)) {
    req.session.flash = { type: 'error', message: 'Invalid outcome. Must be A or B.' };
    return res.redirect(`/predictions/${id}`);
  }

  const prediction = db.prepare('SELECT * FROM predictions WHERE id = ?').get(id);

  if (!prediction) {
    return res.status(404).render('error', { title: '404', code: 404, message: 'Not found.' });
  }

  if (prediction.resolved_as) {
    req.session.flash = { type: 'error', message: 'This prediction has already been resolved.' };
    return res.redirect(`/predictions/${id}`);
  }

  const isOwner = prediction.user_id === req.session.user.id;
  const isAdmin = req.session.user.role === 'admin';

  if (!isOwner && !isAdmin) {
    return res.status(403).render('error', { title: '403', code: 403, message: 'Forbidden.' });
  }

  // ── Resolve + pay out winners (atomic) ────────────────────────────────────
  const resolve = db.transaction(() => {
    // Mark resolved
    db.prepare(
      'UPDATE predictions SET resolved_as = ? WHERE id = ?'
    ).run(outcome, id);

    // Fetch all bets in one query
    const bets = db.prepare(
      'SELECT user_id, choice, amount FROM bets WHERE prediction_id = ?'
    ).all(id);

    const totalPool   = bets.reduce((sum, b) => sum + b.amount, 0);
    const winnerBets  = bets.filter(b => b.choice === outcome);
    const winnerPool  = winnerBets.reduce((sum, b) => sum + b.amount, 0);

    if (winnerPool === 0) return; // No winners — house keeps the pot

    // Proportional payout to winners
    const payCredit = db.prepare('UPDATE users SET credits = credits + ? WHERE id = ?');

    for (const bet of winnerBets) {
      const payout = Math.floor((bet.amount / winnerPool) * totalPool);
      payCredit.run(payout, bet.user_id);
    }
  });

  resolve();

  req.session.flash = { type: 'success', message: `Prediction resolved as outcome ${outcome}. Winners paid out!` };
  res.redirect(`/predictions/${id}`);
});

module.exports = router;
