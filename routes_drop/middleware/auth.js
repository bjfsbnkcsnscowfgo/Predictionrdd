'use strict';

/**
 * middleware/auth.js — Route guard helpers.
 *
 * Usage in any route file:
 *   const { requireAuth, requireAdmin, requireGuest } = require('../middleware/auth');
 *
 *   router.get('/dashboard', requireAuth, (req, res) => { ... });
 *   router.get('/admin',     requireAdmin, (req, res) => { ... });
 *   router.get('/login',     requireGuest, (req, res) => { ... });
 */

/**
 * requireAuth — Blocks unauthenticated users.
 * Redirects to /auth/login with a flash message, preserving the intended URL.
 */
function requireAuth(req, res, next) {
  if (req.session.user) return next();
  req.session.flash       = { type: 'warning', message: 'Please log in to continue.' };
  req.session.returnTo    = req.originalUrl;
  res.redirect('/auth/login');
}

/**
 * requireAdmin — Blocks non-admin users.
 * Must be placed after requireAuth (or combined as [requireAuth, requireAdmin]).
 */
function requireAdmin(req, res, next) {
  if (req.session.user?.role === 'admin') return next();
  res.status(403).render('error', {
    title  : '403 — Forbidden',
    code   : 403,
    message: 'You do not have permission to access this page.',
  });
}

/**
 * requireGuest — Blocks already-authenticated users from auth pages (login/register).
 * Redirects logged-in users straight to the homepage.
 */
function requireGuest(req, res, next) {
  if (!req.session.user) return next();
  res.redirect('/');
}

module.exports = { requireAuth, requireAdmin, requireGuest };
