/**
 * main.js — Predictions Platform
 *
 * Lightweight vanilla JS — no frameworks, no build step.
 * Loaded with `defer` so the DOM is ready when this runs.
 *
 * Guidelines (keep this lean):
 *  - NO polling / auto-refresh loops
 *  - NO repeated fetch calls
 *  - User-triggered actions only
 *  - Add new features in clearly labelled sections below
 */

'use strict';

// ─── Flash Message Auto-dismiss ───────────────────────────────────────────────
// Fade out flash banners after 4 seconds (user can still read them first).
(function dismissFlash() {
  const flash = document.querySelector('.flash');
  if (!flash) return;

  setTimeout(() => {
    flash.style.transition = 'opacity 0.5s ease';
    flash.style.opacity    = '0';
    setTimeout(() => flash.remove(), 500);
  }, 4000);
}());

// ─── Confirm Dialogs ─────────────────────────────────────────────────────────
// Add data-confirm="Are you sure?" to any button/link to show a confirm dialog.
document.addEventListener('click', (e) => {
  const el      = e.target.closest('[data-confirm]');
  if (!el) return;
  const message = el.dataset.confirm || 'Are you sure?';
  if (!window.confirm(message)) e.preventDefault();
});

// ─── Form Double-submit Prevention ───────────────────────────────────────────
// Disable submit buttons after first click to prevent accidental double-posting.
document.addEventListener('submit', (e) => {
  const form    = e.target;
  const submit  = form.querySelector('[type="submit"]');
  if (!submit) return;
  // Re-enable after 5 s in case of validation failure
  submit.disabled = true;
  setTimeout(() => { submit.disabled = false; }, 5000);
});

// ─── Countdown Timers ────────────────────────────────────────────────────────
// Renders human-friendly countdowns for elements with data-closes-at="ISO date".
// Example: <span data-closes-at="2025-12-31T23:59:59Z"></span>
(function initCountdowns() {
  const els = document.querySelectorAll('[data-closes-at]');
  if (!els.length) return;

  function format(ms) {
    if (ms <= 0) return 'Closed';
    const s = Math.floor(ms / 1000);
    const m = Math.floor(s / 60);
    const h = Math.floor(m / 60);
    const d = Math.floor(h / 24);
    if (d > 0)       return `${d}d ${h % 24}h`;
    if (h > 0)       return `${h}h ${m % 60}m`;
    if (m > 0)       return `${m}m ${s % 60}s`;
    return `${s}s`;
  }

  function tick() {
    const now = Date.now();
    els.forEach(el => {
      const target = new Date(el.dataset.closesAt).getTime();
      el.textContent = format(target - now);
    });
  }

  tick();
  // Update every 30 seconds — not every second — to minimise CPU usage.
  setInterval(tick, 30_000);
}());

// ─── TODO: Add feature-specific JS below ─────────────────────────────────────
// Example: bet amount slider, prediction creation form validation, etc.
// Keep each feature in a clearly labelled IIFE or function.
