# How to plug routes into server.js

Find the `─── Routes ───` section in `server.js` and replace the TODO block with:

```js
// ─── Routes ──────────────────────────────────────────────────────────────────
const authRoutes        = require('./routes/auth');
const predictionsRoutes = require('./routes/predictions');
const profileRoutes     = require('./routes/profile');
const adminRoutes       = require('./routes/admin');

// Homepage (already in server.js — keep it or move it into routes/index.js)
app.get('/', (req, res) => { ... });

// CSRF protection is applied to auth + any route with forms
app.use('/auth',        csrfSynchronisedProtection, authRoutes);
app.use('/predictions', csrfSynchronisedProtection, predictionsRoutes);
app.use('/profile',     csrfSynchronisedProtection, profileRoutes);
app.use('/admin',       csrfSynchronisedProtection, adminRoutes);
```

That's it. The `req.db`, `req.authLimiter`, and `res.locals` are already attached
by the app-level middleware in server.js, so every route file has access to them.
