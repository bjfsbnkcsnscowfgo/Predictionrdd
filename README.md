# 🎯 Predictions

A virtual-credit prediction platform built with **Node.js**, **Express**, **EJS**, and **SQLite**.

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Configure environment (optional — defaults work for local dev)
cp .env.example .env
# Edit .env and set SESSION_SECRET to a long random string

# 3. Start the server
npm start          # production
npm run dev        # development (auto-reloads with nodemon)
```

Open → http://localhost:3000

## Stack

| Layer       | Library              |
|-------------|----------------------|
| Server      | Express 4            |
| Templates   | EJS                  |
| Database    | better-sqlite3 (SQLite) |
| Sessions    | express-session + connect-sqlite3 |
| CSRF        | csrf-sync            |
| Security    | helmet, express-rate-limit |
| Auth hashing | bcryptjs            |
| Geo/UA      | geoip-lite, ua-parser-js |

## Project Structure

```
Predictions/
├─ server.js              ← Entry point (Express app + middleware + routes)
├─ package.json
├─ .env.example           ← Copy to .env and fill in secrets
├─ db/
│  └─ main.db             ← SQLite database (auto-created on first run)
├─ sessions/
│  └─ sessions.db         ← Session store (auto-created on first run)
├─ views/
│  ├─ index.ejs           ← Homepage template
│  ├─ error.ejs           ← Error page template
│  ├─ layout.ejs          ← Layout reference (shows include structure)
│  └─ partials/
│     ├─ head.ejs         ← <head> content (meta, CSS link)
│     ├─ header.ejs       ← Navigation bar
│     └─ footer.ejs       ← Footer + JS link
└─ public/
   ├─ css/style.css       ← All styles (dark theme, no framework)
   ├─ js/main.js          ← Vanilla JS (no polling, no frameworks)
   └─ images/             ← Static image assets
```

## Adding Routes

Create route files in a `/routes` folder, then register them in `server.js`:

```js
const authRoutes = require('./routes/auth');
app.use('/auth', csrfSynchronisedProtection, authRoutes);
```

## CSRF Protection

Every HTML form that submits via POST must include the CSRF token:

```html
<form method="POST" action="/some/route">
  <input type="hidden" name="_csrf" value="<%= csrfToken %>" />
  <!-- rest of form fields -->
</form>
```

`csrfToken` is automatically injected into `res.locals` by `server.js`.

## Flash Messages

Set a flash message in any route handler:

```js
req.session.flash = { type: 'success', message: 'Done!' };
res.redirect('/');
```

Types: `success` | `error` | `warning` | `info`

## Database

The SQLite schema is bootstrapped automatically in `server.js` (`db.exec(...)` block).
Add new `CREATE TABLE IF NOT EXISTS` statements there as the project grows.

Access the database in route handlers via `req.db` (attached in middleware):

```js
router.get('/example', (req, res) => {
  const rows = req.db.prepare('SELECT * FROM users LIMIT 10').all();
  res.render('example', { rows });
});
```
