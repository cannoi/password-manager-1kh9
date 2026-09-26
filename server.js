const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8080;

// --- Security headers -------------------------------------------------
// No third-party scripts, no inline execution needed (all JS is external),
// so we can run a fairly strict Content-Security-Policy.
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
      "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
  );
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

// --- Health check ---------------------------------------------------------
// Must never leak vault/secret data - just a liveness signal.
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

// --- Static frontend --------------------------------------------------
// The vault itself is entirely client-side (WebCrypto + IndexedDB).
// This server never sees a master password, a vault key, or plaintext data.
app.use(express.static(path.join(__dirname, 'public')));

// SPA-style fallback for any unknown (non-file) route -> index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Only start listening when this file is run directly (`npm start`),
// not when it's required by tests (supertest needs the bare app object).
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Password Manager listening on port ${PORT}`);
  });
}

module.exports = app;
