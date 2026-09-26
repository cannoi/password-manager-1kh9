# Password Manager — Personal Vault

A local-first, zero-knowledge personal password vault.

- **Your passwords → Your Vault → Your data → Your control.**
- All encryption happens in the browser with the Web Crypto API
  (PBKDF2-SHA-256 key derivation + AES-256-GCM authenticated encryption).
- The vault is stored encrypted in IndexedDB on your device.
- The Node/Express server only serves static files and a `/health` check.
  It never sees your Master Password, your derived key, or any plaintext
  password — there is no backend database of secrets.

## Features

- Create Vault / Unlock Vault with a Master Password (never recoverable,
  never stored, no backdoor, no hardcoded key)
- Add / edit / delete / search / categorize password entries
- Favorites and Recently Used
- Built-in password generator (length 8–64, character set toggles) with a
  local strength meter (Weak / Fair / Strong / Very Strong)
- Auto Lock after inactivity (1 / 5 / 15 / 30 min / Never) + manual Lock Now
- Clipboard copy with best-effort auto-clear (never claims to clear the
  clipboard if the browser doesn't support it)
- Encrypted export/backup (`.pmv`) and encrypted import (Merge or Replace,
  always with confirmation before anything destructive)
- Change Master Password using validate → process → verify → commit, so a
  failure never loses the existing vault
- Local Security Check: weak, reused, old, and duplicate passwords
- Dark / light theme, responsive layout (sidebar on desktop, bottom nav on
  mobile), English UI with an i18n scaffold for future languages

## Installation

```bash
npm install
npm start
```

Then open `http://localhost:8080`.

## Docker / Pi SoloHost

```bash
docker build -t password-manager .
docker run -p 8080:8080 password-manager
```

Single container, internal port `8080`, no Docker socket, no privileged
mode, no host filesystem mount required.

## Tests

```bash
npm test
```

## License

MIT
