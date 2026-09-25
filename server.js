const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const CryptoJS = require('crypto-js');
const speakeasy = require('speakeasy');
const zxcvbn = require('zxcvbn');

const app = express();
const PORT = process.env.PORT || 8080;

// Database setup
const db = new sqlite3.Database('./passwords.db');

db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT, email TEXT, secret TEXT)");
  db.run("CREATE TABLE IF NOT EXISTS passwords (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, service TEXT, username TEXT, password TEXT, notes TEXT, FOREIGN KEY(user_id) REFERENCES users(id))");
});

// Middleware
app.use(express.json());

// Health endpoint
app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

// User registration
app.post('/register', async (req, res) => {
  const { username, password, email } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const secret = speakeasy.generateSecret({ length: 20 });
  
  db.run("INSERT INTO users (username, password, email, secret) VALUES (?, ?, ?, ?)", [username, hashedPassword, email, secret.base32], function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.status(201).json({ id: this.lastID, username, email, secret: secret.otpauth_url });
  });
});

// User login
app.post('/login', async (req, res) => {
  const { username, password, token } = req.body;
  
  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    
    const verified = speakeasy.totp.verify({
      secret: user.secret,
      encoding: 'base32',
      token
    });
    
    if (!verified) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    
    res.status(200).json({ message: 'Login successful' });
  });
});

// Add password
app.post('/passwords', (req, res) => {
  const { user_id, service, username, password, notes } = req.body;
  const encryptedPassword = CryptoJS.AES.encrypt(password, 'secret key 123').toString();
  
  db.run("INSERT INTO passwords (user_id, service, username, password, notes) VALUES (?, ?, ?, ?, ?)", [user_id, service, username, encryptedPassword, notes], function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.status(201).json({ id: this.lastID, user_id, service, username, notes });
  });
});

// Get passwords
app.get('/passwords/:user_id', (req, res) => {
  const { user_id } = req.params;
  
  db.all("SELECT * FROM passwords WHERE user_id = ?", [user_id], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    const decryptedRows = rows.map(row => {
      const bytes = CryptoJS.AES.decrypt(row.password, 'secret key 123');
      const decryptedPassword = bytes.toString(CryptoJS.enc.Utf8);
      return { ...row, password: decryptedPassword };
    });
    res.status(200).json(decryptedRows);
  });
});

// Update password
app.put('/passwords/:id', (req, res) => {
  const { id } = req.params;
  const { service, username, password, notes } = req.body;
  const encryptedPassword = CryptoJS.AES.encrypt(password, 'secret key 123').toString();
  
  db.run("UPDATE passwords SET service = ?, username = ?, password = ?, notes = ? WHERE id = ?", [service, username, encryptedPassword, notes, id], function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.status(200).json({ id, service, username, notes });
  });
});

// Delete password
app.delete('/passwords/:id', (req, res) => {
  const { id } = req.params;
  
  db.run("DELETE FROM passwords WHERE id = ?", [id], function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.status(200).json({ message: 'Password deleted' });
  });
});

// Generate password
app.get('/generate-password', (req, res) => {
  const password = speakeasy.generateSecret({ length: 20 }).base32;
  res.status(200).json({ password });
});

// Check password strength
app.post('/check-password-strength', (req, res) => {
  const { password } = req.body;
  const result = zxcvbn(password);
  res.status(200).json(result);
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});