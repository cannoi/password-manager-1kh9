/**
 * VaultCrypto — all cryptography for the Personal Vault.
 *
 * KDF: PBKDF2-SHA-256 (Argon2id is not available as a native, dependency-free
 * primitive in browsers, so per the spec's fallback rule we use PBKDF2 with a
 * strong iteration count and a random salt per vault).
 * Cipher: AES-256-GCM (authenticated encryption) via the Web Crypto API.
 *
 * Nothing in this file ever logs a password, a derived key, or plaintext.
 */
(function (global) {
  'use strict';

  const PBKDF2_ITERATIONS = 300000;
  const KEY_LENGTH_BITS = 256;
  const SALT_LENGTH_BYTES = 16;
  const IV_LENGTH_BYTES = 12; // recommended for AES-GCM

  function randomBytes(len) {
    const arr = new Uint8Array(len);
    crypto.getRandomValues(arr);
    return arr;
  }

  function bufToB64(buf) {
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }

  function b64ToBuf(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function utf8Encode(str) {
    return new TextEncoder().encode(str);
  }

  function utf8Decode(buf) {
    return new TextDecoder().decode(buf);
  }

  /**
   * Derive a non-extractable AES-GCM CryptoKey from a master password + salt.
   * @param {string} password
   * @param {Uint8Array} salt
   * @param {number} iterations
   * @returns {Promise<CryptoKey>}
   */
  async function deriveKey(password, salt, iterations = PBKDF2_ITERATIONS) {
    const passKey = await crypto.subtle.importKey(
      'raw',
      utf8Encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
      passKey,
      { name: 'AES-GCM', length: KEY_LENGTH_BITS },
      false, // not extractable - key material never leaves the CryptoKey object
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Encrypt a JS value under an AES-GCM key. Returns base64 iv + ciphertext.
   */
  async function encryptJSON(key, value) {
    const iv = randomBytes(IV_LENGTH_BYTES);
    const plaintext = utf8Encode(JSON.stringify(value));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
    return { iv: bufToB64(iv), data: bufToB64(ciphertext) };
  }

  /**
   * Decrypt base64 iv + ciphertext under an AES-GCM key. Throws if the key
   * (i.e. the master password) is wrong - GCM's auth tag makes this safe.
   */
  async function decryptJSON(key, ivB64, dataB64) {
    const iv = b64ToBuf(ivB64);
    const ciphertext = b64ToBuf(dataB64);
    const plaintextBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return JSON.parse(utf8Decode(plaintextBuf));
  }

  // ---------------------------------------------------------------------
  // Password generator
  // ---------------------------------------------------------------------
  const CHARSETS = {
    lower: 'abcdefghijklmnopqrstuvwxyz',
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    numbers: '0123456789',
    symbols: '!@#$%^&*()-_=+[]{};:,.<>/?'
  };

  function generatePassword(opts) {
    const options = Object.assign(
      { length: 20, lower: true, upper: true, numbers: true, symbols: true },
      opts
    );
    let pool = '';
    if (options.lower) pool += CHARSETS.lower;
    if (options.upper) pool += CHARSETS.upper;
    if (options.numbers) pool += CHARSETS.numbers;
    if (options.symbols) pool += CHARSETS.symbols;
    if (!pool) pool = CHARSETS.lower + CHARSETS.numbers;

    const len = Math.max(8, Math.min(64, options.length || 20));
    const values = randomBytes(len);
    let out = '';
    for (let i = 0; i < len; i++) {
      out += pool[values[i] % pool.length];
    }
    return out;
  }

  // ---------------------------------------------------------------------
  // Lightweight local password-strength scorer (no external service call)
  // ---------------------------------------------------------------------
  const COMMON_PASSWORDS = [
    'password', '123456', '12345678', 'qwerty', 'letmein', 'admin',
    '111111', 'welcome', 'monkey', 'iloveyou', 'abc123', 'password1',
    '123456789', 'football', 'dragon'
  ];

  function scorePassword(password) {
    if (!password) return { score: 0, label: 'Weak' };
    const lower = password.toLowerCase();
    let entropy = 0;
    const sets = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/];
    let variety = 0;
    sets.forEach((re) => {
      if (re.test(password)) variety++;
    });
    entropy = password.length * (2 + variety); // rough heuristic

    let score = 0;
    if (password.length >= 8) score++;
    if (password.length >= 12) score++;
    if (variety >= 3) score++;
    if (password.length >= 16 && variety >= 4) score++;

    if (COMMON_PASSWORDS.includes(lower) || /^(.)\1+$/.test(password)) {
      score = 0;
      entropy = 0;
    }
    if (/^(?:0123|1234|2345|3456|4567|5678|6789|abcd|qwer)/i.test(password)) {
      score = Math.min(score, 1);
    }

    score = Math.max(0, Math.min(4, score));
    const labels = ['Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];
    return { score, label: labels[score], entropy };
  }

  global.VaultCrypto = {
    PBKDF2_ITERATIONS,
    SALT_LENGTH_BYTES,
    randomBytes,
    bufToB64,
    b64ToBuf,
    deriveKey,
    encryptJSON,
    decryptJSON,
    generatePassword,
    scorePassword
  };
})(window);
