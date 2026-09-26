/**
 * Personal Vault — app controller.
 * State lives only in memory while unlocked; IndexedDB only ever holds the
 * encrypted container. Nothing here logs a password or a key.
 */
(function () {
  'use strict';

  const DEFAULT_CATEGORIES = [
    { id: 'websites', label: 'Websites', icon: '🌐' },
    { id: 'email', label: 'Email', icon: '📧' },
    { id: 'banking', label: 'Banking', icon: '💳' },
    { id: 'work', label: 'Work', icon: '💼' },
    { id: 'shopping', label: 'Shopping', icon: '🛒' },
    { id: 'games', label: 'Games', icon: '🎮' },
    { id: 'social', label: 'Social', icon: '📱' },
    { id: 'other', label: 'Other', icon: '🔑' }
  ];

  const state = {
    key: null,            // CryptoKey, only while unlocked
    salt: null,            // Uint8Array
    kdfIterations: null,
    vaultMeta: null,       // { version, createdAt, lastUnlocked, lastBackup }
    data: null,            // decrypted { entries, categories, settings }
    view: 'vault',
    activeCategory: null,
    activeFilter: null,    // 'favorites' | 'recent' | null
    editingId: null,
    autoLockTimer: null,
    clipboardTimer: null,
    confirmResolver: null
  };

  const $ = (id) => document.getElementById(id);
  const qs = (sel, root) => (root || document).querySelector(sel);
  const qsa = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  function show(el) { el.hidden = false; }
  function hide(el) { el.hidden = true; }

  function toast(msg) {
    const t = $('toast');
    t.textContent = msg;
    show(t);
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => hide(t), 2200);
  }

  function uid() {
    return (crypto.randomUUID ? crypto.randomUUID() : 'id-' + Date.now() + '-' + Math.random().toString(16).slice(2));
  }

  function escapeHTML(str) {
    return String(str == null ? '' : str).replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
  }

  // ---------------------------------------------------------------------
  // Screen / view routing
  // ---------------------------------------------------------------------
  function showScreen(id) {
    qsa('.screen').forEach((s) => hide(s));
    show($(id));
  }

  function setView(view) {
    state.view = view;
    state.activeFilter = view === 'favorites' || view === 'recent' ? view : null;
    if (view === 'vault' || view === 'favorites' || view === 'recent') {
      qsa('.view').forEach((v) => hide(v));
      show($('view-vault'));
      $('view-title').textContent = view === 'favorites' ? 'Favorites' : view === 'recent' ? 'Recent' : 'Vault';
      renderCategoryChips();
      renderPasswordList();
    } else if (view === 'security') {
      qsa('.view').forEach((v) => hide(v));
      show($('view-security'));
      renderSecurityView();
    } else if (view === 'settings') {
      qsa('.view').forEach((v) => hide(v));
      show($('view-settings'));
      renderSettingsView();
    }
    qsa('.nav-item[data-view]').forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.view === view);
    });
  }

  // ---------------------------------------------------------------------
  // Boot
  // ---------------------------------------------------------------------
  async function boot() {
    applyStoredTheme();
    const record = await VaultDB.getVaultRecord();
    if (record) {
      show($('btn-goto-unlock'));
      $('btn-goto-unlock').addEventListener('click', () => showScreen('screen-unlock'));
      showScreen('screen-welcome');
      $('btn-goto-unlock').click();
    } else {
      showScreen('screen-welcome');
    }
    wireStaticEvents();
  }

  function applyStoredTheme() {
    const theme = localStorage.getItem('pv-theme') || 'system';
    if (theme === 'system') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', theme);
  }

  // ---------------------------------------------------------------------
  // Create vault
  // ---------------------------------------------------------------------
  async function createVault() {
    const pw = $('create-password').value;
    const pw2 = $('create-password-confirm').value;
    const errEl = $('create-error');
    errEl.textContent = '';

    if (pw.length < 8) { errEl.textContent = 'Master Password must be at least 8 characters.'; return; }
    if (pw !== pw2) { errEl.textContent = 'Passwords do not match.'; return; }
    const strength = VaultCrypto.scorePassword(pw);
    if (strength.score < 2) { errEl.textContent = 'Please choose a stronger Master Password.'; return; }

    const salt = VaultCrypto.randomBytes(VaultCrypto.SALT_LENGTH_BYTES);
    const iterations = VaultCrypto.PBKDF2_ITERATIONS;
    const key = await VaultCrypto.deriveKey(pw, salt, iterations);

    const initialData = {
      entries: [],
      categories: DEFAULT_CATEGORIES,
      settings: { autoLockMinutes: 5, clipboardTimeoutSeconds: 20, recent: [] }
    };
    const enc = await VaultCrypto.encryptJSON(key, initialData);
    const now = new Date().toISOString();
    const record = {
      version: 1,
      kdf: { algorithm: 'PBKDF2-SHA-256', salt: VaultCrypto.bufToB64(salt), iterations },
      encryption: { algorithm: 'AES-256-GCM', iv: enc.iv },
      encryptedData: enc.data,
      createdAt: now,
      updatedAt: now,
      lastUnlocked: now,
      lastBackup: null
    };
    await VaultDB.putVaultRecord(record);

    // Clear the password fields from the DOM immediately.
    $('create-password').value = '';
    $('create-password-confirm').value = '';

    state.key = key;
    state.salt = salt;
    state.kdfIterations = iterations;
    state.data = initialData;
    state.vaultMeta = record;

    enterApp();
    toast('Vault created.');
  }

  // ---------------------------------------------------------------------
  // Unlock / lock
  // ---------------------------------------------------------------------
  async function unlockVault() {
    const pw = $('unlock-password').value;
    const errEl = $('unlock-error');
    errEl.textContent = '';
    const record = await VaultDB.getVaultRecord();
    if (!record) { errEl.textContent = 'No vault found on this device.'; return; }

    try {
      const salt = VaultCrypto.b64ToBuf(record.kdf.salt);
      const key = await VaultCrypto.deriveKey(pw, salt, record.kdf.iterations);
      const data = await VaultCrypto.decryptJSON(key, record.encryption.iv, record.encryptedData);

      state.key = key;
      state.salt = salt;
      state.kdfIterations = record.kdf.iterations;
      state.data = data;
      state.vaultMeta = record;
      if (!state.data.settings) state.data.settings = { autoLockMinutes: 5, clipboardTimeoutSeconds: 20, recent: [] };
      if (!state.data.categories) state.data.categories = DEFAULT_CATEGORIES;

      record.lastUnlocked = new Date().toISOString();
      await VaultDB.putVaultRecord(record);

      $('unlock-password').value = '';
      enterApp();
    } catch (e) {
      errEl.textContent = 'Incorrect Master Password.';
    }
  }

  function enterApp() {
    showScreen('screen-app');
    populateCategorySelect();
    setView('vault');
    resetAutoLockTimer();
    const clipSupported = !!(navigator.clipboard && navigator.clipboard.writeText);
    $('clipboard-support-note').textContent = clipSupported
      ? ''
      : 'This browser does not support automatic clipboard clearing.';
  }

  function lockVault() {
    // Wipe sensitive state from memory.
    state.key = null;
    state.salt = null;
    state.data = null;
    state.editingId = null;
    clearTimeout(state.autoLockTimer);
    hide($('modal-item'));
    hide($('modal-generator'));
    hide($('modal-confirm'));
    hide($('modal-change-master'));
    $('search-input').value = '';
    showScreen('screen-unlock');
  }

  // ---------------------------------------------------------------------
  // Auto-lock
  // ---------------------------------------------------------------------
  const ACTIVITY_EVENTS = ['mousemove', 'keydown', 'click', 'touchstart', 'scroll'];

  function resetAutoLockTimer() {
    clearTimeout(state.autoLockTimer);
    const minutes = state.data ? Number(state.data.settings.autoLockMinutes) : 5;
    if (!minutes) return; // 0 = Never
    state.autoLockTimer = setTimeout(() => {
      if (state.key) { lockVault(); toast('Vault locked (inactivity).'); }
    }, minutes * 60 * 1000);
  }

  ACTIVITY_EVENTS.forEach((ev) => {
    document.addEventListener(ev, () => { if (state.key) resetAutoLockTimer(); }, { passive: true });
  });

  // ---------------------------------------------------------------------
  // Persist current decrypted data back into the encrypted container
  // ---------------------------------------------------------------------
  async function persist() {
    const enc = await VaultCrypto.encryptJSON(state.key, state.data);
    state.vaultMeta.encryption.iv = enc.iv;
    state.vaultMeta.encryptedData = enc.data;
    state.vaultMeta.updatedAt = new Date().toISOString();
    await VaultDB.putVaultRecord(state.vaultMeta);
  }

  // ---------------------------------------------------------------------
  // Categories
  // ---------------------------------------------------------------------
  function populateCategorySelect() {
    const sel = $('item-category');
    sel.innerHTML = state.data.categories
      .map((c) => `<option value="${escapeHTML(c.id)}">${escapeHTML(c.icon)} ${escapeHTML(c.label)}</option>`)
      .join('');
  }

  function renderCategoryChips() {
    const wrap = $('category-chips');
    const chips = [{ id: null, label: 'All', icon: '' }].concat(state.data.categories);
    wrap.innerHTML = chips
      .map((c) => `<button class="chip ${state.activeCategory === c.id ? 'active' : ''}" data-cat="${c.id ? escapeHTML(c.id) : ''}">${c.icon ? c.icon + ' ' : ''}${escapeHTML(c.label)}</button>`)
      .join('');
    qsa('.chip', wrap).forEach((btn) => {
      btn.addEventListener('click', () => {
        state.activeCategory = btn.dataset.cat || null;
        renderCategoryChips();
        renderPasswordList();
      });
    });
  }

  function categoryIcon(catId) {
    const c = state.data.categories.find((c) => c.id === catId);
    return c ? c.icon : '🔑';
  }

  // ---------------------------------------------------------------------
  // Password list
  // ---------------------------------------------------------------------
  function getFilteredEntries() {
    let entries = state.data.entries.slice();
    const query = $('search-input').value.trim().toLowerCase();

    if (state.activeFilter === 'favorites') entries = entries.filter((e) => e.favorite);
    if (state.activeFilter === 'recent') {
      const recentIds = (state.data.settings.recent || []).map((r) => r.id);
      entries = entries
        .filter((e) => recentIds.includes(e.id))
        .sort((a, b) => recentIds.indexOf(a.id) - recentIds.indexOf(b.id));
    }
    if (state.activeCategory) entries = entries.filter((e) => e.category === state.activeCategory);

    if (query) {
      entries = entries.filter((e) => {
        const hay = [e.name, e.website, e.username, categoryLabel(e.category), (e.tags || []).join(' ')]
          .join(' ')
          .toLowerCase();
        return hay.includes(query);
      });
    }
    if (state.activeFilter !== 'recent') {
      entries.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
    }
    return entries;
  }

  function categoryLabel(catId) {
    const c = state.data.categories.find((c) => c.id === catId);
    return c ? c.label : 'Other';
  }

  function renderPasswordList() {
    const list = $('password-list');
    const entries = getFilteredEntries();
    $('empty-state').hidden = entries.length !== 0;
    list.innerHTML = entries
      .map((e) => `
        <li class="password-item" data-id="${escapeHTML(e.id)}">
          <span class="item-icon">${categoryIcon(e.category)}</span>
          <span class="item-main">
            <span class="item-name">${escapeHTML(e.name)}${e.favorite ? ' <span class="item-fav">⭐</span>' : ''}</span>
            <span class="item-sub">${escapeHTML(e.username || '')} · ${'••••••••••'}</span>
          </span>
        </li>
      `)
      .join('');
    qsa('.password-item', list).forEach((li) => {
      li.addEventListener('click', () => openItemModal(li.dataset.id));
    });
  }

  // ---------------------------------------------------------------------
  // Add / edit / delete item
  // ---------------------------------------------------------------------
  function clearItemForm() {
    $('item-name').value = '';
    $('item-website').value = '';
    $('item-username').value = '';
    $('item-password').value = '';
    $('item-password').type = 'password';
    $('item-tags').value = '';
    $('item-notes').value = '';
    $('item-favorite').checked = false;
    $('item-category').value = state.data.categories[0] ? state.data.categories[0].id : 'other';
    updateStrengthUI('item', '');
    $('item-security-info').innerHTML = '';
  }

  function openItemModal(id) {
    populateCategorySelect();
    clearItemForm();
    state.editingId = id || null;

    if (id) {
      const entry = state.data.entries.find((e) => e.id === id);
      if (!entry) return;
      $('item-modal-title').textContent = 'Edit Password';
      $('item-name').value = entry.name || '';
      $('item-website').value = entry.website || '';
      $('item-username').value = entry.username || '';
      $('item-password').value = entry.password || '';
      $('item-category').value = entry.category || 'other';
      $('item-tags').value = (entry.tags || []).join(', ');
      $('item-notes').value = entry.notes || '';
      $('item-favorite').checked = !!entry.favorite;
      updateStrengthUI('item', entry.password || '');
      $('item-security-info').innerHTML = `
        <div><span>Created</span><span>${new Date(entry.createdAt).toLocaleDateString()}</span></div>
        <div><span>Updated</span><span>${new Date(entry.updatedAt).toLocaleDateString()}</span></div>
      `;
      show($('btn-delete-item'));
      trackRecent(id);
    } else {
      $('item-modal-title').textContent = 'Add Password';
      hide($('btn-delete-item'));
    }
    show($('modal-item'));
  }

  function trackRecent(id) {
    const recent = state.data.settings.recent || [];
    const filtered = recent.filter((r) => r.id !== id);
    filtered.unshift({ id, ts: Date.now() });
    state.data.settings.recent = filtered.slice(0, 20);
    persist();
  }

  async function saveItem() {
    const name = $('item-name').value.trim();
    if (!name) { toast('Account name is required.'); return; }

    const entry = {
      id: state.editingId || uid(),
      name,
      website: $('item-website').value.trim(),
      username: $('item-username').value.trim(),
      password: $('item-password').value,
      category: $('item-category').value,
      tags: $('item-tags').value.split(',').map((t) => t.trim()).filter(Boolean),
      notes: $('item-notes').value,
      favorite: $('item-favorite').checked,
      createdAt: state.editingId
        ? state.data.entries.find((e) => e.id === state.editingId).createdAt
        : new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    if (state.editingId) {
      const idx = state.data.entries.findIndex((e) => e.id === state.editingId);
      state.data.entries[idx] = entry;
    } else {
      state.data.entries.push(entry);
    }
    await persist();
    hide($('modal-item'));
    renderPasswordList();
    toast('Password saved securely.');
  }

  async function deleteItem() {
    if (!state.editingId) return;
    const ok = await confirmDialog({ title: 'Delete this password?', message: 'This cannot be undone.' });
    if (!ok) return;
    state.data.entries = state.data.entries.filter((e) => e.id !== state.editingId);
    state.data.settings.recent = (state.data.settings.recent || []).filter((r) => r.id !== state.editingId);
    await persist();
    hide($('modal-item'));
    renderPasswordList();
    toast('Password deleted.');
  }

  // ---------------------------------------------------------------------
  // Strength meter UI
  // ---------------------------------------------------------------------
  function updateStrengthUI(prefix, password) {
    const { score, label } = VaultCrypto.scorePassword(password);
    const fill = $(prefix + '-strength-fill');
    const lbl = $(prefix + '-strength-label');
    const pct = [5, 25, 50, 75, 100][score];
    const colors = ['#dc2626', '#dc2626', '#d97706', '#16a34a', '#15803d'];
    if (fill) { fill.style.width = pct + '%'; fill.style.background = colors[score]; }
    if (lbl) lbl.textContent = password ? label : '\u00A0';
  }

  // ---------------------------------------------------------------------
  // Password generator
  // ---------------------------------------------------------------------
  let generatorLastValue = '';
  let generatorTargetField = null; // 'item-password' when opened from item modal

  function generatorOptions() {
    return {
      length: Number($('gen-length').value),
      upper: $('gen-upper').checked,
      lower: $('gen-lower').checked,
      numbers: $('gen-numbers').checked,
      symbols: $('gen-symbols').checked
    };
  }

  function runGenerator() {
    generatorLastValue = VaultCrypto.generatePassword(generatorOptions());
    $('generated-password-display').textContent = generatorLastValue;
    updateStrengthUI('gen', generatorLastValue);
  }

  function openGenerator(targetField) {
    generatorTargetField = targetField || null;
    $('btn-use-generated').hidden = !targetField;
    $('gen-length-value').textContent = $('gen-length').value;
    runGenerator();
    show($('modal-generator'));
  }

  async function copyToClipboard(text) {
    if (!navigator.clipboard || !navigator.clipboard.writeText) {
      toast('Clipboard access is not available in this browser.');
      return;
    }
    await navigator.clipboard.writeText(text);
    toast('Copied to clipboard.');
    clearTimeout(state.clipboardTimer);
    const seconds = state.data ? Number(state.data.settings.clipboardTimeoutSeconds) : 20;
    if (seconds > 0) {
      state.clipboardTimer = setTimeout(async () => {
        try {
          const current = await navigator.clipboard.readText();
          if (current === text) await navigator.clipboard.writeText('');
        } catch (e) {
          // Reading clipboard may be blocked by permissions; clearing is best-effort.
        }
      }, seconds * 1000);
    }
  }

  // ---------------------------------------------------------------------
  // Security audit
  // ---------------------------------------------------------------------
  function computeAudit() {
    const entries = state.data.entries;
    const weak = entries.filter((e) => VaultCrypto.scorePassword(e.password).score < 2);
    const passwordCounts = {};
    entries.forEach((e) => {
      if (!e.password) return;
      passwordCounts[e.password] = (passwordCounts[e.password] || 0) + 1;
    });
    const reused = entries.filter((e) => e.password && passwordCounts[e.password] > 1);
    const OLD_DAYS = 180;
    const old = entries.filter((e) => {
      const days = (Date.now() - new Date(e.updatedAt).getTime()) / 86400000;
      return days > OLD_DAYS;
    });
    const missingInfo = entries.filter((e) => !e.website || !e.username);
    const dupKey = {};
    const duplicates = [];
    entries.forEach((e) => {
      const key = (e.website || e.name).toLowerCase() + '|' + (e.username || '').toLowerCase();
      if (dupKey[key]) duplicates.push(e);
      else dupKey[key] = true;
    });
    return { weak, reused, old, missingInfo, duplicates, strong: entries.filter((e) => VaultCrypto.scorePassword(e.password).score >= 3) };
  }

  function renderSecurityView() {
    const audit = computeAudit();
    const total = state.data.entries.length;
    $('security-summary').textContent = `${total} password${total === 1 ? '' : 's'} · ${audit.weak.length} weak · ${audit.reused.length} reused · ${audit.old.length} old`;

    const cards = [
      { key: 'strong', label: '🟢 Strong', list: audit.strong },
      { key: 'weak', label: '🟡 Weak', list: audit.weak },
      { key: 'reused', label: '🔴 Reused', list: audit.reused },
      { key: 'old', label: '🟠 Old', list: audit.old },
      { key: 'missingInfo', label: 'Missing info', list: audit.missingInfo },
      { key: 'duplicates', label: 'Duplicates', list: audit.duplicates }
    ];
    $('health-cards').innerHTML = cards
      .map((c) => `<div class="health-card" data-key="${c.key}"><div class="num">${c.list.length}</div><div>${c.label}</div></div>`)
      .join('');

    const detailList = $('security-detail-list');
    detailList.innerHTML = '';
    qsa('.health-card', $('health-cards')).forEach((card) => {
      card.addEventListener('click', () => {
        const group = cards.find((c) => c.key === card.dataset.key);
        detailList.innerHTML = group.list
          .map((e) => `<li class="password-item" data-id="${escapeHTML(e.id)}"><span class="item-icon">${categoryIcon(e.category)}</span><span class="item-main"><span class="item-name">${escapeHTML(e.name)}</span><span class="item-sub">${escapeHTML(e.username || '')}</span></span></li>`)
          .join('') || '<p class="muted">Nothing here.</p>';
        qsa('.password-item', detailList).forEach((li) => li.addEventListener('click', () => openItemModal(li.dataset.id)));
      });
    });
  }

  // ---------------------------------------------------------------------
  // Settings view
  // ---------------------------------------------------------------------
  function renderSettingsView() {
    $('setting-theme').value = localStorage.getItem('pv-theme') || 'system';
    $('setting-autolock').value = String(state.data.settings.autoLockMinutes);
    $('setting-clipboard').value = String(state.data.settings.clipboardTimeoutSeconds);

    const meta = state.vaultMeta;
    $('vault-security-info').innerHTML = `
      <div><span>Vault status</span><span>Unlocked</span></div>
      <div><span>Encryption</span><span>${escapeHTML(meta.encryption.algorithm)}</span></div>
      <div><span>KDF</span><span>${escapeHTML(meta.kdf.algorithm)} (${meta.kdf.iterations.toLocaleString()} iterations)</span></div>
      <div><span>Auto Lock</span><span>${state.data.settings.autoLockMinutes ? state.data.settings.autoLockMinutes + ' min' : 'Never'}</span></div>
      <div><span>Last unlocked</span><span>${meta.lastUnlocked ? new Date(meta.lastUnlocked).toLocaleString() : '—'}</span></div>
      <div><span>Last backup</span><span>${meta.lastBackup ? new Date(meta.lastBackup).toLocaleString() : 'Never'}</span></div>
    `;
  }

  // ---------------------------------------------------------------------
  // Generic confirm dialog (returns Promise<boolean>), optionally requires
  // the master password and/or a typed confirmation phrase.
  // ---------------------------------------------------------------------
  function confirmDialog({ title, message, requireMasterPassword = false, requireTypedText = null }) {
    $('confirm-title').textContent = title;
    $('confirm-message').textContent = message;
    $('confirm-error').textContent = '';
    $('confirm-master-password').value = '';
    $('confirm-typed-text').value = '';
    $('confirm-master-password').hidden = !requireMasterPassword;
    if (requireTypedText) {
      $('confirm-typed-text').hidden = false;
      $('confirm-typed-text').placeholder = `Type "${requireTypedText}" to confirm`;
    } else {
      $('confirm-typed-text').hidden = true;
    }
    show($('modal-confirm'));

    return new Promise((resolve) => {
      state.confirmResolver = async () => {
        if (requireMasterPassword) {
          const pw = $('confirm-master-password').value;
          try {
            await VaultCrypto.deriveKey(pw, state.salt, state.kdfIterations).then((k) =>
              VaultCrypto.decryptJSON(k, state.vaultMeta.encryption.iv, state.vaultMeta.encryptedData)
            );
          } catch (e) {
            $('confirm-error').textContent = 'Incorrect Master Password.';
            return;
          }
        }
        if (requireTypedText && $('confirm-typed-text').value !== requireTypedText) {
          $('confirm-error').textContent = `Please type "${requireTypedText}" exactly.`;
          return;
        }
        hide($('modal-confirm'));
        resolve(true);
      };
      $('btn-confirm-cancel').onclick = () => { hide($('modal-confirm')); resolve(false); };
    });
  }

  // ---------------------------------------------------------------------
  // Backup / Export / Import
  // ---------------------------------------------------------------------
  function downloadVaultFile(record, suffix) {
    const dateStr = new Date().toISOString().slice(0, 10);
    const filename = `password-vault-${dateStr}${suffix || ''}.pmv`;
    const blob = new Blob([JSON.stringify(record)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  async function backupVault() {
    const ok = await confirmDialog({
      title: 'Backup Vault',
      message: 'Keep your backup in a safe place. If you lose your Master Password, encrypted backups may not be recoverable.',
      requireMasterPassword: true
    });
    if (!ok) return;
    await persist(); // ensure latest state is encrypted before export
    downloadVaultFile(state.vaultMeta, '-backup');
    state.vaultMeta.lastBackup = new Date().toISOString();
    await VaultDB.putVaultRecord(state.vaultMeta);
    renderSettingsView();
    toast('Encrypted backup downloaded.');
  }

  async function exportVault() {
    const ok = await confirmDialog({
      title: 'Export Vault',
      message: 'This will download an encrypted copy of your vault. It never contains plaintext passwords.',
      requireMasterPassword: true
    });
    if (!ok) return;
    await persist();
    downloadVaultFile(state.vaultMeta, '');
    toast('Encrypted vault exported.');
  }

  function readFileAsText(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(reader.error);
      reader.readAsText(file);
    });
  }

  async function importVaultFile(file) {
    let imported;
    try {
      const text = await readFileAsText(file);
      imported = JSON.parse(text);
    } catch (e) {
      toast('Invalid or corrupted vault file.');
      return;
    }
    if (!imported || !imported.kdf || !imported.encryption || !imported.encryptedData || !imported.version) {
      toast('This file is not a recognized vault export.');
      return;
    }
    if (imported.version > 1) {
      toast('This vault was created by a newer, unsupported version of the app.');
      return;
    }

    const pw = prompt('Enter the Master Password for the vault file you are importing:');
    if (pw == null) return;
    let importedData;
    try {
      const salt = VaultCrypto.b64ToBuf(imported.kdf.salt);
      const key = await VaultCrypto.deriveKey(pw, salt, imported.kdf.iterations);
      importedData = await VaultCrypto.decryptJSON(key, imported.encryption.iv, imported.encryptedData);
    } catch (e) {
      toast('Could not decrypt that file with the given Master Password.');
      return;
    }

    const mode = confirm('Click OK to MERGE the imported vault into your current vault, or Cancel to REPLACE your current vault entirely.')
      ? 'merge'
      : 'replace';

    const ok = await confirmDialog({
      title: mode === 'replace' ? 'Replace your entire vault?' : 'Merge imported passwords?',
      message: mode === 'replace'
        ? 'This will permanently delete all current entries and replace them with the imported vault.'
        : 'Imported entries will be added to your current vault. Duplicates by name+username may appear.',
      requireTypedText: mode === 'replace' ? 'REPLACE' : null
    });
    if (!ok) return;

    if (mode === 'replace') {
      state.data.entries = importedData.entries || [];
      if (importedData.categories) state.data.categories = importedData.categories;
    } else {
      state.data.entries = state.data.entries.concat(
        (importedData.entries || []).map((e) => Object.assign({}, e, { id: uid() }))
      );
    }
    await persist();
    populateCategorySelect();
    setView('vault');
    toast('Vault imported successfully.');
  }

  // ---------------------------------------------------------------------
  // Change master password (validate -> process -> verify -> commit)
  // ---------------------------------------------------------------------
  async function changeMasterPassword() {
    const current = $('cm-current').value;
    const next = $('cm-new').value;
    const confirmPw = $('cm-confirm').value;
    const errEl = $('cm-error');
    errEl.textContent = '';

    try {
      // 1. authenticate current password
      const testKey = await VaultCrypto.deriveKey(current, state.salt, state.kdfIterations);
      await VaultCrypto.decryptJSON(testKey, state.vaultMeta.encryption.iv, state.vaultMeta.encryptedData);
    } catch (e) {
      errEl.textContent = 'Current Master Password is incorrect.';
      return;
    }
    if (next.length < 8 || VaultCrypto.scorePassword(next).score < 2) {
      errEl.textContent = 'New Master Password is too weak.';
      return;
    }
    if (next !== confirmPw) {
      errEl.textContent = 'New passwords do not match.';
      return;
    }

    const previousRecord = JSON.parse(JSON.stringify(state.vaultMeta)); // in-memory checkpoint

    try {
      // 2. decrypt vault (already have state.data in memory)
      // 3. derive new key
      const newSalt = VaultCrypto.randomBytes(VaultCrypto.SALT_LENGTH_BYTES);
      const newKey = await VaultCrypto.deriveKey(next, newSalt, VaultCrypto.PBKDF2_ITERATIONS);
      // 4. re-encrypt vault
      const enc = await VaultCrypto.encryptJSON(newKey, state.data);
      const candidate = Object.assign({}, state.vaultMeta, {
        kdf: { algorithm: 'PBKDF2-SHA-256', salt: VaultCrypto.bufToB64(newSalt), iterations: VaultCrypto.PBKDF2_ITERATIONS },
        encryption: { algorithm: 'AES-256-GCM', iv: enc.iv },
        encryptedData: enc.data,
        updatedAt: new Date().toISOString()
      });
      // 5. verify new encrypted vault decrypts correctly before committing
      const verifyData = await VaultCrypto.decryptJSON(newKey, candidate.encryption.iv, candidate.encryptedData);
      if (!verifyData) throw new Error('verification failed');

      // 6. only now replace the old vault
      await VaultDB.putVaultRecord(candidate);
      state.vaultMeta = candidate;
      state.key = newKey;
      state.salt = newSalt;
      state.kdfIterations = VaultCrypto.PBKDF2_ITERATIONS;

      $('cm-current').value = '';
      $('cm-new').value = '';
      $('cm-confirm').value = '';
      hide($('modal-change-master'));
      renderSettingsView();
      toast('Master Password changed.');
    } catch (e) {
      // Any failure: the vault on disk was never touched, so nothing is lost.
      await VaultDB.putVaultRecord(previousRecord);
      errEl.textContent = 'Could not change Master Password. Your existing vault was not modified.';
    }
  }

  // ---------------------------------------------------------------------
  // Delete vault
  // ---------------------------------------------------------------------
  async function deleteVaultFlow() {
    const ok = await confirmDialog({
      title: 'Delete this vault permanently?',
      message: 'This deletes all passwords stored on this device. This cannot be undone. Make sure you have a backup.',
      requireMasterPassword: true,
      requireTypedText: 'DELETE'
    });
    if (!ok) return;
    await VaultDB.deleteVaultRecord();
    lockVaultHard();
    toast('Vault deleted.');
  }

  function lockVaultHard() {
    state.key = null;
    state.salt = null;
    state.data = null;
    state.vaultMeta = null;
    clearTimeout(state.autoLockTimer);
    hide($('btn-goto-unlock'));
    showScreen('screen-welcome');
  }

  // ---------------------------------------------------------------------
  // Event wiring
  // ---------------------------------------------------------------------
  function wireStaticEvents() {
    $('btn-goto-create').addEventListener('click', () => showScreen('screen-create'));
    $('btn-create-cancel').addEventListener('click', () => showScreen('screen-welcome'));
    $('btn-create-vault').addEventListener('click', createVault);
    $('create-password').addEventListener('input', (e) => updateStrengthUI('create', e.target.value));
    $('btn-unlock').addEventListener('click', unlockVault);
    $('unlock-password').addEventListener('keydown', (e) => { if (e.key === 'Enter') unlockVault(); });

    qsa('[data-toggle-show]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const input = $(btn.dataset.toggleShow);
        input.type = input.type === 'password' ? 'text' : 'password';
      });
    });

    // Nav (sidebar + bottom nav)
    qsa('.nav-item[data-view]').forEach((btn) => {
      btn.addEventListener('click', () => setView(btn.dataset.view));
    });
    $('btn-lock-now').addEventListener('click', () => { lockVault(); toast('Vault locked.'); });
    $('btn-lock-now-mobile').addEventListener('click', () => { lockVault(); toast('Vault locked.'); });

    $('search-input').addEventListener('input', () => { if (state.view !== 'security' && state.view !== 'settings') renderPasswordList(); });

    $('btn-theme-toggle').addEventListener('click', () => {
      const current = localStorage.getItem('pv-theme') || 'system';
      const next = current === 'dark' ? 'light' : current === 'light' ? 'system' : 'dark';
      localStorage.setItem('pv-theme', next);
      applyStoredTheme();
    });

    // Add / edit / delete item
    $('btn-add-password').addEventListener('click', () => openItemModal(null));
    $('btn-close-item-modal').addEventListener('click', () => hide($('modal-item')));
    $('btn-save-item').addEventListener('click', saveItem);
    $('btn-delete-item').addEventListener('click', deleteItem);
    $('item-password').addEventListener('input', (e) => updateStrengthUI('item', e.target.value));
    $('btn-copy-item-password').addEventListener('click', () => copyToClipboard($('item-password').value));
    $('btn-generate-item-password').addEventListener('click', () => openGenerator('item-password'));

    // Generator modal
    $('btn-close-generator-modal').addEventListener('click', () => hide($('modal-generator')));
    $('gen-length').addEventListener('input', (e) => { $('gen-length-value').textContent = e.target.value; runGenerator(); });
    ['gen-upper', 'gen-lower', 'gen-numbers', 'gen-symbols'].forEach((id) => {
      $(id).addEventListener('change', runGenerator);
    });
    $('btn-regenerate').addEventListener('click', runGenerator);
    $('btn-copy-generated').addEventListener('click', () => copyToClipboard(generatorLastValue));
    $('btn-use-generated').addEventListener('click', () => {
      if (generatorTargetField) {
        $(generatorTargetField).value = generatorLastValue;
        updateStrengthUI('item', generatorLastValue);
      }
      hide($('modal-generator'));
    });

    // Confirm modal
    $('btn-confirm-ok').addEventListener('click', () => state.confirmResolver && state.confirmResolver());

    // Settings
    $('setting-theme').addEventListener('change', (e) => { localStorage.setItem('pv-theme', e.target.value); applyStoredTheme(); });
    $('setting-autolock').addEventListener('change', async (e) => {
      state.data.settings.autoLockMinutes = Number(e.target.value);
      await persist();
      resetAutoLockTimer();
      renderSettingsView();
    });
    $('setting-clipboard').addEventListener('change', async (e) => {
      state.data.settings.clipboardTimeoutSeconds = Number(e.target.value);
      await persist();
    });

    $('btn-backup-vault').addEventListener('click', backupVault);
    $('btn-export-vault').addEventListener('click', exportVault);
    $('btn-import-vault').addEventListener('click', () => $('import-file-input').click());
    $('import-file-input').addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (file) importVaultFile(file);
      e.target.value = '';
    });
    $('btn-delete-vault').addEventListener('click', deleteVaultFlow);

    // Change master password
    $('btn-change-master').addEventListener('click', () => show($('modal-change-master')));
    $('btn-close-change-master').addEventListener('click', () => hide($('modal-change-master')));
    $('cm-new').addEventListener('input', (e) => updateStrengthUI('cm', e.target.value));
    $('btn-cm-submit').addEventListener('click', changeMasterPassword);

    // Close modals on overlay click (not on inner modal click)
    qsa('.modal-overlay').forEach((overlay) => {
      overlay.addEventListener('click', (e) => { if (e.target === overlay) hide(overlay); });
    });
  }

  document.addEventListener('DOMContentLoaded', boot);
})();
