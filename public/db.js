/**
 * VaultDB — IndexedDB storage for the encrypted vault container.
 * Only ever stores: version, KDF params, salt, IV, and ciphertext.
 * Never stores plaintext passwords, the master password, or the derived key.
 */
(function (global) {
  'use strict';

  const DB_NAME = 'personal-vault';
  const DB_VERSION = 1;
  const STORE = 'vault';
  const RECORD_ID = 'vault'; // single-record store

  function openDB() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE)) {
          db.createObjectStore(STORE, { keyPath: 'id' });
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async function getVaultRecord() {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readonly');
      const store = tx.objectStore(STORE);
      const req = store.get(RECORD_ID);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error);
    });
  }

  async function putVaultRecord(record) {
    const db = await openDB();
    const payload = Object.assign({}, record, { id: RECORD_ID });
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      const store = tx.objectStore(STORE);
      const req = store.put(payload);
      req.onsuccess = () => resolve(true);
      req.onerror = () => reject(req.error);
    });
  }

  async function deleteVaultRecord() {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      const store = tx.objectStore(STORE);
      const req = store.delete(RECORD_ID);
      req.onsuccess = () => resolve(true);
      req.onerror = () => reject(req.error);
    });
  }

  global.VaultDB = { getVaultRecord, putVaultRecord, deleteVaultRecord };
})(window);
