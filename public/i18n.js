/**
 * Minimal i18n scaffold. Default UI language is English.
 * Add more locales by adding a new key (e.g. "vi") with the same shape.
 */
(function (global) {
  'use strict';

  const STRINGS = {
    en: {
      appName: 'Password Manager',
      tagline: 'Your private password vault.',
      createVault: 'Create Vault',
      unlockVault: 'Unlock Vault',
      cannotRecover: 'Your Master Password protects your vault. We cannot recover it for you.',
      neverShare: 'Never share your Master Password.',
      neverStoreInEntries: 'Never store your Master Password in your password entries.'
    }
  };

  let current = 'en';

  function t(key) {
    return (STRINGS[current] && STRINGS[current][key]) || STRINGS.en[key] || key;
  }

  function setLocale(locale) {
    if (STRINGS[locale]) current = locale;
  }

  function getLocale() {
    return current;
  }

  global.I18N = { t, setLocale, getLocale, locales: Object.keys(STRINGS) };
})(window);
