'use strict';
try {
  document.documentElement.dataset.theme =
    localStorage.getItem('lnc-care-theme') ||
    (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
} catch (e) {
  document.documentElement.dataset.theme = 'dark';
}
