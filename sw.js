'use strict';
// BASTION VAULT 0.9.3 GLOBAL. Cache only this app's public static shell; never touch IndexedDB/localStorage.
const CACHE = 'bastion-shell-v093';
const ROOT = new URL('./', self.registration.scope);
const SHELL = ['./index.html', './styles.css?v=093', './qr-clean.js?v=093', './qr-encode.js?v=093', './locales.js?v=093', './app.js?v=093', './manifest.webmanifest', './icon-192.png', './icon-512.png', './shield.svg'];
self.addEventListener('install', event => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE);
    await Promise.all(SHELL.map(async path => {
      const url = new URL(path, ROOT);
      const response = await fetch(new Request(url, {cache:'reload'}));
      if (!response.ok) throw new Error('Shell update failed: ' + path);
      await cache.put(url, response);
    }));
    await self.skipWaiting();
  })());
});
self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    const names = await caches.keys();
    await Promise.all(names.filter(name => name.startsWith('bastion-shell-') && name !== CACHE).map(name => caches.delete(name)));
    await self.clients.claim();
  })());
});
self.addEventListener('fetch', event => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== ROOT.origin || !url.pathname.startsWith(ROOT.pathname)) return;
  // Network-first for HTML/JS/CSS: newly published updates take priority over old cache.
  event.respondWith((async () => {
    const cache = await caches.open(CACHE);
    try {
      const response = await fetch(new Request(req, {cache:'no-store'}));
      if (response.ok && response.type === 'basic') {
        await cache.put(req, response.clone());
      }
      return response;
    } catch (error) {
      const cached = await cache.match(req, {ignoreSearch:true});
      if (cached) return cached;
      throw error;
    }
  })());
});
