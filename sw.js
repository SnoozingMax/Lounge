// Lounge service worker: shows push notifications
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

self.addEventListener('push', e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch { d = { body: e.data && e.data.text() }; }
  e.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    const ua = self.navigator.userAgent, safari = /AppleWebKit/.test(ua) && !/Chrome|Chromium|Edg|CriOS/.test(ua);
    // already looking at the chat? skip the popup (Safari always needs one shown)
    if (!safari && wins.some(w => w.visibilityState === 'visible' && w.focused)) return;
    await self.registration.showNotification(d.title || 'Lounge', {
      body: d.body || 'New message',
      tag: d.tag || undefined,
      renotify: true,
      silent: !!d.silent,
      icon: 'icon-192.png',
      badge: 'icon-192.png',
      data: { channel: d.channel || null }
    });
  })());
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  const ch = e.notification.data && e.notification.data.channel;
  const url = new URL('./' + (ch ? '?c=' + ch : ''), self.registration.scope).href;
  e.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const w of wins) {
      if (w.url.startsWith(self.registration.scope)) {
        await w.focus();
        if (ch) w.postMessage({ type: 'open', channel: ch });
        return;
      }
    }
    await self.clients.openWindow(url);
  })());
});
