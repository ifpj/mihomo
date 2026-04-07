const CACHE = 'geo-lookup-v1';
const LARGE = ['GeoSite.dat', 'GeoIP.dat', 'main.wasm'];

self.addEventListener('install', e => {
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  const file = url.pathname.split('/').pop();

  if (LARGE.includes(file)) {
    // Cache-first: large static assets
    e.respondWith(
      caches.open(CACHE).then(async cache => {
        const cached = await cache.match(e.request);
        if (cached) return cached;
        const res = await fetch(e.request);
        if (res.ok) cache.put(e.request, res.clone());
        return res;
      })
    );
  }
  // Everything else: network-first (HTML, JS)
});
