// Local Redactor service worker: offline app shell, cached libraries, threads.
const VERSION = 'v1';
const SHELL = `shell-${VERSION}`;
const LIBS = `libs-${VERSION}`;
const SHELL_FILES = ['./', './index.html', './manifest.webmanifest', './icon.svg', './icon-192.png', './icon-512.png'];
// Hosts whose files are versioned and safe to cache forever (libraries, their .wasm, fonts).
const LIB_HOSTS = ['cdn.jsdelivr.net', 'fonts.googleapis.com', 'fonts.gstatic.com'];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(SHELL).then((c) => c.addAll(SHELL_FILES)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    for (const key of await caches.keys()) {
      if ((key.startsWith('shell-') || key.startsWith('libs-')) && key !== SHELL && key !== LIBS) await caches.delete(key);
    }
    await self.clients.claim();
  })());
});

// Cross-origin isolation lets WebAssembly use threads (SharedArrayBuffer).
// "credentialless" keeps cross-origin CDN and Hugging Face downloads working.
function isolate(res) {
  if (!res || res.status === 0 || res.type === 'opaque') return res;
  const h = new Headers(res.headers);
  h.set('Cross-Origin-Opener-Policy', 'same-origin');
  h.set('Cross-Origin-Embedder-Policy', 'credentialless');
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
}

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);

  // Pages: network first so updates arrive, cached copy when offline.
  if (req.mode === 'navigate') {
    event.respondWith((async () => {
      try {
        const res = await fetch(req);
        if (res.ok) (await caches.open(SHELL)).put('./index.html', res.clone());
        return isolate(res);
      } catch (_) {
        const cached = (await caches.match(req)) || (await caches.match('./index.html'));
        return isolate(cached) || new Response('Offline', { status: 503 });
      }
    })());
    return;
  }

  // Same-origin app files: cache first.
  if (url.origin === self.location.origin) {
    event.respondWith(caches.match(req).then((hit) => hit || fetch(req)));
    return;
  }

  // Pinned library versions and fonts: cache first, store on first use.
  if (LIB_HOSTS.includes(url.hostname)) {
    event.respondWith((async () => {
      const cache = await caches.open(LIBS);
      const hit = await cache.match(req);
      if (hit) return hit;
      const res = await fetch(req);
      if (res.ok || res.type === 'opaque') cache.put(req, res.clone());
      return res;
    })());
  }
  // Everything else (Hugging Face model files) passes through:
  // Transformers.js and wllama cache models themselves (Cache API / OPFS).
});
