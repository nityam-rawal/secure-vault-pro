const CACHE_NAME = 'secure-vault-v3';
const urlsToCache = [
    './',
    './index.html',
    './style.css',
    './script.js',
    './manifest.json',
    'https://unpkg.com/peerjs@1.5.2/dist/peerjs.min.js'
];

self.addEventListener('install', event => {
    self.skipWaiting();
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => {
                return cache.addAll(urlsToCache);
            })
    );
});

self.addEventListener('fetch', event => {
    if (event.request.method !== 'GET') return;

    const url = new URL(event.request.url);
    const isLocalAsset =
        url.origin === self.location.origin &&
        (url.pathname.endsWith('.html') ||
            url.pathname.endsWith('.css') ||
            url.pathname.endsWith('.js') ||
            url.pathname === '/' ||
            url.pathname.endsWith('/'));

    // Network-first for app shell files so latest deploy is picked up quickly.
    if (isLocalAsset) {
        event.respondWith(
            fetch(event.request)
                .then(networkResponse => {
                    const cloned = networkResponse.clone();
                    caches.open(CACHE_NAME).then(cache => cache.put(event.request, cloned));
                    return networkResponse;
                })
                .catch(() => caches.match(event.request).then(r => r || caches.match('./index.html')))
        );
        return;
    }

    event.respondWith(
        caches.match(event.request)
            .then(response => {
                // Cache hit - return response
                if (response) {
                    return response;
                }
                return fetch(event.request).catch(() => {
                    // Fallback for offline mode if the fetch fails and it's navigation
                    if (event.request.mode === 'navigate') {
                        return caches.match('./index.html');
                    }
                });
            })
    );
});

self.addEventListener('activate', event => {
    event.waitUntil(self.clients.claim());
    const cacheWhitelist = [CACHE_NAME];
    event.waitUntil(
        caches.keys().then(cacheNames => {
            return Promise.all(
                cacheNames.map(cacheName => {
                    if (cacheWhitelist.indexOf(cacheName) === -1) {
                        return caches.delete(cacheName);
                    }
                })
            );
        })
    );
});
