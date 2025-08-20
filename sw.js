self.addEventListener('install',e=>{self.skipWaiting();e.waitUntil(caches.open('spotops-sf-v1').then(c=>c.addAll(['./','./index.html','./manifest.json'])))});
self.addEventListener('activate', e=> clients.claim());
self.addEventListener('fetch', e=> e.respondWith(caches.match(e.request).then(r=> r || fetch(e.request))));