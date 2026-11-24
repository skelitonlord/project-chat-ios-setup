"use strict";

importScripts("profile.js");

const downloads = new Map();
const scope = new URL(self.registration.scope);
const route = new URL("project-chat-companion.mobileconfig", scope);
const lifetime = 180000;

self.addEventListener("install", (event) => event.waitUntil(self.skipWaiting()));
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

function prune() {
  const now = Date.now();
  for (const [ticket, record] of downloads) {
    if (record.expires <= now) downloads.delete(ticket);
  }
}

self.addEventListener("message", (event) => {
  const {source, data, ports} = event;
  if (!source?.url || !ports[0] || data?.action !== "prepare"
      || typeof data.fragment !== "string" || data.fragment.length > 690) return;
  const parent = new URL(source.url);
  if (parent.origin !== scope.origin || ![scope.pathname, scope.pathname + "index.html"].includes(parent.pathname)) return;

  event.waitUntil((async () => {
    try {
      const certificate = await ProjectChatProfile.validate(data.fragment);
      prune();
      for (const [ticket, record] of downloads) {
        if (record.client === source.id) downloads.delete(ticket);
      }
      if (downloads.size >= 12) throw new Error("Download queue is full.");
      const ticket = crypto.randomUUID();
      downloads.set(ticket, {profile: ProjectChatProfile.makeProfile(certificate), client: source.id,
                             expires: Date.now() + lifetime});
      ports[0].postMessage({ticket});
    } catch {
      ports[0].postMessage({error: true});
    }
  })());
});

self.addEventListener("fetch", (event) => {
  const requested = new URL(event.request.url);
  if (event.request.method !== "GET" || requested.origin !== route.origin || requested.pathname !== route.pathname) return;
  prune();
  const values = [...requested.searchParams];
  const ticket = values.length === 1 && values[0][0] === "download" ? values[0][1] : null;
  const record = downloads.get(ticket);
  // Document navigations can omit clientId. The in-memory UUID is the fallback.
  const valid = record && (!event.clientId || event.clientId === record.client);
  event.respondWith(valid
    ? new Response(record.profile, {headers: {
      "Content-Type": ProjectChatProfile.MIME,
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
    }})
    : new Response("Return to the setup page and prepare another download.", {
      status: 404, headers: {"Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store"},
    }));
});
