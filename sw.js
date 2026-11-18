// Serves the site under <scope>/app/ from encrypted files fetched one by one, only when a page asks for them.
// Each file sits at v/<name>.bin, where <name> is an HMAC of "<version>:<path>" under a key made from the password,
// so the public repository shows neither the content nor the page names. The keys (made on the password screen) live
// in IndexedDB; decrypted files are kept in Cache Storage for the current version only.
// Must match the password screen: an unlock that is not remembered stays open while in use and closes after this much idle time.
const IDLE_MS = 30 * 60 * 1000;
const PREFIX = "oken-proto-";
const DB = "oken-proto-lock";

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

// the password screen asks this before sending the visitor in, so an older worker left on the device is never used
self.addEventListener("message", (e) => {
  if (e.data === "oken-sw?" && e.ports[0]) e.ports[0].postMessage("oken-sw-2");
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  const scope = new URL(self.registration.scope);
  // Next 16 checks links with HEAD before prefetching them, so answer HEAD as well as GET
  if (!["GET", "HEAD"].includes(e.request.method) || url.origin !== scope.origin || !url.pathname.startsWith(scope.pathname + "app/")) return;
  e.respondWith(serve(url, e.request, scope));
});

// ---- the session (keys + version + how long it stays open), shared with the password screen ----
function idb() {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore("s");
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}
async function readSession() {
  try {
    const db = await idb();
    return await new Promise((resolve) => {
      const q = db.transaction("s").objectStore("s").get("session");
      q.onsuccess = () => resolve(q.result || null);
      q.onerror = () => resolve({ error: "read" });
    });
  } catch (e) {
    return { error: (e && e.name) || "open" };
  }
}
async function writeSession(s) {
  const db = await idb();
  await new Promise((resolve) => {
    const t = db.transaction("s", "readwrite");
    if (s) t.objectStore("s").put(s, "session");
    else t.objectStore("s").delete("session");
    t.oncomplete = t.onerror = () => resolve();
  });
}

async function latestVersion(scope) {
  try {
    const r = await fetch(new URL("version.json", scope), { cache: "no-store" });
    if (!r.ok) return null;
    return (await r.json()).id || null;
  } catch {
    return null; // offline: keep using what this device has
  }
}

// The session keeps the 32-byte secret as plain bytes (some browsers, iPhone Safari among them, cannot hand a stored
// CryptoKey to a worker); the keys are made from it here and kept in memory.
const keyMemo = new Map();
function keysOf(raw) {
  const id = hex(raw);
  if (!keyMemo.has(id)) {
    keyMemo.set(id, (async () => {
      const bytes = new Uint8Array(raw);
      const encKey = await crypto.subtle.importKey("raw", bytes, { name: "AES-GCM" }, false, ["decrypt"]);
      const label = new TextEncoder().encode("oken-name\0");
      const nameBytes = await crypto.subtle.digest("SHA-256", new Uint8Array([...label, ...bytes]));
      const nameKey = await crypto.subtle.importKey("raw", nameBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
      return { encKey, nameKey };
    })());
  }
  return keyMemo.get(id);
}

let checking = null; // one version check at a time
async function session(scope, navigate) {
  let s = await readSession();
  // why the visitor is sent back, shown small on the password screen (helps when a phone cannot open the site)
  if (!s) return { why: "none" };
  if (s.error) return { why: "db-" + s.error };
  if (!s.raw) return { why: "noraw" };
  if (s.keep !== true && !(Date.now() < s.until)) {
    await writeSession(null);
    return { why: "timeout" };
  }
  if (navigate) {
    if (!checking) checking = latestVersion(scope).finally(() => { checking = null; });
    const latest = await checking;
    let changed = false;
    if (latest && latest !== s.version) {
      s = { ...s, version: latest };
      changed = true;
    }
    if (s.keep !== true) {
      s = { ...s, until: Date.now() + IDLE_MS };
      changed = true;
    }
    if (changed) await writeSession(s);
    // drop decrypted copies of older versions
    for (const k of await caches.keys()) if (k.startsWith(PREFIX) && k !== PREFIX + s.version) await caches.delete(k);
  }
  return { ...s, ...(await keysOf(s.raw)) };
}

// ---- one encrypted file ----
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
async function fileName(s, rel) {
  return hex(await crypto.subtle.sign("HMAC", s.nameKey, new TextEncoder().encode(s.version + ":" + rel))).slice(0, 40);
}
class BadKey extends Error {}
async function fetchFile(s, scope, rel) {
  const r = await fetch(new URL("v/" + (await fileName(s, rel)) + ".bin", scope));
  if (r.status === 404) return null;
  if (!r.ok) throw new Error("fetch " + r.status);
  const box = new Uint8Array(await r.arrayBuffer());
  let plain;
  try {
    plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: box.subarray(0, 12) }, s.encKey, box.subarray(12)));
  } catch {
    throw new BadKey(); // the password was changed since this device opened the site
  }
  // plain = header JSON, a newline, then the (maybe gzipped) body
  const nl = plain.indexOf(10);
  const head = JSON.parse(new TextDecoder().decode(plain.subarray(0, nl)));
  let body = plain.subarray(nl + 1);
  if (head.z) body = new Uint8Array(await new Response(new Blob([body]).stream().pipeThrough(new DecompressionStream("gzip"))).arrayBuffer());
  return new Response(body, { status: 200, headers: { "content-type": head.t } });
}

async function serve(url, req, scope) {
  const navigate = req.mode === "navigate";
  const toLock = (why) => (navigate ? Response.redirect(scope.href + "?from=" + encodeURIComponent(why), 302) : new Response("", { status: 404 }));
  let s;
  try {
    s = await session(scope, navigate);
  } catch (e) {
    return toLock("sw-" + ((e && e.name) || "error"));
  }
  if (s.why) return toLock(s.why); // not unlocked on this device, or timed out: back to the password screen

  const rel = decodeURIComponent(url.pathname.slice((scope.pathname + "app/").length));
  const candidates = [];
  if (rel === "" || rel.endsWith("/")) candidates.push(rel + "index.html");
  else if (!/\.[a-z0-9]+$/i.test(rel)) candidates.push(rel + "/index.html", rel);
  else candidates.push(rel);

  const cache = await caches.open(PREFIX + s.version);
  try {
    for (const p of candidates) {
      const key = new URL("app/" + p, scope).href;
      let res = await cache.match(key);
      if (!res) {
        res = await fetchFile(s, scope, p);
        if (!res) continue;
        await cache.put(key, res.clone());
      }
      return req.method === "HEAD" ? new Response(null, { status: res.status, headers: res.headers }) : res;
    }
    if (navigate) {
      // the site's own "page not found"
      const key = new URL("app/404.html", scope).href;
      let res = await cache.match(key);
      if (!res) {
        res = await fetchFile(s, scope, "404.html");
        if (res) await cache.put(key, res.clone());
      }
      if (res) return new Response(res.body, { status: 404, headers: res.headers });
    }
    return new Response("", { status: 404 });
  } catch (e) {
    if (e instanceof BadKey) {
      await writeSession(null);
      return toLock("key");
    }
    return new Response("", { status: 503 }); // offline or GitHub unreachable
  }
}
