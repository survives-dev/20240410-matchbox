import { Hono } from "hono";
import { serveStatic } from "hono/deno";
import { basicAuth, cache, compress, cors, etag } from "hono/middleware";

const ENV = {
  TLS_CA_CERT: Deno.env.get("TLS_CA_CERT"),
  TLS_CERT: Deno.env.get("TLS_CERT"),
  TLS_KEY: Deno.env.get("TLS_KEY"),
  HOSTS: Deno.env.get("HOSTS"),
  PORT: Deno.env.get("PORT"),
  CONFIG_JSON: Deno.env.get("CONFIG_JSON"),
  ENABLE_BASIC_AUTH: Deno.env.get("ENABLE_BASIC_AUTH"),
  BASIC_AUTH_USERNAME: Deno.env.get("BASIC_AUTH_USERNAME"),
  BASIC_AUTH_PASSWORD: Deno.env.get("BASIC_AUTH_PASSWORD"),
  SECRET: Deno.env.get("SECRET"),
  PRIVATE_KEY: Deno.env.get("PRIVATE_KEY"),
} as { [key: string]: string };

let tlsCaCertPem, tlsCertPem, tlsKeyPem;
if (ENV.TLS_CA_CERT) {
  tlsCaCertPem = ENV.TLS_CA_CERT.split("\\n").join("\n");
  if (tlsCaCertPem.startsWith('"')) tlsCaCertPem = tlsCaCertPem.slice(1);
  if (tlsCaCertPem.endsWith('"')) tlsCaCertPem = tlsCaCertPem.slice(0, -1);
}
if (ENV.TLS_CERT) {
  tlsCertPem = ENV.TLS_CERT.split("\\n").join("\n");
  if (tlsCertPem.startsWith('"')) tlsCertPem = tlsCertPem.slice(1);
  if (tlsCertPem.endsWith('"')) tlsCertPem = tlsCertPem.slice(0, -1);
}
if (ENV.TLS_KEY) {
  tlsKeyPem = ENV.TLS_KEY.split("\\n").join("\n");
  if (tlsKeyPem.startsWith('"')) tlsKeyPem = tlsKeyPem.slice(1);
  if (tlsKeyPem.endsWith('"')) tlsKeyPem = tlsKeyPem.slice(0, -1);
}
const client = Deno.createHttpClient({ caCerts: [String(tlsCaCertPem || tlsCertPem)] });

const PRIVATE_KEY = await importPrivateKey(ENV.PRIVATE_KEY);
const PUBLIC_KEY = await privateKeyToPublicKey(PRIVATE_KEY);
const publicKeyPem = await exportPublicKey(PUBLIC_KEY);
const publicKeyJwk = await crypto.subtle.exportKey("jwk", PUBLIC_KEY);
let configJsonFile;
if (ENV.CONFIG_JSON) {
  configJsonFile = ENV.CONFIG_JSON;
  if (configJsonFile.startsWith("'")) configJsonFile = configJsonFile.slice(1);
  if (configJsonFile.endsWith("'")) configJsonFile = configJsonFile.slice(0, -1);
} else {
  configJsonFile = await Deno.readTextFile("data/config.json");
}
const CONFIG = JSON.parse(configJsonFile);

const app = new Hono();
app.use("*", async (c, next) => {
  await next();
  c.res.headers.append("Vary", "Accept, Accept-Encoding");
});
if (CONFIG.maxAge === 0) {
  app.use("/", async (c, next) => {
    await next();
    c.res.headers.append("Cache-Control", "public, max-age=0, must-revalidate");
  });
  app.use("/u/:param", async (c, next) => {
    await next();
    c.res.headers.append("Cache-Control", "public, max-age=0, must-revalidate");
  });
  app.use("/.well-known/nodeinfo", async (c, next) => {
    await next();
    c.res.headers.append("Cache-Control", "public, max-age=0, must-revalidate");
  });
  app.use("/.well-known/webfinger", async (c, next) => {
    await next();
    c.res.headers.append("Cache-Control", "public, max-age=0, must-revalidate");
  });
} else if (!(CONFIG.maxAge === null || CONFIG.maxAge === undefined)) {
  app.use(
    "/",
    cache({
      cacheName: "matchbox",
      cacheControl: `public, max-age=${Number(CONFIG.maxAge) || 0}, must-revalidate`,
      wait: true,
    }),
  );
  app.use(
    "/u/:param",
    cache({
      cacheName: "matchbox",
      cacheControl: `public, max-age=${Number(CONFIG.maxAge) || 0}, must-revalidate`,
      wait: true,
    }),
  );
  app.use(
    "/.well-known/nodeinfo",
    cache({
      cacheName: "matchbox",
      cacheControl: `public, max-age=${Number(CONFIG.maxAge) || 0}, must-revalidate`,
      wait: true,
    }),
  );
  app.use(
    "/.well-known/webfinger",
    cache({
      cacheName: "matchbox",
      cacheControl: `public, max-age=${Number(CONFIG.maxAge) || 0}, must-revalidate`,
      wait: true,
    }),
  );
}
app.use("/", compress(), cors());
app.use("/u/:param", compress(), cors());
app.use("/.well-known/nodeinfo", compress(), cors());
app.use("/.well-known/webfinger", compress(), cors());
app.use("/public/*", etag(), serveStatic({ root: "./public/" }));
app.use("/nodeinfo/*", etag(), serveStatic({ root: "./public/" }));
app.use("/favicon.ico", etag(), serveStatic({ path: "./public/favicon.ico" }));
app.use("/humans.txt", etag(), serveStatic({ path: "./public/humans.txt" }));
app.use("/robots.txt", etag(), serveStatic({ path: "./public/robots.txt" }));
app.use("/s/:param/u/:param", async (c, next) => {
  if (ENV.ENABLE_BASIC_AUTH === "true" && c.req.method === "POST") {
    const auth = basicAuth({
      username: ENV.BASIC_AUTH_USERNAME,
      password: ENV.BASIC_AUTH_PASSWORD,
    });
    return auth(c, next);
  } else {
    await next();
  }
});

function stob(s: string) {
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}

function btos(b: ArrayBuffer) {
  return String.fromCharCode(...new Uint8Array(b));
}

async function importPrivateKey(pem: string) {
  const header = "-----BEGIN PRIVATE KEY-----";
  const footer = "-----END PRIVATE KEY-----";
  let b64 = pem;
  b64 = b64.split("\\n").join("");
  b64 = b64.split("\n").join("");
  if (b64.startsWith('"')) b64 = b64.slice(1);
  if (b64.endsWith('"')) b64 = b64.slice(0, -1);
  if (b64.startsWith(header)) b64 = b64.slice(header.length);
  if (b64.endsWith(footer)) b64 = b64.slice(0, -1 * footer.length);
  const der = stob(atob(b64));
  const result = await crypto.subtle.importKey(
    "pkcs8",
    der,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    true,
    ["sign"],
  );
  return result;
}

async function privateKeyToPublicKey(key: CryptoKey) {
  const jwk = await crypto.subtle.exportKey("jwk", key);
  delete jwk.d;
  delete jwk.p;
  delete jwk.q;
  delete jwk.dp;
  delete jwk.dq;
  delete jwk.qi;
  delete jwk.oth;
  jwk.key_ops = ["verify"];
  const result = await crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    true,
    ["verify"],
  );
  return result;
}

async function exportPublicKey(key: CryptoKey) {
  const der = await crypto.subtle.exportKey("spki", key);
  let b64 = btoa(btos(der));
  let pem = "-----BEGIN PUBLIC KEY-----\n";
  while (b64.length > 0) {
    pem += b64.substring(0, 64) + "\n";
    b64 = b64.substring(64);
  }
  pem += "-----END PUBLIC KEY-----\n";
  return pem;
}

function talkScript(req: string) {
  return [
    "<p>",
    `<a href="https://${new URL(req).hostname}/" rel="nofollow noopener noreferrer" target="_blank">`,
    new URL(req).hostname,
    "</a>",
    "</p>",
  ].join("");
}

async function getActivity(strName: string, strHost: string, req: string) {
  const strTime = new Date().toUTCString();
  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    PRIVATE_KEY,
    stob(
      [
        `(request-target): get ${new URL(req).pathname}`,
        `host: ${new URL(req).hostname}`,
        `date: ${strTime}`,
      ].join("\n"),
    ),
  );
  const b64 = btoa(btos(sig));
  const headers = {
    Host: new URL(req).hostname,
    Date: strTime,
    Signature: [
      `keyId="https://${strHost}/u/${strName}#Key"`,
      'algorithm="rsa-sha256"',
      'headers="(request-target) host date"',
      `signature="${b64}"`,
    ].join(),
    Accept: "application/activity+json",
    "Accept-Encoding": "identity",
    "Cache-Control": "no-cache",
    "User-Agent": `Matchbox/0.7.0 (+https://${strHost}/)`,
  };
  const res = await fetch(req, { method: "GET", headers, client });
  console.log(`GET ${req} ${res.status}`);
  return res.json();
}

async function postActivity(strName: string, strHost: string, req: string, x: { [key: string]: any }) {
  const strTime = new Date().toUTCString();
  const body = JSON.stringify(x);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body));
  const s256 = btoa(btos(digest));
  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    PRIVATE_KEY,
    stob(
      [
        `(request-target): post ${new URL(req).pathname}`,
        `host: ${new URL(req).hostname}`,
        `date: ${strTime}`,
        `digest: SHA-256=${s256}`,
      ].join("\n"),
    ),
  );
  const b64 = btoa(btos(sig));
  const headers = {
    Host: new URL(req).hostname,
    Date: strTime,
    Digest: `SHA-256=${s256}`,
    Signature: [
      `keyId="https://${strHost}/u/${strName}#Key"`,
      'algorithm="rsa-sha256"',
      'headers="(request-target) host date digest"',
      `signature="${b64}"`,
    ].join(),
    Accept: "application/json",
    "Accept-Encoding": "gzip",
    "Cache-Control": "max-age=0",
    "Content-Type": "application/activity+json",
    "User-Agent": `Matchbox/0.7.0 (+https://${strHost}/)`,
  };
  console.log(`POST ${req} ${body}`);
  await fetch(req, { method: "POST", body, headers, client });
}

async function acceptFollow(strName: string, strHost: string, x: { [key: string]: any }, y: { [key: string]: any }) {
  const strId = crypto.randomUUID();
  const body = {
    "@context": "https://www.w3.org/ns/activitystreams",
    id: `https://${strHost}/u/${strName}/s/${strId}`,
    type: "Accept",
    actor: `https://${strHost}/u/${strName}`,
    object: y,
  };
  await postActivity(strName, strHost, x.inbox, body);
}

async function follow(strName: string, strHost: string, x: { [key: string]: any }) {
  const strId = crypto.randomUUID();
  const body = {
    "@context": "https://www.w3.org/ns/activitystreams",
    id: `https://${strHost}/u/${strName}/s/${strId}`,
    type: "Follow",
    actor: `https://${strHost}/u/${strName}`,
    object: x.id,
  };
  await postActivity(strName, strHost, x.inbox, body);
}

async function undoFollow(strName: string, strHost: string, x: { [key: string]: any }) {
  const strId = crypto.randomUUID();
  const body = {
    "@context": "https://www.w3.org/ns/activitystreams",
    id: `https://${strHost}/u/${strName}/s/${strId}#Undo`,
    type: "Undo",
    actor: `https://${strHost}/u/${strName}`,
    object: {
      id: `https://${strHost}/u/${strName}/s/${strId}`,
      type: "Follow",
      actor: `https://${strHost}/u/${strName}`,
      object: x.id,
    },
  };
  await postActivity(strName, strHost, x.inbox, body);
}

async function like(strName: string, strHost: string, x: { [key: string]: any }, y: { [key: string]: any }) {
  const strId = crypto.randomUUID();
  const body = {
    "@context": "https://www.w3.org/ns/activitystreams",
    id: `https://${strHost}/u/${strName}/s/${strId}`,
    type: "Like",
    actor: `https://${strHost}/u/${strName}`,
    object: x.id,
  };
  await postActivity(strName, strHost, y.inbox, body);
}

async function undoLike(strName: string, strHost: string, x: { [key: string]: any }, y: { [key: string]: any }) {
  const strId = crypto.randomUUID();
  const body = {
    "@context": "https://www.w3.org/ns/activitystreams",
    id: `https://${strHost}/u/${strName}/s/${strId}#Undo`,
    type: "Undo",
    actor: `https://${strHost}/u/${strName}`,
    object: {
      id: `https://${strHost}/u/${strName}/s/${strId}`,
      type: "Like",
      actor: `https://${strHost}/u/${strName}`,
      object: x.id,
    },
  };
  await postActivity(strName, strHost, y.inbox, body);
}

async function announce(strName: string, strHost: string, x: { [key: string]: any }, y: { [key: string]: any }) {
  const strId = crypto.randomUUID();
  const strTime = new Date().toISOString().substring(0, 19) + "Z";
  const body = {
    "@context": "https://www.w3.org/ns/activitystreams",
    id: `https://${strHost}/u/${strName}/s/${strId}`,
    type: "Announce",
    actor: `https://${strHost}/u/${strName}`,
    published: strTime,
    to: ["https://www.w3.org/ns/activitystreams#Public"],
    cc: [`https://${strHost}/u/${strName}/followers`],
    object: x.id,
  };
  await postActivity(strName, strHost, y.inbox, body);
}

async function undoAnnounce(strName: string, strHost: string, x: { [key: string]: any }, y: { [key: string]: any }) {
  const strId = crypto.randomUUID();
  const body = {
    "@context": "https://www.w3.org/ns/activitystreams",
    id: `https://${strHost}/u/${strName}/s/${strId}#Undo`,
    type: "Undo",
    actor: `https://${strHost}/u/${strName}`,
    object: {
      id: `https://${strHost}/u/${strName}/s/${strId}`,
      type: "Announce",
      actor: `https://${strHost}/u/${strName}`,
      object: x.id,
    },
  };
  await postActivity(strName, strHost, y.inbox, body);
}

async function createNote(strName: string, strHost: string, x: { [key: string]: any }, y: string) {
  const strId = crypto.randomUUID();
  const strTime = new Date().toISOString().substring(0, 19) + "Z";
  const body = {
    "@context": "https://www.w3.org/ns/activitystreams",
    id: `https://${strHost}/u/${strName}/s/${strId}/activity`,
    type: "Create",
    actor: `https://${strHost}/u/${strName}`,
    published: strTime,
    to: ["https://www.w3.org/ns/activitystreams#Public"],
    cc: [`https://${strHost}/u/${strName}/followers`],
    object: {
      id: `https://${strHost}/u/${strName}/s/${strId}`,
      type: "Note",
      attributedTo: `https://${strHost}/u/${strName}`,
      content: talkScript(y),
      url: `https://${strHost}/u/${strName}/s/${strId}`,
      published: strTime,
      to: ["https://www.w3.org/ns/activitystreams#Public"],
      cc: [`https://${strHost}/u/${strName}/followers`],
    },
  };
  await postActivity(strName, strHost, x.inbox, body);
}

async function createNoteMention(
  strName: string,
  strHost: string,
  x: { [key: string]: any },
  y: { [key: string]: any },
  z: string,
) {
  const strId = crypto.randomUUID();
  const strTime = new Date().toISOString().substring(0, 19) + "Z";
  const body = {
    "@context": "https://www.w3.org/ns/activitystreams",
    id: `https://${strHost}/u/${strName}/s/${strId}/activity`,
    type: "Create",
    actor: `https://${strHost}/u/${strName}`,
    published: strTime,
    to: ["https://www.w3.org/ns/activitystreams#Public"],
    cc: [`https://${strHost}/u/${strName}/followers`],
    object: {
      id: `https://${strHost}/u/${strName}/s/${strId}`,
      type: "Note",
      attributedTo: `https://${strHost}/u/${strName}`,
      inReplyTo: x.id,
      content: talkScript(z),
      url: `https://${strHost}/u/${strName}/s/${strId}`,
      published: strTime,
      to: ["https://www.w3.org/ns/activitystreams#Public"],
      cc: [`https://${strHost}/u/${strName}/followers`],
      tag: [
        {
          type: "Mention",
          name: `@${y.preferredUsername}@${new URL(y.inbox).hostname}`,
        },
      ],
    },
  };
  await postActivity(strName, strHost, y.inbox, body);
}

async function createNoteHashtag(
  strName: string,
  strHost: string,
  x: { [key: string]: any },
  y: string,
  z: string,
) {
  const strId = crypto.randomUUID();
  const strTime = new Date().toISOString().substring(0, 19) + "Z";
  const body = {
    "@context": ["https://www.w3.org/ns/activitystreams", { Hashtag: "as:Hashtag" }],
    id: `https://${strHost}/u/${strName}/s/${strId}/activity`,
    type: "Create",
    actor: `https://${strHost}/u/${strName}`,
    published: strTime,
    to: ["https://www.w3.org/ns/activitystreams#Public"],
    cc: [`https://${strHost}/u/${strName}/followers`],
    object: {
      id: `https://${strHost}/u/${strName}/s/${strId}`,
      type: "Note",
      attributedTo: `https://${strHost}/u/${strName}`,
      content: talkScript(y),
      url: `https://${strHost}/u/${strName}/s/${strId}`,
      published: strTime,
      to: ["https://www.w3.org/ns/activitystreams#Public"],
      cc: [`https://${strHost}/u/${strName}/followers`],
      tag: [
        {
          type: "Hashtag",
          name: `#${z}`,
        },
      ],
    },
  };
  await postActivity(strName, strHost, x.inbox, body);
}

async function deleteNote(strName: string, strHost: string, x: { [key: string]: any }, y: string) {
  const strId = crypto.randomUUID();
  const body = {
    "@context": "https://www.w3.org/ns/activitystreams",
    id: `https://${strHost}/u/${strName}/s/${strId}/activity`,
    type: "Delete",
    actor: `https://${strHost}/u/${strName}`,
    object: {
      id: y,
      type: "Note",
      attributedTo: `https://${strHost}/u/${strName}`,
    },
  };
  await postActivity(strName, strHost, x.inbox, body);
}

app.get("/", (c) => c.text("Matchbox: ActivityPub@Hono"));

app.get("/u/:strName", (c) => {
  const strName = c.req.param("strName");
  const strHost = new URL(CONFIG.origin).hostname;
  const strAccept = c.req.header("Accept");
  let boolAccept = false;
  if (strAccept?.includes("application/activity+json")) boolAccept = true;
  if (strAccept?.includes("application/ld+json")) boolAccept = true;
  if (strAccept?.includes('application/ld+json; profile="https://www.w3.org/ns/activitystreams"')) boolAccept = true;
  if (strAccept?.includes("application/json")) boolAccept = true;
  if (!boolAccept) return c.text(`${strName}: ${CONFIG.name}`);
  const body = {
    "@context": [
      "https://www.w3.org/ns/activitystreams",
      "https://w3id.org/security/v1",
      "https://w3id.org/security",
    ],
    id: `https://${strHost}/u/${strName}`,
    type: "Person",
    inbox: `https://${strHost}/u/${strName}/inbox`,
    outbox: `https://${strHost}/u/${strName}/outbox`,
    following: `https://${strHost}/u/${strName}/following`,
    followers: `https://${strHost}/u/${strName}/followers`,
    preferredUsername: strName,
    name: CONFIG.name,
    summary: "<p>0.7.0</p>",
    url: `https://${strHost}/u/${strName}`,
    endpoints: {
      sharedInbox: `https://${strHost}/u/${strName}/inbox`,
    },
    publicKey: {
      id: `https://${strHost}/u/${strName}#Key`,
      type: "Key",
      owner: `https://${strHost}/u/${strName}`,
      publicKeyPem,
    },
    verificationMethod: [{
      id: `https://${strHost}/u/${strName}#Key`,
      type: "JsonWebKey",
      controller: `https://${strHost}/u/${strName}`,
      publicKeyJwk,
    }],
    icon: {
      type: "Image",
      mediaType: "image/png",
      url: `https://${strHost}/public/${strName}u.png`,
    },
    image: {
      type: "Image",
      mediaType: "image/png",
      url: `https://${strHost}/public/${strName}s.png`,
    },
  };
  return c.json(body, 200, { "Content-Type": "application/activity+json" });
});

app.get("/u/:strName/inbox", (c) => c.body(null, 405));
app.post("/u/:strName/inbox", async (c) => {
  const strName = c.req.param("strName");
  const strHost = new URL(CONFIG.origin).hostname;
  const strContentType = c.req.header("Content-Type");
  let boolContentType = false;
  const y = await c.req.json();
  console.log(`INBOX ${y.id} ${y.type}`);
  if (strName !== CONFIG.preferredUsername) return c.notFound();
  if (strContentType?.includes("application/activity+json")) boolContentType = true;
  if (strContentType?.includes("application/ld+json")) boolContentType = true;
  if (strContentType?.includes('application/ld+json; profile="https://www.w3.org/ns/activitystreams"')) {
    boolContentType = true;
  }
  if (strContentType?.includes("application/json")) boolContentType = true;
  if (!boolContentType) return c.body(null, 400);
  if (!c.req.header("Digest") || !c.req.header("Signature")) return c.body(null, 400);
  if (new URL(y.actor || "about:blank").protocol !== "https:") return c.body(null, 400);
  const x = await getActivity(strName, strHost, y.actor);
  if (!x) return c.body(null, 500);
  if (y.type === "Follow") {
    await acceptFollow(strName, strHost, x, y);
    return c.body(null);
  }
  if (y.type === "Undo") {
    const z = y.object;
    if (z.type === "Follow") {
      await acceptFollow(strName, strHost, x, z);
      return c.body(null);
    }
    if (z.type === "Accept" || z.type === "Like" || z.type === "Announce") return c.body(null);
  }
  if (y.type === "Accept" || y.type === "Reject" || y.type === "Add") return c.body(null);
  if (y.type === "Remove" || y.type === "Like" || y.type === "Announce") return c.body(null);
  if (y.type === "Create" || y.type === "Update" || y.type === "Delete") return c.body(null);
  return c.body(null, 500);
});

app.post("/u/:strName/outbox", (c) => c.body(null, 405));
app.get("/u/:strName/outbox", (c) => {
  const strName = c.req.param("strName");
  const strHost = new URL(CONFIG.origin).hostname;
  if (strName !== CONFIG.preferredUsername) return c.notFound();
  const body = {
    "@context": "https://www.w3.org/ns/activitystreams",
    id: `https://${strHost}/u/${strName}/outbox`,
    type: "OrderedCollection",
    totalItems: 0,
  };
  return c.json(body, 200, { "Content-Type": "application/activity+json" });
});

app.get("/u/:strName/following", (c) => {
  const strName = c.req.param("strName");
  const strHost = new URL(CONFIG.origin).hostname;
  if (strName !== CONFIG.preferredUsername) return c.notFound();
  const body = {
    "@context": "https://www.w3.org/ns/activitystreams",
    id: `https://${strHost}/u/${strName}/following`,
    type: "OrderedCollection",
    totalItems: 0,
  };
  return c.json(body, 200, { "Content-Type": "application/activity+json" });
});

app.get("/u/:strName/followers", (c) => {
  const strName = c.req.param("strName");
  const strHost = new URL(CONFIG.origin).hostname;
  if (strName !== CONFIG.preferredUsername) return c.notFound();
  const body = {
    "@context": "https://www.w3.org/ns/activitystreams",
    id: `https://${strHost}/u/${strName}/followers`,
    type: "OrderedCollection",
    totalItems: 0,
  };
  return c.json(body, 200, { "Content-Type": "application/activity+json" });
});

app.post("/s/:strSecret/u/:strName", async (c) => {
  const strName = c.req.param("strName");
  const strHost = new URL(CONFIG.origin).hostname;
  if (strName !== CONFIG.preferredUsername) return c.notFound();
  if (!c.req.param("strSecret") || c.req.param("strSecret") === "-") return c.notFound();
  if (c.req.param("strSecret") !== ENV.SECRET) return c.notFound();
  if (!c.req.query("id") || !c.req.query("type")) return c.body(null, 400);
  if (new URL(c.req.query("id") || "about:blank").protocol !== "https:") return c.body(null, 400);
  const x = await getActivity(strName, strHost, c.req.query("id") || "");
  if (!x) return c.body(null, 500);
  const t = c.req.query("type");
  if (t === "type") {
    console.log(`TYPE ${x.id} ${x.type}`);
    return c.body(null);
  }
  if (t === "follow") {
    await follow(strName, strHost, x);
    return c.body(null);
  }
  if (t === "undo_follow") {
    await undoFollow(strName, strHost, x);
    return c.body(null);
  }
  if (t === "like") {
    if (new URL(x.attributedTo || "about:blank").protocol !== "https:") return c.body(null, 400);
    const y = await getActivity(strName, strHost, x.attributedTo);
    if (!y) return c.body(null, 500);
    await like(strName, strHost, x, y);
    return c.body(null);
  }
  if (t === "undo_like") {
    if (new URL(x.attributedTo || "about:blank").protocol !== "https:") return c.body(null, 400);
    const y = await getActivity(strName, strHost, x.attributedTo);
    if (!y) return c.body(null, 500);
    await undoLike(strName, strHost, x, y);
    return c.body(null);
  }
  if (t === "announce") {
    if (new URL(x.attributedTo || "about:blank").protocol !== "https:") return c.body(null, 400);
    const y = await getActivity(strName, strHost, x.attributedTo);
    if (!y) return c.body(null, 500);
    await announce(strName, strHost, x, y);
    return c.body(null);
  }
  if (t === "undo_announce") {
    if (new URL(x.attributedTo || "about:blank").protocol !== "https:") return c.body(null, 400);
    const y = await getActivity(strName, strHost, x.attributedTo);
    if (!y) return c.body(null, 500);
    await undoAnnounce(strName, strHost, x, y);
    return c.body(null);
  }
  if (t === "create_note") {
    const y = c.req.query("url") || "";
    if (new URL(y || "about:blank").protocol !== "https:") return c.body(null, 400);
    await createNote(strName, strHost, x, y);
    return c.body(null);
  }
  if (t === "create_note_mention") {
    if (new URL(x.attributedTo || "about:blank").protocol !== "https:") return c.body(null, 400);
    const y = await getActivity(strName, strHost, x.attributedTo);
    if (!y) return c.body(null, 500);
    const z = c.req.query("url") || "";
    if (new URL(z || "about:blank").protocol !== "https:") return c.body(null, 400);
    await createNoteMention(strName, strHost, x, y, z);
    return c.body(null);
  }
  if (t === "create_note_hashtag") {
    const y = c.req.query("url") || "";
    if (new URL(y || "about:blank").protocol !== "https:") return c.body(null, 400);
    const z = c.req.query("tag") || "";
    await createNoteHashtag(strName, strHost, x, y, z);
    return c.body(null);
  }
  if (t === "delete_note") {
    const y = c.req.query("url") || "";
    if (new URL(y || "about:blank").protocol !== "https:") return c.body(null, 400);
    await deleteNote(strName, strHost, x, y);
    return c.body(null);
  }
  return c.body(null, 500);
});

app.get("/.well-known/nodeinfo", (c) => {
  const strHost = new URL(CONFIG.origin).hostname;
  const body = {
    links: [
      {
        rel: "http://nodeinfo.diaspora.software/ns/schema/2.0",
        href: `https://${strHost}/nodeinfo/2.0.json`,
      },
      {
        rel: "http://nodeinfo.diaspora.software/ns/schema/2.1",
        href: `https://${strHost}/nodeinfo/2.1.json`,
      },
    ],
  };
  return c.json(body);
});

app.get("/.well-known/webfinger", (c) => {
  const strName = CONFIG.preferredUsername;
  const strHost = new URL(CONFIG.origin).hostname;
  const strResource = c.req.query("resource");
  let boolResource = false;
  if (strResource === `acct:${strName}@${strHost}`) boolResource = true;
  if (strResource === `mailto:${strName}@${strHost}`) boolResource = true;
  if (strResource === `https://${strHost}/@${strName}`) boolResource = true;
  if (strResource === `https://${strHost}/u/${strName}`) boolResource = true;
  if (strResource === `https://${strHost}/user/${strName}`) boolResource = true;
  if (strResource === `https://${strHost}/users/${strName}`) boolResource = true;
  if (!boolResource) return c.notFound();
  const body = {
    subject: `acct:${strName}@${strHost}`,
    aliases: [
      `mailto:${strName}@${strHost}`,
      `https://${strHost}/@${strName}`,
      `https://${strHost}/u/${strName}`,
      `https://${strHost}/user/${strName}`,
      `https://${strHost}/users/${strName}`,
    ],
    links: [
      {
        rel: "self",
        type: "application/activity+json",
        href: `https://${strHost}/u/${strName}`,
      },
      {
        rel: "http://webfinger.net/rel/avatar",
        type: "image/png",
        href: `https://${strHost}/public/${strName}u.png`,
      },
      {
        rel: "http://webfinger.net/rel/profile-page",
        type: "text/plain",
        href: `https://${strHost}/u/${strName}`,
      },
    ],
  };
  return c.json(body, 200, { "Content-Type": "application/jrd+json" });
});

app.get("/s", (c) => c.notFound());
app.get("/@", (c) => c.redirect("/"));
app.get("/u", (c) => c.redirect("/"));
app.get("/user", (c) => c.redirect("/"));
app.get("/users", (c) => c.redirect("/"));

app.get("/users/:strName", (c) => c.redirect(`/u/${c.req.param("strName")}`));
app.get("/user/:strName", (c) => c.redirect(`/u/${c.req.param("strName")}`));
app.get("/:strRoot", (c) => {
  if (!c.req.param("strRoot").startsWith("@")) return c.notFound();
  return c.redirect(`/u/${c.req.param("strRoot").slice(1)}`);
});

Deno.serve({
  hostname: ENV.HOSTS || "localhost",
  port: Number(ENV.PORT) || 8080,
  cert: tlsCertPem,
  key: tlsKeyPem,
}, app.fetch);
