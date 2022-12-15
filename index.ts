import "dotenv/load";
import { serve } from "server";
import { Hono } from "hono";
import { basicAuth } from "hono/basic-auth";
import { serveStatic } from "hono/serve-static";

const ENV = {
  HOSTS: Deno.env.get("HOSTS"),
  PORT: Deno.env.get("PORT"),
  ENABLE_BASIC_AUTH: Deno.env.get("ENABLE_BASIC_AUTH"),
  BASIC_AUTH_USERNAME: Deno.env.get("BASIC_AUTH_USERNAME"),
  BASIC_AUTH_PASSWORD: Deno.env.get("BASIC_AUTH_PASSWORD"),
  SECRET: Deno.env.get("SECRET"),
  PRIVATE_KEY: Deno.env.get("PRIVATE_KEY"),
} as { [key: string]: string };

const app = new Hono();
app.use("/public/*", serveStatic({ root: "./public/" }));
app.use("/nodeinfo/*", serveStatic({ root: "./public/" }));
app.use("/favicon.ico", serveStatic({ path: "./public/favicon.ico" }));
app.use("/robots.txt", serveStatic({ path: "./public/robots.txt" }));
app.use("/s/*", async (c, next) => {
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
app.onError((_err, c) => c.body(null, 500));

const PRIVATE_KEY = await importprivateKey(ENV.PRIVATE_KEY);
const PUBLIC_KEY = await privateKeyToPublicKey(PRIVATE_KEY);
const public_key_pem = await exportPublicKey(PUBLIC_KEY);
const config_json = Deno.readTextFileSync("config.json");
const CONFIG = JSON.parse(config_json);

function stob(s: string) {
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}

function btos(b: ArrayBuffer) {
  return String.fromCharCode(...new Uint8Array(b));
}

async function importprivateKey(pem: string) {
  const pemHeader = "-----BEGIN PRIVATE KEY-----";
  const pemFooter = "-----END PRIVATE KEY-----";
  if (pem.startsWith('"')) pem = pem.slice(1);
  if (pem.endsWith('"')) pem = pem.slice(0, -1);
  pem = pem.split("\\n").join("");
  pem = pem.split("\n").join("");
  const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length);
  const der = stob(atob(pemContents));
  const r = await crypto.subtle.importKey(
    "pkcs8",
    der,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    true,
    ["sign"],
  );
  return r;
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
  const r = await crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    true,
    ["verify"],
  );
  return r;
}

async function exportPublicKey(key: CryptoKey) {
  const der = await crypto.subtle.exportKey("spki", key);
  let pemContents = btoa(btos(der));
  let pem = "-----BEGIN PUBLIC KEY-----\n";
  while (pemContents.length > 0) {
    pem += pemContents.substring(0, 64) + "\n";
    pemContents = pemContents.substring(64);
  }
  pem += "-----END PUBLIC KEY-----\n";
  return pem;
}

function talkScript(req: string) {
  return `<p><a href="https://${new URL(req).hostname}/">${new URL(req).hostname}</a></p>`;
}

async function getInbox(req: string) {
  console.log(req);
  const res = await fetch(req, {
    method: "GET",
    headers: { Accept: "application/activity+json" },
  });
  return res.json();
}

async function postInbox(req: string, data: any, headers: { [key: string]: string }) {
  console.log(req, data);
  await fetch(req, { method: "POST", body: JSON.stringify(data), headers });
}

async function signHeaders(res: any, strName: string, strHost: string, strInbox: string) {
  const strTime = new Date().toUTCString();
  const s = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(res)));
  const s256 = btoa(btos(s));
  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    PRIVATE_KEY,
    stob(
      `(request-target): post ${new URL(strInbox).pathname}\n` +
        `host: ${new URL(strInbox).hostname}\n` +
        `date: ${strTime}\n` +
        `digest: SHA-256=${s256}`,
    ),
  );
  const b64 = btoa(btos(sig));
  const headers = {
    Host: new URL(strInbox).hostname,
    Date: strTime,
    Digest: `SHA-256=${s256}`,
    Signature: `keyId="https://${strHost}/u/${strName}",` +
      `algorithm="rsa-sha256",` +
      `headers="(request-target) host date digest",` +
      `signature="${b64}"`,
    Accept: "application/activity+json",
    "Content-Type": "application/activity+json",
    "Accept-Encoding": "gzip",
    "User-Agent": `Matchbox/0.4.0 (+https://${strHost}/)`,
  };
  return headers;
}

async function acceptFollow(strName: string, strHost: string, x: any, y: any) {
  const strId = crypto.randomUUID();
  const strInbox = x.inbox;
  const res = {
    "@context": "https://www.w3.org/ns/activitystreams",
    id: `https://${strHost}/u/${strName}/s/${strId}`,
    type: "Accept",
    actor: `https://${strHost}/u/${strName}`,
    object: y,
  };
  const headers = await signHeaders(res, strName, strHost, strInbox);
  await postInbox(strInbox, res, headers);
}

async function follow(strName: string, strHost: string, x: any) {
  const strId = crypto.randomUUID();
  const strInbox = x.inbox;
  const res = {
    "@context": "https://www.w3.org/ns/activitystreams",
    id: `https://${strHost}/u/${strName}/s/${strId}`,
    type: "Follow",
    actor: `https://${strHost}/u/${strName}`,
    object: x.id,
  };
  const headers = await signHeaders(res, strName, strHost, strInbox);
  await postInbox(strInbox, res, headers);
}

async function undoFollow(strName: string, strHost: string, x: any) {
  const strId = crypto.randomUUID();
  const strInbox = x.inbox;
  const res = {
    "@context": "https://www.w3.org/ns/activitystreams",
    id: `https://${strHost}/u/${strName}/s/${strId}`,
    type: "Undo",
    actor: `https://${strHost}/u/${strName}`,
    object: {
      type: "Follow",
      object: x.id,
    },
  };
  const headers = await signHeaders(res, strName, strHost, strInbox);
  await postInbox(strInbox, res, headers);
}

async function like(strName: string, strHost: string, x: any, y: any) {
  const strId = crypto.randomUUID();
  const strInbox = y.inbox;
  const res = {
    "@context": "https://www.w3.org/ns/activitystreams",
    id: `https://${strHost}/u/${strName}/s/${strId}`,
    type: "Like",
    actor: `https://${strHost}/u/${strName}`,
    object: x.id,
  };
  const headers = await signHeaders(res, strName, strHost, strInbox);
  await postInbox(strInbox, res, headers);
}

async function undoLike(strName: string, strHost: string, x: any, y: any) {
  const strId = crypto.randomUUID();
  const strInbox = y.inbox;
  const res = {
    "@context": "https://www.w3.org/ns/activitystreams",
    id: `https://${strHost}/u/${strName}/s/${strId}`,
    type: "Undo",
    actor: `https://${strHost}/u/${strName}`,
    object: {
      type: "Like",
      object: x.id,
    },
  };
  const headers = await signHeaders(res, strName, strHost, strInbox);
  await postInbox(strInbox, res, headers);
}

async function announce(strName: string, strHost: string, x: any, y: any) {
  const strId = crypto.randomUUID();
  const strTime = new Date().toISOString().substring(0, 19) + "Z";
  const strInbox = y.inbox;
  const res = {
    "@context": "https://www.w3.org/ns/activitystreams",
    id: `https://${strHost}/u/${strName}/s/${strId}`,
    type: "Announce",
    actor: `https://${strHost}/u/${strName}`,
    published: strTime,
    to: ["https://www.w3.org/ns/activitystreams#Public"],
    cc: [`https://${strHost}/u/${strName}/followers`],
    object: x.id,
  };
  const headers = await signHeaders(res, strName, strHost, strInbox);
  await postInbox(strInbox, res, headers);
}

async function undoAnnounce(strName: string, strHost: string, x: any, y: any) {
  const strId = crypto.randomUUID();
  const strInbox = y.inbox;
  const res = {
    "@context": "https://www.w3.org/ns/activitystreams",
    id: `https://${strHost}/u/${strName}/s/${strId}`,
    type: "Undo",
    actor: `https://${strHost}/u/${strName}`,
    object: {
      type: "Announce",
      object: x.id,
    },
  };
  const headers = await signHeaders(res, strName, strHost, strInbox);
  await postInbox(strInbox, res, headers);
}

async function createNote(strName: string, strHost: string, x: any, y: string) {
  const strId = crypto.randomUUID();
  const strTime = new Date().toISOString().substring(0, 19) + "Z";
  const strInbox = x.inbox;
  const res = {
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
  const headers = await signHeaders(res, strName, strHost, strInbox);
  await postInbox(strInbox, res, headers);
}

async function createNoteMention(strName: string, strHost: string, x: any, y: any, z: string) {
  const strId = crypto.randomUUID();
  const strTime = new Date().toISOString().substring(0, 19) + "Z";
  const strInbox = y.inbox;
  const res = {
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
          name: `@{y.preferredUsername}@${new URL(strInbox).hostname}`,
        },
      ],
    },
  };
  const headers = await signHeaders(res, strName, strHost, strInbox);
  await postInbox(strInbox, res, headers);
}

async function createNoteHashtag(strName: string, strHost: string, x: any, y: string, z: string) {
  const strId = crypto.randomUUID();
  const strTime = new Date().toISOString().substring(0, 19) + "Z";
  const strInbox = x.inbox;
  const res = {
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
  const headers = await signHeaders(res, strName, strHost, strInbox);
  await postInbox(strInbox, res, headers);
}

async function deleteNote(strName: string, strHost: string, x: any, y: string) {
  const strId = crypto.randomUUID();
  const strInbox = x.inbox;
  const res = {
    "@context": "https://www.w3.org/ns/activitystreams",
    id: `https://${strHost}/u/${strName}/s/${strId}/activity`,
    type: "Delete",
    actor: `https://${strHost}/u/${strName}`,
    object: {
      id: y,
      type: "Note",
    },
  };
  const headers = await signHeaders(res, strName, strHost, strInbox);
  await postInbox(strInbox, res, headers);
}

app.get("/", (c) => c.text("Matchbox: ActivityPub@Hono"));

app.get("/u/:strName", (c) => {
  const strName = c.req.param("strName");
  const strHost = new URL(c.req.url).hostname;
  if (strName !== CONFIG.preferredUsername) return c.notFound();
  if (!c.req.header("Accept").includes("application/activity+json")) {
    return c.text(`${strName}: ${CONFIG.name}`);
  }
  const r = {
    "@context": ["https://www.w3.org/ns/activitystreams", "https://w3id.org/security/v1"],
    id: `https://${strHost}/u/${strName}`,
    type: "Person",
    inbox: `https://${strHost}/u/${strName}/inbox`,
    outbox: `https://${strHost}/u/${strName}/outbox`,
    following: `https://${strHost}/u/${strName}/following`,
    followers: `https://${strHost}/u/${strName}/followers`,
    preferredUsername: strName,
    name: CONFIG.name,
    summary: `<p>0.4.0</p>`,
    url: `https://${strHost}/u/${strName}`,
    publicKey: {
      id: `https://${strHost}/u/${strName}`,
      type: "Key",
      owner: `https://${strHost}/u/${strName}`,
      publicKeyPem: public_key_pem,
    },
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
  return c.json(r, 200, { "Content-Type": "activity+json" });
});

app.get("/u/:strName/inbox", (c) => c.body(null, 405));
app.post("/u/:strName/inbox", async (c) => {
  const strName = c.req.param("strName");
  const strHost = new URL(c.req.url).hostname;
  if (strName !== CONFIG.preferredUsername) return c.notFound();
  if (!c.req.header("Content-Type").includes("application/activity+json")) return c.body(null, 400);
  const y = await c.req.json<any>();
  if (new URL(y.actor).protocol !== "https:") return c.body(null, 400);
  console.log(y.id, y.type);
  const x = await getInbox(y.actor);
  if (!x) return c.body(null, 500);
  if (y.type === "Follow") {
    await acceptFollow(strName, strHost, x, y);
    return c.body(null);
  }
  if (y.type === "Like" || y.type === "Announce") return c.body(null);
  if (y.type === "Undo") {
    const z = y.object;
    if (z.type === "Follow") {
      await acceptFollow(strName, strHost, x, z);
      return c.body(null);
    }
    if (z.type === "Like" || z.type === "Announce") return c.body(null);
  }
  if (y.type === "Accept" || y.type === "Reject") return c.body(null);
  if (y.type === "Create" || y.type === "Update" || y.type === "Delete") return c.body(null);
  return c.body(null, 500);
});

app.post("/u/:strName/outbox", (c) => c.body(null, 405));
app.get("/u/:strName/outbox", (c) => {
  const strName = c.req.param("strName");
  const strHost = new URL(c.req.url).hostname;
  if (strName !== CONFIG.preferredUsername) return c.notFound();
  if (!c.req.header("Accept").includes("application/activity+json")) return c.body(null, 400);
  const r = {
    "@context": "https://www.w3.org/ns/activitystreams",
    id: `https://${strHost}/u/${strName}/outbox`,
    type: "OrderedCollection",
    totalItems: 0,
  };
  return c.json(r, 200, { "Content-Type": "activity+json" });
});

app.get("/u/:strName/following", (c) => {
  const strName = c.req.param("strName");
  const strHost = new URL(c.req.url).hostname;
  if (strName !== CONFIG.preferredUsername) return c.notFound();
  if (!c.req.header("Accept").includes("application/activity+json")) return c.body(null, 400);
  const r = {
    "@context": "https://www.w3.org/ns/activitystreams",
    id: `https://${strHost}/u/${strName}/following`,
    type: "OrderedCollection",
    totalItems: 0,
  };
  return c.json(r, 200, { "Content-Type": "activity+json" });
});

app.get("/u/:strName/followers", (c) => {
  const strName = c.req.param("strName");
  const strHost = new URL(c.req.url).hostname;
  if (strName !== CONFIG.preferredUsername) return c.notFound();
  if (!c.req.header("Accept").includes("application/activity+json")) return c.body(null, 400);
  const r = {
    "@context": "https://www.w3.org/ns/activitystreams",
    id: `https://${strHost}/u/${strName}/followers`,
    type: "OrderedCollection",
    totalItems: 0,
  };
  return c.json(r, 200, { "Content-Type": "activity+json" });
});

app.post("/s/:strSecret/u/:strName", async (c) => {
  const strName = c.req.param("strName");
  const strHost = new URL(c.req.url).hostname;
  if (strName !== CONFIG.preferredUsername) return c.notFound();
  if (!c.req.param("strSecret") || c.req.param("strSecret") === "-") return c.notFound();
  if (c.req.param("strSecret") !== ENV.SECRET) return c.notFound();
  if (!c.req.query("id") || !c.req.query("type")) return c.body(null, 400);
  if (new URL(c.req.query("id")).protocol !== "https:") return c.body(null, 400);
  const x = await getInbox(c.req.query("id"));
  if (!x) return c.body(null, 500);
  const t = c.req.query("type");
  if (t === "type") {
    console.log(x.type);
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
    const y = await getInbox(x.attributedTo);
    if (!y) return c.body(null, 500);
    await like(strName, strHost, x, y);
    return c.body(null);
  }
  if (t === "undo_like") {
    const y = await getInbox(x.attributedTo);
    if (!y) return c.body(null, 500);
    await undoLike(strName, strHost, x, y);
    return c.body(null);
  }
  if (t === "announce") {
    const y = await getInbox(x.attributedTo);
    if (!y) return c.body(null, 500);
    await announce(strName, strHost, x, y);
    return c.body(null);
  }
  if (t === "undo_announce") {
    const y = await getInbox(x.attributedTo);
    if (!y) return c.body(null, 500);
    await undoAnnounce(strName, strHost, x, y);
    return c.body(null);
  }
  if (t === "create_note") {
    const y = c.req.query("url");
    if (new URL(y).protocol !== "https:") return c.body(null, 400);
    await createNote(strName, strHost, x, y);
    return c.body(null);
  }
  if (t === "create_note_mention") {
    const y = await getInbox(x.attributedTo);
    if (!y) return c.body(null, 500);
    const z = c.req.query("url");
    if (new URL(z).protocol !== "https:") return c.body(null, 400);
    await createNoteMention(strName, strHost, x, y, z);
    return c.body(null);
  }
  if (t === "create_note_hashtag") {
    const y = c.req.query("url");
    if (new URL(y).protocol !== "https:") return c.body(null, 400);
    const z = c.req.query("tag");
    await createNoteHashtag(strName, strHost, x, y, z);
    return c.body(null);
  }
  if (t === "delete_note") {
    const y = c.req.query("url");
    if (new URL(y).protocol !== "https:") return c.body(null, 400);
    await deleteNote(strName, strHost, x, y);
    return c.body(null);
  }
  return c.body(null, 500);
});

app.get("/.well-known/nodeinfo", (c) => {
  const strHost = new URL(c.req.url).hostname;
  const r = {
    links: [
      {
        href: `https://${strHost}/nodeinfo/2.0.json`,
        rel: "http://nodeinfo.diaspora.software/ns/schema/2.0",
      },
      {
        href: `https://${strHost}/nodeinfo/2.1.json`,
        rel: "http://nodeinfo.diaspora.software/ns/schema/2.1",
      },
    ],
  };
  return c.json(r);
});

app.get("/.well-known/webfinger", (c) => {
  const strName = CONFIG.preferredUsername;
  const strHost = new URL(c.req.url).hostname;
  if (c.req.query("resource") !== `acct:${strName}@${strHost}`) return c.notFound();
  const r = {
    subject: `acct:${strName}@${strHost}`,
    aliases: [
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
    ],
  };
  return c.json(r, 200, { "Content-Type": "jrd+json" });
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

serve(app.fetch, {
  hostname: ENV.HOSTS || "localhost",
  port: Number(ENV.PORT) || 8080,
});
