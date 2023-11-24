import { Hono } from "hono";
import "./index.ts";

Deno.bench(async function req() {
  const app = new Hono();
  app.get("/", (c) => c.body(null));
  await app.request("/");
});
