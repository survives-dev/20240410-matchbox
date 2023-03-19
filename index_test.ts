import { assertEquals } from "testing/asserts";
import { Hono } from "hono";
import "./index.ts";

Deno.test(async function req() {
  const app = new Hono();
  app.get("/", (c) => c.body(null));
  const res = await app.request("http://localhost:8080/");
  assertEquals(res.status, 200);
});
