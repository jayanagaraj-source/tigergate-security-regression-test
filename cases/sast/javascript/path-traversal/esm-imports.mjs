// ES module imports from node:fs/promises: named and aliased bindings are path sinks too.
import express from "express";
import path from "node:path";
import { readFile, rm as remove } from "node:fs/promises";

const router = express.Router();
const BASE = path.resolve("/srv/app/data");

router.get("/esm/read", async (req, res) => {
  res.send(await readFile(req.query.file)); // JS-PT-TP-003
});

router.delete("/esm/dir", async (req, res) => {
  await remove(req.body.dir, { recursive: true }); // JS-PT-TP-004
  res.sendStatus(204);
});

router.get("/esm/contained", async (req, res) => {
  const target = path.resolve(BASE, String(req.query.file));
  const rel = path.relative(BASE, target);
  if (rel.startsWith("..") || path.isAbsolute(rel)) return res.sendStatus(400);
  res.send(await readFile(target)); // JS-PT-TN-005
});

export default router;
