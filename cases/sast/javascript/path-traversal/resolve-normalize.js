// Path traversal cases added for the TG-TAINT-JS-PATH-TRAVERSAL rule (beyond the legacy corpus).
// path.resolve / path.join / path.normalize do not make a request value safe on their own.
const express = require("express");
const fs = require("fs");
const path = require("path");
const { readFileSync } = require("fs");

const router = express.Router();
const BASE = path.resolve("/srv/app/uploads");
const PUBLIC_DIR = path.resolve("/srv/app/public");
const TEMPLATE = "/srv/app/templates/invoice.html";
const REPORTS = { daily: "daily.csv", weekly: "weekly.csv" };

router.get("/resolve", (req, res) => {
  const target = path.resolve(BASE, req.query.file);
  res.send(fs.readFileSync(target)); // JS-PT-TP-001
});

router.get("/normalize/:p", (req, res) => {
  const cleaned = path.normalize(req.params.p);
  fs.readFile(cleaned, (err, data) => res.send(data)); // JS-PT-TP-002
});

router.post("/save", async (req, res) => {
  await fs.promises.writeFile(req.body.path, req.body.content); // JS-PT-TP-005
  res.sendStatus(204);
});

router.get("/send", (req, res) => {
  res.sendFile(req.query.file); // JS-PT-TP-006
});

router.post("/export", (req, res) => {
  fs.copyFile(TEMPLATE, req.body.dest, () => res.sendStatus(204)); // JS-PT-TP-007
});

router.get("/destructured", (req, res) => {
  const size = readFileSync(req.query.file).length; // JS-PT-TP-008
  res.json({ size });
});

router.get("/join-resolve", (req, res) => {
  const target = path.resolve(path.join(BASE, req.query.file));
  res.send(fs.readFileSync(target)); // JS-PT-TP-009
});

router.get("/half-check", (req, res) => {
  const target = path.resolve(BASE, req.query.file);
  const rel = path.relative(BASE, target);
  if (rel.startsWith("..")) throw new Error("outside base");
  res.send(fs.readFileSync(target)); // JS-PT-TP-010
});

router.get("/header", (req, res) => {
  fs.createReadStream(req.headers["x-file"]).pipe(res); // JS-PT-TP-011
});

router.get("/public", (req, res) => {
  res.sendFile(req.query.file, { root: PUBLIC_DIR }); // JS-PT-TN-001
});

router.get("/numeric", (req, res) => {
  const id = parseInt(req.query.id, 10);
  res.send(fs.readFileSync(path.join(BASE, id + ".json"))); // JS-PT-TN-002
});

router.get("/report", (req, res) => {
  const name = REPORTS[req.query.type];
  res.send(fs.readFileSync(path.join(BASE, name))); // JS-PT-TN-003
});

router.get("/strict-name", (req, res) => {
  const name = String(req.query.name);
  if (!/^[a-z0-9_-]+\.txt$/.test(name)) return res.sendStatus(400);
  res.send(fs.readFileSync(path.join(BASE, name))); // JS-PT-TN-004
});

router.get("/coerced", (req, res) => {
  const n = Number(req.query.n);
  res.send(fs.readFileSync(BASE + "/" + n + ".txt")); // JS-PT-TN-006
});

router.get("/template", async (req, res) => {
  res.send(await fs.promises.readFile(TEMPLATE, "utf8")); // JS-PT-TN-007
});

router.get("/archive", (req, res) => {
  res.download(req.query.file, { root: PUBLIC_DIR }); // JS-PT-TN-008
});

const cache = { readFile: (key) => key.toUpperCase() };
router.get("/cache", (req, res) => {
  res.json({ v: cache.readFile(req.query.key) }); // JS-PT-TN-009
});

module.exports = router;
