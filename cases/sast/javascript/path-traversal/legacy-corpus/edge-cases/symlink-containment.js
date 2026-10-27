// TG-PATH-EDGE-004: lexical containment vs. symlinks.
// Classification: CONTEXT_DEPENDENT.
// The resolve/relative check passes for /app/uploads/link, but if "link" is a
// symlink to /etc, the read escapes. Safe only when attackers cannot create
// symlinks under BASE. realpathContained() shows the symlink-aware alternative.
//
// TG-PATH-EDGE-007: path.normalize() without containment.
// Classification: TP. normalize("../../etc/passwd") keeps the leading "..".
const express = require("express");
const fs = require("fs");
const path = require("path");

const router = express.Router();
const BASE = path.resolve("/app/uploads");

function lexicallyContained(target) {
  const rel = path.relative(BASE, target);
  return rel !== "" && rel !== ".." && !rel.startsWith(".." + path.sep) && !path.isAbsolute(rel);
}

function realpathContained(target) {
  const realBase = fs.realpathSync(BASE);
  const realTarget = fs.realpathSync(target);
  return realTarget.startsWith(realBase + path.sep);
}

router.get("/linked", (req, res) => {
  const target = path.resolve(BASE, String(req.query.file));
  if (!lexicallyContained(target)) {
    throw new Error("Path escapes base directory");
  }
  res.send(fs.readFileSync(target)); // TG-PATH-EDGE-004
});

router.get("/normalized", (req, res) => {
  const cleaned = path.normalize(String(req.query.file));
  res.send(fs.readFileSync(path.join(BASE, cleaned))); // TG-PATH-EDGE-007
});

module.exports = { router, realpathContained };
