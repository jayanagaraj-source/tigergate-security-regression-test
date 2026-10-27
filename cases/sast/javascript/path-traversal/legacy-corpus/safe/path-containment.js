// TG-PATH-SAFE-006: lexical containment using path.resolve + path.relative.
// Assumption: nothing inside BASE is a symlink that an attacker can create or
// redirect (uploads are written by the app with server-generated names). If that
// assumption does not hold, use the realpath variant in edge-cases/symlink-containment.js.
const express = require("express");
const fs = require("fs");
const path = require("path");

const router = express.Router();
const BASE = path.resolve("/app/uploads");

router.get("/contained", (req, res) => {
  const target = path.resolve(BASE, String(req.query.file));
  const rel = path.relative(BASE, target);

  if (rel === "" || rel === ".." || rel.startsWith(".." + path.sep) || path.isAbsolute(rel)) {
    throw new Error("Path escapes base directory");
  }

  res.send(fs.readFileSync(target)); // TG-PATH-SAFE-006
});

module.exports = router;
