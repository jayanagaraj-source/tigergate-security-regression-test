// TG-PATH-TP-008, TP-009: validation that looks protective but can be bypassed.
const express = require("express");
const fs = require("fs");
const path = require("path");

const router = express.Router();

router.get("/replace", (req, res) => {
  // replace() removes only the first "../"; "....//" or "../../" still escape.
  const filename = req.query.filename.replace("../", "");
  res.send(fs.readFileSync(path.join("/app/uploads", filename))); // TG-PATH-TP-008
});

router.get("/prefix", (req, res) => {
  const base = "/app/uploads";
  const target = path.resolve(base, req.query.file);

  // Prefix check without a separator: "/app/uploads-private/x" passes.
  if (target.startsWith(base)) {
    res.send(fs.readFileSync(target)); // TG-PATH-TP-009
  }
});

module.exports = router;
