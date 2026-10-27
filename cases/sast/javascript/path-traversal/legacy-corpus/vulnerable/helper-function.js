// TG-PATH-TP-007: tainted value flows through a helper before reaching the sink.
const express = require("express");
const fs = require("fs");
const path = require("path");

const router = express.Router();

function buildPath(name) {
  return path.join("/app/files", name);
}

router.get("/helper", (req, res) => {
  const filename = buildPath(req.query.filename);
  res.send(fs.readFileSync(filename)); // TG-PATH-TP-007
});

module.exports = router;
