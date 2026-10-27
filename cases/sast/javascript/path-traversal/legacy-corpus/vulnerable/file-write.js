// TG-PATH-TP-004, TP-013, TP-014: write, rename and copy with user-controlled paths.
const express = require("express");
const fs = require("fs");
const path = require("path");

const router = express.Router();

router.post("/write", (req, res) => {
  fs.writeFileSync( // TG-PATH-TP-004
    path.join("/app/uploads", req.body.filename),
    req.body.content
  );
  res.sendStatus(204);
});

router.post("/rename", (req, res) => {
  // Both source and destination are attacker-controlled.
  fs.renameSync(path.join("/app/uploads", req.body.from), path.join("/app/uploads", req.body.to)); // TG-PATH-TP-013
  res.sendStatus(204);
});

router.post("/copy", (req, res) => {
  fs.copyFileSync(path.join("/app/uploads", req.body.src), "/app/backup/latest.bin"); // TG-PATH-TP-014
  res.sendStatus(204);
});

module.exports = router;
