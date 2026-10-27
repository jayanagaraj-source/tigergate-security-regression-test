// TG-PATH-TP-001: user-controlled filename passed straight to fs.readFile.
// Fixture only: the router is exported, never mounted or listening.
const express = require("express");
const fs = require("fs");

const router = express.Router();

router.get("/file", (req, res) => {
  // Source: req.query.filename -> Sink: fs.readFile
  fs.readFile(req.query.filename, (err, data) => { // TG-PATH-TP-001
    res.send(data);
  });
});

module.exports = router;
