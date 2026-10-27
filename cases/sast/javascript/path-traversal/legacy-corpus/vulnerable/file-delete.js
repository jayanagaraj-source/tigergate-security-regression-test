// TG-PATH-TP-005, TP-015: deletion with user-controlled paths.
const express = require("express");
const fs = require("fs");
const path = require("path");

const router = express.Router();

router.delete("/upload", (req, res) => {
  fs.unlinkSync( // TG-PATH-TP-005
    path.join("/app/uploads", req.query.name)
  );
  res.sendStatus(204);
});

router.delete("/folder", (req, res) => {
  fs.rmSync(path.join("/app/uploads", req.query.dir), { recursive: true }); // TG-PATH-TP-015
  res.sendStatus(204);
});

module.exports = router;
