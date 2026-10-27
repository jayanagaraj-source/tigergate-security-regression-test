// TG-PATH-TP-002: path.join does not stop "../" segments from escaping the base.
const express = require("express");
const fs = require("fs");
const path = require("path");

const router = express.Router();

router.get("/upload", (req, res) => {
  const filename = path.join(
    "/app/uploads",
    req.query.filename
  );
  res.send(fs.readFileSync(filename)); // TG-PATH-TP-002
});

module.exports = router;
