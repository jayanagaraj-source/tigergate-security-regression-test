// TG-PATH-TP-006: read stream opened on a user-controlled path.
const express = require("express");
const fs = require("fs");
const path = require("path");

const router = express.Router();

router.get("/stream", (req, res) => {
  fs.createReadStream( // TG-PATH-TP-006
    path.join("/app/files", req.query.file)
  ).pipe(res);
});

module.exports = router;
