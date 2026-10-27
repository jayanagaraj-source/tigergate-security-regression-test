// TG-PATH-TP-011: Express res.download with a user-controlled path (not an fs.* call).
const express = require("express");
const path = require("path");

const router = express.Router();

router.get("/download", (req, res) => {
  res.download( // TG-PATH-TP-011
    path.join("/app/files", req.query.filename)
  );
});

module.exports = router;
