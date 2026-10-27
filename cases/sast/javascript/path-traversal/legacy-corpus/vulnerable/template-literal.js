// TG-PATH-TP-003: route parameter interpolated into a template-literal path.
const express = require("express");
const fs = require("fs");

const router = express.Router();

router.get("/files/:name", (req, res) => {
  const filename = `/app/files/${req.params.name}`;
  res.send(fs.readFileSync(filename)); // TG-PATH-TP-003
});

module.exports = router;
