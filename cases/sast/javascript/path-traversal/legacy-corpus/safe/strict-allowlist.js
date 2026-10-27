// TG-PATH-SAFE-004: user input only selects a key from a fixed allowlist.
const express = require("express");
const fs = require("fs");

const router = express.Router();

const files = {
  report: "/app/files/report.pdf",
  invoice: "/app/files/invoice.pdf"
};

router.get("/doc", (req, res) => {
  const type = String(req.query.type);
  const filename = Object.prototype.hasOwnProperty.call(files, type) ? files[type] : undefined;

  if (!filename) {
    throw new Error("Invalid file");
  }

  res.send(fs.readFileSync(filename)); // TG-PATH-SAFE-004
});

module.exports = router;
