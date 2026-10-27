// TG-PATH-EDGE-005: URL-encoded traversal.
// Classification: TP. The check runs on the raw value, then the value is decoded:
// "%2e%2e%2f" passes the check and becomes "../".
//
// TG-PATH-EDGE-006: Windows-style separators.
// Classification: CONTEXT_DEPENDENT (platform). Only "../" is rejected. On POSIX,
// "..\\secret" is a literal filename and stays inside the base; on Windows,
// path.join treats "\\" as a separator and the read escapes.
const express = require("express");
const fs = require("fs");
const path = require("path");

const router = express.Router();

router.get("/encoded", (req, res) => {
  const raw = String(req.query.file);
  if (raw.includes("../")) {
    throw new Error("Traversal rejected");
  }
  const decoded = decodeURIComponent(raw);
  res.send(fs.readFileSync(path.join("/app/files", decoded))); // TG-PATH-EDGE-005
});

router.get("/windows", (req, res) => {
  const name = String(req.query.file);
  if (name.includes("../")) {
    throw new Error("Traversal rejected");
  }
  res.send(fs.readFileSync(path.join("/app/files", name))); // TG-PATH-EDGE-006
});

module.exports = router;
