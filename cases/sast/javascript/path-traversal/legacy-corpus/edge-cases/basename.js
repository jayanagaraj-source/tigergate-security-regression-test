// TG-PATH-EDGE-001: path.basename(userInput).
// Classification: CONTEXT_DEPENDENT.
// basename() strips directory components, so on POSIX the result cannot leave
// /app/uploads. It does NOT prove the caller may read that file (any user can
// fetch any other user's upload by name), and on POSIX a backslash is not a
// separator, so "..\\x" survives as a literal filename.
const express = require("express");
const fs = require("fs");
const path = require("path");

const router = express.Router();

router.get("/basename", (req, res) => {
  const name = path.basename(String(req.query.file));
  res.send(fs.readFileSync(path.join("/app/uploads", name))); // TG-PATH-EDGE-001
});

module.exports = router;
