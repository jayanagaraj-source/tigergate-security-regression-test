// TG-PATH-SAFE-005, SAFE-013: strict format validation before the path is built.
const express = require("express");
const fs = require("fs");
const path = require("path");

const router = express.Router();

router.get("/orders/:id", (req, res) => {
  const id = req.params.id;

  if (!/^[0-9]{1,10}$/.test(id)) {
    throw new Error("Invalid ID");
  }

  res.send(fs.readFileSync( // TG-PATH-SAFE-005
    path.join("/app/orders", `${id}.json`)
  ));
});

router.get("/notes", (req, res) => {
  const name = String(req.query.name);

  // Only [a-z0-9_-] plus a fixed extension: no separators, no dots before .txt.
  if (!/^[a-z0-9_-]{1,64}\.txt$/.test(name)) {
    throw new Error("Invalid filename");
  }

  res.send(fs.readFileSync(path.join("/app/notes", name))); // TG-PATH-SAFE-013
});

module.exports = router;
