// TG-PATH-TP-010, TP-016: promise-based fs APIs with user-controlled paths.
const express = require("express");
const fs = require("fs");
const path = require("path");

const router = express.Router();

router.get("/async", async (req, res) => {
  const data = await fs.promises.readFile( // TG-PATH-TP-010
    path.join("/app/files", req.query.file)
  );
  res.send(data);
});

router.get("/open", async (req, res) => {
  const handle = await fs.promises.open(path.join("/app/files", req.query.file), "r"); // TG-PATH-TP-016
  await handle.close();
  res.sendStatus(204);
});

module.exports = router;
