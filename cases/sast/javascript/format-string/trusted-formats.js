// Format-string negatives: constant formats, internal values, unknown-origin (database / file)
// values, escaped specifiers, IPC messages. Includes the OWASP Juice Shop server.ts:157 shape.
const express = require("express");
const fs = require("fs");
const util = require("util");

const router = express.Router();
const TASKS = ["reindex", "cleanup", "digest"];
const db = { get: async (sql, id) => ({ template: "Order %s shipped", id }) };

router.get("/constant", (req, res) => {
  console.log("%s requested %s", req.ip, req.query.path); // JS-FMT-TN-001 JS-LOG-TP-011
  res.sendStatus(204);
});

router.get("/single", (req, res) => {
  console.log(req.query.msg); // JS-FMT-TN-002 JS-LOG-TP-006
  res.sendStatus(204);
});

// OWASP Juice Shop server.ts:149-161 (collectDurationPromise), reproduced verbatim in shape.
const collectDurationPromise = (name, func) => {
  return async (...args) => {
    try {
      return await func(...args);
    } catch (err) {
      console.error('Error in timed startup function: ' + name, err); // JS-FMT-TN-003
      throw err;
    }
  };
};

function runTasks() {
  for (const taskName of TASKS) {
    console.log("Task " + taskName + " started at", Date.now()); // JS-FMT-TN-004
  }
}

router.get("/order/:id", async (req, res) => {
  const row = await db.get("SELECT template FROM messages WHERE id = ?", req.params.id);
  console.log(row.template, req.params.id); // JS-FMT-TN-005
  res.sendStatus(204);
});

function fileTemplate(count) {
  const tpl = fs.readFileSync("/srv/app/templates/summary.txt", "utf8");
  console.log(tpl, count); // JS-FMT-TN-006
}

router.get("/escaped", (req, res) => {
  console.log(String(req.query.f).replace(/%/g, "%%"), req.ip); // JS-FMT-TN-007
  res.sendStatus(204);
});

router.get("/escaped-all", (req, res) => {
  console.log(String(req.query.f).replaceAll("%", "%%"), req.ip); // JS-FMT-TN-008
  res.sendStatus(204);
});

process.on("message", (m) => {
  console.log(m, process.pid); // JS-FMT-TN-009
});

async function storedComment(Comment, id) {
  const saved = await Comment.findByPk(id);
  console.log(saved.text, id); // JS-FMT-TN-010
}

router.get("/addr", (req, res) => {
  res.json({ addr: util.format("%s:%d", req.query.host, 443) }); // JS-FMT-TN-011
});

module.exports = { router, collectDurationPromise, runTasks, fileTemplate, storedComment };
