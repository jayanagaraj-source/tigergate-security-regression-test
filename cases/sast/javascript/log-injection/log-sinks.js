// Log injection (CWE-117) for TG-TAINT-JS-LOG-INJECTION: request, upload and socket values written to
// console.* raw (positives) versus neutralized, structured or internal values (negatives).
const express = require("express");
const multer = require("multer");
const util = require("util");
const pino = require("pino");
const { WebSocketServer } = require("ws");
const { Server } = require("socket.io");

const router = express.Router();
const upload = multer({ dest: "/srv/app/incoming" });
const logger = pino();

router.post("/login", (req, res) => {
  console.log("login failed for " + req.body.username); // JS-LOG-TP-001
  res.sendStatus(401);
});

router.get("/track", (req, res) => {
  console.warn(`agent=${req.query.agent}`); // JS-LOG-TP-002
  res.sendStatus(204);
});

router.post("/upload", upload.single("doc"), (req, res) => {
  console.info("upload:", req.file.originalname); // JS-LOG-TP-003
  res.sendStatus(201);
});

const wss = new WebSocketServer({ port: 8083 });
wss.on("connection", (ws) => {
  ws.on("message", (data) => {
    console.log("received:", data.toString()); // JS-LOG-TP-004
  });
});

router.get("/ua", (req, res) => {
  console.error(req.headers["user-agent"]); // JS-LOG-TP-005
  res.sendStatus(204);
});

router.get("/user/:user", (req, res) => {
  const u = req.params.user;
  console.debug("profile view", u); // JS-LOG-TP-007
  res.sendStatus(204);
});

router.get("/strip-tags", (req, res) => {
  console.log("search", String(req.query.q).replace(/</g, "")); // JS-LOG-TP-008
  res.sendStatus(204);
});

router.get("/session", (req, res) => {
  console.trace("session cookie", req.cookies.sid); // JS-LOG-TP-009
  res.sendStatus(204);
});

const io = new Server(8084);
io.on("connection", (socket) => {
  socket.on("rename", (newName) => {
    console.info("rename to", newName); // JS-LOG-TP-010
  });
});

router.get("/pino", (req, res) => {
  logger.info("lookup " + req.query.term); // JS-LOG-TP-012
  res.sendStatus(204);
});

router.post("/login-json", (req, res) => {
  console.log("login failed for " + JSON.stringify(req.body.username)); // JS-LOG-TN-001
  res.sendStatus(401);
});

router.get("/track-clean", (req, res) => {
  console.warn("agent=" + String(req.query.agent).replace(/[\r\n]/g, "")); // JS-LOG-TN-002
  res.sendStatus(204);
});

router.get("/q", (req, res) => {
  console.log("q", encodeURIComponent(req.query.q)); // JS-LOG-TN-003
  res.sendStatus(204);
});

router.get("/page", (req, res) => {
  console.log("page", parseInt(req.query.page, 10)); // JS-LOG-TN-004
  res.sendStatus(204);
});

router.get("/obj", (req, res) => {
  console.log({ user: req.query.user }); // JS-LOG-TN-005
  res.sendStatus(204);
});

router.get("/arr", (req, res) => {
  console.log([req.query.a, req.query.b]); // JS-LOG-TN-006
  res.sendStatus(204);
});

function startup() {
  console.log("service started"); // JS-LOG-TN-007
}

router.get("/inspect", (req, res) => {
  console.log("filter", util.inspect(req.query.filter)); // JS-LOG-TN-008
  res.sendStatus(204);
});

function runTask(taskName) {
  console.log("task", taskName); // JS-LOG-TN-009
}

router.get("/num", (req, res) => {
  console.log("n", Number(req.query.n)); // JS-LOG-TN-010
  res.sendStatus(204);
});

process.on("message", (msg) => {
  console.log("ipc", msg); // JS-LOG-TN-011
});

router.get("/ctrl", (req, res) => {
  console.log("q=" + String(req.query.q).replace(/[\x00-\x1f\x7f]/g, "?")); // JS-LOG-TN-012
  res.sendStatus(204);
});

module.exports = { router, startup, runTask };
