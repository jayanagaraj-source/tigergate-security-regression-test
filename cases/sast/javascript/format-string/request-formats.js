// Format-string positives for TG-TAINT-JS-FORMAT-STRING: an attacker-controlled first argument
// to console.* / util.format followed by more arguments.
const express = require("express");
const multer = require("multer");
const util = require("util");
const net = require("net");
const { WebSocketServer } = require("ws");
const { Server } = require("socket.io");

const router = express.Router();
const upload = multer({ dest: "/srv/app/incoming" });

router.get("/fmt", (req, res) => {
  console.log(req.query.fmt, req.ip); // JS-FMT-TP-001
  res.sendStatus(204);
});

router.post("/render", (req, res) => {
  const line = util.format(req.body.template, req.ip, Date.now()); // JS-FMT-TP-002
  res.json({ line });
});

router.get("/hdr", (req, res) => {
  console.error(req.headers["x-message"], new Error("context")); // JS-FMT-TP-003
  res.sendStatus(204);
});

router.post("/upload", upload.single("doc"), (req, res) => {
  console.info(req.file.originalname, req.file.size); // JS-FMT-TP-004
  res.sendStatus(201);
});

const wss = new WebSocketServer({ port: 8081 });
wss.on("connection", (ws, request) => {
  ws.on("message", (data) => {
    console.log(data.toString(), request.socket.remoteAddress); // JS-FMT-TP-005
  });
});

const tcp = net.createServer();
tcp.on("connection", (sock) => {
  sock.on("data", (chunk) => {
    console.warn(String(chunk), sock.remotePort); // JS-FMT-TP-006
  });
});

router.get("/opts", (req, res) => {
  res.json({ v: util.formatWithOptions({ colors: false }, req.query.f, req.ip) }); // JS-FMT-TP-007
});

router.get("/prefix", (req, res) => {
  console.debug(`${req.query.prefix}: %s`, req.path); // JS-FMT-TP-008
  res.sendStatus(204);
});

router.get("/trace/:fmt", (req, res) => {
  const fmt = req.params.fmt;
  console.trace(fmt, res.statusCode); // JS-FMT-TP-009
  res.sendStatus(204);
});

const io = new Server(8082);
io.on("connection", function (socket) {
  socket.on("chat", function (msg) {
    console.log(msg, socket.id); // JS-FMT-TP-010
  });
});

router.get("/login-note", (req, res) => {
  console.log("User " + req.query.name + " logged in", Date.now()); // JS-FMT-TP-011
  res.sendStatus(204);
});

module.exports = router;
