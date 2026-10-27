// Reflected XSS positives for TG-TAINT-JS-XSS. Static-scan fixtures: nothing here is started.
// Each sink line ends with its case ID; expected results live in expected/sast.manifest.json.
const express = require("express");
const fs = require("fs");

const router = express.Router();

router.get("/greet", (req, res) => {
  res.send(`<h1>Hello ${req.query.name}</h1>`); // JS-XSS-TP-001
});

router.post("/comment", (req, res) => {
  const html = "<p>" + req.body.comment + "</p>"; // JS-XSS-TP-002
  res.send(html); // JS-XSS-TP-002
});

router.get("/preview", (req, res) => {
  res.type("html").send(req.query.html); // JS-XSS-TP-003
});

router.get("/page", (req, res) => {
  res.type("text/html").send(fs.readFileSync(req.query.page)); // JS-XSS-TP-004
});

router.get("/banner", (req, res) => {
  res.set("Content-Type", "text/html");
  res.send(req.query.banner); // JS-XSS-TP-005
});

router.get("/item/:id", (req, res) => {
  res.status(404).send("<div>No item " + req.params.id + "</div>"); // JS-XSS-TP-006
});

router.get("/card", (req, res) => {
  res.contentType("text/html").send("<section>" + req.query.title + "</section>"); // JS-XSS-TP-007
});

router.get("/legacy", (req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.end("<main>" + req.query.body + "</main>"); // JS-XSS-TP-008
});

router.get("/list", (req, res) => {
  res.write("<li>" + req.query.item + "</li>"); // JS-XSS-TP-009
  res.end();
});

router.get("/note", (req, res) => {
  const text = fs.readFileSync(req.query.note, "utf8"); // JS-PT-TP-021
  res.send(text); // JS-XSS-TP-010
});

router.get("/promo", (req, res) => {
  res.type("html").status(200).send(req.query.promo); // JS-XSS-TP-011
});

router.get("/theme", (req, res) => {
  res.send("<body class=\"" + req.cookies.theme + "\">"); // JS-XSS-TP-012
});

router.get("/agent", (req, res) => {
  res.status(200).type("html").send("<pre>" + req.headers["user-agent"] + "</pre>"); // JS-XSS-TP-013
});

module.exports = router;
